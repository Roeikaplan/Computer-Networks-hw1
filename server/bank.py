"""In-memory bank: accounts, authentication, balances, transfers, history,
calendar-monthly standing orders and loans.

Designed for a single-threaded select()-based server: no locks. All timestamps
come from the bank's own ``SimTime`` clock. Due standing orders and loan
repayments are processed when the main loop calls ``run_due()`` (and after
the operator advances the bank date via ``on_console_line``).
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Dict, List, Optional, Tuple

from server_utils import SimTime

log = logging.getLogger("bank")

# ----------------------------- constants ------------------------------
CENT = Decimal("0.01")
MAX_AMOUNT = Decimal("10000000.00")          # upper limit for a single amount

TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
TOKEN_LENGTH = 10

NAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")
AMOUNT_RE = re.compile(r"[0-9]+(\.[0-9]{1,2})?")   # [0-9], not \d: \d also matches non-ASCII digits
COUNT_RE = re.compile(r"[0-9]{1,4}")               # standing order payment count, "0" = until cancelled
MIN_PASSWORD_LEN = 4

LOAN_DAYS = 30                       # a loan is repaid automatically this many bank days later
LOAN_FEE = Decimal("1.05")           # repay = principal * 1.05
OVERDRAFT_RATE = Decimal("0.0005")   # 0.05% of a negative balance, charged daily
MAX_DAYS_PER_COMMAND = 366           # most days one console command may advance

PBKDF2_ITERATIONS = 50_000   # keeps one login well under 0.1 s, so the select() loop isn't stalled

CASH = "CASH"                # counterparty for deposits and withdrawals
BANK = "BANK"                # counterparty for loans, repayments and interest

# History entry types (same strings as TxType in client/connection.py)
DEPOSIT = "DEPOSIT"
WITHDRAWAL = "WITHDRAWAL"
TRANSFER_IN = "TRANSFER_IN"
TRANSFER_OUT = "TRANSFER_OUT"
CHARGE = "CHARGE"
LOAN = "LOAN"
LOAN_REPAYMENT = "LOAN_REPAYMENT"
OVERDRAFT_INTEREST = "OVERDRAFT_INTEREST"


class BankError(Exception):
    """A request broke a bank rule. ``str(self)`` is shown to the user."""


# ------------------------------ helpers -------------------------------
def money(value: Decimal) -> str:
    """Format a Decimal as a two-decimal string, e.g. ``"-12.50"``."""
    return str(value.quantize(CENT, rounding=ROUND_HALF_UP))


def parse_amount(text) -> Decimal:
    """Validate a positive amount string from a client and return it as a Decimal.

    Accepts "100", "99.9", "99.90". Rejects "0", "-5", "1e3", "abc", "1.234",
    non-strings, and anything above MAX_AMOUNT.
    """
    if not isinstance(text, str) or not AMOUNT_RE.fullmatch(text):
        raise BankError("Invalid amount")
    value = Decimal(text).quantize(CENT)
    if value <= 0 or value > MAX_AMOUNT:
        raise BankError("Invalid amount")
    return value


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def next_month(d: date, day: int) -> date:
    """The date one month after ``d``, on day ``day`` of that month.

    If the month is too short, use its last day:
    next_month(2026-01-31, 31) -> 2026-02-28, then next_month(2026-02-28, 31) -> 2026-03-31.
    """
    year, month = (d.year + 1, 1) if d.month == 12 else (d.year, d.month + 1)
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(day, last_day))


# ------------------------------- data ---------------------------------
@dataclass
class HistoryEntry:
    ts: float              # simulated Unix time, used for the history filter
    time: str              # the same moment as "YYYY-MM-DD HH:MM:SS"
    type: str              # one of the history entry types above
    party: str             # other account's token, CASH or BANK
    party_name: str
    amount: Decimal        # signed: + money in, - money out
    balance: Decimal       # balance after this entry
    note: str = ""

    def to_wire(self) -> dict:
        return {"time": self.time, "type": self.type, "party": self.party,
                "party_name": self.party_name, "amount": money(self.amount),
                "balance": money(self.balance), "note": self.note}


@dataclass
class Account:
    token: str
    name: str
    salt: bytes
    pw_hash: bytes
    balance: Decimal = Decimal("0.00")
    history: List[HistoryEntry] = field(default_factory=list)


@dataclass
class StandingOrder:
    so_id: int
    payer: str             # token of the account that pays
    payee: str             # token of the account that receives
    amount: Decimal        # per payment
    total: int             # number of payments, 0 = until cancelled
    day: int               # day of month it was created on; later payments keep it
    next_run: date         # date of the next payment
    executed: int = 0      # payments made so far

    def remaining(self) -> Optional[int]:
        return None if self.total == 0 else self.total - self.executed


@dataclass
class Loan:
    loan_id: int
    token: str             # borrower
    principal: Decimal
    repay: Decimal         # principal * 1.05
    taken_on: date
    due_on: date           # taken_on + 30 days


# ------------------------------- bank ---------------------------------
class Bank:
    def __init__(self, start_date: date):
        self.clock = SimTime(start_date=start_date)
        self.accounts: Dict[str, Account] = {}
        self.standing_orders: Dict[int, StandingOrder] = {}   # active orders only
        self.loans: Dict[int, Loan] = {}                      # unpaid loans only
        self._next_so_id = 1
        self._next_loan_id = 1
        # Last bank date whose day-start work (payments) is done. run_due() catches up from here.
        self._processed = self.clock.today()

    # ---------- internal ----------
    def _account(self, token: str) -> Account:
        """The account for ``token``, or BankError if there is none."""
        acct = self.accounts.get(token) if isinstance(token, str) else None
        if acct is None:
            raise BankError("Unknown user id")
        return acct

    def _new_token(self) -> str:
        while True:
            token = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))
            if token not in self.accounts:
                return token

    def _apply(self, acct: Account, delta: Decimal, tx_type: str,
               party: str, party_name: str, note: str = "") -> None:
        """Change a balance and record it in the history.

        Every balance change in the bank goes through here, so the history
        always matches the balance.
        """
        acct.balance += delta
        now = self.clock.now()
        acct.history.append(HistoryEntry(
            ts=now, time=self.clock.format(when=now), type=tx_type,
            party=party, party_name=party_name, amount=delta,
            balance=acct.balance, note=note))

    # ---------- accounts ----------
    def register(self, name, password) -> str:
        """Create an account and return its new token. Does not log in."""
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise BankError("Invalid user name (3-20 letters, digits or _)")
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
            raise BankError(f"Password must be at least {MIN_PASSWORD_LEN} characters")
        salt = secrets.token_bytes(16)
        token = self._new_token()
        self.accounts[token] = Account(token=token, name=name, salt=salt,
                                       pw_hash=hash_password(password, salt))
        log.info("registered %s (%s)", token, name)
        return token

    def login(self, token, password) -> str:
        """Check the credentials and return the account name."""
        acct = self.accounts.get(token) if isinstance(token, str) else None
        if acct is None or not isinstance(password, str) or \
                not hmac.compare_digest(hash_password(password, acct.salt), acct.pw_hash):
            # Same message for both cases, so the reply doesn't reveal which tokens exist.
            raise BankError("Wrong user id or password")
        return acct.name

    # ---------- money ----------
    def balance(self, token: str) -> str:
        return money(self._account(token).balance)

    def deposit(self, token: str, amount) -> str:
        acct = self._account(token)
        value = parse_amount(amount)
        self._apply(acct, value, DEPOSIT, CASH, CASH)
        return money(acct.balance)

    def withdraw(self, token: str, amount) -> str:
        """Withdraw cash. The balance may go negative (overdraft)."""
        acct = self._account(token)
        value = parse_amount(amount)
        self._apply(acct, -value, WITHDRAWAL, CASH, CASH)
        return money(acct.balance)

    def transfer(self, token: str, target, amount) -> str:
        """Send money to another account and return the sender's new balance."""
        sender = self._account(token)
        if target == token:
            raise BankError("Cannot transfer to yourself")
        receiver = self._account(target)
        value = parse_amount(amount)
        self._apply(sender, -value, TRANSFER_OUT, receiver.token, receiver.name)
        self._apply(receiver, value, TRANSFER_IN, sender.token, sender.name)
        return money(sender.balance)

    def history(self, token: str, from_ts=None, to_ts=None) -> List[dict]:
        """History entries, oldest first, optionally limited to [from_ts, to_ts]."""
        acct = self._account(token)
        for bound in (from_ts, to_ts):
            # bool is a subclass of int, so exclude it explicitly
            if bound is not None and (isinstance(bound, bool) or not isinstance(bound, (int, float))):
                raise BankError("Invalid time range")
        return [e.to_wire() for e in acct.history
                if (from_ts is None or e.ts >= from_ts) and (to_ts is None or e.ts <= to_ts)]

    # ---------- standing orders ----------
    def so_create(self, token: str, target, amount, count) -> int:
        """Create a monthly standing order, make its first payment now, return its id."""
        payer = self._account(token)
        if target == token:
            raise BankError("Cannot transfer to yourself")
        payee = self._account(target)
        value = parse_amount(amount)
        if not isinstance(count, str) or not COUNT_RE.fullmatch(count):
            raise BankError("Invalid payment count")
        today = self.clock.today()
        so = StandingOrder(so_id=self._next_so_id, payer=payer.token, payee=payee.token,
                           amount=value, total=int(count), day=today.day, next_run=today)
        self._next_so_id += 1
        self.standing_orders[so.so_id] = so
        log.info("standing order #%d: %s -> %s, %s x %s", so.so_id, payer.token,
                 payee.token, money(value), count)
        self._pay_standing_order(so)          # the first payment is made today
        return so.so_id

    def so_list(self, token: str) -> List[dict]:
        """Active standing orders paid by this account."""
        self._account(token)
        return [{"so_id": so.so_id, "target": so.payee,
                 "target_name": self.accounts[so.payee].name, "amount": money(so.amount),
                 "executed": so.executed, "remaining": so.remaining(),
                 "next_run": so.next_run.isoformat()}
                for so in self.standing_orders.values() if so.payer == token]

    def so_cancel(self, token: str, so_id) -> None:
        self._account(token)
        so = self.standing_orders.get(so_id) if type(so_id) is int else None
        if so is None or so.payer != token:
            # Someone else's order gets the same reply, so ids of other users' orders stay hidden.
            raise BankError("Unknown standing order")
        del self.standing_orders[so_id]
        log.info("standing order #%d cancelled", so_id)

    def _pay_standing_order(self, so: StandingOrder) -> None:
        """Make one payment of ``so`` and schedule the next one (or finish the order)."""
        payer, payee = self.accounts[so.payer], self.accounts[so.payee]
        note = f"Standing order #{so.so_id}"
        self._apply(payer, -so.amount, CHARGE, payee.token, payee.name, note)
        self._apply(payee, so.amount, TRANSFER_IN, payer.token, payer.name, note)
        so.executed += 1
        if so.remaining() == 0:
            del self.standing_orders[so.so_id]
            log.info("standing order #%d finished", so.so_id)
        else:
            so.next_run = next_month(so.next_run, so.day)

    # ---------- loans ----------
    def loan(self, token: str, amount) -> Tuple[int, str]:
        """Credit a loan now. Returns (loan_id, new balance)."""
        acct = self._account(token)
        value = parse_amount(amount)
        if self._in_debt(acct):
            raise BankError("Loan refused: you already owe the bank")
        today = self.clock.today()
        ln = Loan(loan_id=self._next_loan_id, token=acct.token, principal=value,
                  repay=(value * LOAN_FEE).quantize(CENT, rounding=ROUND_HALF_UP),
                  taken_on=today, due_on=today + timedelta(days=LOAN_DAYS))
        self._next_loan_id += 1
        self.loans[ln.loan_id] = ln
        self._apply(acct, value, LOAN, BANK, BANK, f"Loan #{ln.loan_id}")
        log.info("loan #%d: %s borrowed %s, repays %s on %s", ln.loan_id, acct.token,
                 money(ln.principal), money(ln.repay), ln.due_on)
        return ln.loan_id, money(acct.balance)

    def loans_of(self, token: str) -> List[dict]:
        """Unpaid loans of this account."""
        self._account(token)
        return [{"loan_id": ln.loan_id, "principal": money(ln.principal),
                 "repay": money(ln.repay), "taken_on": ln.taken_on.isoformat(),
                 "due_on": ln.due_on.isoformat()}
                for ln in self.loans.values() if ln.token == token]

    def _in_debt(self, acct: Account) -> bool:
        """In debt = negative balance or an unpaid loan."""
        return acct.balance < 0 or any(ln.token == acct.token for ln in self.loans.values())

    def _repay_loan(self, ln: Loan) -> None:
        """Take back principal + 5%, even if the balance goes negative."""
        acct = self.accounts[ln.token]
        self._apply(acct, -ln.repay, LOAN_REPAYMENT, BANK, BANK, f"Loan #{ln.loan_id}")
        del self.loans[ln.loan_id]
        log.info("loan #%d repaid", ln.loan_id)
    # ---------- bank days ----------
    def announce_date(self) -> None:
        """Print the current bank date on the server console."""
        today = self.clock.today()
        print(f"Bank date: {today.isoformat()} ({today:%A})", flush=True)

    def on_console_line(self, line: str) -> None:
        """Operator input. Enter = next day, a number N + Enter = advance N days."""
        text = line.strip()
        if text == "":
            days = 1
        elif text.isdecimal() and 1 <= int(text) <= MAX_DAYS_PER_COMMAND:   # not isdigit(): int("²") fails
            days = int(text)
        else:
            print(f"Press Enter for the next day, or type a number of days (1-{MAX_DAYS_PER_COMMAND}).",
                  flush=True)
            return
        for _ in range(days):
            self.clock.advance_day()
            self.run_due()            # each day is processed before the next one starts
        self.announce_date()

    def run_due(self) -> None:
        """Process every bank day that has started since the last call.

        Called on every server loop iteration. The bank date changes when the
        operator advances it, but also by itself at real midnight, since SimTime
        keeps flowing with wall-clock time. For each new day, in this order:
          1. overdraft interest for the day that ended,
          2. move to the new day,
          3. standing orders due on or before it,
          4. loan repayments due on or before it.
        """
        today = self.clock.today()
        while self._processed < today:
            self._charge_overdraft_interest()
            self._processed += timedelta(days=1)
            self._run_standing_orders(self._processed)
            self._run_loan_repayments(self._processed)

    def _charge_overdraft_interest(self) -> None:
        for acct in self.accounts.values():
            if acct.balance < 0:
                charge = (-acct.balance * OVERDRAFT_RATE).quantize(CENT, rounding=ROUND_HALF_UP)
                if charge > 0:        # a balance above -10.00 gives less than half a cent
                    self._apply(acct, -charge, OVERDRAFT_INTEREST, BANK, BANK,
                                "Daily overdraft interest (0.05%)")

    def _run_standing_orders(self, day: date) -> None:
        # list(...) because paying may delete a finished order from the dict
        for so in list(self.standing_orders.values()):
            while so.so_id in self.standing_orders and so.next_run <= day:
                self._pay_standing_order(so)

    def _run_loan_repayments(self, day: date) -> None:
        for ln in list(self.loans.values()):
            if ln.due_on <= day:
                self._repay_loan(ln)
