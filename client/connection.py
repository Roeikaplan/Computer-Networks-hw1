"""Network layer of the bank client.

Public methods return built-in Python values (str, int, list, tuple, None), except
history types which use the ``TxType`` enum so the GUI does not deal with raw
type strings. On a rejected or unexpected server reply they raise ``RequestFailed``
with a user-facing message. Transport failures raise ``ConnectionError`` / ``OSError``.
"""
from __future__ import annotations

import json
import socket
import struct
from enum import Enum
from typing import Callable, List, Optional, Tuple, Union

# see PROTOCOL.md
HEADER = struct.Struct("!I")      # 4-byte big-endian body length
MAX_REQUEST = 64 * 1024           # server drops the connection above this
MAX_REPLY = 1024 * 1024
RECV_SIZE = 64 * 1024
CONNECT_TIMEOUT = 5.0
REPLY_TIMEOUT = 10.0


class TxType(Enum):
    """Finite set of history entry types the GUI understands.

    ``req_history`` returns these instead of free-form strings. The GUI turns
    them into display text; wire values from the server are mapped here.
    """

    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"
    TRANSFER_IN = "TRANSFER_IN"
    TRANSFER_OUT = "TRANSFER_OUT"
    CHARGE = "CHARGE"
    LOAN = "LOAN"
    LOAN_REPAYMENT = "LOAN_REPAYMENT"
    OVERDRAFT_INTEREST = "OVERDRAFT_INTEREST"

# --------------------------Error Classes --------------------------
# ---------Raise these for the GUI to react appropriately.----------
class ProtocolError(Exception):
    """The server sent something that cannot be parsed."""


class RequestFailed(Exception):
    """The server rejected the request. ``str(self)`` is safe to show to the user."""


def _field(obj: dict, key: str, kind: type, optional: bool = False):
    """Get obj[key] and check its type. optional=True also allows null."""
    value = obj.get(key)
    if value is None and optional:
        return None
    if type(value) is not kind:         # exact type, so true/false don't count as ints
        raise ProtocolError(f"Reply field '{key}' is missing or has the wrong type")
    return value


def _items(reply: dict, key: str) -> List[dict]:
    items = reply.get(key)
    if type(items) is not list or not all(type(item) is dict for item in items):
        raise ProtocolError(f"Reply field '{key}' is not a list of objects")
    return items

### Do not remove any of the existing functions or change their signatures. ###
### You can add new functions and classes if needed. ###
class Connection:
    """One TCP connection to the bank server.

    Not thread-safe: call from a single thread (the GUI network worker, or a shell).
    """

    def __init__(self):
        self._sock: Optional[socket.socket] = None

    @property
    def connected(self) -> bool:
        """Returns True if a TCP connection to the server is currently open."""
        return self._sock is not None

    def connect(self, host: str, port: int) -> None:
        """Open a TCP connection to the bank server.

        Args:
            host: Server hostname or IP (e.g. ``\"127.0.0.1\"``).
            port: Server TCP port (e.g. ``5050``).
            timeout: Seconds to wait for the TCP handshake.

        Returns:
            None.

        Raises:
            OSError / ConnectionError: if the server cannot be reached.
        """
        self.close()
        try:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except socket.timeout as err:
            raise ConnectionError(
                f"No answer from {host}:{port} within {CONNECT_TIMEOUT:g} seconds") from err
        sock.settimeout(REPLY_TIMEOUT)
        self._sock = sock

    def close(self) -> None:
        """Close the TCP connection if one is open. Safe to call more than once.

        Returns:
            None.
        """
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _request(self, op: str, **fields) -> dict:
        """Send a request and wait for the reply. Raises RequestFailed if ok is false."""
        if self._sock is None:
            raise ConnectionError("Not connected to the server")
        body = json.dumps({"op": op, **fields}, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REQUEST:
            raise RequestFailed("Request too large")
        try:
            self._send_all(HEADER.pack(len(body)) + body)
            reply = self._recv_reply()
        except socket.timeout as err:
            # if the reply shows up later we'd take it as the answer to the next
            # request, so the connection is useless now
            self.close()
            raise ConnectionError(f"No reply from the server within {REPLY_TIMEOUT:g} seconds") from err
        except BaseException:
            # anything else mid-request also leaves the stream out of sync
            self.close()
            raise

        ok = reply.get("ok")
        if ok is True:
            return reply
        if ok is False:
            error = reply.get("error")
            if not isinstance(error, str):
                raise ProtocolError("Error reply without a message")
            raise RequestFailed(error)
        raise ProtocolError("Reply has no valid 'ok' field")

    def _send_all(self, data: bytes) -> None:
        # like sendall(), written out so a short send is handled explicitly
        view = memoryview(data)
        while view:
            sent = self._sock.send(view)
            if sent == 0:
                raise ConnectionError("The connection was closed while sending")
            view = view[sent:]

    def _recv_reply(self) -> dict:
        (length,) = HEADER.unpack(self._recv_exact(HEADER.size))
        if not 1 <= length <= MAX_REPLY:
            raise ProtocolError(f"Bad reply length: {length}")
        body = self._recv_exact(length)
        try:
            reply = json.loads(body.decode("utf-8"))
        except (ValueError, RecursionError) as err:
            raise ProtocolError("Reply is not valid JSON") from err
        if not isinstance(reply, dict):
            raise ProtocolError("Reply is not a JSON object")
        return reply

    def _recv_exact(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            chunk = self._sock.recv(min(n - len(data), RECV_SIZE))
            if not chunk:
                raise ConnectionError("The server closed the connection")
            data += chunk
        return bytes(data)

    def req_register(self, user: str, password: str) -> str:
        """Register a new account.

        Args:
            user: Account name (3-20 letters/digits/``_``). Need not be unique.
            password: Password (at least 4 characters).

        Returns:
            The new unique user id (token), a 10-character ``A-Z0-9`` string.

        Raises:
            RequestFailed: registration rejected (bad username/password, …).
            ConnectionError: connection lost.
        """
        reply = self._request("register", name=user, password=password)
        return _field(reply, "token", str)

    def req_login(self, token: str, password: str) -> str:
        """Log in to an existing account on this connection.

        Args:
            token: User id (account id) issued at registration.
            password: Account password.

        Returns:
            The account name (username) for this user id.

        Raises:
            RequestFailed: wrong credentials / unknown user id.
            ConnectionError: connection lost.
        """
        reply = self._request("login", token=token, password=password)
        return _field(reply, "name", str)

    def req_logout(self) -> None:
        """Log out and close the connection.

        Returns:
            None.
        """
        if not self.connected:
            return
        try:
            self._request("logout")
        except RequestFailed:
            pass                    # already logged out
        finally:
            self.close()

    def req_get_balance(self) -> str:
        """Fetch the logged-in account's balance.

        Returns:
            Balance string with two decimals, e.g. ``\"500.00\"`` or ``\"-12.50\"``.

        Raises:
            RequestFailed: not logged in or server error.
            ConnectionError: connection lost.
        """
        return _field(self._request("balance"), "balance", str)

    def req_deposit(self, amount: str) -> str:
        """Deposit cash into the logged-in account.

        Args:
            amount: Positive decimal string, at most 2 fractional digits (e.g. ``\"99.90\"``).

        Returns:
            New balance string (two decimals).

        Raises:
            RequestFailed: invalid amount or not logged in.
            ConnectionError: connection lost.
        """
        return _field(self._request("deposit", amount=amount), "balance", str)

    def req_withdraw(self, amount: str) -> str:
        """Withdraw cash from the logged-in account (may go negative).

        Args:
            amount: Positive decimal string, at most 2 fractional digits.

        Returns:
            New balance string (two decimals).

        Raises:
            RequestFailed: invalid amount or not logged in.
            ConnectionError: connection lost.
        """
        return _field(self._request("withdraw", amount=amount), "balance", str)

    def req_transfer(self, target: str, amount: str) -> str:
        """Transfer money to another account.

        Args:
            target: Recipient user id (token).
            amount: Positive decimal string, at most 2 fractional digits.

        Returns:
            New balance of the sender (two decimals).

        Raises:
            RequestFailed: bad amount, unknown target, self-transfer, …
            ConnectionError: connection lost.
        """
        reply = self._request("transfer", target=target, amount=amount)
        return _field(reply, "balance", str)

    def req_schedule_so(self, target: str, amount: str, count: str) -> int:
        """Create a monthly standing order (first payment today).

        Args:
            target: Payee user id (token).
            amount: Amount per payment (positive decimal string).
            count: Number of payments as a digit string; ``\"0\"`` means until cancelled.

        Returns:
            The new standing-order id (positive int).

        Raises:
            RequestFailed: validation error or unknown target.
            ConnectionError: connection lost.
        """
        reply = self._request("so_create", target=target, amount=amount, count=count)
        return _field(reply, "so_id", int)

    def req_get_so_list(self) -> List[Tuple[int, str, str, str, int, Optional[int], str]]:
        """List active standing orders paid by the logged-in account.

        Returns:
            A list of tuples, one per standing order, in any order::

                (so_id, counterparty_token, counterparty_name,
                 amount, executed, remaining, next_run)

            * ``so_id`` (int)
            * ``counterparty_token`` (str) — payee user id
            * ``counterparty_name`` (str) — payee account name
            * ``amount`` (str) — per-payment amount, two decimals
            * ``executed`` (int) — how many payments have run
            * ``remaining`` (int | None) — payments left, or ``None`` if until cancelled
            * ``next_run`` (str) — next payment date ``YYYY-MM-DD``

        Raises:
            RequestFailed: not logged in or server error.
            ConnectionError: connection lost.
        """
        orders = _items(self._request("so_list"), "orders")
        return [(_field(o, "so_id", int),
                 _field(o, "target", str),
                 _field(o, "target_name", str),
                 _field(o, "amount", str),
                 _field(o, "executed", int),
                 _field(o, "remaining", int, optional=True),
                 _field(o, "next_run", str))
                for o in orders]

    def req_cancel_so(self, so_id: Union[str, int]) -> None:
        """Cancel one of the logged-in account's standing orders.

        Args:
            so_id: Standing-order id (int or digit string).

        Returns:
            None on success.

        Raises:
            RequestFailed: unknown standing order or not owned by this account.
            ConnectionError: connection lost.
        """
        # the GUI passes it as a string
        if type(so_id) is str and so_id.isascii() and so_id.isdigit():
            so_id = int(so_id)
        if type(so_id) is not int:
            raise RequestFailed("Invalid standing order id")
        self._request("so_cancel", so_id=so_id)

    def req_loan(self, amount: str) -> Tuple[int, str]:
        """Take a loan (principal credited now; auto-repay after 30 bank days + 5%).

        Args:
            amount: Principal as a positive decimal string.

        Returns:
            ``(loan_id, new_balance)`` where ``loan_id`` is int and ``new_balance``
            is a two-decimal string.

        Raises:
            RequestFailed: invalid amount or not logged in.
            ConnectionError: connection lost.
        """
        reply = self._request("loan", amount=amount)
        return (_field(reply, "loan_id", int), _field(reply, "balance", str))

    def req_get_loans(self) -> List[Tuple[int, str, str, str, str]]:
        """List unpaid loans for the logged-in account.

        Returns:
            A list of tuples, one per unpaid loan, in any order::

                (loan_id, principal, repay_amount, taken_on, due_on)

            * ``loan_id`` (int)
            * ``principal`` (str) — two decimals
            * ``repay_amount`` (str) — principal * 1.05, two decimals
            * ``taken_on`` (str) — ``YYYY-MM-DD``
            * ``due_on`` (str) — ``YYYY-MM-DD``

        Raises:
            RequestFailed: not logged in or server error.
            ConnectionError: connection lost.
        """
        loans = _items(self._request("loans"), "loans")
        return [(_field(ln, "loan_id", int),
                 _field(ln, "principal", str),
                 _field(ln, "repay", str),
                 _field(ln, "taken_on", str),
                 _field(ln, "due_on", str))
                for ln in loans]

    def req_history(self, from_ts: Optional[float] = None,
                    to_ts: Optional[float] = None) -> List[Tuple[str, TxType, str, str, str, str, str]]:
        """Fetch account history (oldest first). The GUI reverses for display.

        Args:
            from_ts: Optional inclusive lower bound (Unix seconds). The GUI passes
                neither bound (full history).
            to_ts: Optional inclusive upper bound (Unix seconds).

        Returns:
            A list of tuples, **oldest first**::

                (time, type, counterparty, counterparty_name, amount, balance, note)

            * ``time`` (str) — e.g. ``\"2026-10-30 14:13:20\"``
            * ``type`` (``TxType``) — e.g. ``TxType.DEPOSIT``, ``TxType.TRANSFER_IN``, …
            * ``counterparty`` (str) — other party token, ``CASH``, or ``BANK``
            * ``counterparty_name`` (str) — display name (may equal counterparty)
            * ``amount`` (str) — signed two-decimal amount for this entry
            * ``balance`` (str) — balance after this entry, two decimals
            * ``note`` (str) — free text (may be empty)

        Raises:
            RequestFailed: not logged in or bad timestamps.
            ConnectionError: connection lost.
        """
        reply = self._request("history", from_ts=from_ts, to_ts=to_ts)
        history = []
        for e in _items(reply, "entries"):
            raw_type = _field(e, "type", str)
            try:
                tx_type = TxType(raw_type)
            except ValueError as err:
                raise ProtocolError(f"Unknown history entry type: {raw_type!r}") from err
            history.append((_field(e, "time", str),
                            tx_type,
                            _field(e, "party", str),
                            _field(e, "party_name", str),
                            _field(e, "amount", str),
                            _field(e, "balance", str),
                            _field(e, "note", str)))
        return history
