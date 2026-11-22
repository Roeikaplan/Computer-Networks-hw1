# Bank Protocol

## Overview

- TCP, default port 5050.
- Request/reply: the client sends a request and waits for its reply before sending the next one. Replies come back in order, so there are no request ids.
- Login state belongs to the TCP connection. Closing the connection logs you out.

## Framing

Every message is a 4-byte length followed by a UTF-8 JSON object:

```
+-------------------------------+-----------------------+
| length N (uint32, big-endian) | N bytes of UTF-8 JSON |
+-------------------------------+-----------------------+
```

Example: `00 00 00 21` + `{"op":"deposit","amount":"99.90"}` (33 bytes).

- The body is compact JSON (`separators=(",", ":")`) and must be an object.
- Max request size is 64 KiB and max reply size is 1 MiB. N = 0 is invalid.
- The length is checked as soon as the header arrives. A bad length closes the connection.

## Design choices

- **TCP:** a bank can't lose or reorder operations.
- **Length-prefixed frames:** TCP is a byte stream, so messages need boundaries. Fixed-size messages waste space, and a delimiter needs escaping and a scan of every byte. A length field tells the receiver exactly how much to read.
- **Big-endian length (`!I`):** network byte order, so both sides agree regardless of the CPU.
- **JSON body:** easy to read in Wireshark and built into Python. Our messages are small, so a binary body wouldn't save much.
- **Size limits:** without them, one client could make the single-threaded server buffer gigabytes.
- **No checksum:** TCP already checksums every segment, and a corrupted body would fail JSON parsing anyway.
- **Money as strings:** floats can't represent decimal amounts exactly, so the server uses `Decimal`.
- **Server-side validation:** the server checks every field, because it can't trust the client.

## Messages

Request: `{"op": "<name>", ...fields}`. Unknown extra fields are ignored.

Reply: `{"ok": true, ...fields}` or `{"ok": false, "error": "<message>"}`. The error text is shown to the user as is.

Value formats:

| Kind | Format | Example |
|---|---|---|
| Money | string with 2 decimals, never a JSON number | `"-12.50"` |
| Money in a request | positive string, at most 2 decimals, at most 10,000,000 | `"99.9"` |
| Token (user id) | 10 chars from `A-Z0-9` | `"K3Q9ZP0B7A"` |
| `so_id`, `loan_id` | JSON integer | `7` |
| Payment count | string of 1-4 digits, `"0"` = until cancelled | `"12"` |
| Date / time | `YYYY-MM-DD` / `YYYY-MM-DD HH:MM:SS` (bank time) | `"2026-11-20"` |
## Operations

All operations except `register` and `login` require a login.

| op | Request | Reply |
|---|---|---|
| `register` | `name` (3-20 chars `A-Za-z0-9_`), `password` (4+ chars) | `token` |
| `login` | `token`, `password` | `name` |
| `logout` | | |
| `balance` | | `balance` |
| `deposit` | `amount` | `balance` |
| `withdraw` | `amount` | `balance` (may go negative) |
| `transfer` | `target`, `amount` | sender's `balance` |
| `so_create` | `target`, `amount`, `count` | `so_id` |
| `so_list` | | `orders` |
| `so_cancel` | `so_id` | |
| `loan` | `amount` | `loan_id`, `balance` |
| `loans` | | `loans` |
| `history` | `from_ts`, `to_ts` (optional) | `entries` |

Examples of the list replies:

```
so_list  -> {"so_id":7,"target":"ZX81QWE7LM","target_name":"dana","amount":"50.00",
             "executed":1,"remaining":2,"next_run":"2026-12-20"}      remaining is null if count was "0"
loans    -> {"loan_id":3,"principal":"1000.00","repay":"1050.00",
             "taken_on":"2026-11-20","due_on":"2026-12-20"}
history  -> {"time":"2026-11-20 14:15:02","type":"TRANSFER_OUT","party":"ZX81QWE7LM",
             "party_name":"dana","amount":"-100.00","balance":"100.00","note":""}
```

The rules:

- `register` does not log you in. Names don't have to be unique.
- Standing orders pay monthly, and the first payment is made right away.
- A loan is refused while you have a negative balance or an unpaid loan.
- History is oldest first and the time bounds are inclusive. `amount` is signed. `party` is a token, `CASH` (deposits and withdrawals) or `BANK` (loans, repayments, interest).
- History types: `DEPOSIT`, `WITHDRAWAL`, `TRANSFER_IN`, `TRANSFER_OUT`, `CHARGE` (standing order payment), `LOAN`, `LOAN_REPAYMENT`, `OVERDRAFT_INTEREST`.

## Errors

| Situation | Reply | Connection |
|---|---|---|
| Frame length 0 or over the limit | none | closed |
| Invalid UTF-8/JSON, or not an object | `Malformed request` | open |
| Unknown `op` | `Unknown operation` | open |
| Missing or wrongly typed field | `Missing or invalid field: <name>` | open |
| Not logged in / already logged in | `Not logged in` / `Already logged in` | open |
| Business rule, e.g. `Invalid amount`, `Unknown user id`, `Loan refused: ...` | the rule's message | open |
| Server bug | `Internal server error` | open |
| Reply over 1 MiB | `Reply too large` | open |

A wrong token and a wrong password give the same error (`Wrong user id or password`), so login replies don't reveal which tokens exist. The same goes for cancelling someone else's standing order (`Unknown standing order`).

On the client, `ok:false` raises `RequestFailed`, an unreadable reply raises `ProtocolError`, and socket problems raise `ConnectionError`/`OSError`. The client waits up to 5 s to connect and up to 10 s for each reply. After a timeout or a broken frame it closes the connection, because a late reply would otherwise be taken as the answer to the next request.

## Bank days

Pressing Enter on the server console advances one day (typing a number N advances N days). For each day:

1. Every negative balance is charged 0.05% interest for the day that ended.
2. The date advances.
3. Standing orders that are due get paid.
4. Loan repayments that are due get taken.
