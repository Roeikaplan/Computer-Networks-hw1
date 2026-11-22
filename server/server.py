"""Single-threaded TCP banking server multiplexed with ``select()``.

Usage:
    python server.py [--host 127.0.0.1] [--port 5050] [--start-date YYYY-MM-DD] [--verbose]
"""
from __future__ import annotations

import argparse
import json
import logging
import select
import socket
import struct
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from bank import Bank, BankError
from server_utils import Console

log = logging.getLogger("server")

HEADER = struct.Struct("!I")       # 4-byte big-endian body length
MAX_REQUEST = 64 * 1024
MAX_REPLY = 1024 * 1024            # the client rejects anything bigger
MAX_PENDING = 1024 * 1024          # stop reading from a client with this much unsent output
RECV_SIZE = 4096
SELECT_TIMEOUT = 0.1               # so Console.poll() still runs when there's no traffic
BACKLOG = 16


class FrameError(Exception):
    pass


def pack_frame(body: bytes) -> bytes:
    return HEADER.pack(len(body)) + body


def extract_frames(buf: bytearray, max_size: int) -> List[bytes]:
    """Pop all complete frames off the front of buf. A partial frame stays in buf."""
    frames = []
    while len(buf) >= HEADER.size:
        (length,) = HEADER.unpack_from(buf)
        # check the length right away, don't wait for a huge body to arrive
        if length == 0 or length > max_size:
            raise FrameError(f"bad frame length {length}")
        end = HEADER.size + length
        if len(buf) < end:
            break
        frames.append(bytes(buf[HEADER.size:end]))
        del buf[:end]
    return frames


class ClientState:
    def __init__(self, sock: socket.socket, addr: Tuple[str, int]):
        self.sock = sock
        self.addr = f"{addr[0]}:{addr[1]}"
        self.inbuf = bytearray()
        self.outbuf = bytearray()
        self.token: Optional[str] = None  # set after login


class FieldError(Exception):
    """Missing or wrongly typed request field; the message is the field name."""


def str_field(req: dict, name: str) -> str:
    value = req.get(name)
    if not isinstance(value, str):
        raise FieldError(name)
    return value


def int_field(req: dict, name: str) -> int:
    value = req.get(name)
    if type(value) is not int:          # bool is a subclass of int
        raise FieldError(name)
    return value


def reject_constant(name: str):
    # json.loads accepts NaN/Infinity by default
    raise ValueError(f"invalid JSON constant {name}")


### Do not remove any of the existing functions or change their signatures. ###
### You can add new functions and classes if needed. ###
class Server:
    def __init__(self, host: str, port: int, bank: Bank):
        self.host = host
        self.port = port

        self.bank = bank
        self.bank.announce_date()

        self.console = Console()

    def server_loop(self) -> None:
        """Main server loop for the bank server."""
        listener = self._open_listener()
        if listener is None:
            return
        self.clients: Dict[socket.socket, ClientState] = {}
        try:
            while True:
                # only ask about writability when there is something to send,
                # otherwise select() would return immediately every time
                wlist = [s for s, c in self.clients.items() if c.outbuf]
                # don't read from clients that aren't reading their replies
                rlist = [listener] + [s for s, c in self.clients.items()
                                      if len(c.outbuf) < MAX_PENDING]
                readable, writable, _ = select.select(rlist, wlist, [], SELECT_TIMEOUT)
                for sock in readable:
                    if sock is listener:
                        self._accept(listener)
                    elif sock in self.clients:
                        self._read(self.clients[sock])
                for sock in writable:
                    if sock in self.clients:      # might have been closed while reading
                        self._write(self.clients[sock])

                self.console.poll(self.bank.on_console_line)
                self.bank.run_due()
        finally:
            for client in list(self.clients.values()):
                self._close(client, "server shutting down")
            listener.close()

    def _open_listener(self) -> Optional[socket.socket]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # on Windows SO_REUSEADDR lets other processes steal the port
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            # so we can restart while old connections are in TIME_WAIT
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
        except OSError as err:
            listener.close()
            print(f"Cannot listen on port {self.port}: {err}", flush=True)
            return None
        listener.listen(BACKLOG)
        listener.setblocking(False)
        print(f"Listening on {self.host or '0.0.0.0'}:{self.port}. "
              "Press Enter for the next bank day, Ctrl+C to stop.", flush=True)
        return listener

    def _accept(self, listener: socket.socket) -> None:
        try:
            sock, addr = listener.accept()
        except OSError as err:          # e.g. client reset before we accepted
            log.info("accept failed: %s", err)
            return
        sock.setblocking(False)
        client = ClientState(sock, addr)
        self.clients[sock] = client
        log.info("%s connected (%d online)", client.addr, len(self.clients))

    def _close(self, client: ClientState, reason: str) -> None:
        if self.clients.pop(client.sock, None) is None:
            return
        try:
            client.sock.close()
        except OSError:
            pass
        log.info("%s disconnected: %s (%d online)", client.addr, reason, len(self.clients))

    def _read(self, client: ClientState) -> None:
        try:
            data = client.sock.recv(RECV_SIZE)
        except BlockingIOError:
            return
        except OSError as err:
            self._close(client, f"error: {err}")
            return
        if not data:
            self._close(client, "closed by client")
            return
        client.inbuf += data
        try:
            frames = extract_frames(client.inbuf, MAX_REQUEST)
        except FrameError as err:
            log.warning("%s: %s, closing", client.addr, err)
            self._close(client, str(err))
            return
        for body in frames:
            self._handle_frame(client, body)

    def _write(self, client: ClientState) -> None:
        try:
            sent = client.sock.send(client.outbuf)
        except BlockingIOError:
            return
        except OSError as err:
            self._close(client, f"error: {err}")
            return
        del client.outbuf[:sent]        # partial send, the rest goes next round

    def _handle_frame(self, client: ClientState, body: bytes) -> None:
        reply = self._process(client, body)
        log.info("%s <- %s", client.addr, reply)
        data = json.dumps(reply, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_REPLY:       # e.g. a very long history
            log.warning("%s: reply of %d bytes is too large", client.addr, len(data))
            data = b'{"ok":false,"error":"Reply too large"}'
        client.outbuf += pack_frame(data)

    def _process(self, client: ClientState, body: bytes) -> Dict[str, Any]:
        """Build the reply dict for one request. Never raises."""
        try:
            req = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):   # RecursionError: deeply nested JSON
            return {"ok": False, "error": "Malformed request"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "Malformed request"}
        log.info("%s -> %s", client.addr, {k: ("***" if k == "password" else v) for k, v in req.items()})

        op = req.get("op")
        entry = self.OPS.get(op) if isinstance(op, str) else None
        if entry is None:
            return {"ok": False, "error": "Unknown operation"}
        handler_name, needs_login = entry
        if needs_login and client.token is None:
            return {"ok": False, "error": "Not logged in"}
        try:
            return {"ok": True, **getattr(self, handler_name)(client, req)}
        except BankError as err:
            return {"ok": False, "error": str(err)}
        except FieldError as err:
            return {"ok": False, "error": f"Missing or invalid field: {err}"}
        except Exception:
            # a bug on our side; don't let it take down the server
            log.exception("%s: internal error on %r", client.addr, op)
            return {"ok": False, "error": "Internal server error"}

    # op -> (handler method, needs login)
    OPS = {
        "register":  ("_op_register", False),
        "login":     ("_op_login", False),
        "logout":    ("_op_logout", True),
        "balance":   ("_op_balance", True),
        "deposit":   ("_op_deposit", True),
        "withdraw":  ("_op_withdraw", True),
        "transfer":  ("_op_transfer", True),
        "so_create": ("_op_so_create", True),
        "so_list":   ("_op_so_list", True),
        "so_cancel": ("_op_so_cancel", True),
        "loan":      ("_op_loan", True),
        "loans":     ("_op_loans", True),
        "history":   ("_op_history", True),
    }

    def _op_register(self, client: ClientState, req: dict) -> dict:
        return {"token": self.bank.register(str_field(req, "name"), str_field(req, "password"))}

    def _op_login(self, client: ClientState, req: dict) -> dict:
        if client.token is not None:
            raise BankError("Already logged in")
        token = str_field(req, "token")
        name = self.bank.login(token, str_field(req, "password"))
        client.token = token
        log.info("%s logged in as %s", client.addr, token)
        return {"name": name}

    def _op_logout(self, client: ClientState, req: dict) -> dict:
        log.info("%s logged out of %s", client.addr, client.token)
        client.token = None
        return {}

    def _op_balance(self, client: ClientState, req: dict) -> dict:
        return {"balance": self.bank.balance(client.token)}

    def _op_deposit(self, client: ClientState, req: dict) -> dict:
        return {"balance": self.bank.deposit(client.token, str_field(req, "amount"))}

    def _op_withdraw(self, client: ClientState, req: dict) -> dict:
        return {"balance": self.bank.withdraw(client.token, str_field(req, "amount"))}

    def _op_transfer(self, client: ClientState, req: dict) -> dict:
        return {"balance": self.bank.transfer(client.token, str_field(req, "target"),
                                              str_field(req, "amount"))}

    def _op_so_create(self, client: ClientState, req: dict) -> dict:
        return {"so_id": self.bank.so_create(client.token, str_field(req, "target"),
                                             str_field(req, "amount"), str_field(req, "count"))}

    def _op_so_list(self, client: ClientState, req: dict) -> dict:
        return {"orders": self.bank.so_list(client.token)}

    def _op_so_cancel(self, client: ClientState, req: dict) -> dict:
        self.bank.so_cancel(client.token, int_field(req, "so_id"))
        return {}

    def _op_loan(self, client: ClientState, req: dict) -> dict:
        loan_id, balance = self.bank.loan(client.token, str_field(req, "amount"))
        return {"loan_id": loan_id, "balance": balance}

    def _op_loans(self, client: ClientState, req: dict) -> dict:
        return {"loans": self.bank.loans_of(client.token)}

    def _op_history(self, client: ClientState, req: dict) -> dict:
        # bounds are optional, Bank.history() validates them
        return {"entries": self.bank.history(client.token, req.get("from_ts"), req.get("to_ts"))}



### Do not touch anything below this line. ###
def parse_date(text: str) -> date:
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected YYYY-MM-DD, got {text!r}") from None


def main() -> None:
    parser = argparse.ArgumentParser(description="select()-based socket banking server")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--start-date", type=parse_date, default=date.today(),
                        help="first bank date, YYYY-MM-DD (default: today)")
    parser.add_argument("--verbose", action="store_true", help="log every request and reply")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(name)s: %(message)s", datefmt="%H:%M:%S")

    bank = Bank(start_date=args.start_date)
    server = Server(args.host, args.port, bank)
    try:
        server.server_loop()
    except KeyboardInterrupt:
        log.info("shutting down")
        print("\nShutting down.", flush=True)


if __name__ == "__main__":
    main()
