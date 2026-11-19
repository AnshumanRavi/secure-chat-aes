"""
Console + file logging for the server.

* Every event is printed to the console in colour, so a live demo clearly shows
  what is happening (connections, logins, encrypted traffic, attacks).
* Encrypted packets are printed as shortened hex next to the decrypted message
  TYPE (never the message text), proving that only ciphertext crosses the network.
* Security events (failed logins, lockouts, tampering, replays, bad handshakes)
  are also appended to logs/security.log for later auditing.
"""

import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Tuple, Union

from common.console import BLUE, BOLD, CYAN, GREEN, GREY, MAGENTA, RED, YELLOW, Painter

# kind -> (colour, written to security.log?)
EVENT_STYLES = {
    "START":          (GREEN, False),
    "STOP":           (YELLOW, False),
    "CONNECT":        (CYAN, False),
    "HANDSHAKE":      (CYAN, False),
    "REGISTER":       (GREEN, True),
    "LOGIN":          (GREEN, True),
    "LOGOUT":         (BLUE, False),
    "DISCONNECT":     (BLUE, False),
    "OFFLINE":        (MAGENTA, False),
    "GROUP":          (GREEN, False),
    "FILE":           (CYAN, False),
    "PROFILE":        (BLUE, False),
    "E2E":            (GREEN, False),
    "KEY":            (CYAN, False),
    "PLAINTEXT":      (YELLOW, False),
    "AUTH_FAIL":      (YELLOW, True),
    "LOCKOUT":        (RED, True),
    "HANDSHAKE_FAIL": (YELLOW, True),
    "TAMPER":         (RED, True),
    "REPLAY":         (RED, True),
    "PROTOCOL":       (YELLOW, True),
    "TIMEOUT":        (YELLOW, False),
    "ERROR":          (RED, True),
}


def short_hex(data: bytes, head: int = 12, tail: int = 4) -> str:
    """'3f9a1c0b7e44...9d2a (87 B)' - enough to show it's random-looking ciphertext."""
    if len(data) <= head + tail:
        return f"{data.hex()} ({len(data)} B)"
    return f"{data[:head].hex()}...{data[-tail:].hex()} ({len(data)} B)"


class SecurityLog:
    def __init__(self, log_dir: Union[str, Path] = "logs", console: bool = True,
                 show_traffic: bool = True):
        self.console = console
        self.show_traffic = show_traffic
        self._c = Painter(enabled=console)
        self._print_lock = threading.Lock()

        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        self.path = log_dir / "security.log"
        # A separate logger per instance, so tests with temporary folders don't share handlers
        self._file_logger = logging.getLogger(f"securechat.security.{id(self)}")
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False
        self._handler = RotatingFileHandler(self.path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        self._handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
        self._file_logger.addHandler(self._handler)

    # -------------------------------------------------------------- output
    def _print(self, line: str) -> None:
        if not self.console:
            return
        with self._print_lock:
            print(line, flush=True)

    @staticmethod
    def _who(addr: Optional[Tuple[str, int]], user: Optional[str]) -> str:
        parts = []
        if user:
            parts.append(user)
        if addr:
            parts.append(f"{addr[0]}:{addr[1]}")
        return " @ ".join(parts) if parts else "-"

    # -------------------------------------------------------------- events
    def event(self, kind: str, message: str, addr: Optional[Tuple[str, int]] = None,
              user: Optional[str] = None, ciphertext: Optional[bytes] = None) -> None:
        colour, to_file = EVENT_STYLES.get(kind, (BLUE, False))
        who = self._who(addr, user)
        stamp = time.strftime("%H:%M:%S")

        line = f"{self._c(GREY, stamp)} {self._c(colour + BOLD, f'[{kind:<14}]')} {message}  {self._c(GREY, who)}"
        if ciphertext:
            line += "\n" + " " * 26 + self._c(GREY, "ciphertext: ") + self._c(MAGENTA, short_hex(ciphertext))
        self._print(line)

        if to_file:
            record = f"{kind:<14} {who:<32} {message}"
            if ciphertext:
                record += f" | ciphertext={short_hex(ciphertext, 24, 8)}"
            self._file_logger.warning(record)

    def traffic(self, direction: str, user: str, msg_type: str, ciphertext: bytes,
                peer: Optional[str] = None) -> None:
        """Show one encrypted packet: direction, user, decrypted type and the ciphertext on the wire."""
        if not self.show_traffic:
            return
        arrow = self._c(GREEN, "<<  IN") if direction == "IN" else self._c(CYAN, ">> OUT")
        route = f"{user} -> server" if direction == "IN" else f"server -> {user}"
        if peer:
            route += f"  ({peer})"
        stamp = time.strftime("%H:%M:%S")
        self._print(f"{self._c(GREY, stamp)} {arrow} {self._c(BOLD, f'{msg_type:<12}')} {route:<34} "
                    f"{self._c(MAGENTA, short_hex(ciphertext))}")

    def banner(self, lines) -> None:
        width = max(len(l) for l in lines) + 4
        self._print(self._c(GREEN, "+" + "-" * width + "+"))
        for l in lines:
            self._print(self._c(GREEN, "|  ") + l.ljust(width - 4) + self._c(GREEN, "  |"))
        self._print(self._c(GREEN, "+" + "-" * width + "+"))

    def close(self) -> None:
        self._file_logger.removeHandler(self._handler)
        self._handler.close()
