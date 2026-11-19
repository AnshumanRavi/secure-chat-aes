"""Shared helpers for the security demos: projector-friendly output, hex dumps, a throwaway server."""

import math
import os
import shutil
import sys
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from client.network import ChatClient
from common.config import Config
from common.console import BOLD, CYAN, GREEN, GREY, MAGENTA, RED, YELLOW, Painter
from server.security_log import SecurityLog
from server.server import ChatServer

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")    # never crash on ✓ / │ in an old console

P = Painter()
DEMO_PASSWORD = "DemoPassw0rd!"
WIDTH = 78


# ------------------------------------------------------------------ output
def banner(title: str, subtitle: str = "") -> None:
    print()
    print(P(CYAN + BOLD, "═" * WIDTH))
    print(P(CYAN + BOLD, f"  {title}"))
    if subtitle:
        print(P(GREY, f"  {subtitle}"))
    print(P(CYAN + BOLD, "═" * WIDTH))


def step(number, text: str) -> None:
    print()
    print(P(BOLD, f"▶ STEP {number}: {text}"))
    print(P(GREY, "─" * WIDTH))


def attack(text: str) -> None:
    print(P(RED + BOLD, "  ☠ ATTACK  ") + text)


def ok(text: str) -> None:
    print(P(GREEN + BOLD, "  ✓ ") + text)


def bad(text: str) -> None:
    print(P(RED + BOLD, "  ✗ ") + text)


def info(text: str) -> None:
    print(P(GREY, "    " + text))


def note(text: str) -> None:
    print(P(YELLOW, "  ! ") + text)


def verdict(blocked: bool, text: str) -> None:
    label = P(GREEN + BOLD, " RESULT: ATTACK BLOCKED ✓ ") if blocked else P(RED + BOLD, " RESULT: ATTACK SUCCEEDED ✗ ")
    print()
    print(label + " " + text)


def scorecard(rows: List[Tuple[str, bool, str]]) -> None:
    banner("SECURITY SCORECARD")
    for name, blocked, detail in rows:
        mark = P(GREEN + BOLD, "BLOCKED ✓") if blocked else P(RED + BOLD, "FAILED  ✗")
        print(f"  {mark}  {P(BOLD, name):<40} {P(GREY, detail)}")
    print()


# ------------------------------------------------------------ inspecting bytes
def hexdump(data: bytes, limit: int = 48, indent: str = "    ") -> List[str]:
    """Classic hex + ASCII dump, the way Wireshark shows packet bytes."""
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{offset:04x}  {P(MAGENTA, hex_part)}  {P(GREY, ascii_part)}")
    if len(data) > limit:
        lines.append(f"{indent}… {len(data) - limit} more bytes")
    return lines


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: ~8 = looks random (ciphertext), ~4-5 = text."""
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


def utf8_attempt(data: bytes) -> Tuple[bool, str]:
    """Can an eavesdropper read it as text? Returns (readable, preview)."""
    try:
        text = data.decode("utf-8")
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
        return printable > 0.95, text
    except UnicodeDecodeError:
        return False, data.decode("utf-8", errors="replace")


# --------------------------------------------------------- servers & users
class DemoLog(SecurityLog):
    """Prints the server's security events with a 'SERVER │' prefix so they stand out."""

    def __init__(self, folder: Path, show: bool = True):
        super().__init__(folder, console=False)
        self.show = show
        self.events: List[Tuple[str, str]] = []

    def event(self, kind, message, addr=None, user=None, ciphertext=None) -> None:
        self.events.append((kind, message))
        super().event(kind, message, addr, user, ciphertext)
        if self.show and kind in ("TAMPER", "REPLAY", "PROTOCOL", "AUTH_FAIL", "LOCKOUT",
                                  "HANDSHAKE_FAIL", "ERROR", "E2E", "PLAINTEXT"):
            colour = RED if kind in ("TAMPER", "REPLAY", "LOCKOUT") else YELLOW
            print(P(colour, f"    SERVER │ [{kind}] ") + P(GREY, message))


class DemoServer:
    """A throwaway SecureChat server (temporary keys + database) so demos run anywhere."""

    def __init__(self, show_log: bool = True, show_bodies: bool = False):
        self.folder = Path(tempfile.mkdtemp(prefix="securechat-demo-"))
        self.log = DemoLog(self.folder / "logs", show=show_log)
        self.server = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=self.folder / "keys",
                                 db_path=self.folder / "server.db", log=self.log,
                                 passphrase="demo-passphrase", show_bodies=show_bodies)
        self.server.start_in_background()
        self.host, self.port = "127.0.0.1", self.server.port

    def events(self, kind: str) -> List[str]:
        return [m for k, m in self.log.events if k == kind]

    def stop(self) -> None:
        self.server.stop()
        shutil.rmtree(self.folder, ignore_errors=True)


def parse_target(text: Optional[str]) -> Optional[Tuple[str, int]]:
    if not text:
        return None
    host, _, port = text.rpartition(":")
    return (host or "127.0.0.1"), int(port)


def demo_user(host: str, port: int, prefix: str, register: bool = True) -> ChatClient:
    """A connected (and registered) client with a unique demo username."""
    client = ChatClient(host, port, heartbeat_interval=0)
    client.connect()
    if register:
        client.register(f"{prefix}_{uuid.uuid4().hex[:4]}", DEMO_PASSWORD, prefix.title())
        client.user_list_received.wait(3)
    return client


def pause(seconds: float = 0.4) -> None:
    time.sleep(seconds)


def wait_for(condition, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        time.sleep(0.02)
    return bool(condition())


def is_tty() -> bool:
    return sys.stdout.isatty() and not os.environ.get("DEMO_NO_PAUSE")
