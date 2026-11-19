"""
"Man-in-the-middle" sniffer: sits between a client and the server and shows what an attacker sees.

    Terminal 1:  python -m server.server                         (the real server on 5555)
    Terminal 2:  python -m security_demo.sniffer_proxy           (listens on 6666 -> 5555)
    Terminal 3:  python -m client.gui.main --port 6666           (client connects THROUGH the attacker)

Every packet is printed as hex, with an attempt to read it as UTF-8 and its entropy
(how random it looks). With SecureChat the attacker gets only random-looking bytes.

Side-by-side comparison with a deliberately INSECURE chat:
    python -m security_demo.insecure_chat server                 (plain-text server on 5556)
    python -m security_demo.sniffer_proxy --plaintext-mode       (listens on 6667 -> 5556)
    python -m security_demo.insecure_chat client --name alice --port 6667
    python -m security_demo.insecure_chat client --name bob   --port 6667

The MitmProxy class is also used by tamper_test.py and replay_test.py to modify,
drop and re-inject packets.
"""

import argparse
import base64
import json
import math
import socket
import struct
import threading
from typing import Callable, List, Optional, Tuple

from security_demo.demo_utils import (
    BOLD, CYAN, GREEN, GREY, P, RED, YELLOW, banner, entropy, hexdump, info, utf8_attempt,
)

HEADER = struct.Struct(">I")
C2S, S2C = "client → server", "server → client"


class Connection:
    """One client connection passing through the proxy."""

    def __init__(self, number: int, client: socket.socket, server: socket.socket):
        self.number = number
        self.sockets = {C2S: server, S2C: client}           # where each direction's data goes
        self.locks = {C2S: threading.Lock(), S2C: threading.Lock()}
        self.history: List[Tuple[str, int, bytes]] = []      # (direction, index, body) as seen on the wire
        self.counts = {C2S: 0, S2C: 0}
        self.closed = threading.Event()


class MitmProxy:
    """
    A TCP relay that understands SecureChat framing ([4-byte length][body]).

    on_packet(conn, direction, index, body) is called for every packet and returns
    the bytes to forward (modified = tampering) or None (dropped).
    """

    def __init__(self, target: Tuple[str, int], listen_port: int = 6666, framed: bool = True,
                 on_packet: Optional[Callable] = None, listen_host: str = "127.0.0.1"):
        self.target = target
        self.framed = framed
        self.on_packet = on_packet
        self.connections: List[Connection] = []
        self._listener = socket.create_server((listen_host, listen_port))
        self._listener.settimeout(0.5)
        self.port = self._listener.getsockname()[1]
        self._running = threading.Event()

    def start(self) -> "MitmProxy":
        self._running.set()
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def stop(self) -> None:
        self._running.clear()
        self._listener.close()
        for conn in self.connections:
            for sock in conn.sockets.values():
                try:
                    sock.close()
                except OSError:
                    pass

    def _accept_loop(self) -> None:
        while self._running.is_set():
            try:
                client, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                server = socket.create_connection(self.target, timeout=5)
                server.settimeout(None)
            except OSError:
                client.close()
                continue
            conn = Connection(len(self.connections) + 1, client, server)
            self.connections.append(conn)
            threading.Thread(target=self._pump, args=(conn, client, C2S), daemon=True).start()
            threading.Thread(target=self._pump, args=(conn, server, S2C), daemon=True).start()

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data.extend(chunk)
        return bytes(data)

    def _pump(self, conn: Connection, source: socket.socket, direction: str) -> None:
        try:
            while True:
                if self.framed:
                    (length,) = HEADER.unpack(self._recv_exact(source, HEADER.size))
                    body = self._recv_exact(source, length)
                else:
                    body = source.recv(65536)
                    if not body:
                        break
                index = conn.counts[direction]
                conn.counts[direction] += 1
                conn.history.append((direction, index, body))
                if self.on_packet is not None:
                    body = self.on_packet(conn, direction, index, body)
                if body is not None:
                    self.inject(conn, direction, body)
        except (ConnectionError, OSError):
            pass
        finally:
            conn.closed.set()
            for sock in conn.sockets.values():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def inject(self, conn: Connection, direction: str, body: bytes) -> None:
        """Send bytes as if they came from the other side (used to forward, tamper or replay)."""
        data = HEADER.pack(len(body)) + body if self.framed else body
        with conn.locks[direction]:
            conn.sockets[direction].sendall(data)


# ------------------------------------------------------------------ printing
def describe_secure_packet(direction: str, index: int, body: bytes, conn: Connection) -> None:
    arrow = P(CYAN + BOLD, f"[conn {conn.number}] {direction}  packet #{index}  ({len(body)} bytes)")
    print("\n" + arrow)
    # The handshake is the only plain JSON on the wire - and it contains nothing secret
    try:
        hello = json.loads(body)
        kind = hello.get("type", "?")
        if kind == "HANDSHAKE_PUBKEY":
            info("Handshake: the server's RSA PUBLIC key + a random salt (safe to reveal).")
        elif kind == "HANDSHAKE_SESSION_KEY":
            info("Handshake: session secret, RSA-OAEP encrypted - only the server's PRIVATE key opens it:")
            secret = base64.b64decode(hello.get("encrypted_secret", ""))
            for line in hexdump(secret, 32):
                print(line)
        return
    except (ValueError, UnicodeDecodeError):
        pass
    for line in hexdump(body, 48):
        print(line)
    readable, text = utf8_attempt(body)
    print("    UTF-8 decode attempt: " + (P(RED, "readable?!") if readable else
                                           P(GREEN, "✗ unreadable") + P(GREY, f"  → {text[:40]!r}")))
    print_entropy(body)
    print(P(GREY, f"    = 12-byte nonce | {len(body) - 28}-byte AES-256-GCM ciphertext | 16-byte auth tag"))


def describe_plain_packet(direction: str, index: int, body: bytes, conn: Connection) -> None:
    print("\n" + P(YELLOW + BOLD, f"[conn {conn.number}] {direction}  packet #{index}  ({len(body)} bytes)"))
    for line in hexdump(body, 48):
        print(line)
    readable, text = utf8_attempt(body)
    print("    UTF-8 decode attempt: " + (P(RED + BOLD, "⚠ READABLE: ") + P(YELLOW, text.strip()[:120])
                                          if readable else P(GREY, repr(text[:60]))))
    print_entropy(body)


def print_entropy(body: bytes) -> None:
    """Entropy vs the maximum possible for this length (a short packet can't reach 8 bits/byte)."""
    best = min(8.0, math.log2(len(body))) if len(body) > 1 else 0.0
    print(f"    Entropy: {entropy(body):.2f} bits/byte " +
          P(GREY, f"(max possible for {len(body)} bytes: {best:.2f} = random-looking; English text ≈ 4.2)"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Man-in-the-middle sniffer for the SecureChat demo")
    parser.add_argument("--plaintext-mode", action="store_true",
                        help="sniff the deliberately insecure chat (security_demo.insecure_chat) instead")
    parser.add_argument("--listen", type=int, help="port the proxy listens on (6666, or 6667 in plaintext mode)")
    parser.add_argument("--target", help="real server host:port (127.0.0.1:5555, or :5556 in plaintext mode)")
    args = parser.parse_args()

    plain = args.plaintext_mode
    listen = args.listen or (6667 if plain else 6666)
    host, _, port = (args.target or ("127.0.0.1:5556" if plain else "127.0.0.1:5555")).rpartition(":")
    describe = describe_plain_packet if plain else describe_secure_packet
    stats = {"packets": 0, "readable": 0}
    print_lock = threading.Lock()           # both directions print from their own thread

    def on_packet(conn, direction, index, body):
        with print_lock:
            stats["packets"] += 1
            if utf8_attempt(body)[0]:
                stats["readable"] += 1
            describe(direction, index, body, conn)
        return body                        # forward unchanged - this proxy only watches

    proxy = MitmProxy((host or "127.0.0.1", int(port)), listen, framed=not plain, on_packet=on_packet).start()
    banner("MAN-IN-THE-MIDDLE SNIFFER" + (" - INSECURE CHAT" if plain else " - SecureChat"),
           f"Listening on 127.0.0.1:{proxy.port}  →  forwarding to {host or '127.0.0.1'}:{port}")
    if plain:
        print(P(YELLOW, f"  Connect insecure clients to port {proxy.port}:  "
                        f"python -m security_demo.insecure_chat client --name alice --port {proxy.port}"))
    else:
        print(P(GREY, f"  Point a client at port {proxy.port}:  python -m client.gui.main --port {proxy.port}"))
        print(P(GREY, "  (The fingerprint popup will show the REAL server's key - the proxy can't fake it.)"))
    print(P(GREY, "  Press Ctrl+C to stop and see the summary."))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        proxy.stop()
        banner("SUMMARY")
        print(f"  Packets captured: {stats['packets']}")
        colour = RED if plain and stats["readable"] else GREEN
        print(P(colour + BOLD, f"  Packets the attacker could read: {stats['readable']}"))
        if not plain:
            print(P(GREY, "  (Only the handshake is plain JSON - a public key, a salt and an RSA-encrypted secret.)"))


if __name__ == "__main__":
    main()
