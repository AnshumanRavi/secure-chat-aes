"""
A deliberately INSECURE chat - plain text over TCP - to compare against SecureChat.

!!! For the demo only. Never build a real chat like this. !!!

    python -m security_demo.insecure_chat server [--port 5556]
    python -m security_demo.insecure_chat client --name alice [--port 5556]
    python -m security_demo.insecure_chat demo [--port 6667]      # sends a few scripted messages

Messages travel as one JSON line each, e.g. {"from": "alice", "text": "my password is hunter2"}.
A line with a "to" field goes only to that user (used by performance/benchmark_network.py);
without one it goes to everybody else.
Anyone between the client and the server (Wi-Fi sniffer, the proxy, Wireshark) can read
and change everything.
"""

import argparse
import json
import socket
import threading
import time

from security_demo.demo_utils import BOLD, GREEN, GREY, P, RED, YELLOW, banner


class InsecureServer:
    """Relays every JSON line to all other clients - in plain text."""

    def __init__(self, port: int = 5556, host: str = "0.0.0.0", verbose: bool = True):
        self.listener = socket.create_server((host, port))
        self.port = self.listener.getsockname()[1]
        self.verbose = verbose
        self.clients = []
        self.names = {}                 # name -> connection, learned from each line's "from"
        self.lock = threading.Lock()

    def serve_forever(self) -> None:
        while True:
            try:
                conn, addr = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def start_in_background(self) -> "InsecureServer":
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.listener.close()

    def _handle(self, conn: socket.socket, addr) -> None:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # same as the real server
        with self.lock:
            self.clients.append(conn)
        name = "?"
        try:
            for line in conn.makefile("r", encoding="utf-8"):
                message = json.loads(line)
                name = message.get("from", name)
                if self.verbose:
                    print(P(YELLOW, f"  {addr[0]}:{addr[1]} ") + P(GREY, line.strip()))
                with self.lock:
                    self.names[name] = conn
                    if "to" in message:
                        others = [self.names[message["to"]]] if message["to"] in self.names else []
                    else:
                        others = [c for c in self.clients if c is not conn]
                for other in others:
                    try:
                        other.sendall(line.encode("utf-8"))
                    except OSError:
                        pass
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.clients.remove(conn)
                if self.names.get(name) is conn:
                    del self.names[name]
            conn.close()
            if self.verbose:
                print(P(GREY, f"  {name} disconnected"))


def run_server(port: int) -> None:
    server = InsecureServer(port)
    banner("INSECURE CHAT SERVER (no encryption!)", f"Listening on 0.0.0.0:{server.port}")
    server.serve_forever()


def send(sock: socket.socket, name: str, text: str) -> None:
    sock.sendall((json.dumps({"from": name, "text": text}) + "\n").encode("utf-8"))


def run_client(name: str, host: str, port: int) -> None:
    sock = socket.create_connection((host, port))
    banner(f"INSECURE CHAT - {name}", "Type a message and press Enter. Ctrl+C to quit.")

    def reader() -> None:
        for line in sock.makefile("r", encoding="utf-8"):
            message = json.loads(line)
            print(f"\r{P(GREEN + BOLD, message.get('from', '?'))}: {message.get('text', '')}\n> ", end="", flush=True)

    threading.Thread(target=reader, daemon=True).start()
    try:
        while True:
            text = input("> ")
            if text.strip():
                send(sock, name, text)
    except (KeyboardInterrupt, EOFError):
        sock.close()


def run_demo(host: str, port: int) -> None:
    """Two scripted users chat - handy for showing the sniffer output without typing."""
    alice = socket.create_connection((host, port))
    bob = socket.create_connection((host, port))
    lines = [(alice, "alice", "Hi Bob, my bank PIN is 4711"), (bob, "bob", "Got it! My password is hunter2"),
             (alice, "alice", "Meet at the library at 5pm")]
    for sock, name, text in lines:
        send(sock, name, text)
        print(P(RED, f"  sent in PLAIN TEXT: {name}: {text}"))
        time.sleep(0.5)
    alice.close()
    bob.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliberately insecure chat for comparison")
    parser.add_argument("mode", choices=["server", "client", "demo"])
    parser.add_argument("--name", default="alice")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.port or 5556)
    elif args.mode == "client":
        run_client(args.name, args.host, args.port or 5556)
    else:
        run_demo(args.host, args.port or 6667)


if __name__ == "__main__":
    main()
