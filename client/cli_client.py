"""
SecureChat terminal client - for testing the server before the GUI exists.

    python -m client.cli_client                        # connects to config.json client_host
    python -m client.cli_client --host 192.168.1.5     # server on another PC
    python -m client.cli_client --fingerprint "FC3F 09EE ..."   # refuse any other server key

Commands once logged in:
    /users              list everyone, with online status
    /msg <user> <text>  send a message (and make <user> the current chat)
    /chat <user>        switch the current chat; then just type to send
    /ping               measure the round-trip time to the server
    /info               show the server fingerprint and session key id
    /help               show this list
    /quit               log out and exit
"""

import getpass
import sys
import threading
from typing import Dict, Optional

from client.formatting import format_last_seen, format_time
from client.network import AuthFailed, ChatClient, ClientError, ConnectionFailed
from common.config import build_arg_parser, load_config
from common.console import BOLD, CYAN, GREEN, GREY, MAGENTA, RED, YELLOW, Painter

HELP = """Commands:
  /users              list everyone, with online status
  /msg <user> <text>  send a message (and switch to that chat)
  /chat <user>        switch chat - then just type to send
  /ping               round-trip time to the server
  /info               server fingerprint and session key id
  /quit               log out and exit"""


class CliChat:
    def __init__(self, host: str, port: int, fingerprint: Optional[str], heartbeat: float):
        self.client = ChatClient(host, port, expected_fingerprint=fingerprint, heartbeat_interval=heartbeat)
        self.paint = Painter()
        self.current_chat: Optional[str] = None
        self.sent: Dict[str, str] = {}          # message id -> short preview, for receipt lines
        self._print_lock = threading.Lock()
        self._running = True

    # ------------------------------------------------------------- output
    @property
    def prompt(self) -> str:
        return self.paint(CYAN, f"[to {self.current_chat}] > ") if self.current_chat else "> "

    def show(self, text: str) -> None:
        """Print a line from the receiver thread without wrecking the prompt."""
        with self._print_lock:
            clear = "\r\033[K" if self.paint.enabled else "\n"
            print(f"{clear}{text}\n{self.prompt}", end="", flush=True)

    def status(self, text: str) -> None:
        self.show(self.paint(GREY, f"  {text}"))

    # ------------------------------------------------------------- events
    def _register_events(self) -> None:
        c = self.client
        c.on("message", self.on_message)
        c.on("ack", lambda m: None)   # one tick - too chatty to print every time
        c.on("delivered", lambda m: self.status(f"✓✓ delivered to {m['by']}: {self.sent.get(m['id'], '')}"))
        c.on("read", lambda m: [self.status(self.paint(CYAN, f"✓✓ read by {m['by']}: {self.sent.get(i, '')}"))
                                for i in m["ids"] if i in self.sent])
        c.on("presence", self.on_presence)
        c.on("error", lambda m: self.show(self.paint(RED, f"! {m.get('message', m.get('code'))}")))
        c.on("security", lambda kind, text: self.show(self.paint(RED, f"! SECURITY [{kind}] {text}")))
        c.on("disconnected", self.on_disconnected)

    def on_message(self, msg: dict) -> None:
        stamp = format_time(msg.get("sent_at") or 0)
        self.show(f"{self.paint(GREY, stamp)} {self.paint(GREEN + BOLD, msg['from'])}: {msg['text']}")
        if self.current_chat is None:
            self.current_chat = msg["from"]
        try:
            self.client.send_read(msg["from"], [msg["id"]])   # we've displayed it -> blue ticks
        except ClientError:
            pass

    def on_presence(self, msg: dict) -> None:
        if msg["username"] == self.client.username:
            return
        if msg["online"]:
            self.status(self.paint(GREEN, f"* {msg['username']} is online"))
        else:
            self.status(f"* {msg['username']} went offline")

    def on_disconnected(self, reason: str) -> None:
        self._running = False
        self.show(self.paint(RED, f"Disconnected: {reason}. Press Enter to exit."))

    # -------------------------------------------------------------- steps
    def connect(self) -> bool:
        c = self.client
        print(f"Connecting to {c.host}:{c.port} ...")
        try:
            fingerprint = c.connect()
        except ConnectionFailed as exc:
            print(self.paint(RED, str(exc)))
            return False
        groups = fingerprint.split(" ")
        print(self.paint(GREEN, "Secure channel established (RSA-2048-OAEP key exchange, AES-256-GCM)."))
        print(f"  Server key fingerprint: {self.paint(YELLOW, ' '.join(groups[:8]))}")
        print(f"                          {self.paint(YELLOW, ' '.join(groups[8:]))}")
        print(f"  Session key id:         {self.paint(MAGENTA, c.key_fingerprint)}")
        print(self.paint(GREY, "  Check that the fingerprint matches the one printed by the server.\n"))
        return True

    def authenticate(self) -> bool:
        while self.client.connected:
            try:
                choice = input("[L]ogin, [R]egister or [Q]uit? ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return False
            if choice.startswith("q"):
                return False
            if not choice or choice[0] not in "lr":
                continue
            try:
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                if choice.startswith("r"):
                    if getpass.getpass("Repeat password: ") != password:
                        print(self.paint(RED, "Passwords do not match.\n"))
                        continue
                    display = input("Display name (optional): ").strip() or None
                    profile = self.client.register(username, password, display)
                else:
                    profile = self.client.login(username, password)
            except (EOFError, KeyboardInterrupt):
                return False
            except AuthFailed as exc:
                print(self.paint(RED, f"{exc}\n"))
                continue
            except ClientError as exc:
                print(self.paint(RED, str(exc)))
                return False
            print(self.paint(GREEN, f"\nLogged in as {profile['display_name']} ({profile['username']})."))
            print(self.paint(GREY, "Type /help for commands.\n"))
            return True
        return False

    def list_users(self) -> None:
        users = sorted(self.client.users.values(), key=lambda u: (not u.get("online"), u["username"]))
        for u in users:
            if u["username"] == self.client.username:
                continue
            dot = self.paint(GREEN, "●") if u.get("online") else self.paint(GREY, "○")
            seen = format_last_seen(u.get("online", False), u.get("last_seen"))
            print(f"  {dot} {u['username']:<20} {u.get('display_name', ''):<20} {self.paint(GREY, seen)}")
        if len(users) <= 1:
            print(self.paint(GREY, "  (no other users yet - register a second account in another terminal)"))

    def send(self, to: str, text: str) -> None:
        to = to.lower()
        if to not in self.client.users:
            print(self.paint(RED, f"No user called '{to}'. Try /users."))
            return
        msg_id = self.client.send_message(to, text)
        self.sent[msg_id] = (text[:30] + "...") if len(text) > 30 else text
        self.current_chat = to

    def handle(self, line: str) -> None:
        if not line.startswith("/"):
            if self.current_chat:
                self.send(self.current_chat, line)
            else:
                print("Pick someone to talk to first: /msg <user> <text>  or  /chat <user>")
            return

        command, _, rest = line.partition(" ")
        command = command.lower()
        if command == "/help":
            print(HELP)
        elif command == "/users":
            self.list_users()
        elif command == "/msg":
            to, _, text = rest.strip().partition(" ")
            if to and text.strip():
                self.send(to, text.strip())
            else:
                print("Usage: /msg <user> <text>")
        elif command == "/chat":
            if rest.strip().lower() in self.client.users:
                self.current_chat = rest.strip().lower()
            else:
                print(self.paint(RED, f"No user called '{rest.strip()}'. Try /users."))
        elif command == "/ping":
            self.client.ping()
            threading.Timer(0.5, lambda: self.status(
                f"round trip: {self.client.latency_ms:.1f} ms" if self.client.latency_ms else "no reply yet")).start()
        elif command == "/info":
            print(f"  Server fingerprint: {self.client.server_fingerprint}")
            print(f"  Session key id:     {self.client.key_fingerprint}  (AES-256-GCM)")
        elif command == "/quit":
            self._running = False
        else:
            print(f"Unknown command {command}. Type /help.")

    def run(self) -> int:
        self._register_events()
        if not self.connect():
            return 1
        if not self.authenticate():
            self.client.logout()
            return 0
        self.client.user_list_received.wait(timeout=3)   # USER_LIST arrives just after AUTH_OK
        self.list_users()

        while self._running:
            try:
                line = input(self.prompt).strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not self._running:
                break
            if line:
                try:
                    self.handle(line)
                except ClientError as exc:
                    print(self.paint(RED, str(exc)))
        self.client.logout()
        print("Bye!")
        return 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")   # don't crash on emoji in old consoles
    parser = build_arg_parser("SecureChat terminal client")
    parser.add_argument("--fingerprint", help="Only connect if the server key has this fingerprint")
    args = parser.parse_args(argv)
    config = load_config(argv, role="client")
    return CliChat(config.client_host, config.port, args.fingerprint, config.heartbeat_interval).run()


if __name__ == "__main__":
    sys.exit(main())
