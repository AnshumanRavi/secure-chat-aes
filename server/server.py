"""
SecureChat server.

    python -m server.server                 # listen on config.json host/port
    python -m server.server --port 6000     # override the port
    python -m server.server --quiet         # hide the per-packet traffic lines
    python -m server.server --no-discovery  # don't answer "Find server on LAN" (UDP 5555)

What it does for each client (one thread per client):
    1. Handshake      RSA-OAEP key exchange -> AES-256-GCM session key
    2. Authentication REGISTER or LOGIN inside the encrypted channel
    3. Message loop   route chats, receipts, typing and presence between users

Routing is hop-by-hop: the server decrypts a message with the SENDER's
session key and re-encrypts it with the RECIPIENT's session key, so each
connection has its own key. If the recipient is offline, the message is
encrypted with the server's storage key and kept in the database until they
log in. (Prompt 13 adds optional end-to-end mode, where the server can't read
the message at all.)
"""

import getpass
import json
import os
import re
import socket
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Dict, Optional, Set

from common import crypto_utils as cu
from common import discovery, e2e
from common.config import PROJECT_ROOT, Config, build_arg_parser, load_config
from common.protocol import (
    ConnectionClosed, FrameTooLargeError, HandshakeError, IntegrityError, MsgType,
    ProtocolError, ReplayError, SecureChannel, b64d, server_handshake,
)
from server.auth import AccountLockedError, AuthError, AuthManager
from server.database import Database
from server.security_log import SecurityLog

KEYS_DIR = PROJECT_ROOT / "keys"
DB_PATH = PROJECT_ROOT / "data" / "server.db"
LOG_DIR = PROJECT_ROOT / "logs"
PASSPHRASE_ENV = "SECURECHAT_KEY_PASSPHRASE"

AUTH_TIMEOUT = 60            # seconds an unauthenticated client may stay connected
MAX_VIOLATIONS = 3           # tampered/replayed/malformed packets before disconnecting
MAX_TEXT_LENGTH = 10_000     # characters per chat message
MAX_ID_LENGTH = 64
MAX_READ_IDS = 500
MAX_GROUP_NAME = 40
MAX_GROUP_DESCRIPTION = 200
MAX_GROUP_MEMBERS = 50
HEX_COLOUR = re.compile(r"^#[0-9A-Fa-f]{6}$")

MAX_ABOUT = 140
MAX_E2E_LENGTH = 48 * 1024        # base64 of an end-to-end sealed message
FILE_CHUNK_SIZE = 64 * 1024
FILE_KINDS = {"image", "document"}
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_NAME = 255
MAX_THUMBNAIL_B64 = 96 * 1024
LOG_EVERY_NTH_CHUNK = 25          # don't flood the console with hundreds of chunk lines
MAX_OFFLINE_PER_USER = 5000       # queued packets per offline user (a 25 MB file is ~400) - stops disk filling


class SessionTerminated(Exception):
    """Raised to end a client session (e.g. too many security violations)."""


def _short_id(value) -> Optional[str]:
    """A client-chosen id (request_id, ...) if it is a short string, else None - never echo arbitrary JSON."""
    return value if isinstance(value, str) and len(value) <= MAX_ID_LENGTH else None


def _describe_unexpected(exc: Exception) -> str:
    """
    Where an unexpected exception happened - type, function and line only. Its message is left
    out on purpose: it can contain user data (e.g. "invalid literal for int(): '<text>'") and this
    line is written to logs/security.log.
    """
    frames = traceback.extract_tb(exc.__traceback__)
    where = f" in {frames[-1].name}() line {frames[-1].lineno}" if frames else ""
    return f"{type(exc).__name__}{where}"


def _worth_logging(message: dict) -> bool:
    """Log every packet except most FILE_CHUNKs (a 25 MB file is 400 of them)."""
    if MsgType(message["type"]) != MsgType.FILE_CHUNK:
        return True
    return message.get("index", 0) % LOG_EVERY_NTH_CHUNK == 0


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def _ask_new_passphrase() -> str:
    print("\nFirst run: creating the server's RSA-2048 key pair in keys/")
    print("Choose a passphrase. It encrypts the private key file, and you will need it")
    print(f"every time the server starts (or set the {PASSPHRASE_ENV} environment variable).\n")
    while True:
        first = getpass.getpass("New passphrase (min 8 characters): ")
        if len(first) < 8:
            print("  Too short, try again.")
            continue
        if getpass.getpass("Repeat passphrase: ") == first:
            return first
        print("  Passphrases do not match, try again.")


def load_server_keys(keys_dir, passphrase: Optional[str] = None):
    """
    Load (or on first run create) the server's keys. Returns (rsa_private_key, storage_key).

    keys/server_private.pem   RSA private key, encrypted with the passphrase
    keys/server_public.pem    RSA public key (clients see its fingerprint)
    keys/storage_key.bin      random AES-256 key for offline messages, itself
                              RSA-OAEP encrypted, so it is useless without the private key
    """
    keys_dir = Path(keys_dir)
    private_path = keys_dir / "server_private.pem"
    passphrase = passphrase or os.environ.get(PASSPHRASE_ENV)

    if not private_path.exists():
        passphrase = passphrase or _ask_new_passphrase()
        private_key = cu.generate_rsa_keypair()
        cu.save_private_key(private_key, private_path, passphrase)
        cu.save_public_key(private_key, keys_dir / "server_public.pem")
    elif passphrase:
        private_key = cu.load_private_key(private_path, passphrase)   # ValueError if wrong
    else:
        for attempt in range(3):
            try:
                private_key = cu.load_private_key(private_path, getpass.getpass("Private key passphrase: "))
                break
            except ValueError:
                print("  Wrong passphrase.")
        else:
            raise ValueError("Wrong passphrase entered 3 times")

    storage_path = keys_dir / "storage_key.bin"
    if storage_path.exists():
        storage_key = cu.rsa_decrypt(private_key, storage_path.read_bytes())
    else:
        storage_key = cu.generate_aes_key()
        storage_path.write_bytes(cu.rsa_encrypt(private_key.publickey(), storage_key))
    return private_key, storage_key


def get_lan_ips():
    """IPv4 addresses other PCs can use to reach this machine (best guess first)."""
    return discovery.lan_ips()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class ClientSession:
    def __init__(self, channel: SecureChannel, addr):
        self.channel = channel
        self.addr = addr
        self.username: Optional[str] = None
        self.profile: dict = {}
        self.violations = 0
        self.resumed = False              # logged in with a resume token (automatic reconnect)
        self.token_hash: Optional[str] = None
        self.transfers: Dict[str, dict] = {}   # file uploads in progress from this client

    @property
    def label(self) -> str:
        return self.username or f"{self.addr[0]}:{self.addr[1]}"


class ChatServer:
    def __init__(self, config: Config, keys_dir=KEYS_DIR, db_path=DB_PATH,
                 log: Optional[SecurityLog] = None, passphrase: Optional[str] = None,
                 show_bodies: bool = False, lan_discovery: bool = False):
        self.cfg = config
        self.log = log or SecurityLog(LOG_DIR)
        # Demo switch: print the bodies of NON-end-to-end messages, i.e. what a compromised
        # server could read. End-to-end messages are only ever shown as [E2E ciphertext].
        self.show_bodies = show_bodies
        self.private_key, self._storage_key = load_server_keys(keys_dir, passphrase)
        self.fingerprint = cu.public_key_fingerprint(self.private_key)
        self.db = Database(db_path)
        self.auth = AuthManager(self.db)

        self._online: Dict[str, ClientSession] = {}
        self._sessions: Set[ClientSession] = set()
        self._threads: Set[threading.Thread] = set()
        self._lock = threading.RLock()
        self._running = threading.Event()
        self._listener: Optional[socket.socket] = None
        self.port: Optional[int] = None
        # Answers the login screen's "Find server on LAN" button (common/discovery.py)
        self.lan_discovery = lan_discovery
        self._discovery: Optional[discovery.DiscoveryResponder] = None
        self._discovery_error = ""

    # ------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Bind the listening socket and print the startup banner."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":   # on Windows SO_REUSEADDR would let two servers share a port
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.cfg.server_host, self.cfg.port))
        self._listener.listen(50)
        self._listener.settimeout(1.0)   # wake up every second so Ctrl+C works on Windows
        self.port = self._listener.getsockname()[1]
        self._running.set()
        if self.lan_discovery:
            self._start_discovery()
        self._print_banner()

    def _start_discovery(self) -> None:
        bind = self.cfg.server_host if self.cfg.server_host != "0.0.0.0" else "0.0.0.0"
        try:
            self._discovery = discovery.DiscoveryResponder(self.port, self.fingerprint, host=bind).start()
        except OSError as exc:
            self._discovery_error = (f"UDP port {discovery.DISCOVERY_PORT} is in use ({exc.strerror or exc}) - "
                                     f"is another server running? Clients must type the IP address.")

    def _print_banner(self) -> None:
        fp = self.fingerprint.split(" ")
        lines = [
            "SecureChat Server    AES-256-GCM | RSA-2048-OAEP | PBKDF2-SHA256",
            "",
            f"Listening on         {self.cfg.server_host}:{self.port}",
            f"Clients on this PC   127.0.0.1:{self.port}",
            "",
        ]
        lan = discovery.adapters() if self.cfg.server_host in ("0.0.0.0", "") else []
        if lan:
            best = lan[0]
            lines.append(f">>> Clients on other PCs should connect to:  {best.ip}:{self.port}   ({best.name})")
            for other in lan[1:]:
                note = "  - virtual adapter, probably not this one" if other.virtual else ""
                lines.append(f"    or, on another network:                  {other.ip}:{self.port}   ({other.name}{note})")
        elif self.cfg.server_host in ("0.0.0.0", ""):
            lines.append("Clients on other PCs: no network adapter found - connect Wi-Fi/Ethernet first")
        else:
            lines.append(f"Only reachable at {self.cfg.server_host} (bound to that address)")
        if self._discovery:
            lines.append(f"    ... or press \"Find server on LAN\" in the app (UDP {self._discovery.port})")
        elif self._discovery_error:
            lines.append(f"LAN discovery off: {self._discovery_error}")
        lines += [
            "",
            f"Key fingerprint      {' '.join(fp[:8])}",
            f"                     {' '.join(fp[8:])}",
            "(Clients check this on their first connection.)",
            "",
            f"Registered users: {len(self.db.list_users())}    "
            f"Queued offline messages: {self.db.count_offline()}",
            "Press Ctrl+C to stop.",
        ]
        self.log.banner(lines)

    def serve_forever(self) -> None:
        while self._running.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break   # listener closed by stop()
            thread = threading.Thread(target=self._handle_connection, args=(conn, addr),
                                      name=f"client-{addr[0]}:{addr[1]}", daemon=True)
            with self._lock:
                self._threads.add(thread)
            thread.start()

    def start_in_background(self) -> threading.Thread:
        """Start and serve from a background thread (used by tests and benchmarks)."""
        self.start()
        thread = threading.Thread(target=self.serve_forever, name="accept-loop", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self.log.event("STOP", "Shutting down - disconnecting all clients")
        self._running.clear()
        if self._listener:
            self._listener.close()
        if self._discovery:
            self._discovery.stop()

        with self._lock:
            sessions = list(self._sessions)
            threads = list(self._threads)
        for session in sessions:
            self._send(session, {"type": MsgType.ERROR, "code": "SERVER_SHUTDOWN",
                                 "message": "The server is shutting down"})
            session.channel.close()
        for thread in threads:
            thread.join(timeout=3)

        self.db.close()
        self.log.event("STOP", "Server stopped")
        self.log.close()

    # ------------------------------------------------------- per-connection
    def _handle_connection(self, conn: socket.socket, addr) -> None:
        session = None
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.log.event("CONNECT", "New TCP connection", addr)
            try:
                channel = server_handshake(conn, self.private_key,
                                           max_frame_size=self.cfg.max_message_size,
                                           max_clock_skew=self.cfg.max_clock_skew)
            except HandshakeError as exc:
                self.log.event("HANDSHAKE_FAIL", str(exc), addr)
                conn.close()
                return

            session = ClientSession(channel, addr)
            with self._lock:
                self._sessions.add(session)
            self.log.event("HANDSHAKE", f"Secure channel ready: AES-256-GCM, session key id "
                                        f"{channel.key_fingerprint}", addr)

            conn.settimeout(min(AUTH_TIMEOUT, self.cfg.session_timeout))
            if not self._authenticate(session):
                return
            conn.settimeout(self.cfg.session_timeout)
            self._on_login(session)
            self._message_loop(session)

        except socket.timeout:
            self.log.event("TIMEOUT", "No activity - session timed out", addr,
                           session.username if session else None)
        except FrameTooLargeError as exc:
            self._log_violation(session, addr, "PROTOCOL", f"{exc} - disconnecting")
        except SessionTerminated as exc:
            self._log_violation(session, addr, "ERROR", str(exc))
        except (ConnectionClosed, OSError):
            pass   # client closed the connection or the server is stopping
        except Exception as exc:   # never let one bad client crash the server
            self.log.event("ERROR", f"Unexpected error: {_describe_unexpected(exc)} - connection closed",
                           addr, session.username if session else None)
        finally:
            if session:
                self._disconnect(session)
            else:
                conn.close()
            with self._lock:
                self._threads.discard(threading.current_thread())

    def _log_violation(self, session, addr, kind, message) -> None:
        self.log.event(kind, message, addr, session.username if session else None)

    # --------------------------------------------------------- send / recv
    def _recv(self, session: ClientSession) -> Optional[dict]:
        """
        Return the next valid message, or None if a bad packet was dropped.

        A tampered, replayed or malformed packet is logged and dropped; the
        connection survives the occasional bad packet but is closed after
        MAX_VIOLATIONS, since repeated failures mean someone is attacking it.
        """
        channel = session.channel
        try:
            message = channel.recv()
        except IntegrityError:
            self._violation(session, "TAMPER",
                            "GCM tag check FAILED - packet modified or forged, dropped")
            return None
        except ReplayError as exc:
            self._violation(session, "REPLAY", f"{exc} - dropped")
            return None
        except (FrameTooLargeError, ConnectionClosed):
            raise
        except ProtocolError as exc:
            self._violation(session, "PROTOCOL", f"{exc} - dropped")
            return None
        if _worth_logging(message):
            self.log.traffic("IN", session.label, message["type"], channel.last_received_ciphertext)
        return message

    def _violation(self, session: ClientSession, kind: str, message: str) -> None:
        session.violations += 1
        self.log.event(kind, f"{message} ({session.violations}/{MAX_VIOLATIONS})", session.addr,
                       session.username, ciphertext=session.channel.last_received_ciphertext)
        if session.violations >= MAX_VIOLATIONS:
            raise SessionTerminated("Too many security violations - connection closed")

    def _send(self, session: ClientSession, message: dict, peer: Optional[str] = None) -> bool:
        """Encrypt and send to one client. Returns False if the connection is gone."""
        try:
            session.channel.send(message)
        except (OSError, ProtocolError):
            return False
        if _worth_logging(message):
            self.log.traffic("OUT", session.label, MsgType(message["type"]).value,
                             session.channel.last_sent_ciphertext, peer)
        return True

    def _error(self, session: ClientSession, code: str, text: str, **extra) -> None:
        self._send(session, {"type": MsgType.ERROR, "code": code, "message": text, **extra})

    # ------------------------------------------------------- authentication
    def _authenticate(self, session: ClientSession) -> bool:
        """Wait for a successful REGISTER or LOGIN. Returns False if the client leaves."""
        while self._running.is_set():
            message = self._recv(session)
            if message is None:
                continue
            msg_type = message["type"]
            if msg_type == MsgType.PING:
                self._send(session, {"type": MsgType.PONG})
                continue
            if msg_type == MsgType.LOGOUT:
                return False
            if msg_type not in (MsgType.REGISTER, MsgType.LOGIN):
                self._error(session, "NOT_AUTHENTICATED", "Please log in first")
                continue

            username = AuthManager.normalise_username(message.get("username"))
            resuming = msg_type == MsgType.LOGIN and bool(message.get("resume_token"))
            try:
                if msg_type == MsgType.REGISTER:
                    user = self.auth.register(message.get("username"), message.get("password"),
                                              message.get("display_name"))
                    self.log.event("REGISTER", "New account created", session.addr, user["username"])
                elif resuming:
                    user = self.auth.resume(message.get("username"), message.get("resume_token"))
                    session.resumed = True
                else:
                    user = self.auth.login(message.get("username"), message.get("password"))
            except AccountLockedError as exc:
                self.log.event("LOCKOUT", f"Account locked after {self.auth.max_failed_attempts} "
                                          f"failed logins", session.addr, username)
                self._send(session, {"type": MsgType.AUTH_FAIL, "reason": str(exc),
                                     "retry_after": exc.retry_after})
                continue
            except AuthError as exc:
                if resuming:
                    self.log.event("AUTH_FAIL", "Invalid, used or expired resume token", session.addr, username)
                    self._send(session, {"type": MsgType.AUTH_FAIL, "reason": str(exc),
                                         "code": "SESSION_EXPIRED"})
                    continue
                if msg_type == MsgType.LOGIN:
                    self.log.event("AUTH_FAIL", f"Wrong username or password "
                                                f"({self.auth.failed_attempts(username)}/"
                                                f"{self.auth.max_failed_attempts})",
                                   session.addr, username)
                self._send(session, {"type": MsgType.AUTH_FAIL, "reason": str(exc)})
                continue

            session.username = user["username"]
            session.profile = user
            return True
        return False

    def _on_login(self, session: ClientSession) -> None:
        username = session.username
        with self._lock:
            previous = self._online.get(username)
            self._online[username] = session
        if previous:   # same account logged in elsewhere -> close the old session (like WhatsApp Web)
            self._error(previous, "SESSION_REPLACED", "You logged in from another device")
            previous.channel.close()

        self.log.event("LOGIN", "Reconnected (resumed session)" if session.resumed else "Logged in",
                       session.addr, username)
        token, session.token_hash = self.auth.issue_resume_token(username)   # fresh single-use token
        self._send(session, {"type": MsgType.AUTH_OK, "user": session.profile,
                             "server_time": time.time(), "resume_token": token})
        self._send(session, self._user_list(username))
        self._broadcast_presence(username, online=True)
        self._deliver_offline(session)

    # --------------------------------------------------------- message loop
    def _message_loop(self, session: ClientSession) -> None:
        handlers = {
            MsgType.CHAT_MSG: self._handle_chat,
            MsgType.GROUP_MSG: self._handle_group_msg,
            MsgType.CREATE_GROUP: self._handle_create_group,
            MsgType.LEAVE_GROUP: self._handle_leave_group,
            MsgType.UPDATE_PROFILE: self._handle_update_profile,
            MsgType.PUBLISH_KEY: self._handle_publish_key,
            MsgType.FILE_START: self._handle_file_start,
            MsgType.FILE_CHUNK: self._handle_file_chunk,
            MsgType.FILE_END: self._handle_file_end,
            MsgType.READ: self._handle_read,
            MsgType.TYPING: self._handle_typing,
            MsgType.USER_LIST: lambda s, m: self._send(s, self._user_list(s.username)),
            MsgType.PING: lambda s, m: self._send(s, {"type": MsgType.PONG}),
        }
        while self._running.is_set():
            message = self._recv(session)
            if message is None:
                continue
            msg_type = MsgType(message["type"])
            if msg_type == MsgType.LOGOUT:
                if session.token_hash:
                    self.auth.revoke(session.token_hash)   # an explicit logout can't be resumed
                self.log.event("LOGOUT", "Logged out", session.addr, session.username)
                return
            handler = handlers.get(msg_type)
            if handler is None:
                self._error(session, "UNSUPPORTED", f"{msg_type.value} is not supported yet")
                continue
            handler(session, message)

    def _handle_chat(self, session: ClientSession, message: dict) -> None:
        msg_id, text, sealed = message.get("id"), message.get("text"), message.get("e2e")
        recipient = AuthManager.normalise_username(message.get("to"))

        if not (isinstance(msg_id, str) and 0 < len(msg_id) <= MAX_ID_LENGTH):
            return self._error(session, "BAD_MESSAGE", "Message id is missing or invalid")
        if sealed is not None:
            # End-to-end encrypted: the body is AES-GCM ciphertext under a key that only the
            # two users can compute (ECDH of THEIR private keys). The server has no way to
            # decrypt it - it can only check the size and pass it on unchanged.
            if not (isinstance(sealed, dict) and isinstance(sealed.get("ct"), str)
                    and 0 < len(sealed["ct"]) <= MAX_E2E_LENGTH):
                return self._error(session, "BAD_MESSAGE", "Invalid end-to-end encrypted message", id=msg_id)
        elif not (isinstance(text, str) and 0 < len(text) <= MAX_TEXT_LENGTH):
            return self._error(session, "BAD_MESSAGE",
                               f"Message must be 1-{MAX_TEXT_LENGTH} characters", id=msg_id)
        if not self.db.user_exists(recipient):
            return self._error(session, "UNKNOWN_USER", f"No user called '{recipient}'", id=msg_id)

        # "from" is set by the server from the authenticated session, so it can't be spoofed
        forward = {"type": MsgType.CHAT_MSG, "id": msg_id, "from": session.username,
                   "to": recipient, "sent_at": message["ts"]}
        if sealed is not None:
            version = sealed.get("v", 1)
            forward["e2e"] = {"v": version if isinstance(version, int) and 0 < version < 100 else 1,
                              "ct": sealed["ct"]}
            self.log.event("E2E", f"{session.username} -> {recipient}  body: [E2E ciphertext] "
                                  f"{sealed['ct'][:28]}…  (no key on the server - cannot decrypt)",
                           session.addr, session.username)
        else:
            forward["text"] = text
            if self.show_bodies:     # demo mode: what a compromised server could read without E2E
                self.log.event("PLAINTEXT", f"{session.username} -> {recipient}  body readable by the "
                                            f"server: {text[:60]!r}", session.addr, session.username)

        self._send(session, {"type": MsgType.ACK, "id": msg_id, "to": recipient})          # one tick
        if self._route(recipient, forward, peer=f"from {session.username}"):
            self._send(session, {"type": MsgType.DELIVERED, "id": msg_id, "by": recipient,
                                 "at": time.time()})                                        # two ticks

    def _handle_read(self, session: ClientSession, message: dict) -> None:
        sender = AuthManager.normalise_username(message.get("to"))
        ids = message.get("ids")
        if not (isinstance(ids, list) and 0 < len(ids) <= MAX_READ_IDS
                and all(isinstance(i, str) and len(i) <= MAX_ID_LENGTH for i in ids)):
            return self._error(session, "BAD_MESSAGE", "READ needs a list of message ids")
        receipt = {"type": MsgType.READ, "ids": ids, "by": session.username, "at": time.time()}
        group_id = message.get("group_id")
        if group_id is not None:
            if not (isinstance(group_id, str) and self.db.is_member(group_id, session.username)):
                return self._error(session, "NOT_A_MEMBER", "You are not in that group")
            receipt["group_id"] = group_id
        if self.db.user_exists(sender):
            self._route(sender, receipt)

    # --------------------------------------------------------------- groups
    def _handle_create_group(self, session: ClientSession, message: dict) -> None:
        me = session.username
        name = message.get("name").strip() if isinstance(message.get("name"), str) else ""
        description = message.get("description") if isinstance(message.get("description"), str) else ""
        colour = message.get("avatar_color")
        raw_members = message.get("members")
        if not 1 <= len(name) <= MAX_GROUP_NAME:
            return self._error(session, "BAD_GROUP", f"Group name must be 1-{MAX_GROUP_NAME} characters")
        if len(description) > MAX_GROUP_DESCRIPTION:
            return self._error(session, "BAD_GROUP", f"Description must be at most {MAX_GROUP_DESCRIPTION} characters")
        if not isinstance(raw_members, list):
            return self._error(session, "BAD_GROUP", "Pick at least one member")
        members = {AuthManager.normalise_username(m) for m in raw_members} - {me, ""}
        if not 1 <= len(members) < MAX_GROUP_MEMBERS:
            return self._error(session, "BAD_GROUP", f"A group needs 1-{MAX_GROUP_MEMBERS - 1} other members")
        unknown = [m for m in members if not self.db.user_exists(m)]
        if unknown:
            return self._error(session, "UNKNOWN_USER", f"No user called '{unknown[0]}'")
        if not (isinstance(colour, str) and HEX_COLOUR.match(colour)):
            colour = "#00A884"

        group_id = uuid.uuid4().hex
        self.db.create_group(group_id, name, description.strip(), colour, me, sorted(members))
        group = self.db.get_group(group_id)
        self.log.event("GROUP", f"Created group '{name}' with {len(group['members'])} members",
                       session.addr, me)
        event = {"type": MsgType.CREATE_GROUP, "group": group, "actor": me,
                 "request_id": _short_id(message.get("request_id"))}
        for member in group["members"]:
            self._route(member["username"], event)        # offline members get it when they log in

    def _handle_group_msg(self, session: ClientSession, message: dict) -> None:
        me = session.username
        group_id, msg_id, text = message.get("group_id"), message.get("id"), message.get("text")
        if not (isinstance(msg_id, str) and 0 < len(msg_id) <= MAX_ID_LENGTH):
            return self._error(session, "BAD_MESSAGE", "Message id is missing or invalid")
        if not (isinstance(text, str) and 0 < len(text) <= MAX_TEXT_LENGTH):
            return self._error(session, "BAD_MESSAGE",
                               f"Message must be 1-{MAX_TEXT_LENGTH} characters", id=msg_id)
        if not (isinstance(group_id, str) and self.db.is_member(group_id, me)):
            return self._error(session, "NOT_A_MEMBER", "You are not a member of this group", id=msg_id)

        forward = {"type": MsgType.GROUP_MSG, "id": msg_id, "group_id": group_id, "from": me,
                   "text": text, "sent_at": message["ts"]}
        self._send(session, {"type": MsgType.ACK, "id": msg_id, "group_id": group_id})
        # Fan out: the message is re-encrypted with EACH member's own session key
        for member in self.db.group_members(group_id):
            if member == me:
                continue
            if self._route(member, forward, peer=f"group from {me}"):
                self._send(session, {"type": MsgType.DELIVERED, "id": msg_id, "by": member,
                                     "group_id": group_id, "at": time.time()})

    # ------------------------------------------------------- end-to-end keys
    def _handle_publish_key(self, session: ClientSession, message: dict) -> None:
        """Store the user's PUBLIC identity key so contacts can start E2E chats with them."""
        pem = message.get("public_key")
        if not (isinstance(pem, str) and len(pem) <= 1024):
            return self._error(session, "BAD_KEY", "Invalid identity key")
        try:
            e2e.import_public(pem)                 # must be a P-256 public key
        except e2e.E2EError as exc:
            return self._error(session, "BAD_KEY", str(exc))
        if self.db.set_identity_key(session.username, pem):
            self.log.event("KEY", f"Published E2E identity key {e2e.fingerprint(pem)} "
                                  f"(public half only)", session.addr, session.username)
            self._broadcast_presence(session.username, online=True)   # contacts learn the new key

    # --------------------------------------------------------------- profile
    def _handle_update_profile(self, session: ClientSession, message: dict) -> None:
        name, about = message.get("display_name"), message.get("about")
        if name is not None:
            name = name.strip() if isinstance(name, str) else ""
            if not 1 <= len(name) <= 30:
                return self._error(session, "BAD_PROFILE", "Your name must be 1-30 characters")
        if about is not None:
            about = about.strip() if isinstance(about, str) else ""
            if len(about) > MAX_ABOUT:
                return self._error(session, "BAD_PROFILE", f"'About' can be at most {MAX_ABOUT} characters")
        self.db.update_profile(session.username, display_name=name, about=about)
        session.profile = self.db.get_user(session.username)
        self.log.event("PROFILE", "Updated profile", session.addr, session.username)
        self._send(session, {"type": MsgType.UPDATE_PROFILE, "user": session.profile})
        self._broadcast_presence(session.username, online=True)    # carries the new profile to everyone

    # ----------------------------------------------------------- file sharing
    def _file_recipients(self, session: ClientSession, message: dict):
        """(recipients, routing fields) for a direct or group file, or None after sending an error."""
        group_id = message.get("group_id")
        if group_id is not None:
            if not (isinstance(group_id, str) and self.db.is_member(group_id, session.username)):
                self._error(session, "NOT_A_MEMBER", "You are not a member of this group", id=message.get("id"))
                return None
            members = [m for m in self.db.group_members(group_id) if m != session.username]
            return members, {"group_id": group_id}
        recipient = AuthManager.normalise_username(message.get("to"))
        if not self.db.user_exists(recipient):
            self._error(session, "UNKNOWN_USER", f"No user called '{recipient}'", id=message.get("id"))
            return None
        return [recipient], {"to": recipient}

    def _reject_file(self, session: ClientSession, file_id, reason: str) -> None:
        state = session.transfers.pop(file_id, None)
        if state is not None:
            self._abort_transfer(session, file_id, state)
        self.log.event("PROTOCOL", f"File transfer rejected: {reason}", session.addr, session.username)
        self._error(session, "FILE_REJECTED", reason, id=file_id)

    def _abort_transfer(self, session: ClientSession, file_id: str, state: dict) -> None:
        """
        The recipients already got FILE_START (and maybe some chunks): send them FILE_END
        marked as aborted, so their app shows "failed" instead of "receiving..." forever
        and deletes the partial file.
        """
        end = {"type": MsgType.FILE_END, "id": file_id, "from": session.username, "aborted": True,
               **state["routing"]}
        for recipient in state["recipients"]:
            self._route(recipient, end)

    def _handle_file_start(self, session: ClientSession, message: dict) -> None:
        """
        FILE_START announces a file. The server checks the metadata, remembers the transfer
        and forwards the announcement. It never sees a key that could decrypt the file
        outside its own hop - every chunk is decrypted from the sender's channel and
        re-encrypted for each recipient's channel.
        """
        file_id, name, size = message.get("id"), message.get("name"), message.get("size")
        chunks, sha256, kind = message.get("chunks"), message.get("sha256"), message.get("kind")
        thumb = message.get("thumb")
        if not (isinstance(file_id, str) and 0 < len(file_id) <= MAX_ID_LENGTH):
            return self._error(session, "BAD_MESSAGE", "File id is missing or invalid")
        if file_id in session.transfers:
            return self._reject_file(session, file_id, "This transfer is already in progress")
        if not (isinstance(name, str) and 0 < len(name) <= MAX_FILE_NAME):
            return self._reject_file(session, file_id, "Invalid file name")
        if not (isinstance(size, int) and 0 < size <= self.cfg.max_file_size):
            return self._reject_file(session, file_id,
                                     f"Files must be 1 byte to {self.cfg.max_file_size // (1024 * 1024)} MB")
        if chunks != -(-size // FILE_CHUNK_SIZE):          # ceil(size / chunk size)
            return self._reject_file(session, file_id, "Chunk count does not match the file size")
        if not (isinstance(sha256, str) and SHA256_HEX.match(sha256)):
            return self._reject_file(session, file_id, "Missing SHA-256 hash")
        if kind not in FILE_KINDS:
            return self._reject_file(session, file_id, "Unknown file kind")
        if thumb is not None and not (isinstance(thumb, str) and len(thumb) <= MAX_THUMBNAIL_B64):
            return self._reject_file(session, file_id, "Thumbnail too large")
        target = self._file_recipients(session, message)
        if target is None:
            return
        recipients, routing = target

        session.transfers[file_id] = {"recipients": recipients, "routing": routing, "size": size,
                                      "chunks": chunks, "next": 0, "bytes": 0, "name": name}
        forward = {"type": MsgType.FILE_START, "id": file_id, "from": session.username, "name": name,
                   "size": size, "chunks": chunks, "sha256": sha256, "kind": kind,
                   "mime": str(message.get("mime") or "application/octet-stream")[:100],
                   "thumb": thumb, "sent_at": message["ts"], **routing}
        for key in ("width", "height"):
            if isinstance(message.get(key), int) and 0 < message[key] < 100_000:
                forward[key] = message[key]
        self.log.event("FILE", f"'{name}' ({size} bytes) -> {chunks} encrypted chunks for "
                               f"{len(recipients)} recipient(s)", session.addr, session.username)
        for recipient in recipients:
            self._route(recipient, forward)

    def _handle_file_chunk(self, session: ClientSession, message: dict) -> None:
        file_id, index, data = message.get("id"), message.get("index"), message.get("data")
        state = session.transfers.get(file_id)
        if state is None:
            return self._error(session, "FILE_REJECTED", "Unknown file transfer", id=file_id)
        if index != state["next"]:
            return self._reject_file(session, file_id, f"Chunk {index} arrived out of order")
        try:
            length = len(b64d(data))
        except (ValueError, TypeError, AttributeError):
            return self._reject_file(session, file_id, "Chunk data is not valid base64")
        state["bytes"] += length
        if length > FILE_CHUNK_SIZE or state["bytes"] > state["size"]:
            return self._reject_file(session, file_id, "More data than the announced file size")
        state["next"] += 1
        forward = {"type": MsgType.FILE_CHUNK, "id": file_id, "index": index, "data": data,
                   "from": session.username}
        for recipient in state["recipients"]:
            self._route(recipient, forward)

    def _handle_file_end(self, session: ClientSession, message: dict) -> None:
        file_id = message.get("id")
        state = session.transfers.pop(file_id, None)
        if state is None:
            return self._error(session, "FILE_REJECTED", "Unknown file transfer", id=file_id)
        if state["next"] != state["chunks"] or state["bytes"] != state["size"]:
            session.transfers[file_id] = state            # so _reject_file can tell the recipients
            return self._reject_file(session, file_id, "The file ended before all chunks arrived")
        routing = state["routing"]
        self._send(session, {"type": MsgType.ACK, "id": file_id, **routing})              # one tick
        forward = {"type": MsgType.FILE_END, "id": file_id, "from": session.username, **routing}
        for recipient in state["recipients"]:
            if self._route(recipient, forward):
                receipt = {"type": MsgType.DELIVERED, "id": file_id, "by": recipient, "at": time.time()}
                if "group_id" in routing:
                    receipt["group_id"] = routing["group_id"]
                self._send(session, receipt)
        self.log.event("FILE", f"'{state['name']}' relayed ({state['chunks']} chunks)",
                       session.addr, session.username)

    def _handle_leave_group(self, session: ClientSession, message: dict) -> None:
        me, group_id = session.username, message.get("group_id")
        if not (isinstance(group_id, str) and self.db.is_member(group_id, me)):
            return self._error(session, "NOT_A_MEMBER", "You are not a member of this group")
        group = self.db.get_group(group_id)
        remaining = [m["username"] for m in group["members"] if m["username"] != me]
        new_admin = self.db.remove_member(group_id, me)
        updated = self.db.get_group(group_id) or dict(group, members=[])
        self.log.event("GROUP", f"Left group '{group['name']}'", session.addr, me)
        event = {"type": MsgType.GROUP_UPDATE, "event": "left", "actor": me, "group": updated,
                 "new_admin": new_admin}
        for username in [me] + remaining:
            self._route(username, event)

    def _handle_typing(self, session: ClientSession, message: dict) -> None:
        recipient = AuthManager.normalise_username(message.get("to"))
        self._route(recipient, {"type": MsgType.TYPING, "from": session.username,
                                "typing": bool(message.get("typing", True))}, store=False)

    # -------------------------------------------------------------- routing
    def _route(self, username: str, message: dict, store: bool = True,
               peer: Optional[str] = None) -> bool:
        """Send to a user if online. Otherwise queue it (encrypted). True = delivered now."""
        with self._lock:
            target = self._online.get(username)
        if target and self._send(target, message, peer):
            return True
        if store:
            self._store_offline(username, message)
        return False

    def _store_offline(self, username: str, message: dict) -> None:
        if self.db.count_offline(username) >= MAX_OFFLINE_PER_USER:
            self.log.event("PROTOCOL", f"Offline queue for {username} is full ({MAX_OFFLINE_PER_USER}) - "
                                       f"{MsgType(message['type']).value} dropped", user=username)
            return
        plaintext = json.dumps(dict(message, type=MsgType(message["type"]).value)).encode("utf-8")
        blob = cu.aes_encrypt(self._storage_key, plaintext, b"offline|" + username.encode())
        self.db.store_offline(username, blob)
        self.log.event("OFFLINE", f"{username} is offline - message stored encrypted",
                       user=username, ciphertext=blob)

    def _deliver_offline(self, session: ClientSession) -> None:
        username = session.username
        for row_id, blob in self.db.fetch_offline(username):
            try:
                message = json.loads(cu.aes_decrypt(self._storage_key, blob, b"offline|" + username.encode()))
            except IntegrityError:
                self.log.event("TAMPER", "Stored offline message failed its integrity check "
                                         "(database modified?) - discarded", user=username, ciphertext=blob)
                self.db.delete_offline(row_id)
                continue
            if not self._send(session, message, peer="queued"):
                return   # connection lost; the rest stays queued
            self.db.delete_offline(row_id)
            if message["type"] in (MsgType.CHAT_MSG, MsgType.GROUP_MSG, MsgType.FILE_END):
                receipt = {"type": MsgType.DELIVERED, "id": message["id"], "by": username, "at": time.time()}
                if message.get("group_id"):
                    receipt["group_id"] = message["group_id"]
                self._route(message["from"], receipt)

    # ------------------------------------------------------------- presence
    def _user_list(self, username: Optional[str] = None) -> dict:
        """Everyone on the server (with online status) plus the groups this user is in."""
        with self._lock:
            online = set(self._online)
        users = [dict(u, online=u["username"] in online) for u in self.db.list_users()]
        groups = self.db.groups_for_user(username) if username else []
        return {"type": MsgType.USER_LIST, "users": users, "groups": groups}

    def _broadcast_presence(self, username: str, online: bool, last_seen: Optional[float] = None) -> None:
        with self._lock:
            others = [s for name, s in self._online.items() if name != username]
        presence = {"type": MsgType.PRESENCE, "username": username, "online": online,
                    "last_seen": last_seen}
        if online:   # tell everyone about a new user's profile too (e.g. just registered)
            presence["user"] = self.db.get_user(username)
        for other in others:
            self._send(other, presence)

    def _disconnect(self, session: ClientSession) -> None:
        with self._lock:
            self._sessions.discard(session)
            was_online = session.username and self._online.get(session.username) is session
            if was_online:
                del self._online[session.username]
        session.channel.close()
        for file_id, state in list(session.transfers.items()):     # the sender left mid-upload
            self._abort_transfer(session, file_id, state)
        session.transfers.clear()
        if was_online and self._running.is_set():
            last_seen = self.db.update_last_seen(session.username)
            self.log.event("DISCONNECT", "Went offline", session.addr, session.username)
            self._broadcast_presence(session.username, online=False, last_seen=last_seen)
        elif was_online:
            self.db.update_last_seen(session.username)


# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = build_arg_parser("SecureChat server")
    parser.add_argument("--keys-dir", default=str(KEYS_DIR), help="Folder for the server's keys")
    parser.add_argument("--db", default=str(DB_PATH), help="SQLite database file")
    parser.add_argument("--quiet", action="store_true", help="Don't print every encrypted packet")
    parser.add_argument("--no-discovery", action="store_true",
                        help="Don't answer the clients' \"Find server on LAN\" broadcasts")
    parser.add_argument("--show-bodies", action="store_true",
                        help="DEMO: print message text the server can read (messages without end-to-end "
                             "encryption). E2E messages still only show as [E2E ciphertext].")
    args = parser.parse_args(argv)
    config = load_config(argv, role="server")

    try:
        server = ChatServer(config, keys_dir=args.keys_dir, db_path=args.db,
                            log=SecurityLog(LOG_DIR, show_traffic=not args.quiet), show_bodies=args.show_bodies,
                            lan_discovery=not args.no_discovery)
    except ValueError as exc:
        print(f"Could not unlock the server key: {exc}")
        return 1
    except KeyboardInterrupt:
        return 1

    try:
        server.start()
    except OSError as exc:
        print(f"Could not listen on {config.server_host}:{config.port} - {exc}")
        print("Is another server already running? Try a different port with --port.")
        return 1

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
