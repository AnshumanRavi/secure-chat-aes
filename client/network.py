"""
Reusable SecureChat client (used by both the terminal client and the GUI).

    client = ChatClient("127.0.0.1", 5555)
    client.on("message", lambda msg: print(msg["from"], msg["text"]))
    client.connect()                       # TCP + RSA/AES handshake
    print(client.server_fingerprint)       # show to the user to verify
    client.login("alice", "Passw0rd!")     # raises AuthFailed on a bad password
    client.send_message("bob", "Hi Bob!")
    ...
    client.logout()

Threads
-------
* receiver thread  - reads and decrypts every incoming packet and fires events
* heartbeat thread - sends PING every few seconds so the server knows we're alive

Events (register with client.on(name, callback)); callbacks run on the
receiver thread, so a GUI must hand them over to its own thread (Prompt 6):

    message(msg)            new chat message  {id, from, to, text, sent_at}
    ack(msg)                server got our message           -> one tick
    delivered(msg)          recipient's app got it           -> two grey ticks
    read(msg)               recipient read it                -> two blue ticks
    typing(msg)             {from, typing}
    presence(msg)           {username, online, last_seen}
    user_list(users)        list of user dicts (also kept in client.users)
    error(msg)              {code, message} from the server
    security(kind, text)    a received packet failed decryption or replay checks
    disconnected(reason)    connection lost (not called after logout()/close())
"""

import hashlib
import hmac
import math
import os
import queue
import socket
import struct
import sys
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Optional

from client.files import CHUNK_SIZE, MAX_FILE_SIZE, kind_for_path, mime_type, safe_filename, unique_path
from common import e2e
from common.config import PROJECT_ROOT
from common.protocol import (
    ConnectionClosed, HandshakeError, IntegrityError, MsgType, ProtocolError,
    ReplayError, SecureChannel, b64d, b64e, client_handshake,
)

EVENTS = ("message", "ack", "delivered", "read", "typing", "presence",
          "user_list", "error", "security", "disconnected",
          "groups", "group", "group_message",
          "file_incoming", "file_progress", "file_done", "profile")
#   profile(user)         my profile changed (after update_profile)
#   groups(list)          my groups (sent with USER_LIST after login)
#   group(msg)            CREATE_GROUP (a group I'm in was created) or GROUP_UPDATE (someone left)
#   group_message(msg)    {id, group_id, from, text, sent_at}
#   file_incoming(msg)    FILE_START: {id, from, name, size, kind, sha256, thumb, (to|group_id), ...}
#   file_progress(id, received_bytes, total_bytes)
#   file_done(result)     {id, ok, path} or {id, ok: False, error}


E2E_UNREADABLE = "🔒 End-to-end encrypted message - it can't be decrypted on this device."
SEND_TIMEOUT = 10        # seconds a send may block before the connection is treated as dead


def _set_send_timeout(sock: socket.socket, seconds: float) -> None:
    """
    Make a blocking send give up after `seconds` instead of waiting forever. Without it,
    a dead network with a full send buffer would block the sending thread - and the GUI
    thread sends chat messages - until the heartbeat noticed (up to a minute).
    Receiving stays blocking: the receiver thread is meant to wait for data.
    """
    if sys.platform == "win32":
        value = struct.pack("I", int(seconds * 1000))                       # DWORD milliseconds
    else:
        value = struct.pack("ll", int(seconds), int((seconds % 1) * 1e6))   # struct timeval
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, value)
    except (OSError, AttributeError):
        pass                 # not supported here - the heartbeat still detects a dead server


class ClientError(Exception):
    """Something went wrong in the client; str(error) is safe to show to the user."""


class ConnectionFailed(ClientError):
    pass


class ServerKeyChanged(ConnectionFailed):
    """The server presented a different public key than before (possible man-in-the-middle)."""


class AuthFailed(ClientError):
    def __init__(self, reason: str, retry_after: int = 0):
        super().__init__(reason)
        self.retry_after = retry_after


class ChatClient:
    def __init__(self, host: str, port: int, expected_fingerprint: Optional[str] = None,
                 heartbeat_interval: float = 30, timeout: float = 10):
        self.host = host
        self.port = port
        self.expected_fingerprint = expected_fingerprint
        self.heartbeat_interval = heartbeat_interval
        self.timeout = timeout

        self.channel: Optional[SecureChannel] = None
        self.username: Optional[str] = None
        self.profile: dict = {}
        self.users: Dict[str, dict] = {}
        self.groups: Dict[str, dict] = {}
        self.last_pong: Optional[float] = None
        self.latency_ms: Optional[float] = None
        self.user_list_received = threading.Event()   # set once the server has sent USER_LIST
        self.last_message_frame: Optional[bytes] = None
        self.resume_token: Optional[str] = None       # single-use token for automatic reconnects
        self.pinned_fingerprint: Optional[str] = None # server key seen on the first connection
        self.download_dir: Optional[Path] = None      # default: downloads/<username>/
        self._incoming: Dict[str, dict] = {}          # files being received
        # end-to-end encryption (see common/e2e.py)
        self._pair_keys: Dict[tuple, bytes] = {}
        self._e2e_key = None
        self.e2e_enabled = True                       # encrypt 1-to-1 messages end-to-end when possible
        self.last_message_e2e: Optional[str] = None   # sealed body of the last send_message (for the GUI)

        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._auth_replies: "queue.Queue[dict]" = queue.Queue()
        self._users_lock = threading.Lock()
        self._stop = threading.Event()
        self._stop.set()                              # not connected yet
        self._receiver: Optional[threading.Thread] = None
        self._heartbeat: Optional[threading.Thread] = None
        self._ping_sent_at: Optional[float] = None
        self._awaiting_pong_since: Optional[float] = None
        self._drop_reason: Optional[str] = None

    # ------------------------------------------------------------------ events
    def on(self, event: str, callback: Callable) -> None:
        if event not in EVENTS:
            raise ValueError(f"Unknown event {event!r}; choose from {EVENTS}")
        self._handlers[event].append(callback)

    def _emit(self, event: str, *args) -> None:
        for callback in self._handlers[event]:
            try:
                callback(*args)
            except Exception as exc:   # a buggy callback must not kill the receiver thread
                print(f"[ChatClient] error in '{event}' callback: {exc!r}", file=sys.stderr)

    # ---------------------------------------------------------- connection
    @property
    def connected(self) -> bool:
        return self.channel is not None and not self._stop.is_set()

    @property
    def server_fingerprint(self) -> Optional[str]:
        return self.channel.server_fingerprint if self.channel else None

    @property
    def key_fingerprint(self) -> Optional[str]:
        """Short ID of this session's AES key (safe to display; never the key itself)."""
        return self.channel.key_fingerprint if self.channel else None

    def connect(self) -> str:
        """Open the TCP connection and run the secure handshake. Returns the server fingerprint."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except ConnectionRefusedError as exc:
            raise ConnectionFailed(f"No SecureChat server at {self.host}:{self.port}. Is it running?") from exc
        except socket.timeout as exc:
            raise ConnectionFailed(f"Timed out connecting to {self.host}:{self.port}. "
                                   f"Check the IP address and the server's firewall.") from exc
        except OSError as exc:
            raise ConnectionFailed(f"Could not connect to {self.host}:{self.port}: "
                                   f"{exc.strerror or exc}") from exc

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # On a reconnect the server must present the SAME key as before - otherwise it may be an impostor
        expected = self.expected_fingerprint or self.pinned_fingerprint
        try:
            channel = client_handshake(sock, expected, timeout=self.timeout)
        except (ProtocolError, OSError) as exc:
            sock.close()
            if isinstance(exc, HandshakeError) and "fingerprint" in str(exc):
                raise ServerKeyChanged(f"Secure handshake failed: {exc}") from exc
            if isinstance(exc, HandshakeError):
                raise ConnectionFailed(f"Secure handshake failed: {exc}") from exc
            raise ConnectionFailed(f"Connection lost during the handshake: {exc}") from exc
        sock.settimeout(None)   # the receiver thread blocks until data arrives
        _set_send_timeout(sock, SEND_TIMEOUT)

        self.channel = channel
        self.pinned_fingerprint = channel.server_fingerprint
        self._auth_replies = queue.Queue()
        self.user_list_received.clear()
        self._awaiting_pong_since = None
        self._drop_reason = None
        # Each connection gets its own stop flag, so threads of an old connection can't revive
        self._stop = stop = threading.Event()
        self._receiver = threading.Thread(target=self._receive_loop, args=(channel, stop),
                                          name="receiver", daemon=True)
        self._receiver.start()
        if self.heartbeat_interval:
            self._heartbeat = threading.Thread(target=self._heartbeat_loop, args=(channel, stop),
                                               name="heartbeat", daemon=True)
            self._heartbeat.start()
        return channel.server_fingerprint

    def reconnect(self) -> dict:
        """Connect again and resume the session with the saved token (no password needed)."""
        self.close()
        self.connect()
        return self.resume()

    def close(self) -> None:
        """Close the connection without notifying the server."""
        self._stop.set()
        if self.channel:
            self.channel.close()
        if self._receiver and self._receiver is not threading.current_thread():
            self._receiver.join(timeout=2)

    def logout(self) -> None:
        if self.connected:
            try:
                self.channel.send({"type": MsgType.LOGOUT})
            except (OSError, ProtocolError):
                pass
        self.close()

    # -------------------------------------------------------- authentication
    def register(self, username: str, password: str, display_name: Optional[str] = None) -> dict:
        return self._authenticate({"type": MsgType.REGISTER, "username": username,
                                   "password": password, "display_name": display_name})

    def login(self, username: str, password: str) -> dict:
        return self._authenticate({"type": MsgType.LOGIN, "username": username, "password": password})

    def resume(self) -> dict:
        """Log in again with the single-use resume token from the previous AUTH_OK."""
        if not (self.username and self.resume_token):
            raise AuthFailed("No saved session - please log in again")
        token, self.resume_token = self.resume_token, None     # each token works only once
        return self._authenticate({"type": MsgType.LOGIN, "username": self.username, "resume_token": token})

    def _authenticate(self, request: dict) -> dict:
        self._send(request)
        try:
            reply = self._auth_replies.get(timeout=self.timeout)
        except queue.Empty:
            raise ClientError("The server did not answer the login request") from None
        if reply["type"] == "DISCONNECTED":
            raise ConnectionFailed(reply["reason"])
        if reply["type"] == MsgType.AUTH_FAIL.value:
            raise AuthFailed(reply.get("reason", "Login failed"), reply.get("retry_after", 0))
        self.profile = reply["user"]
        self.username = self.profile["username"]
        self.resume_token = reply.get("resume_token")
        return self.profile

    # ------------------------------------------------------------- sending
    def _send(self, message: dict) -> int:
        """Encrypt and send; returns the packet's sequence number."""
        if not self.connected:
            raise ClientError("Not connected to the server")
        channel = self.channel
        try:
            return channel.send(message)
        except OSError as exc:
            # A send that failed half-way leaves a partial packet in the stream, so this
            # connection can't be used again. Closing it ends the receiver thread, which
            # reports 'disconnected' - and the app reconnects and resends what's pending.
            self._drop_reason = "The connection to the server was lost"
            channel.close()
            raise ClientError(f"Could not send: {exc.strerror or exc}") from exc
        except ProtocolError as exc:
            raise ClientError(f"Could not send: {exc}") from exc

    def send_message(self, to: str, text: str, msg_id: Optional[str] = None) -> str:
        """
        Send a chat message. Returns its id (used to match ACK/DELIVERED/READ receipts).
        The encrypted packet that carried it is kept in self.last_message_frame
        (shown in the GUI's "Message info" for the demo).
        """
        msg_id = msg_id or uuid.uuid4().hex
        message = {"type": MsgType.CHAT_MSG, "id": msg_id, "to": to}
        if self.e2e_enabled and self.can_e2e(to):
            # sealed with a key only `to` and I can compute; the server just relays it
            sealed = e2e.seal(self._pair_key(to), self.username, to, msg_id, text)
            message["e2e"] = {"v": e2e.VERSION, "ct": sealed}
            self.last_message_e2e = sealed
        else:
            message["text"] = text
            self.last_message_e2e = None
        seq = self._send(message)
        last_seq, frame = self.channel.last_sent
        self.last_message_frame = frame if last_seq == seq else None   # a heartbeat may have slipped in
        return msg_id

    # ------------------------------------------------------ end-to-end keys
    @property
    def e2e_key(self):
        """My ECC P-256 identity key (private) or None."""
        return self._e2e_key

    @e2e_key.setter
    def e2e_key(self, key) -> None:
        self._e2e_key = key
        self._pair_keys.clear()        # pairwise keys depend on MY key too - recompute them

    @property
    def identity_fingerprint(self) -> Optional[str]:
        return e2e.fingerprint(self.e2e_key) if self.e2e_key is not None else None

    def publish_identity_key(self) -> None:
        """Upload my PUBLIC identity key (the private key never leaves this computer)."""
        if self.e2e_key is not None:
            self._send({"type": MsgType.PUBLISH_KEY, "public_key": e2e.export_public(self.e2e_key)})

    def peer_identity(self, username: str) -> Optional[str]:
        """A contact's public identity key (PEM), as distributed by the server."""
        return (self.users.get(username) or {}).get("identity_key")

    def can_e2e(self, username: str) -> bool:
        return self.e2e_key is not None and bool(self.peer_identity(username))

    def _pair_key(self, username: str) -> bytes:
        pem = self.peer_identity(username)
        if self.e2e_key is None or not pem:
            raise e2e.E2EError("No end-to-end key for this contact")
        cache_key = (username, pem)
        if cache_key not in self._pair_keys:
            self._pair_keys[cache_key] = e2e.pair_key(self.e2e_key, self.username, e2e.import_public(pem), username)
        return self._pair_keys[cache_key]

    def open_e2e(self, message: dict) -> bool:
        """Decrypt an end-to-end message in place (sets message['text']). Returns True on success."""
        sealed = (message.get("e2e") or {}).get("ct")
        if not sealed:
            return False
        try:
            message["text"] = e2e.open_sealed(self._pair_key(message["from"]), message["from"],
                                              self.username, message["id"], sealed)
            return True
        except e2e.E2EError:
            message["text"] = E2E_UNREADABLE
            return False

    def send_read(self, to: str, ids: List[str], group_id: Optional[str] = None) -> None:
        """Tell `to` that we have read their messages with these ids (in a group, if group_id)."""
        ids = list(ids)
        for start in range(0, len(ids), 500):    # the server accepts up to 500 ids per READ
            message = {"type": MsgType.READ, "to": to, "ids": ids[start:start + 500]}
            if group_id:
                message["group_id"] = group_id
            self._send(message)

    # ---------------------------------------------------------------- groups
    def create_group(self, name: str, members: List[str], description: str = "",
                     avatar_color: str = "#00A884") -> str:
        """Ask the server to create a group. Returns a request id that comes back in the
        CREATE_GROUP event, so the creator's GUI can open the new group."""
        request_id = uuid.uuid4().hex
        self._send({"type": MsgType.CREATE_GROUP, "name": name, "members": list(members),
                    "description": description, "avatar_color": avatar_color, "request_id": request_id})
        return request_id

    def send_group_message(self, group_id: str, text: str, msg_id: Optional[str] = None) -> str:
        msg_id = msg_id or uuid.uuid4().hex
        seq = self._send({"type": MsgType.GROUP_MSG, "id": msg_id, "group_id": group_id, "text": text})
        last_seq, frame = self.channel.last_sent
        self.last_message_frame = frame if last_seq == seq else None
        return msg_id

    def leave_group(self, group_id: str) -> None:
        self._send({"type": MsgType.LEAVE_GROUP, "group_id": group_id})

    def update_profile(self, display_name: Optional[str] = None, about: Optional[str] = None) -> None:
        message = {"type": MsgType.UPDATE_PROFILE}
        if display_name is not None:
            message["display_name"] = display_name
        if about is not None:
            message["about"] = about
        self._send(message)

    # ---------------------------------------------------------- file sharing
    def send_file(self, path, to: Optional[str] = None, group_id: Optional[str] = None,
                  kind: Optional[str] = None, msg_id: Optional[str] = None, thumb: Optional[bytes] = None,
                  width: Optional[int] = None, height: Optional[int] = None,
                  progress: Optional[Callable[[int, int], None]] = None) -> dict:
        """
        Send a file in 64 KB chunks: FILE_START -> FILE_CHUNK x N -> FILE_END.

        Every chunk is a separate AES-256-GCM packet (fresh nonce, own auth tag).
        The SHA-256 of the whole file goes in FILE_START so the receiver can prove
        the reassembled file is identical. Blocking - call it from a worker thread.
        Returns {"id", "sha256", "frame"} (frame = the encrypted FILE_START packet).
        """
        path = Path(path)
        size = path.stat().st_size
        if size == 0:
            raise ClientError("The file is empty")
        if size > MAX_FILE_SIZE:
            raise ClientError(f"Files can be at most {MAX_FILE_SIZE // (1024 * 1024)} MB")
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(block)
        chunks = math.ceil(size / CHUNK_SIZE)
        msg_id = msg_id or uuid.uuid4().hex

        start = {"type": MsgType.FILE_START, "id": msg_id, "name": path.name, "size": size,
                 "chunks": chunks, "sha256": sha256.hexdigest(), "kind": kind or kind_for_path(path),
                 "mime": mime_type(path)}
        start.update({"to": to} if to else {"group_id": group_id})
        if thumb:
            start["thumb"] = b64e(thumb)
        if width and height:
            start["width"], start["height"] = int(width), int(height)
        seq = self._send(start)
        last_seq, frame = self.channel.last_sent
        start_frame = frame if last_seq == seq else None

        with open(path, "rb") as f:
            for index in range(chunks):
                data = f.read(CHUNK_SIZE)
                self._send({"type": MsgType.FILE_CHUNK, "id": msg_id, "index": index, "data": b64e(data)})
                if progress:
                    progress(min(size, (index + 1) * CHUNK_SIZE), size)
        self._send({"type": MsgType.FILE_END, "id": msg_id})
        return {"id": msg_id, "sha256": sha256.hexdigest(), "frame": start_frame}

    def _downloads(self) -> Path:
        folder = Path(self.download_dir) if self.download_dir else \
            PROJECT_ROOT / "downloads" / (self.username or "user")
        (folder / ".partial").mkdir(parents=True, exist_ok=True)
        return folder

    def _on_file_start(self, message: dict) -> None:
        file_id = message["id"]
        # The name comes from another user: clean it before it is shown or used as a path
        # (no folders, no Windows device names, no right-to-left tricks like "photo\u202egpj.exe")
        message["name"] = safe_filename(message.get("name", "file"))
        if file_id in self._incoming:                       # a repeated FILE_START: start over
            self._discard_incoming(file_id, "The file was sent again")
        folder = self._downloads()
        part = folder / ".partial" / f"{safe_filename(file_id)}.part"
        self._incoming[file_id] = {"meta": message, "folder": folder, "part": part, "handle": open(part, "wb"),
                                   "sha256": hashlib.sha256(), "next": 0, "bytes": 0, "error": None}
        self._emit("file_incoming", message)

    def _on_file_chunk(self, message: dict) -> None:
        state = self._incoming.get(message.get("id"))
        if state is None or state["error"]:
            return
        if message.get("index") != state["next"]:
            state["error"] = "Chunks arrived out of order"
            return
        data = b64d(message["data"])
        state["bytes"] += len(data)
        if state["bytes"] > state["meta"]["size"]:
            state["error"] = "The file is larger than announced"
            return
        state["handle"].write(data)
        state["sha256"].update(data)
        state["next"] += 1
        self._emit("file_progress", message["id"], state["bytes"], state["meta"]["size"])

    def _discard_incoming(self, file_id: str, error: str) -> None:
        """Stop receiving a file: close and delete the partial download and report the failure."""
        state = self._incoming.pop(file_id, None)
        if state is None:
            return
        state["handle"].close()
        state["part"].unlink(missing_ok=True)
        self._emit("file_done", {"id": file_id, "ok": False, "error": error})

    def _on_file_end(self, message: dict) -> None:
        file_id = message.get("id")
        if message.get("aborted"):
            return self._discard_incoming(file_id, "The sender stopped sending this file")
        state = self._incoming.pop(file_id, None)
        if state is None:
            return
        state["handle"].close()
        meta = state["meta"]
        error = state["error"]
        if not error and (state["next"] != meta["chunks"] or state["bytes"] != meta["size"]):
            error = "Some parts of the file are missing"
        if not error and not hmac.compare_digest(state["sha256"].hexdigest(), meta["sha256"]):
            error = "SHA-256 check failed - the file was corrupted or tampered with"
        if error:
            state["part"].unlink(missing_ok=True)
            self._emit("file_done", {"id": file_id, "ok": False, "error": error})
            return
        final = unique_path(state["folder"], safe_filename(meta["name"]))
        os.replace(state["part"], final)
        self._emit("file_done", {"id": file_id, "ok": True, "path": str(final), "sha256": meta["sha256"]})

    def send_typing(self, to: str, typing: bool = True) -> None:
        self._send({"type": MsgType.TYPING, "to": to, "typing": typing})

    def ping(self) -> None:
        self._ping_sent_at = time.perf_counter()
        self._send({"type": MsgType.PING})

    def online_users(self) -> List[dict]:
        with self._users_lock:
            return [u for u in self.users.values() if u.get("online")]

    # ----------------------------------------------------------- receiving
    def _receive_loop(self, channel: SecureChannel, stop: threading.Event) -> None:
        reason = "Connection closed by the server"
        while not stop.is_set():
            try:
                message = channel.recv()
            except IntegrityError:
                self._emit("security", "TAMPER", "GCM authentication failed — message tampered (packet dropped)")
                continue
            except ReplayError as exc:
                self._emit("security", "REPLAY", f"Dropped a replayed or stale packet: {exc}")
                continue
            except ConnectionClosed:
                break
            except (ProtocolError, OSError) as exc:
                reason = f"Connection lost: {exc}"
                break
            message["_frame"] = channel.last_received_ciphertext   # the encrypted packet, for "Message info"
            self._dispatch(message)

        was_running = not stop.is_set()
        stop.set()
        for file_id in list(self._incoming):        # half-received files can't be finished on a new connection
            self._discard_incoming(file_id, "The connection was lost while receiving this file")
        self._auth_replies.put({"type": "DISCONNECTED", "reason": reason})  # wake a waiting login()
        if was_running:
            self._emit("disconnected", self._drop_reason or reason)

    def _dispatch(self, message: dict) -> None:
        msg_type = message["type"]

        if msg_type in (MsgType.AUTH_OK, MsgType.AUTH_FAIL):
            self._auth_replies.put(message)
        elif msg_type == MsgType.USER_LIST:
            with self._users_lock:
                self.users = {u["username"]: u for u in message["users"]}
                self.groups = {g["group_id"]: g for g in message.get("groups", [])}
            self.user_list_received.set()
            self._emit("user_list", list(self.users.values()))
            self._emit("groups", list(self.groups.values()))
        elif msg_type in (MsgType.CREATE_GROUP, MsgType.GROUP_UPDATE):
            group = message["group"]
            with self._users_lock:
                if any(m["username"] == self.username for m in group["members"]):
                    self.groups[group["group_id"]] = group
                else:
                    self.groups.pop(group["group_id"], None)
            self._emit("group", message)
        elif msg_type == MsgType.GROUP_MSG:
            self._emit("group_message", message)
        elif msg_type == MsgType.UPDATE_PROFILE:
            self.profile = dict(self.profile, **message["user"])
            self._emit("profile", self.profile)
        elif msg_type == MsgType.FILE_START:
            self._on_file_start(message)
        elif msg_type == MsgType.FILE_CHUNK:
            self._on_file_chunk(message)
        elif msg_type == MsgType.FILE_END:
            self._on_file_end(message)
        elif msg_type == MsgType.PRESENCE:
            with self._users_lock:
                user = self.users.setdefault(message["username"], {"username": message["username"]})
                user.update(message.get("user") or {})
                user["online"] = message["online"]
                if message.get("last_seen"):
                    user["last_seen"] = message["last_seen"]
            self._emit("presence", message)
        elif msg_type == MsgType.PONG:
            self.last_pong = time.time()
            self._awaiting_pong_since = None
            if self._ping_sent_at is not None:
                self.latency_ms = (time.perf_counter() - self._ping_sent_at) * 1000
        elif msg_type == MsgType.CHAT_MSG:
            if message.get("e2e") and "text" not in message:
                # decrypted later by the app (open_e2e) - it may not have loaded its key yet.
                # Clients without E2E support (e.g. the terminal client) just see this note.
                message["text"] = E2E_UNREADABLE if self.e2e_key is None else ""
                if self.e2e_key is not None:
                    self.open_e2e(message)
            self._emit("message", message)
        elif msg_type == MsgType.ACK:
            self._emit("ack", message)
        elif msg_type == MsgType.DELIVERED:
            self._emit("delivered", message)
        elif msg_type == MsgType.READ:
            self._emit("read", message)
        elif msg_type == MsgType.TYPING:
            self._emit("typing", message)
        elif msg_type == MsgType.ERROR:
            self._emit("error", message)

    def _heartbeat_loop(self, channel: SecureChannel, stop: threading.Event) -> None:
        """
        PING the server regularly. If two intervals pass without a PONG, the server
        (or the network) is gone even though TCP hasn't noticed yet - e.g. the server
        PC's Wi-Fi dropped - so close the socket, which triggers 'disconnected'.
        """
        while not stop.wait(self.heartbeat_interval):
            waiting = self._awaiting_pong_since
            if waiting is not None and time.monotonic() - waiting > 2 * self.heartbeat_interval:
                self._drop_reason = "The server stopped responding"
                channel.close()
                return
            try:
                self.ping()
            except ClientError:
                return
            if self._awaiting_pong_since is None:
                self._awaiting_pong_since = time.monotonic()
