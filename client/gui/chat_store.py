"""
Client-side state of all conversations (the "model" behind the chat list and chat view).

ChatStore listens to the network bridge and keeps, for every conversation:
the contact's profile and presence (or the group's members), the messages, the
unread count and whether someone is typing. Widgets never talk to the network
directly - they read from the store and call its methods, and redraw when it
emits a signal.

Chat ids: a direct chat uses the contact's username ("bob"); a group uses
"g:" + its group id (usernames can't contain ':' so they never clash).
"""

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from PySide6.QtCore import QObject, QTimer, Signal

from client.files import kind_for_path
from client.gui.media import image_size, make_thumbnail
from client.gui.workers import Task
from client.network import ClientError
from common import e2e
from common.protocol import b64d, b64e

# Status of a message I sent; it only ever moves forward
STATUS_ORDER = {"pending": 0, "sent": 1, "delivered": 2, "read": 3}

# The sender repeats TYPING every few seconds while typing. If we hear nothing for this
# long (e.g. their "stopped typing" packet was lost), hide "typing…" anyway.
TYPING_TIMEOUT = 6.0

GROUP_PREFIX = "g:"


def group_chat_id(group_id: str) -> str:
    return GROUP_PREFIX + group_id


@dataclass
class Message:
    id: str
    chat_id: str
    sender: str
    text: str
    ts: float
    outgoing: bool
    status: str = "pending"     # pending (clock) -> sent (✓) -> delivered (✓✓) -> read (blue ✓✓)
    status_times: Dict[str, float] = field(default_factory=dict)   # status -> when it happened
    frame: Optional[bytes] = None   # the encrypted packet that carried it (nonce || ciphertext || tag)
    read_sent: bool = False         # incoming only: we already told the sender we read it
    system: bool = False            # "Alice created group …", "Bob left" - shown as a centred chip
    # group messages I sent: who should receive it, and who has received / read it so far
    recipients: List[str] = field(default_factory=list)
    delivered_by: Set[str] = field(default_factory=set)
    read_by: Set[str] = field(default_factory=set)
    # files: kind is "image" or "document"; file holds name, size, sha256, path, thumb (bytes),
    # width/height, state ("uploading" | "downloading" | "done" | "failed"), progress (0..1), error
    kind: str = "text"              # text | image | document | security (key-change warning)
    file: Optional[dict] = None
    e2e: bool = False               # sent/received with end-to-end encryption
    e2e_sealed: Optional[str] = None  # the end-to-end ciphertext (base64) - shown in Message info

    @property
    def is_file(self) -> bool:
        return self.file is not None

    @property
    def preview(self) -> str:
        """One-line summary for the chat list and notifications."""
        if self.kind == "image":
            return "📷 Photo"
        if self.kind == "document":
            return f"📄 {self.file['name']}"
        return self.text


@dataclass
class Conversation:
    chat_id: str
    title: str
    avatar_color: str = "#00A884"
    about: str = ""                 # the contact's "About", or the group's description
    online: bool = False
    last_seen: Optional[float] = None
    kind: str = "direct"            # "direct" or "group"
    unread: int = 0
    typing: bool = False
    typing_until: float = 0.0       # time.monotonic() after which "typing…" expires
    messages: List[Message] = field(default_factory=list)
    # groups only
    group_id: Optional[str] = None
    members: List[dict] = field(default_factory=list)   # [{"username": ..., "role": "admin"|"member"}]
    created_by: Optional[str] = None
    left: bool = False              # I'm no longer a member
    history_complete: bool = True   # False while older messages are still only in the local database
    # end-to-end encryption (direct chats)
    identity_fp: Optional[str] = None   # fingerprint of the contact's identity key we last saw
    verified: bool = False              # I compared the security code with them

    @property
    def is_group(self) -> bool:
        return self.kind == "group"

    @property
    def last_message(self) -> Optional[Message]:
        return self.messages[-1] if self.messages else None

    @property
    def last_activity(self) -> float:
        return self.messages[-1].ts if self.messages else 0.0

    def member_names(self) -> List[str]:
        return [m["username"] for m in self.members]


HISTORY_PAGE = 50     # messages loaded per chat at start-up and per "scroll to the top"


def message_to_payload(msg: Message) -> dict:
    """Everything about a message that goes (encrypted) into the local history database."""
    payload = {"sender": msg.sender, "text": msg.text, "outgoing": msg.outgoing, "status": msg.status,
               "status_times": msg.status_times, "read_sent": msg.read_sent, "system": msg.system,
               "recipients": msg.recipients, "delivered_by": sorted(msg.delivered_by),
               "read_by": sorted(msg.read_by), "kind": msg.kind,
               "frame": msg.frame.hex() if msg.frame else None, "e2e": msg.e2e, "e2e_sealed": msg.e2e_sealed}
    if msg.file is not None:
        file = {k: v for k, v in msg.file.items() if k != "thumb"}
        if msg.file.get("thumb"):
            file["thumb"] = b64e(msg.file["thumb"])
        payload["file"] = file
    return payload


def payload_to_message(msg_id: str, chat_id: str, ts: float, p: dict) -> Message:
    file = p.get("file")
    if file is not None:
        file = dict(file)
        if file.get("thumb"):
            file["thumb"] = b64d(file["thumb"])
        if file.get("state") in ("uploading", "downloading"):    # the app closed mid-transfer
            file.update(state="failed", error="Transfer interrupted")
    return Message(id=msg_id, chat_id=chat_id, sender=p.get("sender", ""), text=p.get("text", ""), ts=ts,
                   outgoing=p.get("outgoing", False), status=p.get("status", "read"),
                   status_times=p.get("status_times", {}), read_sent=p.get("read_sent", True),
                   system=p.get("system", False), recipients=p.get("recipients", []),
                   delivered_by=set(p.get("delivered_by", [])), read_by=set(p.get("read_by", [])),
                   kind=p.get("kind", "text"), file=file,
                   frame=bytes.fromhex(p["frame"]) if p.get("frame") else None,
                   e2e=p.get("e2e", False), e2e_sealed=p.get("e2e_sealed"))


class ChatStore(QObject):
    conversation_added = Signal(str)        # chat_id
    conversation_changed = Signal(str)      # chat_id - profile, presence, messages or unread changed
    message_added = Signal(str, object)     # chat_id, Message
    message_updated = Signal(str, object)   # chat_id, Message (tick status changed)
    message_removed = Signal(str, str)      # chat_id, message id
    message_received = Signal(str, object)  # chat_id, Message - incoming only, for notifications
    group_created = Signal(str, str)        # chat_id, request_id - a group *I* created is ready
    # emitted from the upload worker threads; Qt delivers them on the GUI thread
    upload_progress = Signal(str, int, int)  # msg id, bytes sent, total
    upload_error = Signal(str)               # human-readable reason (shown as a toast)

    def __init__(self, client, bridge=None, parent=None, history=None):
        super().__init__(parent)
        self.client = client
        self.me = client.username
        self.history = history               # LocalStore (encrypted SQLite) or None
        self.send_read_receipts = True       # Settings > Privacy
        self.active_chat: Optional[str] = None
        self._chats: Dict[str, Conversation] = {}
        self._by_id: Dict[str, Message] = {}
        self._uploads: Dict[str, Task] = {}
        self.upload_progress.connect(self._on_upload_progress)
        self._typing_timer = QTimer(self, interval=1000)
        self._typing_timer.timeout.connect(self.expire_typing)
        self._typing_timer.start()

        self.on_user_list(list(client.users.values()))
        self.on_groups(list(getattr(client, "groups", {}).values()))

        # Persistence: changes are batched and written ~once a second
        self._dirty_messages: Dict[str, Message] = {}
        self._dirty_chats: Set[str] = set()
        self._flush_timer = QTimer(self, singleShot=True, interval=700)
        self._flush_timer.timeout.connect(self.flush)
        if self.history is not None:
            self._load_history()
            self.message_added.connect(self._remember)
            self.message_updated.connect(self._remember)
            self.message_removed.connect(lambda chat_id, msg_id: self.history.delete_message(msg_id))
            self.conversation_changed.connect(self._remember_chat)
        if bridge is not None:
            bridge.user_list.connect(self.on_user_list)
            bridge.groups.connect(self.on_groups)
            bridge.presence.connect(self.on_presence)
            bridge.message.connect(self.on_message)
            bridge.group_message.connect(self.on_group_message)
            bridge.group.connect(self.on_group_event)
            bridge.ack.connect(lambda m: self.set_status(m.get("id"), "sent"))
            bridge.delivered.connect(self.on_delivered)
            bridge.read.connect(self.on_read)
            bridge.typing.connect(self.on_typing)
            bridge.file_incoming.connect(self.on_file_incoming)
            bridge.file_progress.connect(self.on_file_progress)
            bridge.file_done.connect(self.on_file_done)

    # -------------------------------------------------------- local history
    def _load_history(self) -> None:
        """Restore the newest page of every chat from the encrypted database."""
        for chat_id, state in self.history.chats().items():
            chat = self._chats.get(chat_id)
            if chat is None:
                if chat_id.startswith(GROUP_PREFIX):     # a group the server no longer lists -> I left it
                    chat = self._upsert_group({"group_id": chat_id[len(GROUP_PREFIX):],
                                               "name": state.get("title", "Group"),
                                               "avatar_color": state.get("avatar_color"),
                                               "members": [m for m in state.get("members", [])
                                                           if m.get("username") != self.me]})
                else:
                    chat = self._upsert({"username": chat_id, "display_name": state.get("title"),
                                         "avatar_color": state.get("avatar_color")})
                if chat is None:
                    continue
            rows = self.history.load(chat_id, limit=HISTORY_PAGE)
            chat.messages = [payload_to_message(msg_id, chat_id, ts, p) for msg_id, ts, p in rows]
            for msg in chat.messages:
                self._by_id[msg.id] = msg
            chat.unread = state.get("unread", 0)
            chat.history_complete = len(rows) < HISTORY_PAGE
            stored_fp = state.get("identity_fp")
            if stored_fp and chat.identity_fp and stored_fp != chat.identity_fp:
                self._key_changed(chat)              # changed while we were logged out
            else:
                chat.identity_fp = chat.identity_fp or stored_fp
                chat.verified = bool(state.get("verified"))
            self.conversation_changed.emit(chat_id)

    def load_older(self, chat_id: str) -> int:
        """Load the previous page of a chat from the database. Returns how many were added."""
        chat = self._chats.get(chat_id)
        if self.history is None or chat is None or chat.history_complete:
            return 0
        self.flush()
        before = chat.messages[0].ts if chat.messages else None
        rows = self.history.load(chat_id, limit=HISTORY_PAGE, before_ts=before)
        older = [payload_to_message(msg_id, chat_id, ts, p) for msg_id, ts, p in rows if msg_id not in self._by_id]
        chat.messages[:0] = older
        for msg in older:
            self._by_id[msg.id] = msg
        chat.history_complete = len(rows) < HISTORY_PAGE
        return len(older)

    def load_all(self, chat_id: str) -> None:
        while self.load_older(chat_id):
            pass

    def _remember(self, chat_id: str, msg: Message) -> None:
        self._dirty_messages[msg.id] = msg
        self._flush_timer.start()

    def _remember_chat(self, chat_id: str) -> None:
        chat = self._chats.get(chat_id)
        if chat is not None and (chat.messages or chat.unread):
            self._dirty_chats.add(chat_id)
            self._flush_timer.start()

    def flush(self) -> None:
        """Write pending changes to the encrypted database."""
        if self.history is None:
            return
        messages = [m for m in self._dirty_messages.values() if m.id in self._by_id]
        if messages:
            self.history.save_messages([(m.chat_id, m.id, m.ts, message_to_payload(m)) for m in messages])
        for chat_id in self._dirty_chats:
            chat = self._chats.get(chat_id)
            if chat is not None:
                state = {"unread": chat.unread, "title": chat.title, "avatar_color": chat.avatar_color,
                         "identity_fp": chat.identity_fp, "verified": chat.verified}
                if chat.is_group:
                    state["members"] = chat.members
                self.history.save_chat(chat_id, state)
        self._dirty_messages.clear()
        self._dirty_chats.clear()

    def clear_history(self) -> None:
        """Settings > Security > Clear chat history: wipe this device's copy of every chat."""
        if self.history is not None:
            self._dirty_messages.clear()
            self._dirty_chats.clear()
            self.history.clear()
        self._by_id.clear()
        for chat in self._chats.values():
            chat.messages.clear()
            chat.unread = 0
            chat.history_complete = True
            self.conversation_changed.emit(chat.chat_id)

    def search(self, query: str, chat_id: Optional[str] = None, limit: int = 100) -> List[Message]:
        """Messages containing `query` (case-insensitive), newest first. Searches the full history."""
        query = query.strip().lower()
        if not query:
            return []
        chats = [self._chats[chat_id]] if chat_id in self._chats else list(self._chats.values())
        results = []
        for chat in chats:
            self.load_all(chat.chat_id)       # decrypt older pages too (stays in memory afterwards)
            for msg in chat.messages:
                if msg.system:
                    continue
                haystack = msg.text if not msg.is_file else f"{msg.text} {msg.file['name']}"
                if query in haystack.lower():
                    results.append(msg)
        results.sort(key=lambda m: m.ts, reverse=True)
        return results[:limit]

    # ----------------------------------------------------------------- read
    def conversations(self) -> List[Conversation]:
        return list(self._chats.values())

    def get(self, chat_id: str) -> Optional[Conversation]:
        return self._chats.get(chat_id)

    def message(self, msg_id: str) -> Optional[Message]:
        return self._by_id.get(msg_id)

    def display_name(self, username: str, you: str = "You") -> str:
        """'You' for me, otherwise the contact's display name (or username)."""
        if username == self.me:
            return you
        chat = self._chats.get(username)
        if chat:
            return chat.title
        user = self.client.users.get(username) or {}
        return user.get("display_name") or username

    def first_name(self, username: str) -> str:
        return self.display_name(username).split()[0]

    # ------------------------------------------------------ contacts/presence
    def _upsert(self, user: dict) -> Optional[Conversation]:
        username = user.get("username")
        if not username or username == self.me:
            return None
        chat = self._chats.get(username)
        is_new = chat is None
        if is_new:
            chat = Conversation(chat_id=username, title=user.get("display_name") or username)
            self._chats[username] = chat
        chat.title = user.get("display_name") or chat.title
        chat.avatar_color = user.get("avatar_color") or chat.avatar_color
        chat.about = user.get("about", chat.about) or ""
        if "online" in user:
            chat.online = bool(user["online"])
        if user.get("last_seen"):
            chat.last_seen = user["last_seen"]
        if is_new:
            self.conversation_added.emit(username)
        if user.get("identity_key"):
            try:
                fp = e2e.fingerprint(user["identity_key"])
            except e2e.E2EError:
                fp = None
            if fp and chat.identity_fp and fp != chat.identity_fp:
                chat.identity_fp = fp
                self._key_changed(chat)
            elif fp:
                chat.identity_fp = fp
        return chat

    # ------------------------------------------------------ end-to-end keys
    def _key_changed(self, chat: Conversation) -> None:
        """A contact's identity key is different from before: warn (yellow) and drop 'verified'."""
        chat.verified = False
        self._add_system(chat, f"{chat.title}'s security code changed. Click to verify it with them.",
                         kind="security")

    def set_verified(self, chat_id: str, verified: bool = True) -> None:
        chat = self._chats.get(chat_id)
        if chat:
            chat.verified = verified
            self.conversation_changed.emit(chat_id)

    def e2e_active(self, chat_id: str) -> bool:
        """Are new messages in this chat end-to-end encrypted?"""
        chat = self._chats.get(chat_id)
        return bool(chat and not chat.is_group and getattr(self.client, "e2e_enabled", False)
                    and hasattr(self.client, "can_e2e") and self.client.can_e2e(chat_id))

    def on_user_list(self, users: list) -> None:
        for user in users:
            chat = self._upsert(user)
            if chat:
                self.conversation_changed.emit(chat.chat_id)

    def on_presence(self, message: dict) -> None:
        user = dict(message.get("user") or {}, username=message["username"], online=message["online"])
        if message.get("last_seen"):
            user["last_seen"] = message["last_seen"]
        chat = self._upsert(user)
        if chat:
            if not chat.online:
                chat.typing = False
            self.conversation_changed.emit(chat.chat_id)

    # ----------------------------------------------------------------- groups
    def _upsert_group(self, group: dict) -> Conversation:
        chat_id = group_chat_id(group["group_id"])
        chat = self._chats.get(chat_id)
        is_new = chat is None
        if is_new:
            chat = Conversation(chat_id=chat_id, title=group["name"], kind="group", group_id=group["group_id"])
            self._chats[chat_id] = chat
        chat.title = group.get("name") or chat.title
        chat.avatar_color = group.get("avatar_color") or chat.avatar_color
        chat.about = group.get("description", chat.about) or ""
        chat.created_by = group.get("created_by", chat.created_by)
        chat.members = list(group.get("members", []))
        chat.left = self.me not in chat.member_names()
        if is_new:
            self.conversation_added.emit(chat_id)
        return chat

    def on_groups(self, groups: list) -> None:
        for group in groups:
            self.conversation_changed.emit(self._upsert_group(group).chat_id)

    def on_group_event(self, message: dict) -> None:
        """CREATE_GROUP (new group) or GROUP_UPDATE (someone left) -> update + system message."""
        chat = self._upsert_group(message["group"])
        actor = message.get("actor", "")
        if message["type"] == "CREATE_GROUP":
            if actor == self.me:
                self._add_system(chat, f"You created group “{chat.title}”")
                if message.get("request_id"):
                    self.group_created.emit(chat.chat_id, message["request_id"])
            else:
                self._add_system(chat, f"{self.display_name(actor)} created group “{chat.title}”")
                self._add_system(chat, f"{self.display_name(actor)} added you")
        elif message.get("event") == "left":
            self._add_system(chat, "You left" if actor == self.me else f"{self.display_name(actor)} left")
            new_admin = message.get("new_admin")
            if new_admin:
                self._add_system(chat, "You're now an admin" if new_admin == self.me
                                 else f"{self.display_name(new_admin)} is now an admin")
            # someone who left will never read my earlier messages - stop waiting for them
            for msg in chat.messages:
                if msg.outgoing and actor in msg.recipients:
                    msg.recipients.remove(actor)
                    self._update_group_status(msg)
        self.conversation_changed.emit(chat.chat_id)

    def _add_system(self, chat: Conversation, text: str, kind: str = "text") -> None:
        msg = Message(id=f"sys-{uuid.uuid4().hex}", chat_id=chat.chat_id, sender="", text=text,
                      ts=time.time(), outgoing=False, status="read", system=True, read_sent=True, kind=kind)
        chat.messages.append(msg)
        self._by_id[msg.id] = msg
        self.message_added.emit(chat.chat_id, msg)

    # --------------------------------------------------------------- messages
    def _receive(self, chat: Conversation, message: dict, **extra) -> None:
        if message["id"] in self._by_id:
            return                     # duplicate (e.g. resent after a reconnect)
        received = time.time()
        msg = Message(id=message["id"], chat_id=chat.chat_id, sender=message["from"],
                      text=message.get("text", ""), ts=message.get("sent_at") or received, outgoing=False,
                      status="received", status_times={"received": received}, frame=message.get("_frame"),
                      **extra)
        chat.messages.append(msg)
        self._by_id[msg.id] = msg
        chat.typing = False
        if chat.chat_id != self.active_chat:
            chat.unread += 1
        self.message_added.emit(chat.chat_id, msg)
        self.conversation_changed.emit(chat.chat_id)
        self.message_received.emit(chat.chat_id, msg)

    def on_message(self, message: dict) -> None:
        sender = message["from"]
        chat = self._chats.get(sender) or self._upsert(self.client.users.get(sender) or {"username": sender})
        if chat is None:
            return
        extra = {}
        if message.get("e2e"):
            # Decrypt here (GUI thread) rather than on arrival: offline messages are delivered
            # right after login, before the app has loaded our identity key.
            if hasattr(self.client, "open_e2e"):
                self.client.open_e2e(message)
            extra = {"e2e": True, "e2e_sealed": message["e2e"].get("ct")}
        self._receive(chat, message, **extra)

    def _group_chat(self, group_id: str) -> Conversation:
        chat = self._chats.get(group_chat_id(group_id))
        if chat is None:                 # group details not here yet - use what the client knows
            group = self.client.groups.get(group_id) or {"group_id": group_id, "name": "Group", "members": []}
            chat = self._upsert_group(group)
        return chat

    def on_group_message(self, message: dict) -> None:
        self._receive(self._group_chat(message["group_id"]), message)

    # ------------------------------------------------------------------ files
    def send_file(self, chat_id: str, path: str, kind: Optional[str] = None) -> Optional[Message]:
        """Add a file bubble straight away, then upload it on a worker thread."""
        chat = self._chats.get(chat_id)
        if not chat or chat.left:
            return None
        path = str(Path(path).resolve())
        kind = kind or kind_for_path(path)
        width, height = image_size(path) if kind == "image" else (0, 0)
        if kind == "image" and not width:
            kind = "document"           # not a readable image - send it as a plain file
        now = time.time()
        msg = Message(id=uuid.uuid4().hex, chat_id=chat_id, sender=self.me, text="", ts=now, outgoing=True,
                      status_times={"pending": now}, kind=kind,
                      file={"name": Path(path).name, "size": os.path.getsize(path), "path": path,
                            "width": width, "height": height, "state": "uploading", "progress": 0.0})
        if chat.is_group:
            msg.recipients = [u for u in chat.member_names() if u != self.me]
        chat.messages.append(msg)
        self._by_id[msg.id] = msg
        self.message_added.emit(chat_id, msg)
        self.conversation_changed.emit(chat_id)

        target = {"group_id": chat.group_id} if chat.is_group else {"to": chat_id}
        task = Task(lambda: self._upload(msg.id, path, kind, width, height, target), self)
        # bound methods (not lambdas) so Qt runs these on the GUI thread
        task.succeeded.connect(self._on_upload_finished)
        task.finished.connect(task.deleteLater)
        self._uploads[msg.id] = task
        task.start()
        return msg

    def _upload(self, msg_id: str, path: str, kind: str, width: int, height: int, target: dict) -> dict:
        """Runs on a worker thread - the GUI keeps responding while the chunks go out."""
        try:
            thumb = make_thumbnail(path) if kind == "image" else None
            result = self.client.send_file(
                path, kind=kind, msg_id=msg_id, thumb=thumb, width=width, height=height,
                progress=lambda done, total: self.upload_progress.emit(msg_id, done, total), **target)
        except (ClientError, OSError) as exc:
            return {"id": msg_id, "error": str(exc)}
        return result

    def _on_upload_progress(self, msg_id: str, done: int, total: int) -> None:
        self._set_progress(self._by_id.get(msg_id), done, total)

    def _on_upload_finished(self, result: dict) -> None:
        self._uploads.pop(result["id"], None)
        msg = self._by_id.get(result["id"])
        if msg is None:
            return
        if "error" in result:
            msg.file.update(state="failed", error=result["error"])
            msg.status = "failed"
            self.upload_error.emit(f"Couldn't send {msg.file['name']}: {result['error']}")
            self.conversation_changed.emit(msg.chat_id)
        else:
            msg.file.update(state="done", progress=1.0, sha256=result.get("sha256"))
            msg.frame = result.get("frame")
        self.message_updated.emit(msg.chat_id, msg)

    def _set_progress(self, msg: Optional[Message], done: int, total: int) -> None:
        if msg is None or not msg.file or not total:
            return
        progress = done / total
        if progress - msg.file["progress"] >= 0.01 or progress >= 1:   # redraw at most ~100 times
            msg.file["progress"] = progress
            self.message_updated.emit(msg.chat_id, msg)

    def on_file_incoming(self, message: dict) -> None:
        if message.get("group_id"):
            chat = self._group_chat(message["group_id"])
        else:
            sender = message["from"]
            chat = self._chats.get(sender) or self._upsert(self.client.users.get(sender) or {"username": sender})
        if chat is None:
            return
        thumb = None
        if message.get("thumb"):
            try:
                thumb = b64d(message["thumb"])
            except ValueError:
                thumb = None
        file = {"name": message["name"], "size": message["size"], "sha256": message["sha256"],
                "mime": message.get("mime"), "thumb": thumb, "width": message.get("width", 0),
                "height": message.get("height", 0), "state": "downloading", "progress": 0.0, "path": None}
        self._receive(chat, message, kind=message.get("kind", "document"), file=file)

    def on_file_progress(self, msg_id: str, received: int, total: int) -> None:
        self._set_progress(self._by_id.get(msg_id), received, total)

    def on_file_done(self, result: dict) -> None:
        msg = self._by_id.get(result.get("id"))
        if not (msg and msg.file):
            return
        if result.get("ok"):
            msg.file.update(state="done", progress=1.0, path=result["path"], verified=True)
        else:
            msg.file.update(state="failed", error=result.get("error", "Download failed"))
        self.message_updated.emit(msg.chat_id, msg)
        self.conversation_changed.emit(msg.chat_id)

    def on_typing(self, message: dict) -> None:
        chat = self._chats.get(message.get("from"))
        if chat:
            chat.typing = bool(message.get("typing"))
            chat.typing_until = time.monotonic() + TYPING_TIMEOUT if chat.typing else 0.0
            self.conversation_changed.emit(chat.chat_id)

    def expire_typing(self, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        for chat in self._chats.values():
            if chat.typing and chat.typing_until < now:
                chat.typing = False
                self.conversation_changed.emit(chat.chat_id)

    def connection_lost(self) -> None:
        """While we're offline we can't know who is online or typing, so stop showing it.
        The server sends a fresh USER_LIST when we reconnect."""
        for chat in self._chats.values():
            if chat.online or chat.typing:
                chat.online = chat.typing = False
                self.conversation_changed.emit(chat.chat_id)

    # --------------------------------------------------------------- receipts
    def set_status(self, msg_id: Optional[str], status: str, at: Optional[float] = None) -> None:
        """Move one of my messages forward (sent -> delivered -> read); never backwards."""
        msg = self._by_id.get(msg_id)
        if not (msg and msg.outgoing and STATUS_ORDER.get(status, -1) > STATUS_ORDER.get(msg.status, -1)):
            return
        msg.status = status
        when = at or time.time()
        for earlier, order in STATUS_ORDER.items():   # a READ implies sent and delivered too
            if 0 < order <= STATUS_ORDER[status]:
                msg.status_times.setdefault(earlier, when)
        self.message_updated.emit(msg.chat_id, msg)
        self.conversation_changed.emit(msg.chat_id)

    def on_delivered(self, receipt: dict) -> None:
        msg = self._by_id.get(receipt.get("id"))
        if msg and msg.recipients:                     # group: wait until every member has it
            msg.delivered_by.add(receipt.get("by"))
            self._update_group_status(msg, receipt.get("at"))
        else:
            self.set_status(receipt.get("id"), "delivered", receipt.get("at"))

    def on_read(self, receipt: dict) -> None:
        for msg_id in receipt.get("ids", []):
            msg = self._by_id.get(msg_id)
            if msg and msg.recipients:                 # group: blue only when EVERY member has read it
                msg.read_by.add(receipt.get("by"))
                msg.delivered_by.add(receipt.get("by"))
                self._update_group_status(msg, receipt.get("at"))
            else:
                self.set_status(msg_id, "read", receipt.get("at"))

    def _update_group_status(self, msg: Message, at: Optional[float] = None) -> None:
        everyone = set(msg.recipients)
        if everyone and everyone <= msg.read_by:
            self.set_status(msg.id, "read", at)
        elif everyone and everyone <= msg.delivered_by:
            self.set_status(msg.id, "delivered", at)
        else:
            self.message_updated.emit(msg.chat_id, msg)   # e.g. Message info's "read by" list

    # -------------------------------------------------------------- actions
    def open_chat(self, chat_id: Optional[str]) -> None:
        self.active_chat = chat_id
        chat = self._chats.get(chat_id) if chat_id else None
        if chat and chat.unread:
            chat.unread = 0
            self.conversation_changed.emit(chat_id)

    def mark_read(self, chat_id: Optional[str]) -> int:
        """Send READ receipts for incoming messages not yet acknowledged. Returns how many."""
        chat = self._chats.get(chat_id) if chat_id else None
        if not chat or not self.send_read_receipts:     # Settings > Privacy > Read receipts
            return 0
        unread = [m for m in chat.messages if not m.outgoing and not m.read_sent and not m.system]
        if not unread:
            return 0
        by_sender: Dict[str, List[Message]] = {}
        for m in unread:                                # in a group, each sender gets their own receipt
            by_sender.setdefault(m.sender, []).append(m)
        try:
            for sender, messages in by_sender.items():
                self.client.send_read(sender, [m.id for m in messages],
                                      **({"group_id": chat.group_id} if chat.is_group else {}))
                for m in messages:
                    m.read_sent = True
        except ClientError:
            pass
        return sum(1 for m in unread if m.read_sent)

    def send_text(self, chat_id: str, text: str) -> Optional[Message]:
        """Add my message to the chat (clock icon) and send it; ticks update as receipts arrive."""
        chat = self._chats.get(chat_id)
        text = text.strip()
        if not chat or not text or chat.left:
            return None
        now = time.time()
        msg = Message(id=uuid.uuid4().hex, chat_id=chat_id, sender=self.me, text=text, ts=now,
                      outgoing=True, status_times={"pending": now})
        if chat.is_group:
            msg.recipients = [u for u in chat.member_names() if u != self.me]
        chat.messages.append(msg)
        self._by_id[msg.id] = msg
        self._transmit(msg)          # if we're offline it stays "pending" and is resent later
        self.message_added.emit(chat_id, msg)
        self.conversation_changed.emit(chat_id)
        return msg

    def _transmit(self, msg: Message) -> bool:
        chat = self._chats.get(msg.chat_id)
        try:
            if chat and chat.is_group:
                self.client.send_group_message(chat.group_id, msg.text, msg_id=msg.id)
            else:
                self.client.send_message(msg.chat_id, msg.text, msg_id=msg.id)
                sealed = getattr(self.client, "last_message_e2e", None)
                msg.e2e, msg.e2e_sealed = bool(sealed), sealed
        except ClientError:
            return False
        msg.frame = getattr(self.client, "last_message_frame", None)
        return True

    def pending_messages(self) -> List[Message]:
        return [m for chat in self._chats.values() for m in chat.messages
                if m.outgoing and m.status == "pending" and not m.is_file]

    def resend_pending(self) -> int:
        """
        After a reconnect, send everything that is still waiting for the server's ✓.
        The same message id is reused, so if the server did get it before the drop,
        the receiver recognises the duplicate and ignores it.
        """
        sent = 0
        for msg in sorted(self.pending_messages(), key=lambda m: m.ts):
            if not self._transmit(msg):
                break
            sent += 1
        return sent

    def create_group(self, name: str, members: List[str], description: str = "",
                     avatar_color: str = "#00A884") -> Optional[str]:
        """Returns the request id (matched by group_created), or None if we're offline."""
        try:
            return self.client.create_group(name, members, description, avatar_color)
        except ClientError:
            return None

    def leave_group(self, chat_id: str) -> bool:
        chat = self._chats.get(chat_id)
        if not (chat and chat.is_group and not chat.left):
            return False
        try:
            self.client.leave_group(chat.group_id)
        except ClientError:
            return False
        return True

    def delete_message(self, chat_id: str, msg_id: str) -> None:
        """'Delete for me': remove it from this device only."""
        chat = self._chats.get(chat_id)
        msg = self._by_id.pop(msg_id, None)
        if chat and msg in chat.messages:
            chat.messages.remove(msg)
            self.message_removed.emit(chat_id, msg_id)
            self.conversation_changed.emit(chat_id)
