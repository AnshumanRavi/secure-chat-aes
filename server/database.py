"""
Server-side SQLite storage.

Tables
------
users             one row per account; only a PBKDF2 hash of the password is stored
groups            group chats (used from Prompt 10)
group_members     who is in which group, and who is admin
offline_messages  messages waiting for a user who is offline. The "blob" column
                  holds AES-GCM ciphertext only - the server encrypts each message
                  with its storage key before writing it, so a stolen database file
                  reveals no message content.

One connection is shared by all client threads and protected by a lock, which
is simple and plenty fast for a chat server of this size.
"""

import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple, Union

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    about         TEXT NOT NULL DEFAULT 'Hey there! I am using SecureChat.',
    avatar_color  TEXT NOT NULL,
    created_at    REAL NOT NULL,
    last_seen     REAL
);

CREATE TABLE IF NOT EXISTS groups (
    group_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    avatar_color  TEXT NOT NULL,
    created_by    TEXT NOT NULL REFERENCES users(username),
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id   TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    username   TEXT NOT NULL REFERENCES users(username),
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    joined_at  REAL NOT NULL,
    PRIMARY KEY (group_id, username)
);

CREATE TABLE IF NOT EXISTS offline_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient   TEXT NOT NULL REFERENCES users(username),
    blob        BLOB NOT NULL,
    created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline_messages(recipient);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,            -- SHA-256 of the resume token, never the token itself
    username    TEXT NOT NULL REFERENCES users(username),
    expires_at  REAL NOT NULL
);
"""

# Columns that are safe to send to other users (never the password hash).
# identity_key is the user's PUBLIC end-to-end key - the private half never reaches the server.
PUBLIC_USER_COLUMNS = "username, display_name, about, avatar_color, last_seen, identity_key"

MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN identity_key TEXT",     # Prompt 13: end-to-end encryption
]


class Database:
    def __init__(self, path: Union[str, Path]):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)
            for statement in MIGRATIONS:          # upgrade databases created by older versions
                try:
                    self._conn.execute(statement)
                except sqlite3.OperationalError:
                    pass                          # already applied

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ users
    def create_user(self, username: str, display_name: str, password_hash: str,
                    avatar_color: str) -> bool:
        """Insert a new user. Returns False if the username is already taken."""
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO users (username, display_name, password_hash, avatar_color, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (username, display_name, password_hash, avatar_color, time.time()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_password_hash(self, username: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["password_hash"] if row else None

    def get_user(self, username: str) -> Optional[dict]:
        """Public profile of one user (no password hash)."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT {PUBLIC_USER_COLUMNS} FROM users WHERE username = ?", (username,)
            ).fetchone()
        return dict(row) if row else None

    def user_exists(self, username: str) -> bool:
        return self.get_user(username) is not None

    def list_users(self) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {PUBLIC_USER_COLUMNS} FROM users ORDER BY display_name COLLATE NOCASE"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_last_seen(self, username: str, when: Optional[float] = None) -> float:
        when = when if when is not None else time.time()
        with self._lock, self._conn:
            self._conn.execute("UPDATE users SET last_seen = ? WHERE username = ?", (when, username))
        return when

    def set_identity_key(self, username: str, public_key_pem: str) -> bool:
        """Store a user's public E2E key. Returns True if it changed."""
        with self._lock, self._conn:
            row = self._conn.execute("SELECT identity_key FROM users WHERE username = ?", (username,)).fetchone()
            if row is not None and row["identity_key"] == public_key_pem:
                return False
            self._conn.execute("UPDATE users SET identity_key = ? WHERE username = ?", (public_key_pem, username))
        return True

    def update_profile(self, username: str, display_name: Optional[str] = None,
                       about: Optional[str] = None) -> None:
        with self._lock, self._conn:
            if display_name is not None:
                self._conn.execute("UPDATE users SET display_name = ? WHERE username = ?",
                                   (display_name, username))
            if about is not None:
                self._conn.execute("UPDATE users SET about = ? WHERE username = ?", (about, username))

    # --------------------------------------------------------------- groups
    def create_group(self, group_id: str, name: str, description: str, avatar_color: str,
                     created_by: str, members: List[str]) -> None:
        """Create a group; the creator becomes its admin."""
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO groups (group_id, name, description, avatar_color, created_by, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)", (group_id, name, description, avatar_color, created_by, now))
            self._conn.execute("INSERT INTO group_members (group_id, username, role, joined_at)"
                               " VALUES (?, ?, 'admin', ?)", (group_id, created_by, now))
            self._conn.executemany(
                "INSERT INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, 'member', ?)",
                [(group_id, m, now) for m in members if m != created_by])

    def _group_unlocked(self, group_id: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone()
        if not row:
            return None
        members = self._conn.execute(
            "SELECT username, role FROM group_members WHERE group_id = ?"
            " ORDER BY role = 'admin' DESC, joined_at, username", (group_id,)).fetchall()
        return dict(row, members=[dict(m) for m in members])

    def get_group(self, group_id: str) -> Optional[dict]:
        """Group details plus its members: [{"username": ..., "role": "admin"|"member"}, ...]."""
        with self._lock:
            return self._group_unlocked(group_id)

    def groups_for_user(self, username: str) -> List[dict]:
        with self._lock:
            ids = [r["group_id"] for r in self._conn.execute(
                "SELECT group_id FROM group_members WHERE username = ?", (username,))]
            return [g for g in (self._group_unlocked(i) for i in ids) if g]

    def group_members(self, group_id: str) -> List[str]:
        with self._lock:
            return [r["username"] for r in self._conn.execute(
                "SELECT username FROM group_members WHERE group_id = ?", (group_id,))]

    def is_member(self, group_id: str, username: str) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1 FROM group_members WHERE group_id = ? AND username = ?",
                                      (group_id, username)).fetchone() is not None

    def remove_member(self, group_id: str, username: str) -> Optional[str]:
        """
        Remove a member. If the last admin leaves, the longest-standing member becomes
        admin (returned). A group with no members left is deleted.
        """
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM group_members WHERE group_id = ? AND username = ?",
                               (group_id, username))
            remaining = self._conn.execute(
                "SELECT username, role FROM group_members WHERE group_id = ? ORDER BY joined_at, username",
                (group_id,)).fetchall()
            if not remaining:
                self._conn.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))
                return None
            if not any(r["role"] == "admin" for r in remaining):
                new_admin = remaining[0]["username"]
                self._conn.execute("UPDATE group_members SET role = 'admin' WHERE group_id = ? AND username = ?",
                                   (group_id, new_admin))
                return new_admin
        return None

    # --------------------------------------------------- resume sessions
    def store_session(self, token_hash: str, username: str, expires_at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            self._conn.execute("INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
                               (token_hash, username, expires_at))

    def pop_session(self, token_hash: str) -> Optional[Tuple[str, float]]:
        """Fetch AND delete a session (tokens are single-use). Returns (username, expires_at)."""
        with self._lock, self._conn:
            row = self._conn.execute("SELECT username, expires_at FROM sessions WHERE token_hash = ?",
                                     (token_hash,)).fetchone()
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return (row["username"], row["expires_at"]) if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    # ------------------------------------------------------- offline messages
    def store_offline(self, recipient: str, blob: bytes) -> int:
        """Queue an ENCRYPTED message for a user who is offline."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO offline_messages (recipient, blob, created_at) VALUES (?, ?, ?)",
                (recipient, blob, time.time()),
            )
        return cur.lastrowid

    def fetch_offline(self, recipient: str) -> List[Tuple[int, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, blob FROM offline_messages WHERE recipient = ? ORDER BY id", (recipient,)
            ).fetchall()
        return [(r["id"], r["blob"]) for r in rows]

    def delete_offline(self, message_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM offline_messages WHERE id = ?", (message_id,))

    def count_offline(self, recipient: Optional[str] = None) -> int:
        with self._lock:
            if recipient is None:
                row = self._conn.execute("SELECT COUNT(*) FROM offline_messages").fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM offline_messages WHERE recipient = ?", (recipient,)
                ).fetchone()
        return row[0]
