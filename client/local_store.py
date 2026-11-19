"""
Encrypted local chat history (one SQLite file per user: data/history/<username>.db).

How it is protected
-------------------
* Key: PBKDF2-HMAC-SHA256(password, random 16-byte salt, 200,000 rounds). Only the
  salt is stored; the key exists in memory only while you are logged in.
* Three sub-keys are derived from it with HKDF: one encrypts, one indexes, one
  checks the password - the password key itself is never used to encrypt anything.
* Every message is stored as AES-256-GCM ciphertext. The message id is used as
  associated data, so encrypted rows can't be swapped between messages unnoticed.
* Chats are indexed by HMAC-SHA256(index_key, chat_id), so the file doesn't even
  reveal WHO you talk to - only the timestamps are stored in the clear (for ordering).
* A "verifier" (a known value encrypted with the key) tells us immediately whether
  the password is right, without decrypting any messages.

See it for yourself:
    python -m client.local_store data/history/alice.db             # raw contents - unreadable
    python -m client.local_store data/history/alice.db --user alice # asks for the password, decrypts
"""

import argparse
import getpass
import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from common import crypto_utils as cu
from common import e2e
from common.config import PROJECT_ROOT

HISTORY_DIR = PROJECT_ROOT / "data" / "history"
VERIFIER = b"SecureChat local history v1"
VERIFIER_CONTEXT = b"SecureChat history verifier"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta     (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, chat_key TEXT NOT NULL, ts REAL NOT NULL,
                                     blob BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_key, ts);
CREATE TABLE IF NOT EXISTS chats    (chat_key TEXT PRIMARY KEY, blob BLOB NOT NULL);
"""


class HistoryLocked(Exception):
    """The history file was encrypted with a different password."""


def _verifier_key(key: bytes, salt: bytes) -> bytes:
    return cu.derive_session_key(key, salt, VERIFIER_CONTEXT)


def _check_verifier(key: bytes, salt: bytes, blob: Optional[bytes]) -> Optional[str]:
    """'current', 'legacy' (an older file whose verifier used the password key directly) or None (wrong password)."""
    if blob is None:
        return None
    for status, candidate in (("current", _verifier_key(key, salt)), ("legacy", key)):
        try:
            if cu.aes_decrypt(candidate, blob, b"verifier") == VERIFIER:
                return status
        except cu.IntegrityError:
            continue
    return None


def history_path(username: str, folder: Path = HISTORY_DIR) -> Path:
    safe = "".join(c for c in username if c.isalnum() or c == "_") or "user"
    return Path(folder) / f"{safe}.db"


class LocalStore:
    def __init__(self, path: Path, conn: sqlite3.Connection, key: bytes):
        self.path = Path(path)
        self._conn = conn
        salt = self._meta("salt")
        self._enc_key = cu.derive_session_key(key, salt, b"SecureChat history encryption")
        self._index_key = cu.derive_session_key(key, salt, b"SecureChat history index")

    # ------------------------------------------------------------- opening
    @classmethod
    def open(cls, username: str, password: str, folder: Path = HISTORY_DIR,
             reset_if_locked: bool = False) -> "LocalStore":
        """
        Open (or create) the user's history. Raises HistoryLocked if the file was
        made with another password - or, with reset_if_locked, moves it aside and
        starts a fresh one.
        """
        path = history_path(username, folder)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()
        if row is None:
            salt = cu.generate_salt()
            key = cu.derive_key_from_password(password, salt)
            with conn:
                conn.execute("INSERT INTO meta VALUES ('salt', ?)", (salt,))
                conn.execute("INSERT INTO meta VALUES ('verifier', ?)",
                             (cu.aes_encrypt(_verifier_key(key, salt), VERIFIER, b"verifier"),))
            return cls(path, conn, key)

        salt = row[0]
        key = cu.derive_key_from_password(password, salt)
        verifier = conn.execute("SELECT value FROM meta WHERE key = 'verifier'").fetchone()
        status = _check_verifier(key, salt, verifier[0] if verifier else None)
        if status is None:
            conn.close()
            if not reset_if_locked:
                raise HistoryLocked(f"{path.name} was encrypted with a different password")
            path.rename(path.with_name(f"{path.stem}.unreadable-{int(time.time())}.db"))
            return cls.open(username, password, folder)
        if status == "legacy":           # upgrade in place: re-encrypt the verifier with its own sub-key
            with conn:
                conn.execute("UPDATE meta SET value = ? WHERE key = 'verifier'",
                             (cu.aes_encrypt(_verifier_key(key, salt), VERIFIER, b"verifier"),))
        return cls(path, conn, key)

    def close(self) -> None:
        self._conn.close()

    def _meta(self, key: str) -> bytes:
        return self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()[0]

    def chat_key(self, chat_id: str) -> str:
        return hmac.new(self._index_key, chat_id.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------- messages
    def _seal(self, payload: dict, aad: str) -> bytes:
        return cu.aes_encrypt(self._enc_key, json.dumps(payload).encode("utf-8"), aad.encode("utf-8"))

    def _open(self, blob: bytes, aad: str) -> dict:
        return json.loads(cu.aes_decrypt(self._enc_key, blob, aad.encode("utf-8")))

    def save_messages(self, items: List[Tuple[str, str, float, dict]]) -> None:
        """items: (chat_id, message id, timestamp, payload dict) - saved in one transaction."""
        rows = [(msg_id, self.chat_key(chat_id), ts, self._seal(dict(payload, chat_id=chat_id), msg_id))
                for chat_id, msg_id, ts, payload in items]
        with self._conn:
            self._conn.executemany("INSERT OR REPLACE INTO messages (id, chat_key, ts, blob) VALUES (?, ?, ?, ?)",
                                   rows)

    def delete_message(self, msg_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM messages WHERE id = ?", (msg_id,))

    def load(self, chat_id: str, limit: Optional[int] = None,
             before_ts: Optional[float] = None) -> List[Tuple[str, float, dict]]:
        """Messages of one chat, oldest first. With limit/before_ts: the newest page older than before_ts."""
        sql = "SELECT id, ts, blob FROM messages WHERE chat_key = ?"
        args: list = [self.chat_key(chat_id)]
        if before_ts is not None:
            sql += " AND ts < ?"
            args.append(before_ts)
        sql += " ORDER BY ts DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        result = []
        for msg_id, ts, blob in self._conn.execute(sql, args):
            try:
                result.append((msg_id, ts, self._open(blob, msg_id)))
            except (cu.IntegrityError, ValueError):
                continue        # a damaged or tampered row is skipped, never shown
        result.reverse()
        return result

    def count(self, chat_id: Optional[str] = None) -> int:
        if chat_id is None:
            return self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        return self._conn.execute("SELECT COUNT(*) FROM messages WHERE chat_key = ?",
                                  (self.chat_key(chat_id),)).fetchone()[0]

    # ---------------------------------------------------------------- chats
    def save_chat(self, chat_id: str, state: dict) -> None:
        key = self.chat_key(chat_id)
        with self._conn:
            self._conn.execute("INSERT OR REPLACE INTO chats (chat_key, blob) VALUES (?, ?)",
                               (key, self._seal(dict(state, chat_id=chat_id), key)))

    def chats(self) -> Dict[str, dict]:
        result = {}
        for key, blob in self._conn.execute("SELECT chat_key, blob FROM chats"):
            try:
                state = self._open(blob, key)
                result[state["chat_id"]] = state
            except (cu.IntegrityError, ValueError, KeyError):
                continue
        return result

    # ---------------------------------------------------- end-to-end identity
    def identity_key(self):
        """
        My long-term ECC identity key for end-to-end encryption. It is created on
        first use and stored here, encrypted with the password-derived key - so the
        private key is as safe as the rest of the history and survives restarts.
        """
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()
        if row is not None:
            return e2e.import_private(cu.aes_decrypt(self._enc_key, row[0], b"identity"))
        key = e2e.generate_identity()
        with self._conn:
            self._conn.execute("INSERT INTO meta VALUES ('identity', ?)",
                               (cu.aes_encrypt(self._enc_key, e2e.export_private(key), b"identity"),))
        return key

    # ------------------------------------------------------------- admin
    def clear(self) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM messages")
            self._conn.execute("DELETE FROM chats")
        self._conn.execute("VACUUM")          # really drop the old pages from the file

    def file_size(self) -> int:
        return self.path.stat().st_size if self.path.exists() else 0

    def raw_rows(self, limit: int = 5) -> List[Tuple[str, float, bytes]]:
        """What an attacker who copies the file sees: (chat key, timestamp, ciphertext)."""
        return list(self._conn.execute("SELECT chat_key, ts, blob FROM messages ORDER BY ts DESC LIMIT ?",
                                       (limit,)))


# ---------------------------------------------------------------- demo CLI
def _main() -> None:
    parser = argparse.ArgumentParser(description="Inspect an encrypted SecureChat history file")
    parser.add_argument("db", help="path to data/history/<username>.db")
    parser.add_argument("--user", help="decrypt as this user (asks for the password)")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    print(f"{args.db}: {conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0]} messages\n")
    if not args.user:
        print("Raw rows (this is all someone who copies the file can see):\n")
        for chat_key, ts, blob in conn.execute("SELECT chat_key, ts, blob FROM messages ORDER BY ts DESC LIMIT 8"):
            print(f"  chat {chat_key[:16]}…  {time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))}  "
                  f"{blob[:28].hex()}… ({len(blob)} bytes)")
        print("\nRun again with --user <username> to decrypt with the password.")
        return
    store = LocalStore.open(args.user, getpass.getpass("Password: "), Path(args.db).parent)
    for chat_id in store.chats():
        print(f"== {chat_id}")
        for _, ts, payload in store.load(chat_id, limit=10):
            who = "me" if payload.get("outgoing") else payload.get("sender")
            text = payload.get("text") or (payload.get("file") or {}).get("name", "")
            print(f"  {time.strftime('%H:%M', time.localtime(ts))} {who}: {text}")


if __name__ == "__main__":
    _main()
