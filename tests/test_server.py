"""Tests for server/ (database, auth, routing).  Run with:  pytest tests/test_server.py -v"""

import os
import socket
import time
import uuid

import pytest

from common.protocol import MsgType, ProtocolError, client_handshake, send_frame
from server.auth import AccountLockedError, AuthError, AuthManager
from server.database import Database
from server.server import load_server_keys

PASSWORD = "Passw0rd!"


# ---------------------------------------------------------------- helpers ---
# The `server` fixture (a real server on a random port) lives in tests/conftest.py

def unique(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:6]}"


class RawClient:
    """Minimal client speaking the protocol directly (the real ChatClient comes in Prompt 5)."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.channel = client_handshake(self.sock)
        self.inbox = []

    def send(self, msg_type, **fields):
        self.channel.send({"type": msg_type, **fields})

    def expect(self, msg_type, timeout=5):
        """Return the next message of this type; other messages are kept in self.inbox."""
        msg_type = MsgType(msg_type).value
        for i, msg in enumerate(self.inbox):
            if msg["type"] == msg_type:
                return self.inbox.pop(i)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.channel.recv()
            if msg["type"] == msg_type:
                return msg
            self.inbox.append(msg)
        raise AssertionError(f"No {msg_type} received")

    def nothing_of(self, msg_type, wait=0.3):
        self.sock.settimeout(wait)
        try:
            while True:
                self.inbox.append(self.channel.recv())
        except (socket.timeout, OSError):
            pass
        finally:
            self.sock.settimeout(5)
        return all(m["type"] != MsgType(msg_type).value for m in self.inbox)

    def close(self):
        self.channel.close()


def registered(server, name=None):
    client = RawClient(server.port)
    name = name or unique("user")
    client.send(MsgType.REGISTER, username=name, password=PASSWORD, display_name=name.title())
    client.expect(MsgType.AUTH_OK)
    client.username = name
    return client


def logged_in(server, name):
    client = RawClient(server.port)
    client.send(MsgType.LOGIN, username=name, password=PASSWORD)
    client.expect(MsgType.AUTH_OK)
    client.username = name
    return client


# ---------------------------------------------------------- database/auth ---
@pytest.fixture
def auth():
    return AuthManager(Database(":memory:"), lockout_seconds=0.5)


def test_register_and_login(auth):
    user = auth.register("Alice", "secret123", "Alice A")
    assert user["username"] == "alice" and user["display_name"] == "Alice A"
    assert auth.login("ALICE", "secret123")["username"] == "alice"


def test_password_is_stored_hashed(auth):
    auth.register("bob", "secret123")
    stored = auth.db.get_password_hash("bob")
    assert "secret123" not in stored and stored.startswith("pbkdf2_sha256$")
    assert "password_hash" not in auth.db.get_user("bob")   # never leaves the server


@pytest.mark.parametrize("username,password", [
    ("ab", "secret123"), ("has space", "secret123"), ("bad!", "secret123"),
    ("carol", "short1"), ("carol", "onlyletters"), ("carol", "12345678"),
])
def test_register_validation(auth, username, password):
    with pytest.raises(AuthError):
        auth.register(username, password)


def test_duplicate_username_rejected(auth):
    auth.register("dave", "secret123")
    with pytest.raises(AuthError, match="taken"):
        auth.register("DAVE", "secret123")


def test_unknown_user_and_wrong_password_look_the_same(auth):
    auth.register("erin", "secret123")
    with pytest.raises(AuthError) as wrong_password:
        auth.login("erin", "nope12345")
    with pytest.raises(AuthError) as unknown_user:
        auth.login("nobody", "nope12345")
    assert str(wrong_password.value) == str(unknown_user.value)


def test_lockout_after_five_failures(auth):
    auth.register("frank", "secret123")
    for _ in range(4):
        with pytest.raises(AuthError):
            auth.login("frank", "wrong1234")
    with pytest.raises(AccountLockedError):
        auth.login("frank", "wrong1234")
    with pytest.raises(AccountLockedError):          # even the right password is refused now
        auth.login("frank", "secret123")
    time.sleep(0.6)                                  # lockout_seconds=0.5 in this fixture
    assert auth.login("frank", "secret123")["username"] == "frank"


def test_offline_queue(auth):
    db = auth.db
    auth.register("gina", "secret123")
    first = db.store_offline("gina", b"\x01\x02")
    db.store_offline("gina", b"\x03")
    assert [blob for _, blob in db.fetch_offline("gina")] == [b"\x01\x02", b"\x03"]
    db.delete_offline(first)
    assert db.count_offline("gina") == 1


def test_server_keys_persist_and_need_passphrase(tmp_path):
    key1, storage1 = load_server_keys(tmp_path, "my-passphrase")
    key2, storage2 = load_server_keys(tmp_path, "my-passphrase")
    assert key1 == key2 and storage1 == storage2
    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "server_private.pem").read_bytes()
    assert storage1 not in (tmp_path / "storage_key.bin").read_bytes()
    with pytest.raises(ValueError):
        load_server_keys(tmp_path, "wrong-passphrase")


# --------------------------------------------------------- live server ---
def test_register_returns_profile_and_user_list(server):
    client = RawClient(server.port)
    name = unique("reg")
    client.send(MsgType.REGISTER, username=name, password=PASSWORD, display_name="Reg User")
    ok = client.expect(MsgType.AUTH_OK)
    assert ok["user"]["username"] == name and ok["user"]["display_name"] == "Reg User"
    users = client.expect(MsgType.USER_LIST)["users"]
    me = next(u for u in users if u["username"] == name)
    assert me["online"] is True and "password_hash" not in me
    client.close()


def test_must_log_in_before_chatting(server):
    client = RawClient(server.port)
    client.send(MsgType.CHAT_MSG, to="anyone", id="1", text="hi")
    assert client.expect(MsgType.ERROR)["code"] == "NOT_AUTHENTICATED"
    client.close()


def test_chat_between_online_users(server):
    alice, bob = registered(server), registered(server)
    alice.send(MsgType.CHAT_MSG, to=bob.username, id="m1", text="Hello Bob 👋")

    assert alice.expect(MsgType.ACK)["id"] == "m1"
    received = bob.expect(MsgType.CHAT_MSG)
    assert received["from"] == alice.username and received["text"] == "Hello Bob 👋"
    delivered = alice.expect(MsgType.DELIVERED)
    assert delivered["id"] == "m1" and delivered["by"] == bob.username
    alice.close(), bob.close()


def test_sender_cannot_be_spoofed(server):
    alice, bob, carol = registered(server), registered(server), registered(server)
    alice.send(MsgType.CHAT_MSG, to=bob.username, id="m1", text="hi", **{"from": carol.username})
    assert bob.expect(MsgType.CHAT_MSG)["from"] == alice.username
    for c in (alice, bob, carol):
        c.close()


def test_offline_message_is_stored_encrypted_and_delivered_later(server):
    alice, bob = registered(server), registered(server)
    bob.send(MsgType.LOGOUT)
    bob.close()
    time.sleep(0.2)

    secret = "the exam paper is in drawer 3"
    alice.send(MsgType.CHAT_MSG, to=bob.username, id="m2", text=secret)
    alice.expect(MsgType.ACK)
    time.sleep(0.2)
    stored = server.db.fetch_offline(bob.username)
    assert len(stored) == 1 and secret.encode() not in stored[0][1]

    bob = logged_in(server, bob.username)
    assert bob.expect(MsgType.CHAT_MSG)["text"] == secret
    assert alice.expect(MsgType.DELIVERED)["id"] == "m2"
    assert server.db.count_offline(bob.username) == 0
    alice.close(), bob.close()


def test_read_receipts_and_typing_are_forwarded(server):
    alice, bob = registered(server), registered(server)
    bob.send(MsgType.TYPING, to=alice.username, typing=True)
    typing = alice.expect(MsgType.TYPING)
    assert typing["from"] == bob.username and typing["typing"] is True

    bob.send(MsgType.READ, to=alice.username, ids=["m1", "m2"])
    read = alice.expect(MsgType.READ)
    assert read["ids"] == ["m1", "m2"] and read["by"] == bob.username
    alice.close(), bob.close()


def test_presence_online_and_offline(server):
    alice = registered(server)
    bob = registered(server)
    online = alice.expect(MsgType.PRESENCE)
    assert online["username"] == bob.username and online["online"] is True

    bob.close()
    offline = alice.expect(MsgType.PRESENCE)
    assert offline["username"] == bob.username and offline["online"] is False
    assert abs(offline["last_seen"] - time.time()) < 5
    alice.close()


def test_unknown_recipient(server):
    alice = registered(server)
    alice.send(MsgType.CHAT_MSG, to="no_such_user", id="m1", text="hello?")
    assert alice.expect(MsgType.ERROR)["code"] == "UNKNOWN_USER"
    alice.close()


def test_ping_pong(server):
    alice = registered(server)
    alice.send(MsgType.PING)
    alice.expect(MsgType.PONG)
    alice.close()


def test_second_login_replaces_first_session(server):
    first = registered(server)
    second = logged_in(server, first.username)
    assert first.expect(MsgType.ERROR)["code"] == "SESSION_REPLACED"
    second.send(MsgType.PING)
    second.expect(MsgType.PONG)
    second.close()


def test_brute_force_lockout_is_logged(server):
    victim = registered(server)
    victim.close()
    attacker = RawClient(server.port)
    for _ in range(5):
        attacker.send(MsgType.LOGIN, username=victim.username, password="guess1234")
        fail = attacker.expect(MsgType.AUTH_FAIL)
    assert fail["retry_after"] > 0
    attacker.send(MsgType.LOGIN, username=victim.username, password=PASSWORD)
    assert "Try again" in attacker.expect(MsgType.AUTH_FAIL)["reason"]
    attacker.close()
    assert "LOCKOUT" in server.log.path.read_text(encoding="utf-8")


def test_tampered_packets_are_dropped_then_disconnected(server):
    client = registered(server)
    for _ in range(3):
        send_frame(client.sock, os.urandom(60))     # forged packets
    with pytest.raises((ProtocolError, OSError)):
        while True:                                 # server hangs up after 3 violations
            client.channel.recv()
    assert "TAMPER" in server.log.path.read_text(encoding="utf-8")
