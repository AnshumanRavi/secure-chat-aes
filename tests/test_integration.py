"""
End-to-end tests: a real server + real ChatClient objects talking over TCP.

Run with:  pytest tests/test_integration.py -v
"""

import queue
import time
import uuid

import pytest

from client.network import EVENTS, AuthFailed, ChatClient, ConnectionFailed
from common import crypto_utils as cu

PASSWORD = "Passw0rd!"


class EventRecorder:
    """Collects every event a ChatClient fires so tests can wait for them."""

    def __init__(self, client: ChatClient):
        self._queue = queue.Queue()
        self._seen = []
        for name in EVENTS:
            client.on(name, lambda *args, _n=name: self._queue.put((_n, args)))

    def wait(self, event, match=lambda *a: True, timeout=5):
        for i, (name, args) in enumerate(self._seen):
            if name == event and match(*args):
                return self._seen.pop(i)[1][0] if args else None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                name, args = self._queue.get(timeout=max(0.01, deadline - time.time()))
            except queue.Empty:
                break
            if name == event and match(*args):
                return args[0] if args else None
            self._seen.append((name, args))
        raise AssertionError(f"Timed out waiting for '{event}' event")


def new_client(server, **kwargs):
    client = ChatClient("127.0.0.1", server.port, **kwargs)
    events = EventRecorder(client)
    client.connect()
    return client, events


def new_user(server, name=None):
    client, events = new_client(server)
    name = name or f"user_{uuid.uuid4().hex[:6]}"
    client.register(name, PASSWORD, name.title())
    return client, events


# ---------------------------------------------------------------- tests ---
def test_connect_shows_server_fingerprint(server):
    client, _ = new_client(server)
    assert client.server_fingerprint == server.fingerprint
    assert len(client.key_fingerprint.split(" ")) == 4
    client.close()


def test_two_users_chat_both_ways(server):
    alice, alice_events = new_user(server)
    bob, bob_events = new_user(server)

    # Alice -> Bob
    msg_id = alice.send_message(bob.username, "Hi Bob! Did you finish the crypto assignment? 📚")
    assert alice_events.wait("ack")["id"] == msg_id
    received = bob_events.wait("message")
    assert received["from"] == alice.username
    assert received["text"] == "Hi Bob! Did you finish the crypto assignment? 📚"
    assert alice_events.wait("delivered")["id"] == msg_id

    # Bob -> Alice
    reply_id = bob.send_message(alice.username, "Yes! AES-GCM was fun 😄")
    reply = alice_events.wait("message")
    assert reply["from"] == bob.username and reply["text"] == "Yes! AES-GCM was fun 😄"
    assert bob_events.wait("delivered")["id"] == reply_id

    # Bob reads Alice's message -> Alice sees blue ticks
    bob.send_read(alice.username, [msg_id])
    assert alice_events.wait("read")["ids"] == [msg_id]

    alice.logout(), bob.logout()


def test_offline_message_delivered_after_login(server):
    alice, alice_events = new_user(server)
    bob, _ = new_user(server)
    bob_name = bob.username
    bob.logout()
    alice_events.wait("presence", lambda m: m["username"] == bob_name and not m["online"])

    msg_id = alice.send_message(bob_name, "Message while you were away")
    alice_events.wait("ack")

    bob, bob_events = new_client(server)
    bob.login(bob_name, PASSWORD)
    received = bob_events.wait("message")
    assert received["id"] == msg_id and received["text"] == "Message while you were away"
    assert alice_events.wait("delivered", lambda m: m["id"] == msg_id)["by"] == bob_name

    alice.logout(), bob.logout()


def test_presence_and_user_list(server):
    alice, alice_events = new_user(server)
    bob, _ = new_user(server)

    online = alice_events.wait("presence", lambda m: m["username"] == bob.username)
    assert online["online"] is True
    assert alice.users[bob.username]["online"] is True
    assert alice.users[bob.username]["display_name"] == bob.username.title()

    bob.logout()
    alice_events.wait("presence", lambda m: m["username"] == bob.username and not m["online"])
    assert alice.users[bob.username]["online"] is False
    assert alice.users[bob.username]["last_seen"]
    alice.logout()


def test_typing_indicator(server):
    alice, alice_events = new_user(server)
    bob, _ = new_user(server)
    bob.send_typing(alice.username, True)
    typing = alice_events.wait("typing")
    assert typing["from"] == bob.username and typing["typing"] is True
    alice.logout(), bob.logout()


def test_wrong_password_raises(server):
    alice, _ = new_user(server)
    alice.logout()
    client, _ = new_client(server)
    with pytest.raises(AuthFailed, match="Invalid username or password"):
        client.login(alice.username, "WrongPass1")
    client.close()


def test_duplicate_registration_raises(server):
    alice, _ = new_user(server)
    client, _ = new_client(server)
    with pytest.raises(AuthFailed, match="taken"):
        client.register(alice.username, PASSWORD)
    alice.logout(), client.close()


def test_pinned_fingerprint_mismatch_refuses_connection(server):
    impostor = cu.public_key_fingerprint(cu.generate_rsa_keypair())
    client = ChatClient("127.0.0.1", server.port, expected_fingerprint=impostor)
    with pytest.raises(ConnectionFailed, match="man-in-the-middle"):
        client.connect()


def test_no_server_gives_friendly_error():
    # Nothing listens on port 1. Windows retries refused connections for ~2 s, so
    # depending on timing the client reports "refused" or "timed out" - both are friendly.
    client = ChatClient("127.0.0.1", 1, timeout=3)
    with pytest.raises(ConnectionFailed, match="Is it running|Timed out connecting"):
        client.connect()


def test_heartbeat_keeps_connection_alive(server):
    client, _ = new_client(server, heartbeat_interval=0.2)
    client.register(f"hb_{uuid.uuid4().hex[:6]}", PASSWORD)
    time.sleep(0.7)
    assert client.last_pong and time.time() - client.last_pong < 1
    assert client.latency_ms is not None and client.latency_ms < 1000
    client.logout()


def test_disconnect_event_when_server_kicks_session(server):
    first, first_events = new_user(server)
    second, _ = new_client(server)
    second.login(first.username, PASSWORD)          # same account from another "device"
    assert first_events.wait("error")["code"] == "SESSION_REPLACED"
    assert first_events.wait("disconnected")
    second.logout()
