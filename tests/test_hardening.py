"""
Regression tests for the issues found in the Prompt 19 security review.
Each test fails on the code as it was before the fix.
"""

import json
import socket
import sqlite3
import sys
import threading
import time
import uuid

import pytest
from Crypto.PublicKey import RSA

from client import local_store as ls
from client.files import CHUNK_SIZE, safe_filename
from client.network import ClientError
from common import crypto_utils as cu
from common.protocol import (
    HandshakeError, MsgType, ProtocolError, SecureChannel, b64e, client_handshake, recv_frame,
    send_frame, server_handshake,
)
from server import server as server_module
from server.server import ChatServer
from tests.test_files import user


def background(fn, *args):
    """Run fn in a thread; returns (thread, result dict with 'error' if it raised)."""
    result = {}

    def run():
        try:
            result["value"] = fn(*args)
        except Exception as exc:
            result["error"] = exc
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, result


# ================================================================== protocol
def test_client_refuses_a_weak_server_key():
    weak = RSA.generate(1024)
    a, b = socket.socketpair()
    thread, _ = background(server_handshake, b, weak)
    with pytest.raises(HandshakeError, match="too weak"):
        client_handshake(a)
    a.close()
    thread.join(5)
    b.close()


def test_non_finite_timestamps_are_rejected():
    key = cu.generate_aes_key()
    a, b = socket.socketpair()
    sender = SecureChannel(a, key, "client", clock=lambda: float("nan"))
    receiver = SecureChannel(b, key, "server")
    sender.send({"type": MsgType.PING})
    with pytest.raises(ProtocolError, match="timestamp"):
        receiver.recv()
    a.close()
    b.close()


def test_malformed_handshake_secret_is_a_clean_handshake_error():
    a, b = socket.socketpair()
    thread, result = background(server_handshake, b, cu.generate_rsa_keypair())
    recv_frame(a)                                                        # HANDSHAKE_PUBKEY
    send_frame(a, json.dumps({"type": "HANDSHAKE_SESSION_KEY", "encrypted_secret": 12345}).encode())
    thread.join(5)
    assert isinstance(result.get("error"), HandshakeError)               # not an AttributeError
    a.close()
    b.close()


# ================================================================== server input validation
def test_group_request_id_is_only_echoed_if_it_is_a_short_string(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    alice._send({"type": MsgType.CREATE_GROUP, "name": "Junk id", "members": [bob.username],
                 "request_id": {"nested": "x" * 5000}})
    assert bob_events.wait("group")["request_id"] is None
    request_id = alice.create_group("Real id", [bob.username])
    assert bob_events.wait("group", lambda m: m["group"]["name"] == "Real id")["request_id"] == request_id


def test_e2e_version_field_is_sanitised(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    alice._send({"type": MsgType.CHAT_MSG, "id": uuid.uuid4().hex, "to": bob.username,
                 "e2e": {"v": ["x"] * 1000, "ct": "AAAA"}})
    assert bob_events.wait("message")["e2e"]["v"] == 1


def test_offline_queue_is_capped(server, tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "MAX_OFFLINE_PER_USER", 3)
    alice, alice_events = user(server, tmp_path)
    offline, _ = user(server, tmp_path)
    name = offline.username
    offline.logout()
    time.sleep(0.2)
    for i in range(5):
        alice.send_message(name, f"message {i}")
        alice_events.wait("ack")
    assert server.db.count_offline(name) == 3


def test_unexpected_errors_are_logged_without_user_data(server, tmp_path, monkeypatch):
    def boom(self, session, message):
        int(message["secret_field"])                # ValueError: invalid literal for int(): 'TOP SECRET'
    monkeypatch.setattr(ChatServer, "_handle_typing", boom)
    alice, events = user(server, tmp_path)
    alice._send({"type": MsgType.TYPING, "to": alice.username, "secret_field": "TOP SECRET"})
    events.wait("disconnected")
    log = server.log.path.read_text(encoding="utf-8")
    assert "ValueError in boom()" in log
    assert "TOP SECRET" not in log


# ================================================================== file transfers
def start_transfer(sender, to, size=3 * CHUNK_SIZE, chunks_to_send=1, name="report.pdf"):
    file_id = uuid.uuid4().hex
    sender._send({"type": MsgType.FILE_START, "id": file_id, "to": to, "name": name, "size": size,
                  "chunks": -(-size // CHUNK_SIZE), "kind": "document", "sha256": "0" * 64})
    for index in range(chunks_to_send):
        sender._send({"type": MsgType.FILE_CHUNK, "id": file_id, "index": index, "data": b64e(b"x" * CHUNK_SIZE)})
    return file_id


def partial_files(client):
    folder = client.download_dir / ".partial"
    return list(folder.glob("*.part")) if folder.exists() else []


def test_recipient_is_told_when_the_sender_disconnects_mid_upload(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    file_id = start_transfer(alice, bob.username)
    bob_events.wait("file_progress")
    alice.close()                                           # gone before FILE_END
    done = bob_events.wait("file_done", lambda r: r["id"] == file_id)
    assert not done["ok"] and "stopped sending" in done["error"]
    assert partial_files(bob) == []


def test_recipient_is_told_when_the_server_rejects_a_transfer(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    file_id = start_transfer(alice, bob.username)
    alice._send({"type": MsgType.FILE_CHUNK, "id": file_id, "index": 5, "data": b64e(b"y")})   # out of order
    done = bob_events.wait("file_done", lambda r: r["id"] == file_id)
    assert not done["ok"]
    assert partial_files(bob) == []


def test_receiver_cleans_up_when_its_own_connection_drops(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    file_id = start_transfer(alice, bob.username)
    bob_events.wait("file_progress")
    assert len(partial_files(bob)) == 1
    bob.channel.close()                                     # the network goes away
    done = bob_events.wait("file_done", lambda r: r["id"] == file_id)
    assert "connection was lost" in done["error"]
    assert partial_files(bob) == []


def test_incoming_file_names_are_cleaned_before_display(server, tmp_path):
    alice, _ = user(server, tmp_path)
    bob, bob_events = user(server, tmp_path)
    start_transfer(alice, bob.username, name="holiday‮gpj.exe")
    assert bob_events.wait("file_incoming")["name"] == "holidaygpj.exe"      # the real .exe is visible


@pytest.mark.parametrize("name, expected", [
    ("invoice‮gpj.exe", "invoicegpj.exe"),     # right-to-left override (extension spoofing)
    ("a​b⁦c.txt", "abc.txt"),             # zero-width / isolate characters
    ("CON", "_CON"),
    ("nul.txt", "_nul.txt"),
    ("com1.pdf", "_com1.pdf"),
    ("console.log", "console.log"),                 # only exact device names are changed
    ("..\\..\\x.png", "x.png"),
])
def test_safe_filename_blocks_spoofing_and_device_names(name, expected):
    assert safe_filename(name) == expected


# ================================================================== client connection handling
def test_failed_send_closes_the_connection_so_the_app_reconnects(server, tmp_path, monkeypatch):
    alice, events = user(server, tmp_path)
    bob, _ = user(server, tmp_path)

    def broken(message):
        raise OSError(10060, "A send timed out")
    monkeypatch.setattr(alice.channel, "send", broken)
    with pytest.raises(ClientError):
        alice.send_message(bob.username, "hello")
    assert "lost" in events.wait("disconnected")
    assert not alice.connected


@pytest.mark.skipif(sys.platform != "win32", reason="the option's value format is platform-specific")
def test_send_timeout_is_set_on_the_socket(server, tmp_path):
    alice, _ = user(server, tmp_path)
    assert alice.channel.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO) == 10_000


# ================================================================== local store
def test_new_history_uses_a_separate_verifier_key(tmp_path):
    store = ls.LocalStore.open("kim", "Passw0rd1", tmp_path)
    store.close()
    conn = sqlite3.connect(str(tmp_path / "kim.db"))
    salt, verifier = (conn.execute("SELECT value FROM meta WHERE key = ?", (k,)).fetchone()[0]
                      for k in ("salt", "verifier"))
    conn.close()
    key = cu.derive_key_from_password("Passw0rd1", salt)
    assert ls._check_verifier(key, salt, verifier) == "current"
    with pytest.raises(cu.IntegrityError):                       # not encrypted with the password key itself
        cu.aes_decrypt(key, verifier, b"verifier")


def test_old_history_files_still_open_and_are_upgraded(tmp_path):
    store = ls.LocalStore.open("lee", "Passw0rd1", tmp_path)
    store.save_messages([("bob", "m1", 1.0, {"text": "kept"})])
    store.close()
    path = tmp_path / "lee.db"
    conn = sqlite3.connect(str(path))
    salt = conn.execute("SELECT value FROM meta WHERE key = 'salt'").fetchone()[0]
    legacy = cu.aes_encrypt(cu.derive_key_from_password("Passw0rd1", salt), ls.VERIFIER, b"verifier")
    with conn:                                                  # make it look like a file from before the fix
        conn.execute("UPDATE meta SET value = ? WHERE key = 'verifier'", (legacy,))
    conn.close()

    store = ls.LocalStore.open("lee", "Passw0rd1", tmp_path)
    assert store.load("bob")[0][2]["text"] == "kept"
    store.close()
    conn = sqlite3.connect(str(path))
    upgraded = conn.execute("SELECT value FROM meta WHERE key = 'verifier'").fetchone()[0]
    conn.close()
    key = cu.derive_key_from_password("Passw0rd1", salt)
    assert ls._check_verifier(key, salt, upgraded) == "current"
    with pytest.raises(ls.HistoryLocked):
        ls.LocalStore.open("lee", "Wrong1234", tmp_path)


def test_history_with_a_non_latin_password(tmp_path):
    store = ls.LocalStore.open("maya", "पासवर्ड123", tmp_path)
    store.save_messages([("ravi", "m1", 1.0, {"text": "नमस्ते"})])
    store.close()
    assert ls.LocalStore.open("maya", "पासवर्ड123", tmp_path).load("ravi")[0][2]["text"] == "नमस्ते"
    with pytest.raises(ls.HistoryLocked):
        ls.LocalStore.open("maya", "पासवर्ड124", tmp_path)
