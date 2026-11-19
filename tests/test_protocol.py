"""Unit tests for common/protocol.py.  Run with:  pytest tests/test_protocol.py -v"""

import socket
import threading
import time

import pytest

from common import crypto_utils as cu
from common.protocol import (
    HEADER, ConnectionClosed, FrameTooLargeError, HandshakeError, IntegrityError,
    MsgType, ProtocolError, ReplayError, SecureChannel, client_handshake,
    recv_frame, send_frame, server_handshake,
)


@pytest.fixture(scope="module")
def rsa_key():
    return cu.generate_rsa_keypair()


@pytest.fixture
def sockets():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


@pytest.fixture
def channels(sockets):
    """A client/server channel pair sharing a key, without running the handshake."""
    client_sock, server_sock = sockets
    key = cu.generate_aes_key()
    return SecureChannel(client_sock, key, "client"), SecureChannel(server_sock, key, "server")


def handshake(rsa_key, client_sock, server_sock, expected_fp=None):
    """Run both sides of the handshake (server in a thread) and return (client, server)."""
    result = {}

    def run_server():
        try:
            result["server"] = server_handshake(server_sock, rsa_key)
        except Exception as exc:  # surfaced to the test below
            result["error"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    client = client_handshake(client_sock, expected_fp)
    thread.join(5)
    if "error" in result:
        raise result["error"]
    return client, result["server"]


class RecordingSocket:
    """Wraps a socket and keeps a copy of every byte sent - an eavesdropper's recording."""

    def __init__(self, sock):
        self._sock = sock
        self.sent = []

    def sendall(self, data):
        self.sent.append(bytes(data))
        self._sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self._sock, name)


# --------------------------------------------------------------- framing ---
@pytest.mark.parametrize("size", [0, 1, 1000, 300_000], ids=["empty", "1B", "1KB", "300KB"])
def test_frame_round_trip(sockets, size):
    a, b = sockets
    body = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
    sender = threading.Thread(target=send_frame, args=(a, body))
    sender.start()
    assert recv_frame(b) == body
    sender.join()


def test_frame_split_into_pieces(sockets):
    a, b = sockets
    data = HEADER.pack(11) + b"hello world"
    for i in range(len(data)):           # deliver one byte at a time
        a.sendall(data[i:i + 1])
    assert recv_frame(b) == b"hello world"


def test_two_frames_back_to_back(sockets):
    a, b = sockets
    send_frame(a, b"first")
    send_frame(a, b"second")
    assert recv_frame(b) == b"first"
    assert recv_frame(b) == b"second"


def test_oversized_frame_header_rejected(sockets):
    a, b = sockets
    a.sendall(HEADER.pack(2_000_000_000))  # attacker claims a 2 GB message
    with pytest.raises(FrameTooLargeError):
        recv_frame(b, max_size=1024)


def test_send_rejects_oversized_frame(sockets):
    with pytest.raises(FrameTooLargeError):
        send_frame(sockets[0], b"x" * 2048, max_size=1024)


def test_connection_closed_mid_frame(sockets):
    a, b = sockets
    a.sendall(HEADER.pack(100) + b"only 20 bytes here..")
    a.close()
    with pytest.raises(ConnectionClosed):
        recv_frame(b)


# ------------------------------------------------------------- handshake ---
def test_handshake_and_chat_both_directions(rsa_key, sockets):
    client, server = handshake(rsa_key, *sockets)

    assert client.server_fingerprint == cu.public_key_fingerprint(rsa_key)
    assert client.key_fingerprint == server.key_fingerprint

    client.send({"type": MsgType.CHAT_MSG, "to": "bob", "text": "Hi Bob! 👋 नमस्ते"})
    msg = server.recv()
    assert msg["type"] == "CHAT_MSG" and msg["to"] == "bob" and msg["text"] == "Hi Bob! 👋 नमस्ते"
    assert msg["seq"] == 1 and abs(msg["ts"] - time.time()) < 5

    server.send({"type": MsgType.DELIVERED, "id": "m1"})
    reply = client.recv()
    assert reply["type"] == "DELIVERED" and reply["seq"] == 2  # seq 1 was HANDSHAKE_OK


def test_handshake_with_correct_pinned_fingerprint(rsa_key, sockets):
    pinned = cu.public_key_fingerprint(rsa_key).lower().replace(" ", ":")  # format doesn't matter
    client, _ = handshake(rsa_key, *sockets, expected_fp=pinned)
    assert client.server_fingerprint == cu.public_key_fingerprint(rsa_key)


def test_handshake_rejects_wrong_fingerprint(rsa_key, sockets):
    client_sock, server_sock = sockets
    impostor_key = cu.generate_rsa_keypair()     # a man-in-the-middle's key

    def impostor_server():
        try:
            server_handshake(server_sock, impostor_key)
        except ProtocolError:
            pass                                 # the client hangs up on the impostor

    thread = threading.Thread(target=impostor_server, daemon=True)
    thread.start()
    with pytest.raises(HandshakeError, match="man-in-the-middle"):
        client_handshake(client_sock, expected_fingerprint=cu.public_key_fingerprint(rsa_key))
    client_sock.close()
    thread.join(5)


def test_every_session_gets_a_new_key(rsa_key):
    fingerprints = set()
    for _ in range(3):
        a, b = socket.socketpair()
        client, _ = handshake(rsa_key, a, b)
        fingerprints.add(client.key_fingerprint)
        a.close()
        b.close()
    assert len(fingerprints) == 3


def test_server_rejects_garbage_handshake(rsa_key, sockets):
    client_sock, server_sock = sockets
    send_frame(client_sock, b'{"type": "HANDSHAKE_SESSION_KEY", "encrypted_secret": "AAAA"}')
    with pytest.raises(HandshakeError):
        server_handshake(server_sock, rsa_key)


def test_handshake_times_out_on_silent_client(rsa_key, sockets):
    with pytest.raises(HandshakeError, match="timed out"):
        server_handshake(sockets[1], rsa_key, timeout=0.3)


def test_recorded_session_cannot_be_replayed(rsa_key):
    # Session 1: Eve records everything the real client sends
    a1, b1 = socket.socketpair()
    recorder = RecordingSocket(a1)
    client, server = handshake(rsa_key, recorder, b1)
    client.send({"type": MsgType.CHAT_MSG, "to": "bob", "text": "send 500 rupees"})
    server.recv()
    recorded_session_key_msg, recorded_chat_msg = recorder.sent

    # Session 2: Eve replays the recording to the server
    a2, b2 = socket.socketpair()
    result = {}
    thread = threading.Thread(target=lambda: result.setdefault("server", server_handshake(b2, rsa_key)))
    thread.start()
    recv_frame(a2)                          # server's hello with a NEW salt
    a2.sendall(recorded_session_key_msg)    # replay the old encrypted secret
    thread.join(5)
    a2.sendall(recorded_chat_msg)           # replay the old chat message
    with pytest.raises(IntegrityError):     # new salt -> new key -> decryption fails
        result["server"].recv()

    for s in (a1, b1, a2, b2):
        s.close()


# ------------------------------------------------------- secure channel ---
def test_message_type_and_text_are_hidden(channels, sockets):
    client, _ = channels
    client.send({"type": MsgType.CHAT_MSG, "text": "top secret plan"})
    raw = recv_frame(sockets[1])
    assert b"CHAT_MSG" not in raw and b"top secret" not in raw


def test_sequence_numbers_increase(channels):
    client, server = channels
    seqs = [client.send({"type": MsgType.PING}) for _ in range(5)]
    assert seqs == [1, 2, 3, 4, 5]
    assert [server.recv()["seq"] for _ in range(5)] == seqs


def test_replay_rejected(channels, sockets):
    client, server = channels
    client_sock, server_sock = sockets
    client.send({"type": MsgType.CHAT_MSG, "text": "pay 100"})
    captured = recv_frame(server_sock)          # attacker captures the packet...

    send_frame(client_sock, captured)           # ...delivers it once (looks normal)
    assert server.recv()["text"] == "pay 100"
    send_frame(client_sock, captured)           # ...then replays it
    with pytest.raises(ReplayError, match="Replayed"):
        server.recv()


def test_stale_message_rejected(sockets):
    key = cu.generate_aes_key()
    two_minutes_ago = lambda: time.time() - 120
    client = SecureChannel(sockets[0], key, "client", clock=two_minutes_ago)
    server = SecureChannel(sockets[1], key, "server")
    client.send({"type": MsgType.CHAT_MSG, "text": "delayed"})
    with pytest.raises(ReplayError, match="Stale"):
        server.recv()


def test_tampered_message_rejected(channels, sockets):
    client, server = channels
    client_sock, server_sock = sockets
    client.send({"type": MsgType.CHAT_MSG, "text": "pay 100"})
    frame = bytearray(recv_frame(server_sock))
    frame[20] ^= 0x01                           # flip one bit
    send_frame(client_sock, bytes(frame))
    with pytest.raises(IntegrityError):
        server.recv()


def test_reflected_message_rejected(channels, sockets):
    client, server = channels
    client_sock, server_sock = sockets
    server.send({"type": MsgType.AUTH_OK})
    captured = recv_frame(client_sock)          # a server->client packet...
    send_frame(client_sock, captured)           # ...bounced back to the server
    with pytest.raises(IntegrityError):
        server.recv()


def test_wrong_key_rejected(sockets):
    client = SecureChannel(sockets[0], cu.generate_aes_key(), "client")
    server = SecureChannel(sockets[1], cu.generate_aes_key(), "server")
    client.send({"type": MsgType.PING})
    with pytest.raises(IntegrityError):
        server.recv()


def test_unknown_message_type_rejected(channels):
    with pytest.raises(ProtocolError):
        channels[0].send({"type": "HACK_THE_SERVER"})


def test_concurrent_sends_keep_order(channels):
    client, server = channels
    threads = [threading.Thread(target=lambda: [client.send({"type": MsgType.TYPING}) for _ in range(50)])
               for _ in range(8)]
    for t in threads:
        t.start()
    seqs = [server.recv()["seq"] for _ in range(400)]
    for t in threads:
        t.join()
    assert seqs == list(range(1, 401))


def test_statistics_tracked(channels):
    client, server = channels
    client.send({"type": MsgType.PING})
    server.recv()
    assert client.bytes_sent == server.bytes_received > 0
    assert client.last_sent_ciphertext == server.last_received_ciphertext
