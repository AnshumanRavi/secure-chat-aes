"""
SecureChat wire protocol.

Layers (bottom to top)
----------------------
1. Framing      TCP is a byte stream with no message boundaries, so every
                message is sent as  [4-byte big-endian length][body].
2. Handshake    RSA-OAEP key transport + HKDF gives both sides a fresh
                AES-256 session key (see server_handshake / client_handshake).
3. SecureChannel  every message after the handshake is a JSON object that is
                AES-256-GCM encrypted. Each one carries a sequence number and a
                timestamp so replayed or delayed packets are rejected.

Handshake
---------
    Client                                         Server
      |  ---------------- TCP connect -------------->  |
      |  <-- HANDSHAKE_PUBKEY {public_key, salt} -----  |  salt = 16 random bytes
      |  check fingerprint (optional pinning)          |
      |  secret = 32 random bytes                      |
      |  --- HANDSHAKE_SESSION_KEY {RSA-OAEP(secret)} ->|  secret = RSA-decrypt
      |  key = HKDF(secret, salt)                      |  key = HKDF(secret, salt)
      |  <------ AES-GCM( HANDSHAKE_OK ) -------------  |  key confirmation
      |  ======== all further traffic AES-GCM ========  |

Encrypted frame body
--------------------
    nonce (12) || ciphertext || tag (16)
    plaintext  = JSON {"type": ..., "seq": n, "ts": unix_time, ...fields}
    associated data = b"SecureChat/1|C2S" (client->server) or b"SecureChat/1|S2C"

The message type lives INSIDE the ciphertext so an eavesdropper cannot even
tell a chat message from a typing notification. The associated data binds each
packet to its direction, so a packet the server sent cannot be reflected back
to the server (it would fail the GCM check).
"""

import base64
import json
import math
import socket
import struct
import threading
import time
from enum import Enum
from typing import Callable, Optional

from Crypto.PublicKey.RSA import RsaKey

from common import crypto_utils as cu
from common.crypto_utils import IntegrityError  # re-exported for callers

PROTOCOL_VERSION = 1
HEADER = struct.Struct(">I")              # 4-byte unsigned big-endian length
DEFAULT_MAX_FRAME_SIZE = 1024 * 1024      # 1 MiB
HANDSHAKE_MAX_FRAME_SIZE = 8 * 1024       # handshake messages are small; limit unauthenticated input
HANDSHAKE_TIMEOUT = 10.0                  # seconds
DEFAULT_MAX_CLOCK_SKEW = 60.0             # seconds
SECRET_SIZE = 32
SALT_SIZE = 16
MIN_SERVER_KEY_BITS = 2048                # refuse weak RSA keys offered by a (fake) server

_AAD_PREFIX = b"SecureChat/%d|" % PROTOCOL_VERSION
AAD_CLIENT_TO_SERVER = _AAD_PREFIX + b"C2S"
AAD_SERVER_TO_CLIENT = _AAD_PREFIX + b"S2C"


class MsgType(str, Enum):
    HANDSHAKE_PUBKEY = "HANDSHAKE_PUBKEY"
    HANDSHAKE_SESSION_KEY = "HANDSHAKE_SESSION_KEY"
    HANDSHAKE_OK = "HANDSHAKE_OK"
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    AUTH_OK = "AUTH_OK"
    AUTH_FAIL = "AUTH_FAIL"
    CHAT_MSG = "CHAT_MSG"
    GROUP_MSG = "GROUP_MSG"
    ACK = "ACK"                  # server received the message      -> one grey tick
    DELIVERED = "DELIVERED"      # recipient's app received it      -> two grey ticks
    READ = "READ"                # recipient opened the chat        -> two blue ticks
    TYPING = "TYPING"
    PRESENCE = "PRESENCE"
    USER_LIST = "USER_LIST"
    CREATE_GROUP = "CREATE_GROUP"
    LEAVE_GROUP = "LEAVE_GROUP"
    UPDATE_PROFILE = "UPDATE_PROFILE"  # change my display name / "About"
    PUBLISH_KEY = "PUBLISH_KEY"        # upload my PUBLIC end-to-end identity key
    GROUP_UPDATE = "GROUP_UPDATE"      # server -> members: someone left / new admin
    FILE_START = "FILE_START"
    FILE_CHUNK = "FILE_CHUNK"
    FILE_END = "FILE_END"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"
    LOGOUT = "LOGOUT"


_VALID_TYPES = {t.value for t in MsgType}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """A message broke the protocol rules (bad format, unknown type, ...)."""


class ConnectionClosed(ProtocolError):
    """The other side closed the connection."""


class FrameTooLargeError(ProtocolError):
    """A frame header announced more bytes than allowed (possible memory attack)."""


class ReplayError(ProtocolError):
    """A message was replayed (old sequence number) or is too old/new (timestamp)."""


class HandshakeError(ProtocolError):
    """The key exchange failed or the server's key fingerprint did not match."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def b64e(data: bytes) -> str:
    """bytes -> base64 text, for putting binary data (file chunks, keys) in JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _type_value(msg_type) -> str:
    return msg_type.value if isinstance(msg_type, MsgType) else str(msg_type)


# ---------------------------------------------------------------------------
# Layer 1: length-prefixed framing
# ---------------------------------------------------------------------------
def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes. sock.recv() may return fewer bytes than asked for
    (TCP delivers data in arbitrary pieces), so keep reading until done.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ConnectionClosed("Connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, body: bytes,
               max_size: int = DEFAULT_MAX_FRAME_SIZE) -> None:
    if len(body) > max_size:
        raise FrameTooLargeError(f"Frame of {len(body)} bytes exceeds limit of {max_size}")
    sock.sendall(HEADER.pack(len(body)) + body)


def recv_frame(sock: socket.socket, max_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
    """
    Read one frame. The length is checked BEFORE reading the body, so a
    malicious header claiming 4 GB is rejected without allocating memory.
    """
    (length,) = HEADER.unpack(recv_exact(sock, HEADER.size))
    if length > max_size:
        raise FrameTooLargeError(f"Peer announced a {length}-byte frame (limit {max_size})")
    return recv_exact(sock, length)


def _send_json(sock: socket.socket, obj: dict) -> None:
    send_frame(sock, json.dumps(obj).encode("utf-8"), HANDSHAKE_MAX_FRAME_SIZE)


def _recv_json(sock: socket.socket, expected_type: MsgType) -> dict:
    try:
        obj = json.loads(recv_frame(sock, HANDSHAKE_MAX_FRAME_SIZE))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandshakeError("Malformed handshake message") from exc
    if not isinstance(obj, dict) or obj.get("type") != expected_type.value:
        raise HandshakeError(f"Expected {expected_type.value} during handshake")
    return obj


# ---------------------------------------------------------------------------
# Layer 3: encrypted channel
# ---------------------------------------------------------------------------
class SecureChannel:
    """
    An encrypted, authenticated, replay-protected message channel over a socket.

        channel.send({"type": MsgType.CHAT_MSG, "to": "bob", "text": "hi"})
        msg = channel.recv()     # -> {"type": "CHAT_MSG", "seq": 7, "ts": ..., ...}

    Security checks on every received message:
      1. GCM tag      - the packet was not modified and was made with our key
                        (raises IntegrityError)
      2. direction    - the packet was sent by the other side, not reflected
                        back from our own traffic (part of the GCM check)
      3. sequence no. - must be larger than the last one seen (raises ReplayError)
      4. timestamp    - must be within max_clock_skew seconds (raises ReplayError)
    """

    def __init__(self, sock: socket.socket, session_key: bytes, role: str,
                 max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
                 max_clock_skew: float = DEFAULT_MAX_CLOCK_SKEW,
                 clock: Callable[[], float] = time.time):
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        self.sock = sock
        self.role = role
        self._key = session_key
        self.max_frame_size = max_frame_size
        self.max_clock_skew = max_clock_skew
        self._clock = clock

        if role == "client":
            self._send_aad, self._recv_aad = AAD_CLIENT_TO_SERVER, AAD_SERVER_TO_CLIENT
        else:
            self._send_aad, self._recv_aad = AAD_SERVER_TO_CLIENT, AAD_CLIENT_TO_SERVER

        self._send_seq = 0
        self._recv_seq = 0
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()

        self.server_fingerprint: Optional[str] = None  # set by client_handshake
        # Statistics, used by the security demo and performance tests
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_sent_ciphertext = b""
        self.last_sent = (0, b"")
        self.last_received_ciphertext = b""

    @property
    def key_fingerprint(self) -> str:
        """Safe-to-display ID of the session key (never the key itself)."""
        return cu.key_fingerprint(self._key)

    def send(self, message: dict) -> int:
        """Encrypt and send a message dict. Returns the sequence number used."""
        msg_type = _type_value(message.get("type"))
        if msg_type not in _VALID_TYPES:
            raise ProtocolError(f"Unknown message type: {msg_type!r}")

        # The lock keeps "next sequence number" and "write to socket" together,
        # so two threads can never put packets on the wire out of order.
        with self._send_lock:
            self._send_seq += 1
            body = dict(message, type=msg_type, seq=self._send_seq, ts=self._clock())
            plaintext = json.dumps(body, ensure_ascii=False).encode("utf-8")
            frame = cu.aes_encrypt(self._key, plaintext, self._send_aad)
            send_frame(self.sock, frame, self.max_frame_size)
            self.bytes_sent += HEADER.size + len(frame)
            self.last_sent_ciphertext = frame
            self.last_sent = (self._send_seq, frame)   # read together, so callers can match seq -> frame
            return self._send_seq

    def recv(self) -> dict:
        """Receive, decrypt and verify the next message."""
        with self._recv_lock:
            frame = recv_frame(self.sock, self.max_frame_size)
            self.bytes_received += HEADER.size + len(frame)
            self.last_received_ciphertext = frame

            plaintext = cu.aes_decrypt(self._key, frame, self._recv_aad)  # IntegrityError if tampered

            try:
                message = json.loads(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProtocolError("Decrypted message is not valid JSON") from exc
            if not isinstance(message, dict) or message.get("type") not in _VALID_TYPES:
                raise ProtocolError("Message has a missing or unknown type")

            seq, ts = message.get("seq"), message.get("ts")
            # (json accepts NaN/Infinity, and every comparison with NaN is False - reject them)
            if not isinstance(seq, int) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
                raise ProtocolError("Message is missing its sequence number or timestamp")
            if seq <= self._recv_seq:
                raise ReplayError(f"Replayed message: seq {seq} <= last seen {self._recv_seq}")
            if abs(self._clock() - ts) > self.max_clock_skew:
                raise ReplayError(f"Stale message: timestamp is {self._clock() - ts:+.0f}s off")

            self._recv_seq = seq
            return message

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ---------------------------------------------------------------------------
# Layer 2: handshake
# ---------------------------------------------------------------------------
def server_handshake(sock: socket.socket, private_key: RsaKey,
                     timeout: float = HANDSHAKE_TIMEOUT, **channel_kwargs) -> SecureChannel:
    """Run the server side of the handshake and return the encrypted channel."""
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)   # a client that connects and says nothing can't hold a thread forever
    try:
        salt = cu.generate_salt(SALT_SIZE)
        _send_json(sock, {
            "type": MsgType.HANDSHAKE_PUBKEY.value,
            "version": PROTOCOL_VERSION,
            "public_key": cu.export_public_key(private_key).decode("ascii"),
            "salt": b64e(salt),
        })

        reply = _recv_json(sock, MsgType.HANDSHAKE_SESSION_KEY)
        try:
            secret = cu.rsa_decrypt(private_key, b64d(reply["encrypted_secret"]))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:   # AttributeError: not a string
            raise HandshakeError("Could not decrypt the client's session secret") from exc
        if len(secret) != SECRET_SIZE:
            raise HandshakeError("Session secret has the wrong length")

        channel = SecureChannel(sock, cu.derive_session_key(secret, salt), "server", **channel_kwargs)
        channel.send({"type": MsgType.HANDSHAKE_OK})   # proves the server derived the same key
        return channel
    except socket.timeout as exc:
        raise HandshakeError("Handshake timed out") from exc
    finally:
        sock.settimeout(previous_timeout)


def client_handshake(sock: socket.socket, expected_fingerprint: Optional[str] = None,
                     timeout: float = HANDSHAKE_TIMEOUT, **channel_kwargs) -> SecureChannel:
    """
    Run the client side of the handshake and return the encrypted channel.

    expected_fingerprint: if given, the server's public key MUST have this
    fingerprint, otherwise HandshakeError is raised before any secret is sent.
    This defeats a man-in-the-middle who substitutes their own RSA key.
    The fingerprint actually seen is available as channel.server_fingerprint.
    """
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        hello = _recv_json(sock, MsgType.HANDSHAKE_PUBKEY)
        if hello.get("version") != PROTOCOL_VERSION:
            raise HandshakeError(f"Unsupported protocol version: {hello.get('version')}")
        try:
            server_key = cu.import_public_key(hello["public_key"])
            salt = b64d(hello["salt"])
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise HandshakeError("Invalid server public key or salt") from exc
        if len(salt) != SALT_SIZE:
            raise HandshakeError("Server salt has the wrong length")
        if server_key.size_in_bits() < MIN_SERVER_KEY_BITS:
            raise HandshakeError(f"Server RSA key is too weak ({server_key.size_in_bits()} bits, "
                                 f"need {MIN_SERVER_KEY_BITS})")

        fingerprint = cu.public_key_fingerprint(server_key)
        if expected_fingerprint and _normalise_fp(expected_fingerprint) != _normalise_fp(fingerprint):
            raise HandshakeError("Server key fingerprint does not match - possible man-in-the-middle!")

        secret = cu.generate_aes_key(SECRET_SIZE)
        _send_json(sock, {
            "type": MsgType.HANDSHAKE_SESSION_KEY.value,
            "encrypted_secret": b64e(cu.rsa_encrypt(server_key, secret)),
        })

        channel = SecureChannel(sock, cu.derive_session_key(secret, salt), "client", **channel_kwargs)
        channel.server_fingerprint = fingerprint
        try:
            confirmation = channel.recv()
        except IntegrityError as exc:
            raise HandshakeError("Server could not prove it has the session key") from exc
        if confirmation["type"] != MsgType.HANDSHAKE_OK.value:
            raise HandshakeError("Expected HANDSHAKE_OK")
        return channel
    except socket.timeout as exc:
        raise HandshakeError("Handshake timed out") from exc
    finally:
        sock.settimeout(previous_timeout)


def _normalise_fp(fp: str) -> str:
    return fp.replace(" ", "").replace(":", "").upper()
