"""
End-to-end encryption (E2EE) for 1-to-1 chats.

Why it is needed
----------------
Without E2EE the server decrypts every message with the sender's session key and
re-encrypts it for the recipient (hop-by-hop encryption). That protects against
eavesdroppers on the network, but the SERVER itself sees the plaintext: if it is
hacked, run by a malicious admin or forced to hand over data, every message leaks.

How E2EE fixes that
-------------------
1. Identity keys. Each desktop client has a long-term ECC P-256 key pair. The
   private key never leaves the user's computer (it is stored inside the user's
   password-encrypted history). Only the PUBLIC key is uploaded to the server.

2. Pairwise key with ECDH. Alice computes  ECDH(Alice_private, Bob_public) and
   Bob computes ECDH(Bob_private, Alice_public). Both get the SAME shared secret
   (that's the magic of Diffie-Hellman), which is stretched with HKDF-SHA256 into
   a 256-bit AES key. The key is never transmitted - the server only ever sees
   public keys, and from public keys alone the secret can't be computed (that would
   require solving the elliptic-curve discrete logarithm problem).

3. Sealing. Each message is encrypted with AES-256-GCM under the pairwise key,
   using a fresh random nonce and "sender|recipient|message id" as associated data.
   So the server can't read it, can't modify it, and can't re-address it to
   someone else or replay it under another id without the tag check failing.

4. Double encryption. The sealed message is then sent through the normal
   transport channel (AES-256-GCM with the per-connection session key), so on the
   wire it is encrypted twice.

5. Authentication. Because the pairwise key needs one of the two PRIVATE keys,
   only Alice or Bob can create a valid message. A compromised server cannot forge
   messages "from Alice".

What the server CAN still do: it distributes the public keys, so a malicious server
could hand Alice its own key instead of Bob's (a man-in-the-middle). That is what the
security code is for: Alice and Bob compare a number derived from BOTH real public
keys - in person or over a phone call. If the server swapped a key, the numbers differ.
(WhatsApp/Signal work the same way.)
"""

import base64
import hashlib
from functools import lru_cache
from typing import Tuple, Union

from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey

from common import crypto_utils as cu

CURVE = "P-256"
VERSION = 1
HKDF_SALT = b"SecureChat E2E v1"
SECURITY_CODE_ITERATIONS = 5200          # same idea as Signal: slow down brute-forcing a look-alike key


class E2EError(Exception):
    """An end-to-end message could not be decrypted or verified."""


# --------------------------------------------------------------- identity keys
def generate_identity() -> EccKey:
    return ECC.generate(curve=CURVE)


def export_private(key: EccKey) -> bytes:
    return key.export_key(format="DER")


def import_private(data: bytes) -> EccKey:
    return ECC.import_key(data)


def export_public(key: EccKey) -> str:
    return key.public_key().export_key(format="PEM")


@lru_cache(maxsize=256)
def import_public(pem: str) -> EccKey:
    """Load a contact's public identity key; rejects anything that isn't a P-256 PUBLIC key."""
    try:
        key = ECC.import_key(pem)
    except (ValueError, TypeError, IndexError) as exc:
        raise E2EError("Invalid identity key") from exc
    if key.has_private() or key.curve not in ("NIST P-256", "p256", "P-256", "prime256v1", "secp256r1"):
        raise E2EError("Identity keys must be P-256 public keys")
    return key


def _der(key: Union[EccKey, str]) -> bytes:
    if isinstance(key, str):
        key = import_public(key)
    return key.public_key().export_key(format="DER")


def fingerprint(key: Union[EccKey, str]) -> str:
    """Short id of a public identity key, e.g. '3F9A 1C0B 7E44 9D2A'."""
    digest = hashlib.sha256(_der(key)).hexdigest()[:16].upper()
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


# ------------------------------------------------------------- pairwise keys
def pair_key(my_key: EccKey, my_name: str, their_key: EccKey, their_name: str) -> bytes:
    """
    The AES-256 key shared by exactly these two users.

    ECDH gives both sides the same secret; HKDF turns it into a key and binds it to
    the two usernames (sorted, so both sides use the same context).
    """
    names = "|".join(sorted([my_name, their_name])).encode("utf-8")
    kdf = lambda shared: HKDF(shared, 32, HKDF_SALT, SHA256, context=b"pair|" + names)
    return key_agreement(static_priv=my_key, static_pub=their_key, kdf=kdf)


def _aad(sender: str, recipient: str, msg_id: str) -> bytes:
    return f"e2e|v{VERSION}|{sender}|{recipient}|{msg_id}".encode("utf-8")


def seal(key: bytes, sender: str, recipient: str, msg_id: str, text: str) -> str:
    """Encrypt a message end-to-end. Returns base64(nonce || ciphertext || tag)."""
    blob = cu.aes_encrypt(key, text.encode("utf-8"), _aad(sender, recipient, msg_id))
    return base64.b64encode(blob).decode("ascii")


def open_sealed(key: bytes, sender: str, recipient: str, msg_id: str, sealed: str) -> str:
    try:
        blob = base64.b64decode(sealed, validate=True)
        return cu.aes_decrypt(key, blob, _aad(sender, recipient, msg_id)).decode("utf-8")
    except (ValueError, cu.IntegrityError) as exc:
        raise E2EError("End-to-end decryption failed - wrong key or tampered message") from exc


# ------------------------------------------------------------- security code
def _code_half(username: str, key: Union[EccKey, str]) -> str:
    """30 digits that depend on one user's name + public key."""
    data = b"\x00\x00" + _der(key) + username.encode("utf-8")
    digest = data
    for _ in range(SECURITY_CODE_ITERATIONS):
        digest = hashlib.sha512(digest + _der(key)).digest()
    chunks = [int.from_bytes(digest[i:i + 5], "big") % 100000 for i in range(0, 30, 5)]
    return "".join(f"{c:05d}" for c in chunks)


def security_code(name_a: str, key_a: Union[EccKey, str], name_b: str, key_b: Union[EccKey, str]) -> str:
    """
    The 60-digit "security code" both users see (same order on both screens).
    Returned as 12 groups of 5 digits: '12345 67890 ...'.
    """
    halves = sorted([(name_a, _code_half(name_a, key_a)), (name_b, _code_half(name_b, key_b))])
    digits = halves[0][1] + halves[1][1]
    return " ".join(digits[i:i + 5] for i in range(0, 60, 5))


def code_grid(code: str, size: int = 25) -> Tuple[Tuple[bool, ...], ...]:
    """A QR-like square pattern derived from the security code (for comparing at a glance)."""
    bits = []
    seed = code.encode("utf-8")
    while len(bits) < size * size:
        seed = hashlib.sha256(seed).digest()
        bits.extend((byte >> i) & 1 == 1 for byte in seed for i in range(8))
    return tuple(tuple(bits[r * size:(r + 1) * size]) for r in range(size))
