"""
Cryptographic primitives for SecureChat (built on PyCryptodome).

Summary of the design
---------------------
* Chat messages     -> AES-256 in GCM mode (confidentiality + integrity in one step).
* Key exchange      -> RSA-2048 with OAEP padding (SHA-256) carries the AES session key.
* Passwords         -> PBKDF2-HMAC-SHA256, 16-byte random salt, 200,000 iterations.
* Local data keys   -> derived from the user's password with the same PBKDF2 setup.

Why this split? RSA (asymmetric) solves the "how do we agree on a secret key over
an open network" problem but is slow and can only encrypt ~190 bytes. AES
(symmetric) is extremely fast and can encrypt any amount of data, but both sides
need the same key. So RSA is used ONCE per session to send a random AES key, and
AES encrypts every message after that. This is called hybrid encryption and is
how TLS/HTTPS works too.

The CBC, CTR and ECB helpers at the bottom exist ONLY for the performance
comparison in performance/benchmark_crypto.py. The chat itself uses GCM only.
"""

import base64
import hashlib
import hmac
from pathlib import Path
from typing import Optional, Union

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_SIZE = 32          # 32 bytes = 256-bit key (AES-256)
GCM_NONCE_SIZE = 12        # 96-bit nonce, the size recommended for GCM by NIST SP 800-38D
GCM_TAG_SIZE = 16          # 128-bit authentication tag (full strength)
RSA_KEY_BITS = 2048
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
CBC_IV_SIZE = 16
CTR_NONCE_SIZE = 8         # 64-bit nonce + 64-bit internal block counter
HMAC_SIZE = 32             # HMAC-SHA256 output

_PASSWORD_SCHEME = "pbkdf2_sha256"


class IntegrityError(Exception):
    """
    Raised when a ciphertext fails its integrity check.

    This means the data was modified (tampered with), corrupted in transit,
    or decrypted with the wrong key. The plaintext is never returned in that
    case, so an attacker cannot learn anything from a forged message.
    """


def _to_bytes(data: Union[str, bytes]) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def _password_bytes(password: str) -> bytes:
    """
    The bytes PBKDF2 hashes for a password.

    PyCryptodome encodes a str password as Latin-1, which fails for any character
    outside it (Hindi, Chinese, emoji ...). Latin-1 is kept wherever it works, so every
    existing password hash stays valid; everything else is encoded as UTF-8.
    """
    try:
        return password.encode("latin-1")
    except UnicodeEncodeError:
        return password.encode("utf-8")


def _check_aes_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")


# ---------------------------------------------------------------------------
# AES-256-GCM  (used for all chat traffic)
# ---------------------------------------------------------------------------
def generate_aes_key(size: int = AES_KEY_SIZE) -> bytes:
    """
    Create a new random AES key.

    get_random_bytes() reads from the operating system's cryptographically
    secure random number generator (CSPRNG). Python's normal `random` module
    must never be used for keys because its output is predictable.
    """
    if size not in (16, 24, 32):
        raise ValueError("AES key size must be 16, 24 or 32 bytes")
    return get_random_bytes(size)


def aes_encrypt(key: bytes, plaintext: Union[str, bytes],
                associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypt with AES-GCM and return  nonce(12) || ciphertext || tag(16).

    Why GCM (Galois/Counter Mode)?
      * It is an AEAD mode (Authenticated Encryption with Associated Data):
        it encrypts AND produces an authentication tag in one pass, so any
        change to the ciphertext is detected on decryption.
      * It is a stream-style mode (built on CTR), so no padding is needed and
        the ciphertext is exactly as long as the plaintext.
      * It is fast (hardware AES-NI + parallelisable) and is the mode used by
        TLS 1.3, SSH and WhatsApp's media encryption.

    The nonce:
      A fresh random 12-byte nonce is created for EVERY message. Reusing a
      nonce with the same key in GCM is catastrophic (it leaks the XOR of the
      two plaintexts and lets an attacker forge tags), so it must never repeat.
      With random 96-bit nonces the chance of a repeat is negligible for the
      number of messages a chat session sends.

    associated_data (AAD):
      Extra data that is authenticated but NOT encrypted (e.g. the message
      type). If the attacker changes it, decryption fails.
    """
    _check_aes_key(key)
    nonce = get_random_bytes(GCM_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(_to_bytes(plaintext))
    return nonce + ciphertext + tag


def aes_decrypt(key: bytes, blob: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt a blob produced by aes_encrypt() and verify its tag.

    decrypt_and_verify() recomputes the tag and compares it in constant time.
    If the ciphertext, nonce, tag or associated data were changed - or the key
    is wrong - it fails and IntegrityError is raised instead of returning
    garbage plaintext.
    """
    _check_aes_key(key)
    if len(blob) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
        raise IntegrityError("Ciphertext is too short to be valid")

    nonce = blob[:GCM_NONCE_SIZE]
    tag = blob[-GCM_TAG_SIZE:]
    ciphertext = blob[GCM_NONCE_SIZE:-GCM_TAG_SIZE]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
    if associated_data:
        cipher.update(associated_data)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:  # PyCryptodome raises ValueError("MAC check failed")
        raise IntegrityError("GCM authentication failed - message tampered or wrong key") from exc


def derive_session_key(secret: bytes, salt: bytes,
                       context: bytes = b"SecureChat v1 session key") -> bytes:
    """
    Derive the AES-256 session key with HKDF-SHA256.

    During the handshake the client sends a random secret (RSA-encrypted) and
    the server contributes a random salt. Mixing both means that if an attacker
    records a whole session and replays it to the server later, the server's
    new salt produces a different key and every replayed packet fails to
    decrypt.
    """
    return HKDF(secret, AES_KEY_SIZE, salt, SHA256, context=context)


def key_fingerprint(key: bytes) -> str:
    """
    Short, safe-to-display identifier for a symmetric key (first 8 bytes of
    its SHA-256 hash). Used in the UI so the RAW key is never shown or logged.
    """
    return _group_hex(hashlib.sha256(key).hexdigest()[:16])


# ---------------------------------------------------------------------------
# RSA-2048 with OAEP  (used only to transport the AES session key)
# ---------------------------------------------------------------------------
def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> RsaKey:
    """
    Generate an RSA key pair. The returned private key object also contains
    the public key (key.publickey()).

    2048 bits gives ~112-bit security, which is NIST's minimum recommended
    level until 2030.
    """
    return RSA.generate(bits)


def export_public_key(key: RsaKey) -> bytes:
    """Return the public key in PEM format (safe to send over the network)."""
    return key.publickey().export_key(format="PEM")


def import_public_key(pem: Union[str, bytes]) -> RsaKey:
    """Load a public key from PEM bytes received over the network."""
    key = RSA.import_key(pem)
    if key.has_private():
        raise ValueError("Expected a public key, got a private key")
    return key


def save_private_key(key: RsaKey, path: Union[str, Path], passphrase: str) -> None:
    """
    Save the private key as an encrypted PKCS#8 PEM file.

    The file is protected with a passphrase: PBKDF2-HMAC-SHA256 turns the
    passphrase into an AES-256 key that encrypts the PEM. Anyone who steals the
    file still needs the passphrase to use the key.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.export_key(
        format="PEM",
        passphrase=passphrase,
        pkcs=8,
        protection="PBKDF2WithHMAC-SHA256AndAES256-CBC",
        prot_params={"iteration_count": PBKDF2_ITERATIONS},
    )
    path.write_bytes(pem)


def load_private_key(path: Union[str, Path], passphrase: str) -> RsaKey:
    """Load an encrypted private key. Raises ValueError on a wrong passphrase."""
    return RSA.import_key(Path(path).read_bytes(), passphrase=passphrase)


def save_public_key(key: RsaKey, path: Union[str, Path]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(export_public_key(key))


def load_public_key(path: Union[str, Path]) -> RsaKey:
    return import_public_key(Path(path).read_bytes())


def rsa_encrypt(public_key: RsaKey, data: bytes) -> bytes:
    """
    Encrypt a small piece of data (e.g. a 32-byte AES key) with RSA-OAEP.

    Why OAEP? "Textbook" RSA is deterministic and malleable. OAEP adds random
    padding so the same key encrypts to a different ciphertext every time, and
    it is proven secure against chosen-ciphertext attacks. The older PKCS#1
    v1.5 padding is vulnerable to Bleichenbacher's attack, so it is not used.

    With a 2048-bit key and SHA-256, OAEP can encrypt at most 190 bytes.
    """
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(data)


def rsa_decrypt(private_key: RsaKey, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP data. Raises ValueError if the key or data is wrong."""
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


def public_key_fingerprint(public_key: Union[RsaKey, str, bytes]) -> str:
    """
    SHA-256 fingerprint of a public key, e.g. "A1B2 C3D4 E5F6 ...".

    Users compare this on both screens to make sure they are talking to the
    real server and not to a man-in-the-middle who swapped in their own key
    (the same idea as WhatsApp's "Verify security code").
    """
    if not isinstance(public_key, RsaKey):
        public_key = RSA.import_key(public_key)
    der = public_key.publickey().export_key(format="DER")
    return _group_hex(hashlib.sha256(der).hexdigest())


def _group_hex(hex_string: str) -> str:
    hex_string = hex_string.upper()
    return " ".join(hex_string[i:i + 4] for i in range(0, len(hex_string), 4))


# ---------------------------------------------------------------------------
# Password hashing and key derivation
# ---------------------------------------------------------------------------
def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """
    Hash a password for storage on the server.

    Returns "pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>".

    * Never store the password itself - if the database leaks, attackers
      would get every password.
    * Salt: 16 random bytes per user, so two users with the same password get
      different hashes and precomputed "rainbow tables" are useless.
    * Iterations: PBKDF2 repeats HMAC-SHA256 200,000 times. That costs the
      server a few milliseconds per login, but makes each brute-force guess
      200,000x more expensive for an attacker.
    """
    salt = get_random_bytes(SALT_SIZE)
    digest = PBKDF2(_password_bytes(password), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return "$".join([
        _PASSWORD_SCHEME,
        str(iterations),
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    ])


def verify_password(password: str, stored: str) -> bool:
    """
    Check a password against a stored hash.

    hmac.compare_digest() takes the same time whether the first byte or the
    last byte differs, so an attacker cannot use response timing to guess the
    hash byte by byte (a "timing attack").
    """
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$")
        if scheme != _PASSWORD_SCHEME:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        digest = PBKDF2(_password_bytes(password), salt, dkLen=len(expected), count=int(iterations),
                        hmac_hash_module=SHA256)
    except (ValueError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(digest, expected)


def derive_key_from_password(password: str, salt: bytes,
                             iterations: int = PBKDF2_ITERATIONS,
                             key_size: int = AES_KEY_SIZE) -> bytes:
    """
    Turn a password into an AES key (used to encrypt the local chat history).

    The same password + salt always gives the same key, so the key never has
    to be stored on disk - it is re-derived when the user logs in. The salt is
    random and stored next to the encrypted data (it is not secret).
    """
    return PBKDF2(_password_bytes(password), salt, dkLen=key_size, count=iterations, hmac_hash_module=SHA256)


def generate_salt(size: int = SALT_SIZE) -> bytes:
    return get_random_bytes(size)


# ---------------------------------------------------------------------------
# Other AES modes - FOR THE PERFORMANCE COMPARISON ONLY
# ---------------------------------------------------------------------------
def aes_cbc_encrypt(key: bytes, mac_key: bytes, plaintext: Union[str, bytes]) -> bytes:
    """
    AES-CBC + HMAC-SHA256 (Encrypt-then-MAC). Returns iv(16) || ciphertext || hmac(32).

    CBC on its own only gives confidentiality, so an HMAC over iv+ciphertext
    is added for integrity. Two separate keys are used for encryption and MAC.
    Needs PKCS#7 padding to a multiple of 16 bytes, and cannot be
    parallelised when encrypting - which is why it is slower than GCM.
    """
    _check_aes_key(key)
    iv = get_random_bytes(CBC_IV_SIZE)
    ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(_to_bytes(plaintext), AES.block_size))
    mac = HMAC.new(mac_key, iv + ciphertext, digestmod=SHA256).digest()
    return iv + ciphertext + mac


def aes_cbc_decrypt(key: bytes, mac_key: bytes, blob: bytes) -> bytes:
    """Verify the HMAC FIRST, then decrypt (prevents padding-oracle attacks)."""
    _check_aes_key(key)
    if len(blob) < CBC_IV_SIZE + AES.block_size + HMAC_SIZE:
        raise IntegrityError("Ciphertext is too short to be valid")
    data, mac = blob[:-HMAC_SIZE], blob[-HMAC_SIZE:]
    try:
        HMAC.new(mac_key, data, digestmod=SHA256).verify(mac)
    except ValueError as exc:
        raise IntegrityError("HMAC check failed - message tampered or wrong key") from exc
    iv, ciphertext = data[:CBC_IV_SIZE], data[CBC_IV_SIZE:]
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), AES.block_size)


def aes_ctr_encrypt(key: bytes, plaintext: Union[str, bytes]) -> bytes:
    """
    AES-CTR. Returns nonce(8) || ciphertext.

    Fast and needs no padding, but provides NO integrity: an attacker can flip
    bits in the ciphertext and the same bits flip in the plaintext, undetected.
    GCM = CTR + an authentication tag, which fixes exactly this problem.
    """
    _check_aes_key(key)
    nonce = get_random_bytes(CTR_NONCE_SIZE)
    return nonce + AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(_to_bytes(plaintext))


def aes_ctr_decrypt(key: bytes, blob: bytes) -> bytes:
    _check_aes_key(key)
    nonce, ciphertext = blob[:CTR_NONCE_SIZE], blob[CTR_NONCE_SIZE:]
    return AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)


def aes_ecb_encrypt(key: bytes, plaintext: Union[str, bytes]) -> bytes:
    """
    !!! INSECURE - DO NOT USE FOR REAL DATA !!!

    AES-ECB encrypts every 16-byte block independently with the same key, so
    identical plaintext blocks give identical ciphertext blocks. Patterns in
    the data stay visible (the famous "ECB penguin" image). It also has no IV
    and no integrity. Included only as a baseline in the benchmarks.
    """
    _check_aes_key(key)
    return AES.new(key, AES.MODE_ECB).encrypt(pad(_to_bytes(plaintext), AES.block_size))


def aes_ecb_decrypt(key: bytes, blob: bytes) -> bytes:
    """!!! INSECURE - benchmark baseline only. See aes_ecb_encrypt(). !!!"""
    _check_aes_key(key)
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(blob), AES.block_size)
