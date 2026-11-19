"""Unit tests for common/crypto_utils.py.  Run with:  pytest tests/test_crypto.py -v"""

import pytest

from common import crypto_utils as cu


@pytest.fixture(scope="module")
def rsa_key():
    # RSA key generation takes ~1 s, so share one key pair across the tests
    return cu.generate_rsa_keypair()


@pytest.fixture
def key():
    return cu.generate_aes_key()


# --------------------------------------------------------------- AES-GCM ---
def test_aes_key_is_256_bits(key):
    assert len(key) == 32


@pytest.mark.parametrize("message", [b"", b"hi", "Hello Bob! 👋 नमस्ते".encode(), b"A" * 100_000],
                         ids=["empty", "short", "unicode-emoji", "100KB"])
def test_aes_round_trip(key, message):
    assert cu.aes_decrypt(key, cu.aes_encrypt(key, message)) == message


def test_aes_accepts_str(key):
    assert cu.aes_decrypt(key, cu.aes_encrypt(key, "secret")) == b"secret"


def test_ciphertext_layout_and_no_plaintext_leak(key):
    message = b"meet me at the library at 5pm"
    blob = cu.aes_encrypt(key, message)
    assert len(blob) == cu.GCM_NONCE_SIZE + len(message) + cu.GCM_TAG_SIZE
    assert message not in blob


def test_same_message_encrypts_differently(key):
    assert cu.aes_encrypt(key, b"same") != cu.aes_encrypt(key, b"same")


def test_nonces_are_unique(key):
    nonces = {cu.aes_encrypt(key, b"x")[:cu.GCM_NONCE_SIZE] for _ in range(5000)}
    assert len(nonces) == 5000


@pytest.mark.parametrize("position", ["nonce", "ciphertext", "tag"])
def test_tamper_detection(key, position):
    blob = bytearray(cu.aes_encrypt(key, b"transfer 100 rupees"))
    index = {"nonce": 0, "ciphertext": cu.GCM_NONCE_SIZE + 3, "tag": len(blob) - 1}[position]
    blob[index] ^= 0x01  # flip a single bit
    with pytest.raises(cu.IntegrityError):
        cu.aes_decrypt(key, bytes(blob))


def test_wrong_key_fails(key):
    blob = cu.aes_encrypt(key, b"for Bob only")
    with pytest.raises(cu.IntegrityError):
        cu.aes_decrypt(cu.generate_aes_key(), blob)


def test_associated_data_must_match(key):
    blob = cu.aes_encrypt(key, b"hello", associated_data=b"CHAT_MSG")
    assert cu.aes_decrypt(key, blob, associated_data=b"CHAT_MSG") == b"hello"
    with pytest.raises(cu.IntegrityError):
        cu.aes_decrypt(key, blob, associated_data=b"GROUP_MSG")


def test_truncated_ciphertext_rejected(key):
    with pytest.raises(cu.IntegrityError):
        cu.aes_decrypt(key, b"short")


def test_invalid_key_length_rejected():
    with pytest.raises(ValueError):
        cu.aes_encrypt(b"too-short-key", b"data")


def test_key_fingerprint_does_not_reveal_key(key):
    fp = cu.key_fingerprint(key)
    assert key.hex().upper() not in fp.replace(" ", "")
    assert fp == cu.key_fingerprint(key)


# ------------------------------------------------------------------- RSA ---
def test_rsa_round_trip(rsa_key):
    session_key = cu.generate_aes_key()
    public = cu.import_public_key(cu.export_public_key(rsa_key))
    assert cu.rsa_decrypt(rsa_key, cu.rsa_encrypt(public, session_key)) == session_key


def test_rsa_oaep_is_randomised(rsa_key):
    assert cu.rsa_encrypt(rsa_key.publickey(), b"k") != cu.rsa_encrypt(rsa_key.publickey(), b"k")


def test_rsa_wrong_private_key_fails(rsa_key):
    other = cu.generate_rsa_keypair()
    ciphertext = cu.rsa_encrypt(rsa_key.publickey(), b"session key")
    with pytest.raises(ValueError):
        cu.rsa_decrypt(other, ciphertext)


def test_import_public_key_rejects_private_key(rsa_key):
    with pytest.raises(ValueError):
        cu.import_public_key(rsa_key.export_key())


def test_save_and_load_keys(rsa_key, tmp_path):
    cu.save_private_key(rsa_key, tmp_path / "server_private.pem", "correct horse")
    cu.save_public_key(rsa_key, tmp_path / "server_public.pem")

    pem = (tmp_path / "server_private.pem").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in pem

    loaded = cu.load_private_key(tmp_path / "server_private.pem", "correct horse")
    assert loaded == rsa_key
    assert cu.load_public_key(tmp_path / "server_public.pem") == rsa_key.publickey()

    with pytest.raises(ValueError):
        cu.load_private_key(tmp_path / "server_private.pem", "wrong passphrase")


def test_public_key_fingerprint(rsa_key):
    fp = cu.public_key_fingerprint(rsa_key.publickey())
    groups = fp.split(" ")
    assert len(groups) == 16 and all(len(g) == 4 for g in groups)
    assert fp == cu.public_key_fingerprint(rsa_key)                    # private key -> same fingerprint
    assert fp == cu.public_key_fingerprint(cu.export_public_key(rsa_key))  # PEM bytes -> same
    assert fp != cu.public_key_fingerprint(cu.generate_rsa_keypair())


# ------------------------------------------------------ password hashing ---
def test_password_hash_and_verify():
    stored = cu.hash_password("S3cure!pass")
    assert stored.startswith("pbkdf2_sha256$200000$")
    assert "S3cure!pass" not in stored
    assert cu.verify_password("S3cure!pass", stored)
    assert not cu.verify_password("s3cure!pass", stored)
    assert not cu.verify_password("", stored)


def test_same_password_different_hashes():
    assert cu.hash_password("password123") != cu.hash_password("password123")


@pytest.mark.parametrize("stored", ["", "garbage", "md5$1$abc$def", "pbkdf2_sha256$x$y$z"])
def test_verify_rejects_malformed_hash(stored):
    assert cu.verify_password("anything", stored) is False


def test_derive_key_from_password():
    salt = cu.generate_salt()
    k1 = cu.derive_key_from_password("my password", salt)
    assert len(k1) == 32
    assert k1 == cu.derive_key_from_password("my password", salt)
    assert k1 != cu.derive_key_from_password("my password", cu.generate_salt())
    assert k1 != cu.derive_key_from_password("other password", salt)


# ------------------------------------------- comparison modes (benchmarks) ---
def test_cbc_hmac_round_trip_and_tamper(key):
    mac_key = cu.generate_aes_key()
    blob = cu.aes_cbc_encrypt(key, mac_key, b"cbc message")
    assert cu.aes_cbc_decrypt(key, mac_key, blob) == b"cbc message"
    tampered = bytearray(blob)
    tampered[20] ^= 0x01
    with pytest.raises(cu.IntegrityError):
        cu.aes_cbc_decrypt(key, mac_key, bytes(tampered))


def test_ctr_round_trip_but_no_integrity(key):
    blob = cu.aes_ctr_encrypt(key, b"pay 100")
    assert cu.aes_ctr_decrypt(key, blob) == b"pay 100"
    # Flipping a ciphertext bit silently changes the plaintext - CTR cannot detect it
    tampered = bytearray(blob)
    tampered[cu.CTR_NONCE_SIZE + 4] ^= ord("1") ^ ord("9")
    assert cu.aes_ctr_decrypt(key, bytes(tampered)) == b"pay 900"


def test_ecb_round_trip_and_pattern_leak(key):
    message = b"SIXTEEN BYTE BLK" * 4
    blob = cu.aes_ecb_encrypt(key, message)
    assert cu.aes_ecb_decrypt(key, blob) == message
    # Identical plaintext blocks -> identical ciphertext blocks (why ECB is insecure)
    assert blob[0:16] == blob[16:32] == blob[32:48]
