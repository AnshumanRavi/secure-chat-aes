"""
Unit tests for server/auth.py: registration, login, lockout and resume tokens
(the network-level versions of some of these are in test_server.py).
"""

import base64
import time

import pytest
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from common import crypto_utils as cu
from server import auth as auth_module
from server.auth import AccountLockedError, AuthError, AuthManager
from server.database import Database

PASSWORD = "Passw0rd1"


@pytest.fixture
def auth():
    db = Database(":memory:")
    yield AuthManager(db)
    db.close()


# ------------------------------------------------------------------ register / login
def test_register_then_login_returns_public_profile(auth):
    profile = auth.register("  Alice_1 ", PASSWORD, "Alice")
    assert profile["username"] == "alice_1"                 # trimmed and lower-cased
    assert "password_hash" not in profile
    assert auth.login("ALICE_1", PASSWORD)["display_name"] == "Alice"


@pytest.mark.parametrize("username, password, display, message", [
    ("ab", PASSWORD, None, "3-20 characters"),
    ("bad name!", PASSWORD, None, "3-20 characters"),
    ("okname", "short1", None, "at least 8"),
    ("okname", "a" * 129 + "1", None, "at most 128"),
    ("okname", "lettersonly", None, "one letter and one number"),
    ("okname", "12345678", None, "one letter and one number"),
    ("okname", PASSWORD, "x" * 31, "Display name"),
    ("okname", None, None, "at least 8"),
])
def test_register_validation(auth, username, password, display, message):
    with pytest.raises(AuthError, match=message):
        auth.register(username, password, display)


def test_display_name_defaults_to_username(auth):
    assert auth.register("bob", PASSWORD, "   ")["display_name"] == "bob"


@pytest.mark.parametrize("password", ["पासवर्ड123", "密码abc12345", "secret🔑12", "pässwörd123"])
def test_passwords_in_any_language(auth, password):
    """Non-Latin-1 passwords used to crash PBKDF2 (PyCryptodome encodes str as Latin-1)."""
    auth.register("intl_user", password)
    assert auth.login("intl_user", password)["username"] == "intl_user"
    with pytest.raises(AuthError):
        auth.login("intl_user", password + "x")


def test_existing_latin1_hashes_still_verify():
    """Hashes made before the encoding fix (PyCryptodome's Latin-1) must keep working."""
    salt = b"0123456789abcdef"
    legacy = PBKDF2("pässwörd1", salt, dkLen=32, count=1000, hmac_hash_module=SHA256)   # str -> Latin-1
    stored = "$".join(["pbkdf2_sha256", "1000", base64.b64encode(salt).decode(), base64.b64encode(legacy).decode()])
    assert cu.verify_password("pässwörd1", stored)
    assert not cu.verify_password("passwords1", stored)


def test_verify_password_rejects_garbage():
    assert not cu.verify_password(PASSWORD, "not-a-hash")
    assert not cu.verify_password(PASSWORD, "md5$1$abc$def")
    assert not cu.verify_password(None, cu.hash_password(PASSWORD, iterations=1000))


def test_duplicate_username(auth):
    auth.register("carol", PASSWORD)
    with pytest.raises(AuthError, match="taken"):
        auth.register("CAROL", PASSWORD)


def test_unknown_user_and_wrong_password_give_the_same_error(auth):
    auth.register("dave", PASSWORD)
    with pytest.raises(AuthError) as wrong:
        auth.login("dave", "Wrong1234")
    with pytest.raises(AuthError) as unknown:
        auth.login("nobody_here", PASSWORD)
    assert str(wrong.value) == str(unknown.value) == auth_module.GENERIC_LOGIN_ERROR
    with pytest.raises(AuthError):
        auth.login(None, None)


# ------------------------------------------------------------------ lockout
def test_lockout_and_unlock(auth, monkeypatch):
    auth.register("erin", PASSWORD)
    for _ in range(auth.max_failed_attempts - 1):
        with pytest.raises(AuthError):
            auth.login("erin", "Wrong1234")
    with pytest.raises(AccountLockedError) as locked:
        auth.login("erin", "Wrong1234")
    assert locked.value.retry_after == auth.lockout_seconds
    with pytest.raises(AccountLockedError):              # even the right password is refused while locked
        auth.login("erin", PASSWORD)
    later = time.time() + auth.lockout_seconds + 1
    monkeypatch.setattr(auth_module.time, "time", lambda: later)
    assert auth.login("erin", PASSWORD)["username"] == "erin"
    assert auth.failed_attempts("erin") == 0


def test_unknown_usernames_lock_like_real_ones(auth):
    """Otherwise an attacker could find real accounts by seeing which ones lock."""
    for _ in range(auth.max_failed_attempts - 1):
        with pytest.raises(AuthError):
            auth.login("ghost_user", PASSWORD)
    with pytest.raises(AccountLockedError):
        auth.login("ghost_user", PASSWORD)


def test_old_failures_are_forgotten(auth, monkeypatch):
    auth.register("frank", PASSWORD)
    for _ in range(auth.max_failed_attempts - 1):
        with pytest.raises(AuthError):
            auth.login("frank", "Wrong1234")
    assert auth.failed_attempts("frank") == auth.max_failed_attempts - 1
    later = time.time() + auth_module.FAILURE_WINDOW + 1
    monkeypatch.setattr(auth_module.time, "time", lambda: later)
    assert auth.failed_attempts("frank") == 0
    with pytest.raises(AuthError) as one_more:           # counts from 1 again - no lockout
        auth.login("frank", "Wrong1234")
    assert not isinstance(one_more.value, AccountLockedError)


def test_failed_login_tracking_is_bounded(auth, monkeypatch):
    monkeypatch.setattr(auth_module, "MAX_TRACKED_USERNAMES", 5)
    auth.max_failed_attempts = 1                         # every failure locks...
    with pytest.raises(AccountLockedError):
        auth.login("victim", "Wrong1234")
    auth.max_failed_attempts = 99                        # ...then made-up names that never lock
    for i in range(20):
        auth._record_failure(f"random_{i}")
    assert len(auth._attempts) <= 5
    assert auth.lockout_remaining("victim") > 0          # locked accounts are never pruned


# ------------------------------------------------------------------ resume tokens
def test_resume_token_is_single_use(auth):
    auth.register("gina", PASSWORD)
    token, token_hash = auth.issue_resume_token("gina")
    assert token not in token_hash and len(token_hash) == 64      # only the hash is stored
    assert auth.resume("gina", token)["username"] == "gina"
    with pytest.raises(AuthError):
        auth.resume("gina", token)


def test_resume_token_checks_user_and_expiry(auth, monkeypatch):
    auth.register("hank", PASSWORD)
    auth.register("ivy", PASSWORD)
    token, _ = auth.issue_resume_token("hank")
    with pytest.raises(AuthError):
        auth.resume("ivy", token)                         # someone else's token
    with pytest.raises(AuthError):
        auth.resume("hank", token)                        # ...and that attempt used it up
    expired, _ = auth.issue_resume_token("hank")
    later = time.time() + auth_module.RESUME_TOKEN_LIFETIME + 1
    monkeypatch.setattr(auth_module.time, "time", lambda: later)
    with pytest.raises(AuthError):
        auth.resume("hank", expired)
    for bad in (None, "", 123):
        with pytest.raises(AuthError):
            auth.resume("hank", bad)


def test_revoked_token_cannot_resume(auth):
    auth.register("jack", PASSWORD)
    token, token_hash = auth.issue_resume_token("jack")
    auth.revoke(token_hash)
    with pytest.raises(AuthError):
        auth.resume("jack", token)
