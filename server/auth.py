"""
Registration and login.

Security measures
-----------------
* Passwords are hashed with PBKDF2-HMAC-SHA256 (see common/crypto_utils.py);
  the plain password is never stored or logged.
* Brute-force protection: after 5 wrong passwords (within 15 minutes) an account
  is locked for 60 seconds. Unknown usernames are counted and locked exactly like
  real ones, so the lockout doesn't reveal which accounts exist.
* No user enumeration: "unknown user" and "wrong password" return the same
  message, and an unknown user still costs one PBKDF2 computation, so an
  attacker can't tell from the reply - or from its timing - which usernames exist.
* Resume tokens (for automatic reconnects without re-typing the password):
  a random 256-bit token is given to the client after login. The server only
  stores its SHA-256 hash, so a stolen database doesn't contain usable tokens.
  Each token works ONCE and is replaced by a new one on every resume, and it
  expires after 24 hours.
"""

import base64
import hashlib
import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from common import crypto_utils as cu
from server.database import Database

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
FAILURE_WINDOW = 15 * 60          # wrong passwords older than this are forgotten
MAX_TRACKED_USERNAMES = 10_000    # bound the memory an attacker can fill with made-up usernames
RESUME_TOKEN_LIFETIME = 24 * 3600
SESSION_EXPIRED = "Your session expired. Please log in again."

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_DISPLAY_NAME_LENGTH = 30

# WhatsApp-like avatar colours
AVATAR_COLORS = ["#00A884", "#53BDEB", "#FF7F50", "#A66CFF", "#F15C6D",
                 "#FFBC38", "#02A698", "#7F66FF", "#E26AB6", "#3BA55C"]

GENERIC_LOGIN_ERROR = "Invalid username or password"


def has_letter_and_digit(password: str) -> bool:
    """A letter from ANY alphabet (Hindi, Chinese, ...) counts - not only A-Z."""
    return any(ch.isalpha() for ch in password) and any(ch.isdigit() for ch in password)


class AuthError(Exception):
    """Registration or login failed. str(error) is safe to show to the user."""

    def __init__(self, message: str, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


class AccountLockedError(AuthError):
    """Too many failed logins - the account is temporarily locked."""


@dataclass
class _Attempts:
    failures: int = 0
    locked_until: float = 0.0
    last_failure: float = 0.0


@dataclass
class AuthManager:
    db: Database
    max_failed_attempts: int = MAX_FAILED_ATTEMPTS
    lockout_seconds: float = LOCKOUT_SECONDS
    _attempts: Dict[str, _Attempts] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        # Hash of a random password, used so unknown usernames take as long as real ones
        self._dummy_hash = cu.hash_password(cu.generate_aes_key().hex())

    # ----------------------------------------------------------- validation
    @staticmethod
    def normalise_username(username) -> str:
        return username.strip().lower() if isinstance(username, str) else ""

    @staticmethod
    def validate_username(username: str) -> None:
        if not USERNAME_RE.match(username):
            raise AuthError("Username must be 3-20 characters: lowercase letters, digits or _")

    @staticmethod
    def validate_password(password) -> None:
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise AuthError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
        if not has_letter_and_digit(password):
            raise AuthError("Password must contain at least one letter and one number")

    @staticmethod
    def clean_display_name(display_name, fallback: str) -> str:
        name = display_name.strip() if isinstance(display_name, str) else ""
        name = name or fallback
        if len(name) > MAX_DISPLAY_NAME_LENGTH:
            raise AuthError(f"Display name must be at most {MAX_DISPLAY_NAME_LENGTH} characters")
        return name

    # -------------------------------------------------------------- actions
    def register(self, username, password, display_name=None) -> dict:
        """Create an account and return the user's public profile."""
        username = self.normalise_username(username)
        self.validate_username(username)
        self.validate_password(password)
        display_name = self.clean_display_name(display_name, username)

        password_hash = cu.hash_password(password)
        if not self.db.create_user(username, display_name, password_hash, random.choice(AVATAR_COLORS)):
            raise AuthError("That username is already taken")
        return self.db.get_user(username)

    def login(self, username, password) -> dict:
        """Check the credentials and return the user's public profile."""
        username = self.normalise_username(username)
        password = password if isinstance(password, str) else ""

        remaining = self.lockout_remaining(username)
        if remaining:
            raise AccountLockedError(
                f"Too many failed attempts. Try again in {remaining} seconds", retry_after=remaining)

        stored = self.db.get_password_hash(username) if username else None
        valid = cu.verify_password(password, stored or self._dummy_hash) and stored is not None

        if not valid:
            locked = self._record_failure(username)
            if locked:
                raise AccountLockedError(
                    f"Too many failed attempts. Account locked for {int(self.lockout_seconds)} seconds",
                    retry_after=int(self.lockout_seconds))
            raise AuthError(GENERIC_LOGIN_ERROR)

        with self._lock:
            self._attempts.pop(username, None)
        return self.db.get_user(username)

    # ------------------------------------------------------- resume tokens
    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue_resume_token(self, username: str) -> Tuple[str, str]:
        """Create a single-use resume token. Returns (token for the client, hash stored on the server)."""
        token = base64.urlsafe_b64encode(cu.generate_aes_key(32)).decode("ascii")
        token_hash = self._token_hash(token)
        self.db.store_session(token_hash, username, time.time() + RESUME_TOKEN_LIFETIME)
        return token, token_hash

    def resume(self, username, token) -> dict:
        """Log in with a resume token instead of a password (used by automatic reconnects)."""
        username = self.normalise_username(username)
        if not isinstance(token, str) or not token:
            raise AuthError(SESSION_EXPIRED)
        session = self.db.pop_session(self._token_hash(token))   # single use: removed immediately
        if session is None or session[0] != username or session[1] < time.time():
            raise AuthError(SESSION_EXPIRED)
        return self.db.get_user(username)

    def revoke(self, token_hash: str) -> None:
        self.db.delete_session(token_hash)

    # -------------------------------------------------------------- lockout
    def lockout_remaining(self, username: str) -> int:
        """Seconds until the account unlocks (0 = not locked)."""
        with self._lock:
            state = self._attempts.get(username)
            if not state:
                return 0
            remaining = state.locked_until - time.time()
            if remaining > 0:
                return int(remaining) + 1
            if state.locked_until:                # lock expired: start counting afresh
                self._attempts.pop(username, None)
            return 0

    def failed_attempts(self, username: str) -> int:
        with self._lock:
            state = self._attempts.get(username)
            if state is None or self._stale(state, time.time()):
                return 0
            return state.failures

    @staticmethod
    def _stale(state: _Attempts, now: float) -> bool:
        """Not locked, and the last wrong password is older than FAILURE_WINDOW."""
        return state.locked_until <= now and now - state.last_failure > FAILURE_WINDOW

    def _record_failure(self, username: str) -> bool:
        """Count a failed login. Returns True if this failure locked the account."""
        now = time.time()
        with self._lock:
            state = self._attempts.get(username)
            if state is None or self._stale(state, now):
                if len(self._attempts) >= MAX_TRACKED_USERNAMES:
                    self._prune(now)
                state = self._attempts[username] = _Attempts()
            state.failures += 1
            state.last_failure = now
            if state.failures >= self.max_failed_attempts:
                state.locked_until = now + self.lockout_seconds
                return True
            return False

    def _prune(self, now: float) -> None:
        """Forget stale entries; if that isn't enough, the oldest unlocked ones (lock held by caller)."""
        for name in [n for n, st in self._attempts.items() if self._stale(st, now)]:
            del self._attempts[name]
        if len(self._attempts) >= MAX_TRACKED_USERNAMES:
            unlocked = sorted((st.last_failure, n) for n, st in self._attempts.items() if st.locked_until <= now)
            for _, name in unlocked[:len(self._attempts) - MAX_TRACKED_USERNAMES + 1]:
                del self._attempts[name]
