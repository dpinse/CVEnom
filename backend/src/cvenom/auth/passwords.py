import secrets
import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 256

_hasher = PasswordHasher()  # argon2id defaults

# argon2id defaults use 64 MiB per verify: cap concurrent verifies per process
# (~256 MiB) so a multi-IP login flood cannot exhaust memory. Excess callers wait.
VERIFY_CONCURRENCY = 4
_VERIFY_SLOTS = threading.BoundedSemaphore(VERIFY_CONCURRENCY)


class WeakPassword(ValueError):
    pass


def validate_password(pw: str) -> None:
    """Length in characters only (NIST 800-63B): no composition rules."""
    if not isinstance(pw, str) or not (MIN_LENGTH <= len(pw) <= MAX_LENGTH):
        raise WeakPassword(
            f"password must be between {MIN_LENGTH} and {MAX_LENGTH} characters"
        )
    if not pw.strip():
        raise WeakPassword("password must not be only whitespace")


def hash_password(pw: str) -> str:
    validate_password(pw)
    return _hasher.hash(pw)


def verify_password(hashed: str, pw: str) -> bool:
    with _VERIFY_SLOTS:
        try:
            return _hasher.verify(hashed, pw)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


def rehash(pw: str) -> str:
    """Hash without the password policy (used when upgrading a verified login)."""
    return _hasher.hash(pw)


# Same parameters as real hashes: burned when no real hash applies.
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def dummy_verify(pw: str = "") -> None:
    """Spend one verify's worth of time against a dummy hash."""
    verify_password(DUMMY_HASH, pw)
