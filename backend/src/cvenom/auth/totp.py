"""TOTP (RFC 6238) on the standard library: HMAC-SHA-1, 6 digits, 30 s step.

No third-party dependency. Verified against the RFC 4226 HOTP and RFC 6238
SHA-1 test vectors (tests/auth/test_totp.py). Codes are compared with
`hmac.compare_digest`; nothing here logs or raises with a secret or code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
from urllib.parse import quote, urlencode

DIGEST = hashlib.sha1
DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 1  # accept the previous and the next step (clock drift)
SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommendation for SHA-1

# ASCII digits only: `\d` and str.isdigit() also accept other Unicode digits.
_CODE_RE = re.compile(r"[0-9]{%d}" % DIGITS)


def generate_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def b32(secret: bytes) -> str:
    """Unpadded RFC 4648 base32, the form authenticator apps expect."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=DIGEST) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def step_of(unix_time: float) -> int:
    return int(unix_time // STEP_SECONDS)


def totp_at(key: bytes, unix_time: float, digits: int = DIGITS, digest=DIGEST) -> str:
    return hotp(key, step_of(unix_time), digits, digest)


def match_step(key: bytes, code: object, unix_time: float, last_step: int | None) -> int | None:
    """The time step `code` belongs to, within ±DRIFT_STEPS of `unix_time`, or None.

    Replay protection: a step at or before `last_step` (the last accepted step)
    never matches. Every candidate is computed and compared, so the work done
    does not depend on which step (if any) matched.
    """
    if not isinstance(code, str):
        return None
    code = code.strip()
    if not _CODE_RE.fullmatch(code):
        return None
    now_step = step_of(unix_time)
    found: int | None = None
    for step in range(now_step - DRIFT_STEPS, now_step + DRIFT_STEPS + 1):
        ok = hmac.compare_digest(hotp(key, step).encode(), code.encode())
        if ok and found is None and (last_step is None or step > last_step):
            found = step
    return found


def provisioning_uri(key: bytes, account: str, issuer: str = "CVEnom") -> str:
    """`otpauth://totp/<issuer>:<account>?secret=...` (Key URI format)."""
    label = quote(issuer, safe="") + ":" + quote(account, safe="")
    query = urlencode(
        {
            "secret": b32(key),
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(DIGITS),
            "period": str(STEP_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{query}"
