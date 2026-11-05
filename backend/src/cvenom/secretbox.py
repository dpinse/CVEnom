"""AES-256-GCM encryption for secrets stored at rest (JWT keys, webhook secrets, SMTP)."""

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cvenom.config import get_settings

PREFIX = "v1:"
_NONCE_LEN = 12


class SecretsKeyMissing(Exception):
    """SECRETS_KEY is not configured."""


def _aesgcm() -> AESGCM:
    secret = get_settings().secrets_key
    if secret is None:
        raise SecretsKeyMissing("SECRETS_KEY is not configured")
    try:
        key = base64.b64decode(secret.get_secret_value(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("SECRETS_KEY is not valid base64") from None
    if len(key) != 32:
        raise ValueError("SECRETS_KEY must decode to exactly 32 bytes")
    return AESGCM(key)


def encrypt(plaintext: bytes) -> str:
    aes = _aesgcm()
    nonce = os.urandom(_NONCE_LEN)
    blob = nonce + aes.encrypt(nonce, plaintext, None)
    return PREFIX + base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt(token: str) -> bytes:
    if not token.startswith(PREFIX):
        raise ValueError("unsupported secret token version")
    aes = _aesgcm()
    try:
        blob = base64.urlsafe_b64decode(token[len(PREFIX):].encode("ascii"))
    except (binascii.Error, ValueError):
        raise ValueError("malformed secret token") from None
    if len(blob) < _NONCE_LEN + 16:
        raise ValueError("malformed secret token")
    try:
        return aes.decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], None)
    except InvalidTag:
        raise ValueError("secret token failed authentication") from None
