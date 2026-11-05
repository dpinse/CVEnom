import base64
import os

import pytest


def _set_key(monkeypatch, raw: bytes | None = None, text: str | None = None):
    from cvenom.config import get_settings

    value = text if text is not None else base64.b64encode(raw or os.urandom(32)).decode()
    monkeypatch.setenv("SECRETS_KEY", value)
    get_settings.cache_clear()
    return value


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    from cvenom.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_secretbox_roundtrip_and_tamper(monkeypatch):
    _set_key(monkeypatch)
    from cvenom import secretbox

    tok = secretbox.encrypt(b"hook-secret")
    assert tok.startswith("v1:") and b"hook-secret" not in tok.encode()
    assert secretbox.decrypt(tok) == b"hook-secret"
    assert secretbox.encrypt(b"x") != secretbox.encrypt(b"x")  # random nonce
    bad = tok[:-4] + ("A" if tok[-4] != "A" else "B") + tok[-3:]
    with pytest.raises(Exception):
        secretbox.decrypt(bad)  # GCM tag check


def test_decrypt_rejects_unknown_prefix(monkeypatch):
    _set_key(monkeypatch)
    from cvenom import secretbox

    tok = secretbox.encrypt(b"a")
    with pytest.raises(ValueError):
        secretbox.decrypt("v2:" + tok[3:])
    with pytest.raises(ValueError):
        secretbox.decrypt(tok[3:])


def test_decrypt_with_other_key_fails(monkeypatch):
    _set_key(monkeypatch)
    from cvenom import secretbox
    from cvenom.config import get_settings

    tok = secretbox.encrypt(b"a")
    _set_key(monkeypatch)
    get_settings.cache_clear()
    with pytest.raises(Exception):
        secretbox.decrypt(tok)


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("SECRETS_KEY", raising=False)
    from cvenom import secretbox
    from cvenom.config import Settings, get_settings

    monkeypatch.setattr(
        "cvenom.secretbox.get_settings",
        lambda: Settings(database_url="postgresql://x", redis_url="redis://y", _env_file=None),
    )
    get_settings.cache_clear()
    with pytest.raises(secretbox.SecretsKeyMissing):
        secretbox.encrypt(b"x")
    with pytest.raises(secretbox.SecretsKeyMissing):
        secretbox.decrypt("v1:AAAA")


@pytest.mark.parametrize(
    "text",
    [
        "!!!not-base64-KEYMATERIAL!!!",
        base64.b64encode(b"short-key-material-16").decode(),
        base64.b64encode(os.urandom(33)).decode(),
    ],
)
def test_bad_key_raises_without_leaking(monkeypatch, text):
    _set_key(monkeypatch, text=text)
    from cvenom import secretbox

    with pytest.raises(ValueError) as ei:
        secretbox.encrypt(b"PLAINTEXT-MARKER")
    msg = str(ei.value) + repr(ei.value)
    assert text not in msg and "PLAINTEXT-MARKER" not in msg


def test_check_key(monkeypatch):
    from cvenom import secretbox

    _set_key(monkeypatch)
    secretbox.check_key()
    _set_key(monkeypatch, raw=b"x" * 16)
    with pytest.raises(ValueError):
        secretbox.check_key()
    monkeypatch.delenv("SECRETS_KEY")
    from cvenom.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(secretbox.SecretsKeyMissing):
        secretbox.check_key()
