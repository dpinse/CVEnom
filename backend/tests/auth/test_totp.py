"""TOTP (RFC 6238) on the stdlib: vectors, drift window, replay, provisioning URI."""

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest

from cvenom.auth import totp

RFC_KEY = b"12345678901234567890"  # RFC 4226 / RFC 6238 SHA-1 seed


@pytest.mark.parametrize(
    "counter,code",
    list(enumerate(["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"])),
)
def test_hotp_rfc4226_vectors(counter, code):
    assert totp.hotp(RFC_KEY, counter) == code


@pytest.mark.parametrize(
    "t,code",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_rfc6238_sha1_vectors(t, code):
    assert totp.totp_at(RFC_KEY, t, digits=8) == code


def test_defaults_are_sha1_six_digits_thirty_seconds():
    assert totp.DIGITS == 6 and totp.STEP_SECONDS == 30 and totp.DRIFT_STEPS == 1
    assert totp.DIGEST is hashlib.sha1
    # 6-digit code is the low 6 digits of the 8-digit RFC value
    assert totp.totp_at(RFC_KEY, 59) == "287082"
    assert totp.step_of(59) == 1 and totp.step_of(60) == 2


def test_generate_secret_is_160_bits_and_random():
    a, b = totp.generate_secret(), totp.generate_secret()
    assert len(a) == 20 and len(b) == 20 and a != b


def test_b32_roundtrip_no_padding():
    s = totp.generate_secret()
    enc = totp.b32(s)
    assert "=" not in enc and len(enc) == 32
    assert base64.b32decode(enc) == s


@pytest.mark.parametrize("offset,ok", [(-2, False), (-1, True), (0, True), (1, True), (2, False)])
def test_drift_plus_minus_one_step(offset, ok):
    key = totp.generate_secret()
    now = 1_700_000_000
    code = totp.totp_at(key, now + offset * 30)
    got = totp.match_step(key, code, now, last_step=None)
    if ok:
        assert got == totp.step_of(now) + offset
    else:
        assert got is None


def test_replay_of_same_or_earlier_step_rejected():
    key = totp.generate_secret()
    now = 1_700_000_000
    step = totp.step_of(now)
    code = totp.totp_at(key, now)
    assert totp.match_step(key, code, now, last_step=step - 1) == step
    assert totp.match_step(key, code, now, last_step=step) is None
    # a code from the previous step is also dead once a later step was used
    prev = totp.totp_at(key, now - 30)
    assert totp.match_step(key, prev, now, last_step=step) is None
    # the next step is still fine
    nxt = totp.totp_at(key, now + 30)
    assert totp.match_step(key, nxt, now, last_step=step) == step + 1


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 345", "١٢٣٤٥٦", None, 123456])
def test_malformed_codes_rejected(bad):
    key = totp.generate_secret()
    assert totp.match_step(key, bad, 1_700_000_000, last_step=None) is None


def test_whitespace_around_code_tolerated():
    key = totp.generate_secret()
    code = totp.totp_at(key, 1_700_000_000)
    assert totp.match_step(key, f" {code}\n", 1_700_000_000, None) == totp.step_of(1_700_000_000)


def test_provisioning_uri():
    key = RFC_KEY
    uri = totp.provisioning_uri(key, "a+b@example.com", issuer="CVEnom")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth" and parts.netloc == "totp"
    assert parts.path == "/CVEnom:a%2Bb%40example.com"
    q = parse_qs(parts.query)
    assert q == {
        "secret": [totp.b32(key)],
        "issuer": ["CVEnom"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
    }
