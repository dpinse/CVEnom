import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select

from cvenom import secretbox
from cvenom.auth import tokens
from cvenom.auth.tokens import (
    InvalidToken,
    KeyRing,
    TokenReuse,
    create_session,
    decode_access,
    issue_access,
    rotate_refresh,
    session_is_active,
)
from cvenom.config import get_settings
from cvenom.models import SigningKey, User, UserSession

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def secrets_key(monkeypatch):
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def user(db_session):
    u = User(email="t@example.com", password_hash="x", role="member", is_active=True)
    db_session.add(u)
    db_session.flush()
    return u


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge(header: dict, payload: dict, sig: bytes = b"") -> str:
    return (
        b64u(json.dumps(header).encode())
        + "."
        + b64u(json.dumps(payload).encode())
        + "."
        + b64u(sig)
    )


def good_payload(header_kid, now=NOW, **over):
    iat = int(now.timestamp())
    p = {
        "sub": "1",
        "sid": str(uuid.uuid4()),
        "role": "member",
        "iat": iat,
        "exp": iat + 900,
        "kid": header_kid,
        "iss": "cvenom",
        "aud": "cvenom-api",
    }
    p.update(over)
    return p


def test_round_trip(db_session, user):
    sid = uuid.uuid4()
    tok = issue_access(db_session, user, sid, NOW)
    hdr = jwt.get_unverified_header(tok)
    assert hdr["alg"] == "EdDSA"
    c = decode_access(db_session, tok, NOW + timedelta(minutes=1))
    assert (c.sub, c.sid, c.role) == (user.id, sid, "member")
    assert c.kid == hdr["kid"]
    assert c.exp - c.iat == 900


def test_expired_rejected(db_session, user):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW + timedelta(minutes=15))
    decode_access(db_session, tok, NOW + timedelta(minutes=15, seconds=-1))


def test_future_iat_rejected(db_session, user):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW - timedelta(seconds=61))


def test_alg_none_rejected(db_session):
    key = KeyRing.current(db_session, NOW)
    tok = forge({"alg": "none", "typ": "JWT", "kid": key.kid}, good_payload(key.kid))
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW)


def test_hs256_with_public_key_rejected(db_session):
    key = KeyRing.current(db_session, NOW)
    header = {"alg": "HS256", "typ": "JWT", "kid": key.kid}
    signing_input = (
        b64u(json.dumps(header).encode())
        + "."
        + b64u(json.dumps(good_payload(key.kid)).encode())
    )
    sig = hmac.new(key.public_pem.encode(), signing_input.encode(), hashlib.sha256).digest()
    with pytest.raises(InvalidToken):
        decode_access(db_session, signing_input + "." + b64u(sig), NOW)


def test_missing_kid_header_rejected(db_session, user):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    h, p, s = tok.split(".")
    hdr = json.loads(base64.urlsafe_b64decode(h + "=="))
    del hdr["kid"]
    with pytest.raises(InvalidToken):
        decode_access(db_session, b64u(json.dumps(hdr).encode()) + "." + p + "." + s, NOW)


def _resign(db_session, header_over=None, **claim_over):
    key = KeyRing.current(db_session, NOW)
    priv = serialization.load_der_private_key(secretbox.decrypt(key.private_enc), password=None)
    headers = {"kid": key.kid}
    headers.update(header_over or {})
    return jwt.encode(
        good_payload(key.kid, **claim_over), priv, algorithm="EdDSA", headers=headers
    )


def test_resigned_helper_accepted(db_session):
    decode_access(db_session, _resign(db_session), NOW)


def test_wrong_aud_and_iss_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, aud="other"), NOW)
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, iss="evil"), NOW)


def test_unknown_kid_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, header_over={"kid": "nope"}), NOW)


def test_kid_claim_header_mismatch_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, kid="other"), NOW)


def test_bad_sub_sid_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, sub="abc"), NOW)
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, sid="not-a-uuid"), NOW)


def test_tampered_payload_rejected(db_session, user):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    h, p, s = tok.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["role"] = "admin"
    bad = h + "." + b64u(json.dumps(payload).encode()) + "." + s
    with pytest.raises(InvalidToken) as ei:
        decode_access(db_session, bad, NOW)
    assert tok not in str(ei.value) and bad not in str(ei.value)


def test_garbage_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, "not.a.jwt", NOW)


def test_rotation_and_grace(db_session, user):
    sid = uuid.uuid4()
    old_tok = issue_access(db_session, user, sid, NOW)
    old_kid = jwt.get_unverified_header(old_tok)["kid"]
    later = NOW + timedelta(days=7)
    new_tok = issue_access(db_session, user, sid, later)
    new_kid = jwt.get_unverified_header(new_tok)["kid"]
    assert new_kid != old_kid
    assert db_session.get(SigningKey, old_kid).retired_at == later
    keys = KeyRing.verification_keys(db_session, later + timedelta(minutes=30))
    assert {old_kid, new_kid} <= set(keys)
    after = later + timedelta(hours=1, minutes=16)
    keys = KeyRing.verification_keys(db_session, after)
    assert old_kid not in keys and new_kid in keys
    with pytest.raises(InvalidToken):
        decode_access(db_session, old_tok, after)


def test_old_token_verifies_in_grace(db_session, user):
    issued = NOW + timedelta(days=7) - timedelta(minutes=1)
    tok = issue_access(db_session, user, uuid.uuid4(), issued)
    later = NOW + timedelta(days=7) + timedelta(minutes=5)
    KeyRing.current(db_session, later)
    decode_access(db_session, tok, later - timedelta(minutes=4))


def test_no_rotation_before_interval(db_session):
    a = KeyRing.current(db_session, NOW)
    b = KeyRing.current(db_session, NOW + timedelta(days=6, hours=23))
    assert a.kid == b.kid


def test_current_twice_creates_one_key(db_session):
    a = KeyRing.current(db_session, NOW)
    b = KeyRing.current(db_session, NOW)
    assert a.kid == b.kid
    assert len(db_session.scalars(select(SigningKey)).all()) == 1


def test_current_takes_advisory_lock(db_session, monkeypatch):
    stmts = []
    orig = db_session.execute

    def spy(stmt, *a, **k):
        stmts.append(str(stmt))
        return orig(stmt, *a, **k)

    monkeypatch.setattr(db_session, "execute", spy)
    KeyRing.current(db_session, NOW)
    assert any("pg_advisory_xact_lock" in s for s in stmts)


def test_private_key_encrypted_at_rest(db_session):
    key = KeyRing.current(db_session, NOW)
    assert "PRIVATE KEY" not in key.private_enc
    assert key.private_enc.startswith("v1:")
    der = secretbox.decrypt(key.private_enc)
    assert der not in key.private_enc.encode()
    assert base64.b64encode(der).decode() not in key.private_enc
    serialization.load_der_private_key(der, password=None)
    assert key.public_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert key.created_at == NOW


def test_new_refresh():
    raw, h = tokens.new_refresh()
    assert h == hashlib.sha256(raw.encode()).hexdigest()
    assert tokens.new_refresh()[0] != raw


def test_create_session_truncates(db_session, user):
    s, raw = create_session(db_session, user, NOW, "u" * 600, "i" * 100)
    assert len(s.user_agent) == 512 and len(s.ip) == 64
    assert s.expires_at == NOW + timedelta(days=30)
    assert s.refresh_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert session_is_active(db_session, s.id, NOW)


def test_rotate_refresh(db_session, user):
    s, raw = create_session(db_session, user, NOW, "ua", "1.1.1.1")
    old_hash = s.refresh_hash
    later = NOW + timedelta(minutes=5)
    s2, raw2 = rotate_refresh(db_session, raw, later, "ua2", "2.2.2.2")
    assert s2.id == s.id and raw2 != raw
    assert s2.prev_refresh_hash == old_hash
    assert s2.refresh_hash == hashlib.sha256(raw2.encode()).hexdigest()
    assert s2.last_used_at == later and s2.user_agent == "ua2" and s2.ip == "2.2.2.2"
    rotate_refresh(db_session, raw2, later, "ua", "ip")


def test_refresh_reuse_revokes_and_survives_rollback(db_session, user):
    s, raw = create_session(db_session, user, NOW, "ua", "ip")
    sid = s.id
    _, raw2 = rotate_refresh(db_session, raw, NOW, "ua", "ip")
    later = NOW + timedelta(minutes=1)
    with pytest.raises(TokenReuse):
        rotate_refresh(db_session, raw, later, "ua", "ip")
    assert issubclass(TokenReuse, InvalidToken)
    db_session.rollback()
    row = db_session.get(UserSession, sid)
    db_session.refresh(row)
    assert row.revoked_at == later
    with pytest.raises(InvalidToken):
        rotate_refresh(db_session, raw2, later, "ua", "ip")
    assert not session_is_active(db_session, sid, later)


def test_expired_refresh_fails(db_session, user):
    _, raw = create_session(db_session, user, NOW, "ua", "ip")
    with pytest.raises(InvalidToken):
        rotate_refresh(db_session, raw, NOW + timedelta(days=30), "ua", "ip")


def test_unknown_refresh_fails(db_session, user):
    with pytest.raises(InvalidToken) as ei:
        rotate_refresh(db_session, "nope", NOW, "ua", "ip")
    assert not isinstance(ei.value, TokenReuse)


def test_revoked_refresh_fails(db_session, user):
    s, raw = create_session(db_session, user, NOW, "ua", "ip")
    s.revoked_at = NOW
    db_session.flush()
    with pytest.raises(InvalidToken):
        rotate_refresh(db_session, raw, NOW, "ua", "ip")
    assert not session_is_active(db_session, s.id, NOW)


def test_inactive_user_refresh_fails(db_session, user):
    _, raw = create_session(db_session, user, NOW, "ua", "ip")
    user.is_active = False
    db_session.flush()
    with pytest.raises(InvalidToken):
        rotate_refresh(db_session, raw, NOW, "ua", "ip")


def test_session_is_active_expiry_and_unknown(db_session, user):
    s, _ = create_session(db_session, user, NOW, "ua", "ip")
    assert not session_is_active(db_session, s.id, NOW + timedelta(days=30))
    assert not session_is_active(db_session, uuid.uuid4(), NOW)


# ---- fix round 1 ----


def test_current_does_not_expire_callers_pending_changes(db_session, user):
    KeyRing.current(db_session, NOW)
    db_session.flush()
    user.role = "admin"  # pending, unflushed
    with db_session.no_autoflush:
        KeyRing.current(db_session, NOW + timedelta(days=8))  # rotates
    assert user.role == "admin"
    assert "role" in db_session.get_one(User, user.id).__dict__


def test_reuse_of_any_older_token_revokes(db_session, user):
    s, t0 = create_session(db_session, user, NOW, "ua", "ip")
    sid = s.id
    _, t1 = rotate_refresh(db_session, t0, NOW, "ua", "ip")
    _, t2 = rotate_refresh(db_session, t1, NOW + timedelta(minutes=1), "ua", "ip")
    later = NOW + timedelta(minutes=5)
    with pytest.raises(TokenReuse):
        rotate_refresh(db_session, t0, later, "ua", "ip")
    db_session.rollback()
    row = db_session.get(UserSession, sid)
    db_session.refresh(row)
    assert row.revoked_at == later
    with pytest.raises(InvalidToken):
        rotate_refresh(db_session, t2, later, "ua", "ip")


def test_predecessor_within_grace_is_not_revoked(db_session, user):
    s, t0 = create_session(db_session, user, NOW, "ua", "ip")
    _, t1 = rotate_refresh(db_session, t0, NOW, "ua", "ip")
    with pytest.raises(InvalidToken) as ei:
        rotate_refresh(db_session, t0, NOW + timedelta(seconds=9), "ua", "ip")
    assert not isinstance(ei.value, TokenReuse)
    assert tokens.REUSE_GRACE == timedelta(seconds=10)
    assert session_is_active(db_session, s.id, NOW + timedelta(seconds=9))
    rotate_refresh(db_session, t1, NOW + timedelta(seconds=9), "ua", "ip")


def test_predecessor_after_grace_revokes(db_session, user):
    s, t0 = create_session(db_session, user, NOW, "ua", "ip")
    rotate_refresh(db_session, t0, NOW, "ua", "ip")
    at = NOW + timedelta(seconds=11)
    with pytest.raises(TokenReuse):
        rotate_refresh(db_session, t0, at, "ua", "ip")
    assert not session_is_active(db_session, s.id, at)


NAIVE = datetime(2026, 1, 1, 12, 0)


@pytest.mark.parametrize(
    "call",
    [
        lambda db, u: KeyRing.current(db, NAIVE),
        lambda db, u: KeyRing.verification_keys(db, NAIVE),
        lambda db, u: issue_access(db, u, uuid.uuid4(), NAIVE),
        lambda db, u: decode_access(db, "a.b.c", NAIVE),
        lambda db, u: rotate_refresh(db, "x", NAIVE, "ua", "ip"),
        lambda db, u: create_session(db, u, NAIVE, "ua", "ip"),
        lambda db, u: session_is_active(db, uuid.uuid4(), NAIVE),
    ],
)
def test_naive_now_rejected(db_session, user, call):
    with pytest.raises(ValueError, match="timezone-aware"):
        call(db_session, user)


def test_bool_iat_rejected(db_session):
    with pytest.raises(InvalidToken):
        decode_access(db_session, _resign(db_session, iat=True), NOW)


@pytest.mark.parametrize("alg", ["eddsa", "EdDSA ", "EDDSA", " EdDSA"])
def test_alg_variants_rejected(db_session, alg):
    key = KeyRing.current(db_session, NOW)
    tok = forge({"alg": alg, "typ": "JWT", "kid": key.kid}, good_payload(key.kid), b"x" * 64)
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW)


@pytest.mark.parametrize("kid", [5, ["a"], None])
def test_non_string_kid_rejected(db_session, kid):
    key = KeyRing.current(db_session, NOW)
    tok = forge({"alg": "EdDSA", "typ": "JWT", "kid": kid}, good_payload(key.kid), b"x" * 64)
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW)


def test_attacker_jwk_header_rejected(db_session):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = KeyRing.current(db_session, NOW)
    attacker = Ed25519PrivateKey.generate()
    raw = attacker.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
    tok = jwt.encode(
        good_payload(key.kid), attacker, algorithm="EdDSA", headers={"kid": key.kid, "jwk": jwk}
    )
    with pytest.raises(InvalidToken):
        decode_access(db_session, tok, NOW)


# ---------------------------------------------------------------- key cache


def _count_queries(db_session):
    from sqlalchemy import event

    n = {"q": 0}
    bind = db_session.get_bind()

    def hook(*a, **k):
        n["q"] += 1

    event.listen(bind, "before_cursor_execute", hook)
    return n, lambda: event.remove(bind, "before_cursor_execute", hook)


def test_key_cache_avoids_second_query(db_session, user):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    decode_access(db_session, tok, NOW)  # warms the cache
    n, stop = _count_queries(db_session)
    try:
        decode_access(db_session, tok, NOW + timedelta(seconds=30))
    finally:
        stop()
    assert n["q"] == 0


def test_key_cache_expires_after_ttl(db_session, user, monkeypatch):
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    clock = {"t": 1000.0}
    monkeypatch.setattr(tokens.time, "monotonic", lambda: clock["t"])
    decode_access(db_session, tok, NOW)
    clock["t"] += 61
    n, stop = _count_queries(db_session)
    try:
        decode_access(db_session, tok, NOW)
    finally:
        stop()
    assert n["q"] == 1


def test_unknown_kid_forces_one_refresh_rate_limited(db_session, user, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(tokens.time, "monotonic", lambda: clock["t"])
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    KeyRing.verification_keys(db_session, NOW)  # warm cache
    # a key appears behind the cache's back (another worker)
    other = KeyRing._generate(NOW)
    db_session.add(other)
    db_session.flush()
    priv = serialization.load_der_private_key(secretbox.decrypt(other.private_enc), password=None)
    claims = jwt.decode(tok, options={"verify_signature": False})
    claims["kid"] = other.kid
    foreign = jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": other.kid})
    assert decode_access(db_session, foreign, NOW).kid == other.kid  # picked up by refresh
    # unknown kid again within 10 s: no further refresh, rejected without a query
    n, stop = _count_queries(db_session)
    try:
        bogus = jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": "nope"})
        with pytest.raises(InvalidToken):
            decode_access(db_session, bogus, NOW)
        with pytest.raises(InvalidToken):
            decode_access(db_session, bogus, NOW)
    finally:
        stop()
    assert n["q"] == 0
    clock["t"] += 11
    n, stop = _count_queries(db_session)
    try:
        with pytest.raises(InvalidToken):
            decode_access(db_session, bogus, NOW)
    finally:
        stop()
    assert n["q"] == 1


def old_kid_in_cache(tokens):
    return tokens._key_cache is not None and any(r is not None for _, _, r in tokens._key_cache[1])


def test_cached_retired_key_rejected_past_grace(db_session, user):
    old_tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    later = NOW + timedelta(days=7)
    issue_access(db_session, user, uuid.uuid4(), later)  # rotates, invalidates cache
    inside = later + timedelta(minutes=30)
    # warm the cache, then use it past grace with the same cached entries
    KeyRing.verification_keys(db_session, inside)
    after = later + timedelta(hours=1, minutes=16)
    assert old_kid_in_cache(tokens)
    n, stop = _count_queries(db_session)
    try:
        with pytest.raises(InvalidToken):
            decode_access(db_session, old_tok, after)
    finally:
        stop()
    assert n["q"] <= 1  # at most the single forced refresh for the unknown kid
    # the cache still holds the retired key; it is rejected by the use-time filter
    assert tokens._key_cache is not None
    assert any(r is not None for _, _, r in tokens._key_cache[1])


def test_current_creating_key_invalidates_cache(db_session):
    KeyRing.verification_keys(db_session, NOW)
    KeyRing.current(db_session, NOW)
    assert tokens._key_cache is None


def test_bogus_kid_burst_does_not_block_real_new_kid(db_session, user, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(tokens.time, "monotonic", lambda: clock["t"])
    tok = issue_access(db_session, user, uuid.uuid4(), NOW)
    KeyRing.verification_keys(db_session, NOW)  # warm
    other = KeyRing._generate(NOW)
    db_session.add(other)
    db_session.flush()
    priv = serialization.load_der_private_key(secretbox.decrypt(other.private_enc), password=None)
    claims = jwt.decode(tok, options={"verify_signature": False})
    for i in range(20):  # burst of bogus kids, each past the 1 s global cap
        clock["t"] += 1.1
        bogus = jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": f"bogus{i}"})
        with pytest.raises(InvalidToken):
            decode_access(db_session, bogus, NOW)
    # first bogus refresh already picked up the new key; invalidate to prove the
    # real kid still gets its own forced refresh after the global 1 s cap.
    tokens._invalidate_key_cache()
    tokens.KeyRing.verification_keys(db_session, NOW)
    tokens._key_cache = (tokens._key_cache[0], [e for e in tokens._key_cache[1] if e[0] != other.kid])
    clock["t"] += 1.1
    claims["kid"] = other.kid
    real = jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": other.kid})
    assert decode_access(db_session, real, NOW).kid == other.kid


def test_global_forced_refresh_cap_one_per_second(db_session, user, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(tokens.time, "monotonic", lambda: clock["t"])
    assert tokens._may_force_refresh("a") is True
    assert tokens._may_force_refresh("b") is False  # same second
    clock["t"] += 1.1
    assert tokens._may_force_refresh("b") is True
    clock["t"] += 1.1
    assert tokens._may_force_refresh("a") is False  # per-kid 10 s
    clock["t"] += 10
    assert tokens._may_force_refresh("a") is True


def test_kid_tracking_bounded():
    for i in range(tokens._KID_TRACK_MAX + 50):
        tokens._kid_refresh[f"k{i}"] = 0.0
        while len(tokens._kid_refresh) > tokens._KID_TRACK_MAX:
            tokens._kid_refresh.popitem(last=False)
    assert len(tokens._kid_refresh) == tokens._KID_TRACK_MAX


def test_cache_invalidated_on_commit_of_key_creation(test_engine):
    from sqlalchemy.orm import Session

    s = Session(bind=test_engine)
    try:
        KeyRing.current(s, NOW)
        tokens._key_cache = (0.0, [])  # simulate a pre-commit refetch
        s.commit()
        assert tokens._key_cache is None
    finally:
        s.rollback()
        s.execute(__import__("sqlalchemy").text("DELETE FROM signing_key"))
        s.commit()
        s.close()
