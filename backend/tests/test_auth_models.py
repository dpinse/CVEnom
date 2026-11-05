import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from cvenom.models import (
    AlertDelivery,
    AlertEvent,
    AlertRecipient,
    AlertRule,
    Invite,
    SigningKey,
    User,
    UserSession,
)


def test_user_email_normalized_on_set():
    assert User(email="  A@B.Com ").email == "a@b.com"
    assert Invite(email=" Z@Q.ORG ").email == "z@q.org"


def test_user_email_unique_case_insensitive(db_session):
    db_session.add(User(email="X@Y.com", password_hash="h", role="member"))
    db_session.flush()
    db_session.add(User(email="x@y.com", password_hash="h", role="member"))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_user_defaults(db_session):
    u = User(email="d@e.com", password_hash="h", role="admin")
    db_session.add(u)
    db_session.flush()
    assert u.is_active is True and u.created_at is not None


@pytest.mark.parametrize("role", ["root", ""])
def test_invalid_role_rejected(db_session, role):
    db_session.add(User(email="r@e.com", password_hash="h", role=role))
    with pytest.raises(IntegrityError):
        db_session.flush()


def _rule_recipient_event(db_session):
    rule = AlertRule(name="r", kind="kev_added")
    ev = AlertEvent(type="kev_added", cve_id="CVE-2024-0001", source="t")
    db_session.add_all([rule, ev])
    db_session.flush()
    rec = AlertRecipient(rule_id=rule.id, channel="email", email="a@b.com")
    db_session.add(rec)
    db_session.flush()
    return rule, rec, ev


def test_invalid_status_kind_channel_rejected(db_session):
    rule, rec, ev = _rule_recipient_event(db_session)
    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(AlertDelivery(event_id=ev.id, rule_id=rule.id, recipient_id=rec.id,
                                         cve_id="CVE-2024-0001", status="bogus"))
    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(AlertRule(name="x", kind="nope"))
    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(AlertRecipient(rule_id=rule.id, channel="sms"))


def test_delivery_defaults_and_dedupe(db_session):
    rule, rec, ev = _rule_recipient_event(db_session)
    d = AlertDelivery(event_id=ev.id, rule_id=rule.id, recipient_id=rec.id, cve_id="CVE-2024-0001")
    db_session.add(d)
    db_session.flush()
    assert d.status == "pending" and d.attempts == 0 and d.next_attempt_at is None
    assert rule.enabled is True and ev.payload == {} and ev.processed_at is None
    db_session.add(AlertDelivery(event_id=ev.id, rule_id=rule.id, recipient_id=rec.id,
                                 cve_id="CVE-2024-0001"))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_session_signing_key_invite_roundtrip(db_session):
    u = User(email="s@e.com", password_hash="h", role="member")
    db_session.add(u)
    db_session.flush()
    s = UserSession(user_id=u.id, refresh_hash="a" * 64, expires_at=u.created_at)
    inv = Invite(email="i@e.com", role="member", token_hash="b" * 64, expires_at=u.created_at,
                 created_by=u.id)
    db_session.add_all([s, inv, SigningKey(kid="k1", private_enc="enc", public_pem="pem")])
    db_session.flush()
    assert isinstance(s.id, uuid.UUID) and s.created_at is not None and s.revoked_at is None


def test_email_normalizer_none_safe():
    assert User(email=None).email is None
    assert Invite(email=None).email is None


@pytest.mark.parametrize("table", ["app_user", "invite"])
def test_raw_mixed_case_email_rejected(db_session, table):
    from sqlalchemy import text

    if table == "app_user":
        sql = "INSERT INTO app_user (email, password_hash, role) VALUES ('Mixed@Case.com', 'h', 'member')"
    else:
        sql = (
            "INSERT INTO invite (email, role, token_hash, expires_at) "
            "VALUES ('Mixed@Case.com', 'member', 'abc', now())"
        )
    with pytest.raises(IntegrityError):
        db_session.execute(text(sql))
