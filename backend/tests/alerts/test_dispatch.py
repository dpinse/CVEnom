import base64
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from cvenom import secretbox
from cvenom.alerts.dispatch import dispatch_once
from cvenom.alerts.sinks import SinkError, SinkNotConfigured
from cvenom.models import AlertDelivery, AlertEvent, AlertRecipient, AlertRule, Cve

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
CVE = "CVE-2099-0001"


@pytest.fixture(autouse=True)
def _secrets_key(monkeypatch):
    from cvenom.config import get_settings

    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def factory(db_session):
    @contextmanager
    def f():
        yield db_session
        db_session.flush()
    return f


class FakeSink:
    def __init__(self, exc=None):
        self.exc = exc
        self.calls = []

    def send(self, delivery, cve, rule, recipient):
        self.calls.append((delivery.id, cve.cve_id, rule.id, recipient.id))
        if self.exc is not None:
            raise self.exc


def _cve(s, cve_id=CVE, **kw):
    kw.setdefault("summary", "s")
    c = Cve(cve_id=cve_id, **kw)
    s.add(c)
    s.flush()
    return c


def _rule(s, kind="kev_added", n_email=1, n_hook=0, **kw):
    r = AlertRule(name="r", kind=kind, **kw)
    s.add(r)
    s.flush()
    recs = [AlertRecipient(rule_id=r.id, channel="email", email=f"a{i}@x.io") for i in range(n_email)]
    recs += [AlertRecipient(rule_id=r.id, channel="webhook",
                            webhook_url=secretbox.encrypt(b"https://hooks.example.com/T123/SECRETPATH"),
                            webhook_secret_enc=secretbox.encrypt(b"s3cr3t-value"))
             for _ in range(n_hook)]
    s.add_all(recs)
    s.flush()
    return r, recs


def _event(s, cve_id=CVE, type="kev_added", source="cisa_kev"):
    e = AlertEvent(type=type, cve_id=cve_id, source=source)
    s.add(e)
    s.flush()
    return e


def _deliveries(s):
    return s.scalars(select(AlertDelivery).order_by(AlertDelivery.id)).all()


def test_kev_event_two_recipients_sent(db_session, factory):
    _cve(db_session)
    _rule(db_session, n_email=2)
    _event(db_session)
    sink = FakeSink()
    out = dispatch_once(factory, NOW, {"email": sink})
    assert out == {"events": 1, "deliveries_created": 2, "sent": 2, "failed": 0, "retry": 0, "deferred": 0}
    ds = _deliveries(db_session)
    assert [d.status for d in ds] == ["sent", "sent"]
    assert all(d.sent_at == NOW and d.last_error is None for d in ds)
    assert len(sink.calls) == 2
    ev = db_session.scalars(select(AlertEvent)).one()
    assert ev.processed_at == NOW


def test_naive_now_rejected(factory):
    with pytest.raises(ValueError):
        dispatch_once(factory, datetime(2026, 1, 1), {})


def test_same_cve_other_source_dedupes(db_session, factory):
    _cve(db_session)
    _rule(db_session, n_email=2)
    _event(db_session, source="cisa_kev")
    sink = FakeSink()
    dispatch_once(factory, NOW, {"email": sink})
    _event(db_session, source="vulncheck_kev")
    out = dispatch_once(factory, NOW + timedelta(minutes=1), {"email": sink})
    assert out["events"] == 1 and out["deliveries_created"] == 0 and out["sent"] == 0
    assert len(_deliveries(db_session)) == 2
    assert len(sink.calls) == 2


def test_disabled_rule_produces_nothing(db_session, factory):
    _cve(db_session)
    r, _ = _rule(db_session)
    r.enabled = False
    _event(db_session)
    out = dispatch_once(factory, NOW, {"email": FakeSink()})
    assert out["events"] == 1 and out["deliveries_created"] == 0
    assert _deliveries(db_session) == []


@pytest.mark.parametrize("kind,field,threshold,value,expected", [
    ("cvss_min", "cvss", 7.0, 7.0, 1),
    ("cvss_min", "cvss", 7.0, 6.9, 0),
    ("cvss_min", "cvss", 7.0, None, 0),
    ("epss_min", "epss_percentile", 0.9, 0.95, 1),
    ("epss_min", "epss_percentile", 0.9, 0.5, 0),
    ("epss_min", "epss_percentile", 0.9, None, 0),
])
def test_threshold_rules(db_session, factory, kind, field, threshold, value, expected):
    _cve(db_session, **{field: value})
    _rule(db_session, kind=kind, threshold=threshold)
    _event(db_session)
    out = dispatch_once(factory, NOW, {"email": FakeSink()})
    assert out["deliveries_created"] == expected


def test_keyword_matches_entity_escaped_summary(db_session, factory):
    _cve(db_session, summary="Flaw in &lt;Apache&gt; Struts &amp; more")
    _rule(db_session, kind="keyword", keyword="<apache>")
    _event(db_session)
    assert dispatch_once(factory, NOW, {"email": FakeSink()})["deliveries_created"] == 1


def test_keyword_matches_affected_and_nonmatch(db_session, factory):
    _cve(db_session, summary="nothing", affected=["Vendor:WidgetPro 1.2", {"p": "x"}])
    _rule(db_session, kind="keyword", keyword="widgetpro")
    _rule(db_session, kind="keyword", keyword="absent")
    _event(db_session)
    assert dispatch_once(factory, NOW, {"email": FakeSink()})["deliveries_created"] == 1


def test_event_without_cve_id_processed_no_deliveries(db_session, factory):
    _rule(db_session)
    _event(db_session, cve_id=None)
    out = dispatch_once(factory, NOW, {"email": FakeSink()})
    assert out["events"] == 1 and out["deliveries_created"] == 0
    assert db_session.scalars(select(AlertEvent)).one().processed_at == NOW


def test_non_kev_event_processed_no_deliveries(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session, type="other")
    out = dispatch_once(factory, NOW, {"email": FakeSink()})
    assert out["events"] == 1 and out["deliveries_created"] == 0


def test_missing_cve_row_processed_with_warning(db_session, factory, caplog):
    _rule(db_session)
    _event(db_session, cve_id="CVE-2099-9999")
    with caplog.at_level("WARNING", logger="cvenom.alerts.dispatch"):
        out = dispatch_once(factory, NOW, {"email": FakeSink()})
    assert out["events"] == 1 and out["deliveries_created"] == 0
    assert "missing CVE" in caplog.text
    assert db_session.scalars(select(AlertEvent)).one().processed_at == NOW


def test_processed_events_not_reprocessed(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    dispatch_once(factory, NOW, {"email": FakeSink()})
    assert dispatch_once(factory, NOW, {"email": FakeSink()})["events"] == 0


def test_core_insert_uses_server_defaults(db_session):
    _cve(db_session)
    r, recs = _rule(db_session)
    e = _event(db_session)
    db_session.execute(insert(AlertDelivery).values(
        event_id=e.id, rule_id=r.id, recipient_id=recs[0].id, cve_id=CVE))
    d = db_session.scalars(select(AlertDelivery)).one()
    assert d.status == "pending" and d.attempts == 0 and d.created_at is not None
    assert d.next_attempt_at is None


def test_failure_backoff_retry_then_failed_on_sixth(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    sink = FakeSink(SinkError("boom"))
    now = NOW
    out = dispatch_once(factory, now, {"email": sink})
    assert out["retry"] == 1 and out["sent"] == 0
    d = _deliveries(db_session)[0]
    assert (d.attempts, d.status, d.next_attempt_at) == (1, "pending", now + timedelta(minutes=2))
    assert d.last_error == "boom"

    # backoff not yet elapsed: not attempted
    out = dispatch_once(factory, now + timedelta(minutes=1), {"email": sink})
    assert out["retry"] == 0 and len(sink.calls) == 1

    now = now + timedelta(minutes=2)
    dispatch_once(factory, now, {"email": sink})
    d = _deliveries(db_session)[0]
    assert (d.attempts, d.next_attempt_at) == (2, now + timedelta(minutes=4))

    for expected in (3, 4, 5):
        now = d.next_attempt_at
        out = dispatch_once(factory, now, {"email": sink})
        d = _deliveries(db_session)[0]
        assert d.attempts == expected and d.status == "pending" and out["retry"] == 1
    now = d.next_attempt_at
    out = dispatch_once(factory, now, {"email": sink})
    d = _deliveries(db_session)[0]
    assert d.attempts == 6 and d.status == "failed" and out["failed"] == 1
    # failed rows are never retried
    assert dispatch_once(factory, now + timedelta(days=1), {"email": sink})["failed"] == 0
    assert len(sink.calls) == 6


def test_retry_after_backoff_succeeds(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    dispatch_once(factory, NOW, {"email": FakeSink(SinkError("x"))})
    out = dispatch_once(factory, NOW + timedelta(minutes=2), {"email": FakeSink()})
    assert out["sent"] == 1
    d = _deliveries(db_session)[0]
    assert d.status == "sent" and d.attempts == 1 and d.last_error is None


def test_unexpected_sink_exception_counts_as_failure(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    out = dispatch_once(factory, NOW, {"email": FakeSink(RuntimeError("kaput"))})
    assert out["retry"] == 1
    assert _deliveries(db_session)[0].attempts == 1


def test_last_error_truncated_and_scrubbed(db_session, factory):
    _cve(db_session)
    _rule(db_session, n_email=0, n_hook=1)
    _event(db_session)
    msg = ("connect failed https://hooks.example.com/T123/SECRETPATH secret=s3cr3t-value /T123/SECRETPATH "
           + "x" * 1000)
    dispatch_once(factory, NOW, {"webhook": FakeSink(SinkError(msg))})
    err = _deliveries(db_session)[0].last_error
    assert len(err) == 300
    for leaked in ("s3cr3t-value", "hooks.example.com/T123", "SECRETPATH"):
        assert leaked not in err
    assert "[redacted]" in err


def test_scrub_survives_undecryptable_credentials(db_session, factory):
    _cve(db_session)
    r, recs = _rule(db_session, n_email=0, n_hook=1)
    recs[0].webhook_secret_enc = "garbage"
    db_session.flush()
    _event(db_session)
    dispatch_once(factory, NOW, {"webhook": FakeSink(SinkError("plain"))})
    assert _deliveries(db_session)[0].last_error == "plain"


@pytest.mark.parametrize("sinks", [{}, {"email": FakeSink(SinkNotConfigured("no smtp"))}])
def test_missing_or_unconfigured_sink_defers(db_session, factory, sinks):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    out = dispatch_once(factory, NOW, sinks)
    assert out["deferred"] == 1 and out["sent"] == 0 and out["retry"] == 0
    d = _deliveries(db_session)[0]
    assert d.status == "pending" and d.attempts == 0
    assert d.next_attempt_at == NOW + timedelta(hours=1)
    # not re-tried within the hour; picked up afterwards
    assert dispatch_once(factory, NOW + timedelta(minutes=30), {"email": FakeSink()})["sent"] == 0
    assert dispatch_once(factory, NOW + timedelta(hours=1), {"email": FakeSink()})["sent"] == 1


def test_non_pending_delivery_ignored(db_session, factory):
    _cve(db_session)
    _rule(db_session)
    _event(db_session)
    dispatch_once(factory, NOW, {})  # creates a pending delivery, deferred
    d = _deliveries(db_session)[0]
    d.status = "sent"
    db_session.flush()
    sink = FakeSink()
    out = dispatch_once(factory, NOW + timedelta(hours=2), {"email": sink})
    assert out["sent"] == 0 and sink.calls == []


def test_sql_uses_skip_locked():
    # Both row-claim queries must carry FOR UPDATE SKIP LOCKED (also exercised for real below).
    import inspect

    from cvenom.alerts import dispatch
    src = inspect.getsource(dispatch)
    assert src.count("with_for_update(skip_locked=True)") == 2


def test_concurrent_dispatchers_do_not_double_process(test_engine):
    """Real two-connection SKIP LOCKED test on committed data; cleaned up in finally."""
    @contextmanager
    def real_factory():
        s = Session(test_engine)
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    try:
        with real_factory() as s:
            _cve(s, cve_id="CVE-2099-7777")
            _rule(s)
            _event(s, cve_id="CVE-2099-7777")
        sink = FakeSink()
        holder = Session(test_engine)
        try:
            # Dispatcher A is mid-evaluate: it holds the row lock on the event.
            held = holder.scalars(select(AlertEvent).where(AlertEvent.processed_at.is_(None))
                                  .with_for_update(skip_locked=True)).all()
            assert len(held) == 1
            out_b = dispatch_once(real_factory, NOW, {"email": sink})
            assert out_b["events"] == 0 and out_b["deliveries_created"] == 0
            assert sink.calls == []
        finally:
            holder.rollback()
            holder.close()
        out = dispatch_once(real_factory, NOW, {"email": sink})
        assert out["events"] == 1 and out["sent"] == 1
        assert dispatch_once(real_factory, NOW, {"email": sink})["events"] == 0
        assert len(sink.calls) == 1
    finally:
        with real_factory() as s:
            s.execute(delete(AlertEvent))
            s.execute(delete(AlertRule))
            s.execute(delete(Cve).where(Cve.cve_id == "CVE-2099-7777"))
