"""Alert dispatcher: consume the outbox, fan out deduped deliveries, send with retries."""

from __future__ import annotations

import html
import logging
import time
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from cvenom import secretbox
from cvenom.alerts.sinks import Sink, SinkError, SinkNotConfigured
from cvenom.models import (
    AlertDelivery,
    AlertEvent,
    AlertRecipient,
    AlertRule,
    Cve,
)

log = logging.getLogger(__name__)

EVENT_BATCH = 200
SEND_BATCH = 100
MAX_ATTEMPTS = 6
DEFER = timedelta(hours=1)
EXPIRE_AFTER = timedelta(days=7)
SEND_DEADLINE_S = 90  # keeps a run inside the 120s dispatch lock TTL
ERROR_MAX = 300
DEDUPE_CONSTRAINT = "uq_alert_delivery_rule_recipient_cve"


def _at_least(value: float | None, threshold: float | None) -> bool:
    """Threshold filter for KEV-gated rules: a known score must meet the
    threshold, but an UNKNOWN score (not scored yet) matches, so an exploited
    CVE is alerted on rather than silently dropped."""
    if threshold is None:
        return False  # misconfigured rule
    return value is None or value >= threshold


def _matches(rule: AlertRule, cve: Cve) -> bool:
    # Rules only ever see kev_added events (anti-firehose); kinds narrow them.
    kind = rule.kind
    if kind == "kev_added":
        return True
    if kind == "cvss_min":
        return _at_least(cve.cvss, rule.threshold)
    if kind == "epss_min":
        return _at_least(cve.epss_percentile, rule.threshold)
    if kind == "keyword":
        if not rule.keyword:
            return False
        kw = rule.keyword.casefold()
        if kw in html.unescape(cve.summary or "").casefold():
            return True
        return any(kw in str(item).casefold() for item in (cve.affected or []))
    return False


def _evaluate_batch(session, now: datetime, counts: dict) -> int:
    events = session.scalars(
        select(AlertEvent).where(AlertEvent.processed_at.is_(None))
        .order_by(AlertEvent.id).limit(EVENT_BATCH)
        .with_for_update(skip_locked=True)
    ).all()
    if not events:
        return 0
    rules = session.scalars(select(AlertRule).where(AlertRule.enabled.is_(True)).order_by(AlertRule.id)).all()
    recipients: dict[int, list[AlertRecipient]] = {r.id: [] for r in rules}
    if rules:
        for rec in session.scalars(
            select(AlertRecipient).where(AlertRecipient.rule_id.in_(list(recipients))).order_by(AlertRecipient.id)
        ):
            recipients[rec.rule_id].append(rec)
    for ev in events:
        counts["events"] += 1
        ev.processed_at = now
        if ev.type != "kev_added" or ev.cve_id is None:
            continue
        cve = session.get(Cve, ev.cve_id)
        if cve is None:
            log.warning("alert event %s references missing CVE; marked processed", ev.id)
            continue
        rows = [
            {"event_id": ev.id, "rule_id": rule.id, "recipient_id": rec.id, "cve_id": ev.cve_id}
            for rule in rules if _matches(rule, cve)
            for rec in recipients[rule.id]
        ]
        if rows:
            inserted = session.execute(
                insert(AlertDelivery).values(rows)
                .on_conflict_do_nothing(constraint=DEDUPE_CONSTRAINT)
                .returning(AlertDelivery.id)
            ).all()
            counts["deliveries_created"] += len(inserted)
    session.flush()
    return len(events)


def _decrypt_quiet(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return secretbox.decrypt(token).decode()
    except Exception:
        return None


def _scrub(text: str, recipient: AlertRecipient) -> str:
    """Remove the recipient's decrypted secret and URL (and its path) from text."""
    needles: set[str] = set()
    secret = _decrypt_quiet(recipient.webhook_secret_enc)
    url = _decrypt_quiet(recipient.webhook_url)
    if secret:
        needles.add(secret)
    if url:
        needles.add(url)
        try:
            path = urlsplit(url).path
            if len(path) > 1:
                needles.add(path)
        except ValueError:
            pass
    for needle in sorted(needles, key=len, reverse=True):
        text = text.replace(needle, "[redacted]")
    return text


def error_text(exc: Exception, recipient: AlertRecipient) -> str:
    """The only error string ever stored or returned for a failed send: SinkError
    messages are secret-free by contract and scrubbed again; anything else is
    reduced to its type name (it could carry URLs, headers or credentials)."""
    if isinstance(exc, SinkError):
        return _scrub(str(exc), recipient)[:ERROR_MAX]
    return type(exc).__name__[:ERROR_MAX]


def _send_one(session_factory, delivery_id: int, now: datetime, sinks: dict[str, Sink], counts: dict) -> None:
    with session_factory() as session:
        d = session.scalars(
            select(AlertDelivery).where(AlertDelivery.id == delivery_id)
            .with_for_update(skip_locked=True).execution_options(populate_existing=True)
        ).first()
        if d is None or d.status != "pending":
            return
        # Another run may have retried/deferred it since our candidate query.
        if d.next_attempt_at is not None and d.next_attempt_at > now:
            return
        if d.created_at is not None and d.created_at < now - EXPIRE_AFTER:
            d.status = "failed"
            d.last_error = "expired"
            d.next_attempt_at = None
            counts["failed"] += 1
            return
        recipient = session.get(AlertRecipient, d.recipient_id)
        rule = session.get(AlertRule, d.rule_id)
        cve = session.get(Cve, d.cve_id)
        sink = sinks.get(recipient.channel) if recipient is not None else None
        if (sink is None or recipient is None or rule is None or cve is None
                or not rule.enabled):
            d.next_attempt_at = now + DEFER
            counts["deferred"] += 1
            return
        try:
            sink.send(d, cve, rule, recipient)
        except SinkNotConfigured:
            d.next_attempt_at = now + DEFER
            counts["deferred"] += 1
            return
        except Exception as exc:
            d.attempts += 1
            d.last_error = error_text(exc, recipient)
            if d.attempts >= MAX_ATTEMPTS:
                d.status = "failed"
                d.next_attempt_at = None
                counts["failed"] += 1
            else:
                d.next_attempt_at = now + timedelta(minutes=2 ** d.attempts)
                counts["retry"] += 1
            return
        d.status = "sent"
        d.sent_at = now
        d.last_error = None
        d.next_attempt_at = None
        counts["sent"] += 1


def dispatch_once(session_factory, now: datetime, sinks: dict[str, Sink], *,
                  monotonic=time.monotonic) -> dict:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    counts = {"events": 0, "deliveries_created": 0, "sent": 0, "failed": 0, "retry": 0, "deferred": 0}
    started = monotonic()
    try:
        while True:
            with session_factory() as session:
                n = _evaluate_batch(session, now, counts)
            if n < EVENT_BATCH:
                break
    except Exception as exc:
        # Message omitted: it could carry row data. The send stage still runs.
        log.error("alert evaluate stage failed: %s\n%s", type(exc).__name__,
                  "".join(traceback.format_tb(exc.__traceback__)))
    with session_factory() as session:
        ids = list(session.scalars(
            select(AlertDelivery.id)
            .where(AlertDelivery.status == "pending",
                   (AlertDelivery.next_attempt_at.is_(None)) | (AlertDelivery.next_attempt_at <= now))
            .order_by(AlertDelivery.id).limit(SEND_BATCH)
        ))
    for delivery_id in ids:
        if monotonic() - started > SEND_DEADLINE_S:
            log.warning("alert send deadline reached; remaining deliveries wait for the next run")
            break
        _send_one(session_factory, delivery_id, now, sinks, counts)
    return counts
