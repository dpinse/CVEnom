"""Delivery sink protocol shared by the dispatcher and the email/webhook sinks."""

from __future__ import annotations

import html
from typing import Protocol

from cvenom.models import AlertDelivery, AlertRecipient, AlertRule, Cve


class SinkError(Exception):
    """Delivery failed. The message must be secret-free."""


class SinkNotConfigured(SinkError):
    """The channel is not configured; the delivery stays pending and is retried later."""


class Sink(Protocol):
    def send(self, delivery: AlertDelivery, cve: Cve, rule: AlertRule,
             recipient: AlertRecipient) -> None: ...


SUMMARY_MAX = 2000


def clean_summary(text: str | None) -> str:
    """Stored summaries are HTML-escaped; decode exactly once and cap the length."""
    return html.unescape(text or "")[:SUMMARY_MAX]


def build_sinks() -> dict[str, Sink]:
    """Registry of live sinks by channel."""
    from cvenom.alerts.email import EmailSink
    from cvenom.alerts.webhook import WebhookSink

    return {"email": EmailSink(), "webhook": WebhookSink()}
