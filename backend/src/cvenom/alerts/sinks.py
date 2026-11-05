"""Delivery sink protocol shared by the dispatcher and the email/webhook sinks."""

from __future__ import annotations

from typing import Protocol

from cvenom.models import AlertDelivery, AlertRecipient, AlertRule, Cve


class SinkError(Exception):
    """Delivery failed. The message must be secret-free."""


class SinkNotConfigured(SinkError):
    """The channel is not configured; the delivery stays pending and is retried later."""


class Sink(Protocol):
    def send(self, delivery: AlertDelivery, cve: Cve, rule: AlertRule,
             recipient: AlertRecipient) -> None: ...


def build_sinks() -> dict[str, Sink]:
    """Registry of live sinks by channel. Task 12 registers email and webhook."""
    return {}
