"""Cloudflare Radar internet outages and BGP hijack events (token-gated).

The endpoints were confirmed from Cloudflare docs and the Go SDK, but the response field
names below were NOT verified against a live response (a token is required). Parsing is
defensive and alias-tolerant; verify the field names against a real response once
CF_RADAR_TOKEN is configured.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
from cvenom.config import get_settings
from cvenom.schemas import COUNTRY_RE, NormalizedGeoEvent

log = logging.getLogger(__name__)

BASE = "https://api.cloudflare.com/client/v4"
OUTAGES_URL = f"{BASE}/radar/annotations/outages"
HIJACKS_URL = f"{BASE}/radar/bgp/hijacks/events"
OUTAGE_PARAMS = {"dateRange": "7d", "format": "json", "limit": 100}
HIJACK_PARAMS = {"dateRange": "7d", "format": "json", "per_page": 100}
_SKIP = (ValidationError, ValueError, TypeError, AttributeError, KeyError, OverflowError, OSError)


def _parse_time(value: object) -> datetime:
    """ISO-8601 (trailing Z ok) or epoch seconds -> aware UTC datetime. Raises ValueError."""
    if isinstance(value, bool):
        raise TypeError("bool is not a timestamp")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("non-finite timestamp")
        secs = value / 1000 if abs(value) > 1e11 else value  # epoch milliseconds
        if not 0 < secs < 4_102_444_800:  # 1970 .. 2100
            raise ValueError("timestamp out of range")
        return datetime.fromtimestamp(secs, UTC)
    if isinstance(value, str) and value.strip():
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    raise ValueError("unparseable timestamp")


def _cc(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    code = value.strip().upper()
    return code if COUNTRY_RE.fullmatch(code) else None


def _codes(*values: object) -> list[str]:
    out: list[str] = []
    for v in values:
        if isinstance(v, list):
            for item in v:
                code = _cc(item)
                if code and code not in out:
                    out.append(code)
    return out


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def _records(envelope: dict, key: str) -> list:
    result = envelope.get("result")
    return _list(result.get(key)) if isinstance(result, dict) else []


def _record_id(value: object) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)) or value == "":
        raise ValueError("record id missing or invalid")
    return value


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


@register
class CloudflareRadarCollector(Collector):
    name = "cf_radar"
    cadence_seconds = 300

    async def run(self) -> CollectorResult:
        if not get_settings().cf_radar_token:
            log.info("%s: no CF_RADAR_TOKEN configured; collector disabled", self.name)
            return CollectorResult()
        return await super().run()

    async def fetch(self) -> dict:
        token = get_settings().cf_radar_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"}
        outages = await http_get_json(
            OUTAGES_URL, headers=headers, params=OUTAGE_PARAMS, max_bytes=5_000_000
        )
        hijacks = await http_get_json(
            HIJACKS_URL, headers=headers, params=HIJACK_PARAMS, max_bytes=5_000_000
        )
        return {"outages": outages, "hijacks": hijacks}

    def normalize(self, raw) -> CollectorResult:
        for part in ("outages", "hijacks"):
            env = raw.get(part) if isinstance(raw, dict) else None
            if not isinstance(env, dict) or env.get("success") is not True:
                raise ValueError(f"{self.name}: unsuccessful or malformed {part} response")
        events: list[NormalizedGeoEvent] = []
        for rec in _records(raw["outages"], "annotations"):
            try:
                events.extend(self._outage(rec))
            except _SKIP as exc:
                log.warning("%s: skipping bad outage record: %s", self.name, exc)
        for rec in _records(raw["hijacks"], "events"):
            try:
                events.extend(self._hijack(rec))
            except _SKIP as exc:
                log.warning("%s: skipping bad hijack record: %s", self.name, exc)
        return CollectorResult(geo_events=events)

    def _outage(self, rec: dict) -> list[NormalizedGeoEvent]:
        oid = _record_id(rec["id"])
        observed = _parse_time(rec["startDate"])
        details_codes = [
            d.get("code") for d in _list(rec.get("locationsDetails")) if isinstance(d, dict)
        ]
        codes = _codes(_list(rec.get("locations")), details_codes)
        if not codes:
            return []
        outage = rec.get("outage") if isinstance(rec.get("outage"), dict) else {}
        cause = _text(outage.get("outageCause"))
        otype = _text(outage.get("outageType"))
        scope = _text(rec.get("scope"))
        label = (cause or scope or _text(rec.get("description")))[:200] or None
        magnitude = min(1.0 + len(_list(rec.get("asns"))), 10.0)
        details = {
            "cause": cause or None,
            "type": otype or None,
            "scope": scope or None,
            "ongoing": rec.get("endDate") is None,
        }
        return [
            NormalizedGeoEvent(
                source=self.name,
                external_id=f"{oid}:{cc}",
                kind="outage",
                country_code=cc,
                observed_at=observed,
                magnitude=magnitude,
                label=label,
                details=details,
            )
            for cc in codes
        ]

    def _hijack(self, rec: dict) -> list[NormalizedGeoEvent]:
        hid = _record_id(rec["id"])
        observed = _parse_time(rec["min_hijack_ts"])
        asn = rec.get("hijacker_asn")
        if isinstance(asn, bool) or not isinstance(asn, int) or asn < 0:
            asn = None
        score = rec.get("confidence_score")
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
            or not 0 <= score <= 10
        ):
            magnitude, confidence = 1.0, None
        else:
            magnitude = confidence = float(score)
        codes = _codes(_list(rec.get("victim_countries")))
        if not codes:
            fallback = _cc(rec.get("hijacker_country"))
            codes = [fallback] if fallback else [None]
        victims = [v for v in _list(rec.get("victim_asns")) if isinstance(v, int)]
        details = {"victim_asns": victims, "confidence": confidence}
        label = f"BGP hijack by AS{asn}" if asn is not None else "BGP hijack"
        return [
            NormalizedGeoEvent(
                source=self.name,
                external_id=f"bgp:{hid}:{cc or '-'}",
                kind="bgp",
                country_code=cc,
                asn=asn,
                observed_at=observed,
                magnitude=magnitude,
                label=label,
                details=details,
            )
            for cc in codes
        ]
