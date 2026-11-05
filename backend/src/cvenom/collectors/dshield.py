"""DShield (SANS ISC) top scan sources, geolocated locally and aggregated by country.

Verified: GET /api/sources/attacks/100/?json returns a JSON list of
{ip, attacks, count, firstseen, lastseen}; there is no country field, so we geolocate
each IP with the local GeoIP database.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
from cvenom.config import get_settings
from cvenom.geoip import GeoIP
from cvenom.schemas import NormalizedGeoEvent

log = logging.getLogger(__name__)

URL = "https://isc.sans.edu/api/sources/attacks/100/?json"
_SKIP = (ValidationError, ValueError, TypeError, AttributeError, KeyError, OverflowError)


def _now() -> datetime:
    return datetime.now(UTC)


def _clean_ip(ip: object) -> str:
    """Strip leading zeros from dotted-quad octets ("079.124.059.078" -> "79.124.59.78")."""
    if not isinstance(ip, str):
        raise TypeError("ip is not a string")
    parts = ip.strip().split(".")
    if len(parts) == 4 and all(p.isascii() and p.isdigit() for p in parts):
        return ".".join(str(int(p)) for p in parts)
    return ip.strip()


def _num(value: object) -> int:
    if isinstance(value, bool):
        raise TypeError("bool is not a count")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite count")
    n = int(value)  # type: ignore[arg-type]
    if n < 0:
        raise ValueError("negative count")
    return n


@register
class DShieldCollector(Collector):
    name = "dshield"
    cadence_seconds = 3600

    geoip_factory = staticmethod(lambda: GeoIP.open(get_settings().geoip_dir))

    def __init__(self, since=None, state=None) -> None:
        super().__init__(since, state)
        self._geo = None

    async def run(self) -> CollectorResult:
        try:
            geo = self.geoip_factory()
        except Exception:
            log.warning("%s: GeoIP factory failed", self.name, exc_info=True)
            geo = None
        if geo is None:
            self.last_error = None
            log.warning("%s: no GeoIP database available; skipping", self.name)
            return CollectorResult()
        self._geo = geo
        try:
            return await super().run()
        finally:
            self._geo = None
            geo.close()

    async def fetch(self) -> list:
        return await http_get_json(URL, max_bytes=2_000_000)

    def normalize(self, raw) -> CollectorResult:
        if not isinstance(raw, list):
            raise ValueError(f"{self.name}: unexpected response shape {type(raw).__name__}")
        if self._geo is None:
            raise RuntimeError(f"{self.name}: GeoIP not available")
        agg: dict[str, list[int]] = {}  # cc -> [magnitude, sources, targets]
        for rec in raw:
            try:
                ip = _clean_ip(rec["ip"])
                count = _num(rec["count"])
                attacks = _num(rec["attacks"])
                hit = self._geo.lookup(ip)
            except _SKIP as exc:
                log.warning("%s: skipping bad record: %s", self.name, exc)
                continue
            if hit is None or not hit.country_code:
                continue
            a = agg.setdefault(hit.country_code, [0, 0, 0])
            a[0] += count
            a[1] += 1
            a[2] += attacks
        hour = _now().astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        events: list[NormalizedGeoEvent] = []
        for cc, (magnitude, sources, targets) in sorted(agg.items()):
            try:
                events.append(
                    NormalizedGeoEvent(
                        source="dshield",
                        external_id=f"{cc}:{hour:%Y-%m-%dT%H}",
                        kind="scan",
                        country_code=cc,
                        observed_at=hour,
                        magnitude=magnitude,
                        label=f"{sources} scanning sources",
                        details={"sources": sources, "targets": targets},
                    )
                )
            except _SKIP as exc:
                log.warning("%s: skipping country %s: %s", self.name, cc, exc)
        return CollectorResult(geo_events=events)
