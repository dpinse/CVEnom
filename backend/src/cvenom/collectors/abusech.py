"""abuse.ch botnet C2 collector: Feodo Tracker (keyless) and ThreatFox (needs an Auth-Key).

Feodo: GET ipblocklist.json returns a list of C2 records with a country field.
ThreatFox: POST get_iocs; only runs when ABUSECH_AUTH_KEY is configured. The key is sent
only as a header and never logged.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_json,
    http_post_json,
    register,
)
from cvenom.config import get_settings
from cvenom.geoip import GeoIP
from cvenom.schemas import COUNTRY_RE, NormalizedGeoEvent

log = logging.getLogger(__name__)

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
_SKIP = (ValidationError, ValueError, TypeError, AttributeError, KeyError, OverflowError, OSError)


def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4]
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _valid_cc(value: object) -> str | None:
    if isinstance(value, str) and COUNTRY_RE.fullmatch(value.upper()):
        return value.upper()
    return None


def _str_or_none(value: object) -> str | None:
    return str(value) if isinstance(value, str) else None


def _int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


@register
class AbuseChCollector(Collector):
    name = "abusech"
    cadence_seconds = 3600

    geoip_factory = staticmethod(lambda: GeoIP.open(get_settings().geoip_dir))

    def __init__(self, since=None, state=None) -> None:
        super().__init__(since, state)
        self._geo = None
        self._geo_tried = False

    def _lookup_country(self, ip: str) -> str | None:
        if not self._geo_tried:
            self._geo_tried = True
            try:
                self._geo = self.geoip_factory()
            except Exception:
                log.warning("%s: GeoIP factory failed", self.name, exc_info=True)
        if self._geo is None:
            return None
        hit = self._geo.lookup(ip)
        return _valid_cc(hit.country_code) if hit else None

    async def run(self) -> CollectorResult:
        self._geo, self._geo_tried = None, False
        try:
            return await super().run()
        finally:
            geo, self._geo = self._geo, None
            if geo is not None:
                geo.close()

    async def fetch(self) -> dict:
        feodo = await http_get_json(FEODO_URL, max_bytes=5_000_000)
        tf = None
        key = get_settings().abusech_auth_key
        if key is None:
            log.debug("%s: no auth key; skipping ThreatFox", self.name)
        else:
            tf = await http_post_json(
                TF_URL,
                json_body={"query": "get_iocs", "days": 1},
                headers={"Auth-Key": key.get_secret_value()},
            )
        return {"feodo": feodo, "threatfox": tf}

    def normalize(self, raw: dict) -> CollectorResult:
        feodo = raw["feodo"]
        if not isinstance(feodo, list):
            raise ValueError(f"{self.name}: unexpected Feodo response shape {type(feodo).__name__}")
        events = self._feodo(feodo)
        if raw["threatfox"] is not None:
            events += self._threatfox(raw["threatfox"])
        return CollectorResult(geo_events=events)

    def _feodo(self, records: list) -> list[NormalizedGeoEvent]:
        events: list[NormalizedGeoEvent] = []
        for rec in records:
            try:
                ip = str(ipaddress.ip_address(rec["ip_address"]))
                port = rec["port"]
                if isinstance(port, bool) or not isinstance(port, int):
                    raise TypeError("bad port")
                observed = _parse_dt(rec.get("last_online")) or _parse_dt(rec.get("first_seen"))
                if observed is None:
                    raise ValueError("no parseable date")
                cc = _valid_cc(rec.get("country")) or self._lookup_country(ip)
                malware = rec.get("malware")
                events.append(
                    NormalizedGeoEvent(
                        source="feodo",
                        external_id=f"{ip}:{port}",
                        kind="c2",
                        country_code=cc,
                        asn=_int(rec.get("as_number")),
                        observed_at=observed,
                        magnitude=2.0 if rec.get("status") == "online" else 1.0,
                        label=f"{malware} C2" if malware else "Botnet C2",
                        details={
                            "status": _str_or_none(rec.get("status")),
                            "port": port,
                            "as_name": _str_or_none(rec.get("as_name")),
                        },
                    )
                )
            except _SKIP as exc:
                log.warning("%s: skipping bad Feodo record: %s", self.name, exc)
        return events

    def _threatfox(self, resp: object) -> list[NormalizedGeoEvent]:
        if not isinstance(resp, dict):
            raise ValueError(f"{self.name}: unexpected ThreatFox response shape")
        status = resp.get("query_status")
        if status == "no_result":
            return []
        if status != "ok":
            raise ValueError(f"{self.name}: ThreatFox query_status {status!r}")
        events: list[NormalizedGeoEvent] = []
        for ioc in resp.get("data") or []:
            try:
                if ioc.get("ioc_type") != "ip:port":
                    continue
                host, _, port = ioc["ioc"].rpartition(":")
                if not port.isdigit():
                    raise ValueError("bad port")
                ip = ipaddress.ip_address(host.strip("[]"))
                if not ip.is_global:
                    continue
                observed = _parse_dt(ioc.get("first_seen"))
                if observed is None:
                    raise ValueError("no parseable date")
                conf = ioc.get("confidence_level")
                if (
                    isinstance(conf, bool)
                    or not isinstance(conf, (int, float))
                    or not math.isfinite(conf)
                    or not 0 <= conf <= 100
                ):
                    conf = None
                tags = ioc.get("tags")
                tags = [t for t in tags if isinstance(t, str)][:10] if isinstance(tags, list) else []
                name = ioc.get("malware_printable") or ioc.get("malware")
                events.append(
                    NormalizedGeoEvent(
                        source="threatfox",
                        external_id=str(ioc["id"]),
                        kind="c2",
                        country_code=self._lookup_country(str(ip)),
                        observed_at=observed,
                        label=f"{name} C2" if name else "Botnet C2",
                        details={
                            "threat_type": _str_or_none(ioc.get("threat_type")),
                            "confidence": conf,
                            "tags": tags,
                        },
                    )
                )
            except _SKIP as exc:
                log.warning("%s: skipping bad ThreatFox IOC: %s", self.name, exc)
        return events
