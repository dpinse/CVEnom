"""OSV collector (covers GHSA): patch availability and affected packages."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from cvenom.collectors import base
from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_json,
    http_get_text,
    register,
)
from cvenom.schemas import NormalizedCve

log = logging.getLogger(__name__)

INDEX_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
MAX_IDS = 1000
DEFAULT_WINDOW = timedelta(days=7)
REQUEST_DELAY = 0.1


async def _sleep(delay: float) -> None:
    # Resolved through base at call time so tests can patch it.
    await base._sleep(delay)


def _parse_ts(text: str) -> datetime:
    ts = datetime.fromisoformat(text.strip())
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def parse_index(text: str, since: datetime) -> list[str]:
    """Return unique OSV ids modified at/after since (index is newest first)."""
    if since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    ids: list[str] = []
    seen: set[str] = set()
    malformed = 0
    for line in text.splitlines():
        ts_text, sep, key = line.partition(",")
        if not sep or not key.strip():
            malformed += 1
            continue
        try:
            ts = _parse_ts(ts_text)
        except ValueError:
            malformed += 1
            continue
        if ts < since:
            break
        vuln_id = key.strip().rsplit("/", 1)[-1]
        if not vuln_id or vuln_id in seen:
            continue
        if len(ids) >= MAX_IDS:
            log.warning("osv: capped at %d ids; older ids not processed this run", MAX_IDS)
            break
        seen.add(vuln_id)
        ids.append(vuln_id)
    if malformed:
        log.warning("osv: skipped %d malformed index line(s)", malformed)
    return ids


@register
class OsvCollector(Collector):
    name = "osv"
    cadence_seconds = 7200
    # Updates existing CVE rows only; never creates new ones.
    enrich_only = True

    async def fetch(self, since: datetime | None = None) -> list[dict]:
        cutoff = since or self.since or datetime.now(UTC) - DEFAULT_WINDOW
        ids = parse_index(await http_get_text(INDEX_URL), cutoff)
        records: list[dict] = []
        for i, vuln_id in enumerate(ids):
            if i:
                await _sleep(REQUEST_DELAY)
            try:
                rec = await http_get_json(VULN_URL.format(id=vuln_id))
            except Exception as exc:
                log.warning("osv: failed to fetch %s: %s", vuln_id, exc)
                continue
            if isinstance(rec, dict):
                records.append(rec)
        return records

    def normalize(self, raw: list[dict]) -> CollectorResult:
        cves: list[NormalizedCve] = []
        for rec in raw:
            try:
                own = rec.get("id")
                cve_ids = [a for a in rec.get("aliases") or [] if str(a).startswith("CVE-")]
                if isinstance(own, str) and own.startswith("CVE-") and own not in cve_ids:
                    cve_ids.append(own)
                if not cve_ids:
                    continue
                patch = False
                affected: list[str] = []
                for aff in rec.get("affected") or []:
                    pkg = aff.get("package") or {}
                    if pkg.get("name"):
                        label = f"{pkg.get('ecosystem', '')}:{pkg['name']}"
                        if label not in affected:
                            affected.append(label)
                    for rng in aff.get("ranges") or []:
                        if any("fixed" in ev for ev in rng.get("events") or []):
                            patch = True
                for cve_id in dict.fromkeys(cve_ids):
                    cves.append(
                        NormalizedCve(cve_id=cve_id, patch_available=patch, affected=list(affected))
                    )
            except (AttributeError, TypeError, ValueError):  # incl. ValidationError
                rid = rec.get("id") if isinstance(rec, dict) else "?"
                log.warning("osv: skipping malformed record %s", rid)
        return CollectorResult(cves=cves)
