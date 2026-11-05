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
from cvenom.schemas import CVE_ID_RE, NormalizedCve

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

    @staticmethod
    def _cve_ids(rec: dict) -> list[str]:
        """Valid, normalized CVE ids from the record's aliases and its own id."""
        own = rec.get("id")
        aliases = rec.get("aliases") or []
        if not isinstance(aliases, list):
            raise TypeError("aliases is not a list")
        candidates = [a for a in aliases if isinstance(a, str)]
        if isinstance(own, str):
            candidates.append(own)
        ids: list[str] = []
        for cand in candidates:
            norm = cand.strip().upper()
            if not norm.startswith("CVE-"):
                continue
            if not CVE_ID_RE.fullmatch(norm):
                log.warning("osv: skipping invalid cve alias %r in %s", cand, own)
                continue
            if norm not in ids:
                ids.append(norm)
        return ids

    @staticmethod
    def _signals(rec: dict) -> tuple[bool, list[str]]:
        """(patch available, affected package labels) for one OSV record."""
        patch = False
        affected: list[str] = []
        for aff in rec.get("affected") or []:
            pkg = aff.get("package") or {}
            if pkg.get("name"):
                label = f"{pkg.get('ecosystem', '')}:{pkg['name']}"
                if label not in affected:
                    affected.append(label)
            for rng in aff.get("ranges") or []:
                events = rng.get("events") or []
                if any(isinstance(ev, dict) and "fixed" in ev for ev in events):
                    patch = True
        return patch, affected

    def normalize(self, raw: list[dict]) -> CollectorResult:
        # Several OSV records (GHSA, PYSEC, GO, ...) can describe one CVE: aggregate
        # per CVE across the run so the result is order-independent.
        patch_by_cve: dict[str, bool] = {}
        affected_by_cve: dict[str, list[str]] = {}
        for rec in raw:
            try:
                if not isinstance(rec, dict):
                    raise TypeError("record is not an object")
                cve_ids = self._cve_ids(rec)
                if not cve_ids:
                    continue
                patch, affected = self._signals(rec)
            except (AttributeError, TypeError, ValueError):
                rid = rec.get("id") if isinstance(rec, dict) else "?"
                log.warning("osv: skipping malformed record %s", rid)
                continue
            for cve_id in cve_ids:
                patch_by_cve[cve_id] = patch_by_cve.get(cve_id, False) or patch
                merged = affected_by_cve.setdefault(cve_id, [])
                merged.extend(a for a in affected if a not in merged)
        cves = [
            NormalizedCve(cve_id=cve_id, patch_available=patch, affected=affected_by_cve[cve_id])
            for cve_id, patch in patch_by_cve.items()
        ]
        return CollectorResult(cves=cves)
