"""OSV collector (covers GHSA): patch availability and affected packages."""

from __future__ import annotations

import logging
import re
from contextlib import aclosing
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from cvenom.collectors import base
from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    ResponseTooLarge,
    http_get_json,
    http_stream_lines,
    register,
)
from cvenom.schemas import CVE_ID_RE, NormalizedCve

log = logging.getLogger(__name__)

INDEX_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
MAX_IDS = 1000
# Byte budget for the streamed index (same as the shared 25 MB response cap).
INDEX_MAX_BYTES = 25_000_000
DEFAULT_WINDOW = timedelta(days=7)
REQUEST_DELAY = 0.1
# A run with more than this share of per-id fetch failures fails as a whole.
MAX_FAILURE_RATIO = 0.2
_ID_RE = re.compile(r"[A-Za-z0-9._:-]+")


async def _sleep(delay: float) -> None:
    # Resolved through base at call time so tests can patch it.
    await base._sleep(delay)


def _parse_ts(text: str) -> datetime:
    ts = datetime.fromisoformat(text.strip())
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _valid_id(vuln_id: str) -> bool:
    # Dot-only ids ("." / "..") pass the character class but are path segments.
    return bool(_ID_RE.fullmatch(vuln_id)) and bool(vuln_id.strip("."))


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


class _IndexScan:
    """Incremental parser for modified_id.csv rows (newest first).

    Ordering assumption: reading stops at the first row older than the cutoff.
    A newer row after that point is never seen (no tolerance window); rows that
    are out of order before it are simply read and kept.

    `backlog` is an earlier run's uncovered span (lo, hi): rows inside it are read
    again even though they are older than `since`; rows between it and `since` were
    covered and are skipped. When the scan stops early (MAX_IDS or the byte budget),
    `truncated` is set and `cursor` is the newest timestamp still owed.
    """

    def __init__(self, since: datetime, backlog: tuple[datetime, datetime] | None = None) -> None:
        self.since = _aware(since)
        self.backlog = backlog
        self.floor = min(self.since, backlog[0]) if backlog else self.since
        self.ids: list[str] = []
        self.malformed = 0
        self.truncated = False
        self.cursor: datetime | None = None  # newest in-range timestamp not known to be covered
        self._seen: set[str] = set()

    def _wanted(self, ts: datetime) -> bool:
        return ts >= self.since or (self.backlog is not None and self.backlog[0] <= ts <= self.backlog[1])

    def feed(self, line: str) -> bool:
        """Consume one row; return False when no further rows are needed."""
        ts_text, sep, key = line.partition(",")
        if not sep or not key.strip():
            self.malformed += 1
            return True
        try:
            ts = _parse_ts(ts_text)
        except ValueError:
            self.malformed += 1
            return True
        if ts < self.floor:
            return False
        if not self._wanted(ts):
            return True
        self.cursor = ts  # rows at this timestamp may still follow
        vuln_id = key.strip().rsplit("/", 1)[-1]
        if not vuln_id or vuln_id in self._seen:
            return True
        if len(self.ids) >= MAX_IDS:
            log.warning("osv: capped at %d ids; older ids not processed this run", MAX_IDS)
            self.truncated = True
            return False
        self._seen.add(vuln_id)
        self.ids.append(vuln_id)
        return True

    def uncovered(self) -> tuple[datetime, datetime] | None:
        """The span a truncated scan still owes (from the oldest cutoff to `cursor`), else None."""
        if not self.truncated:
            return None
        return self.floor, self.cursor or datetime.now(UTC)

    def finish(self) -> list[str]:
        if self.malformed:
            log.warning("osv: skipped %d malformed index line(s)", self.malformed)
        return self.ids


def parse_index(text: str, since: datetime) -> list[str]:
    """Return unique OSV ids modified at/after since (index is newest first)."""
    scan = _IndexScan(since)
    for line in text.splitlines():
        if not scan.feed(line):
            break
    return scan.finish()


async def read_index(since: datetime, backlog: tuple[datetime, datetime] | None = None) -> _IndexScan:
    """Stream the index, stopping at the cutoff, MAX_IDS or the byte budget."""
    scan = _IndexScan(since, backlog)
    try:
        async with aclosing(http_stream_lines(INDEX_URL, max_bytes=INDEX_MAX_BYTES)) as lines:
            async for line in lines:
                if not scan.feed(line):
                    break
    except ResponseTooLarge:
        scan.truncated = True
        log.warning(
            "osv: index byte budget (%d) exhausted before the cutoff; processing the %d ids read",
            INDEX_MAX_BYTES,
            len(scan.ids),
        )
    scan.finish()
    return scan


# Collector state key: [lo, hi] ISO timestamps of index rows a truncated run did not cover.
BACKLOG_KEY = "osv_index_backlog"


def _load_backlog(state: dict) -> tuple[datetime, datetime] | None:
    raw = state.get(BACKLOG_KEY)
    try:
        lo, hi = (_aware(datetime.fromisoformat(v)) for v in raw)
    except (TypeError, ValueError):
        return None
    return (lo, hi) if lo <= hi else None


@register
class OsvCollector(Collector):
    name = "osv"
    cadence_seconds = 7200
    # Updates existing CVE rows only; never creates new ones.
    enrich_only = True

    async def fetch(self, since: datetime | None = None) -> list[dict]:
        cutoff = since or self.since or datetime.now(UTC) - DEFAULT_WINDOW
        # The scheduler advances `since` on every successful run. A truncated scan
        # (MAX_IDS or the byte budget) keeps the span it did not cover in state, so
        # the next run reads it again instead of skipping those ids for good.
        scan = await read_index(cutoff, _load_backlog(self.state))
        if (owed := scan.uncovered()) is not None:
            self.state[BACKLOG_KEY] = [owed[0].isoformat(), owed[1].isoformat()]
        else:
            self.state.pop(BACKLOG_KEY, None)
        ids = []
        for vuln_id in scan.ids:
            if _valid_id(vuln_id):
                ids.append(vuln_id)
            else:
                log.warning("osv: skipping invalid id %r", vuln_id)
        records: list[dict] = []
        failed = 0
        for i, vuln_id in enumerate(ids):
            if i:
                await _sleep(REQUEST_DELAY)
            try:
                rec = await http_get_json(VULN_URL.format(id=quote(vuln_id, safe="")))
            except Exception as exc:
                failed += 1
                log.warning("osv: failed to fetch %s: %s", vuln_id, exc)
                continue
            if isinstance(rec, dict):
                records.append(rec)
        if ids and failed / len(ids) > MAX_FAILURE_RATIO:
            # Fail the run so the window does not advance past the lost ids.
            raise RuntimeError(
                f"osv: {failed}/{len(ids)} vuln fetches failed "
                f"(> {MAX_FAILURE_RATIO:.0%}); not advancing window"
            )
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
    def _versions(rec: dict) -> list[dict]:
        """Affected version ranges from SEMVER/ECOSYSTEM ranges (GIT and `versions` ignored).

        Each ``introduced`` event opens an entry; the next ``fixed`` / ``last_affected`` closes it.
        """
        out: list[dict] = []
        for aff in rec.get("affected") or []:
            pkg = aff.get("package") or {}
            name = pkg.get("name")
            if not isinstance(name, str) or not name:
                continue
            ecosystem = pkg.get("ecosystem")
            for rng in aff.get("ranges") or []:
                if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                current: dict | None = None
                for ev in rng.get("events") or []:
                    if not isinstance(ev, dict):
                        continue
                    if isinstance(ev.get("introduced"), str):
                        if current is not None:
                            out.append(current)
                        intro = ev["introduced"]
                        current = {
                            "product": name,
                            "vendor": None,
                            "ecosystem": ecosystem if isinstance(ecosystem, str) else None,
                            "introduced": None if intro == "0" else intro,
                            "fixed": None,
                            "last_affected": None,
                            "source": "OSV",
                        }
                    elif current is not None:
                        for key in ("fixed", "last_affected"):
                            if isinstance(ev.get(key), str):
                                current[key] = ev[key]
                                out.append(current)
                                current = None
                                break
                if current is not None:
                    out.append(current)
        return out

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
        versions_by_cve: dict[str, list[dict]] = {}
        for rec in raw:
            try:
                if not isinstance(rec, dict):
                    raise TypeError("record is not an object")
                cve_ids = self._cve_ids(rec)
                if not cve_ids:
                    continue
                patch, affected = self._signals(rec)
                versions = self._versions(rec)
            except (AttributeError, TypeError, ValueError):
                rid = rec.get("id") if isinstance(rec, dict) else "?"
                log.warning("osv: skipping malformed record %s", rid)
                continue
            for cve_id in cve_ids:
                patch_by_cve[cve_id] = patch_by_cve.get(cve_id, False) or patch
                merged = affected_by_cve.setdefault(cve_id, [])
                merged.extend(a for a in affected if a not in merged)
                vmerged = versions_by_cve.setdefault(cve_id, [])
                vmerged.extend(v for v in versions if v not in vmerged)
        cves = [
            NormalizedCve(
                cve_id=cve_id,
                patch_available=patch,
                affected=affected_by_cve[cve_id],
                affected_versions=versions_by_cve[cve_id] or None,
            )
            for cve_id, patch in patch_by_cve.items()
        ]
        return CollectorResult(cves=cves)
