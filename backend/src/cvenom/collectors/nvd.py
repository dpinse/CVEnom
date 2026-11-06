"""NVD CVE 2.0 collector."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from cvenom.collectors import base
from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
from cvenom.config import get_settings
from cvenom.schemas import NormalizedCve

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)  # NVD rejects wider date ranges
DELAY_NO_KEY = 6.0
DELAY_WITH_KEY = 0.6


async def _sleep(delay: float) -> None:
    # Resolved through base at call time so tests can patch either module.
    await base._sleep(delay)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _metric(metrics: dict[str, Any]) -> dict[str, Any] | None:
    """The chosen cvssData: V3.1 then V3.0, Primary preferred."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        if data.get("baseScore") is not None:
            return data
    return None


def _tolerant_ts(value: object) -> datetime | None:
    """Like _parse_ts but a malformed or non-str value gives None."""
    if not isinstance(value, str):
        return None
    try:
        return _parse_ts(value)
    except ValueError:
        return None


def _cwes(weaknesses: object) -> list[str] | None:
    vals = [
        d.get("value")
        for w in (weaknesses if isinstance(weaknesses, list) else [])
        if isinstance(w, dict)
        for d in (w.get("description") if isinstance(w.get("description"), list) else [])
        if isinstance(d, dict)
    ]
    return vals or None


def _refs(references: object) -> list[dict[str, Any]] | None:
    out = [
        {"url": r.get("url"), "tags": r.get("tags") or []}
        for r in (references if isinstance(references, list) else [])
        if isinstance(r, dict)
    ]
    return out or None


def _summary(descriptions: list[dict[str, Any]]) -> str | None:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value")
    return None


@register
class NvdCollector(Collector):
    name = "nvd"
    cadence_seconds = 7200

    async def fetch(self, since: datetime | None = None) -> list[dict]:
        settings = get_settings()
        end = datetime.now(UTC)
        if since is None:
            since = self.since
        if since is None:
            since = end - timedelta(days=settings.backfill_days)
        elif since.tzinfo is None:
            since = since.replace(tzinfo=UTC)

        secret = settings.nvd_api_key
        key = secret.get_secret_value() if secret else None
        headers = {"apiKey": key} if key else None
        delay = DELAY_WITH_KEY if key else DELAY_NO_KEY

        pages: list[dict] = []
        first = True
        start = since
        while start < end:
            chunk_end = min(start + MAX_WINDOW, end)
            index = 0
            while True:
                if not first:
                    await _sleep(delay)
                first = False
                page = await http_get_json(
                    NVD_URL,
                    headers=headers,
                    params={
                        "lastModStartDate": _fmt(start),
                        "lastModEndDate": _fmt(chunk_end),
                        "startIndex": index,
                        "resultsPerPage": PAGE_SIZE,
                    },
                )
                pages.append(page)
                index += PAGE_SIZE
                total = page.get("totalResults", 0)
                if index >= total or not page.get("vulnerabilities"):
                    break
            start = chunk_end
        return pages

    def normalize(self, raw: list[dict]) -> CollectorResult:
        cves: list[NormalizedCve] = []
        for page in raw:
            items = page.get("vulnerabilities") if isinstance(page, dict) else None
            for item in items if isinstance(items, list) else []:
                # ALL per-record field access stays inside the try: one poison
                # record must never fail the run (a failed run does not advance
                # the window, so it would fail on the same data forever).
                cve_id = None
                try:
                    cve = item.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        log.warning("nvd: skipping record without id")
                        continue
                    m = _metric(cve.get("metrics") or {})
                    score = m.get("baseScore") if m else None
                    cves.append(
                        NormalizedCve(
                            cve_id=cve_id,
                            published=_parse_ts(cve.get("published")),
                            last_modified=_tolerant_ts(cve.get("lastModified")),
                            cvss=float(score) if score is not None else None,
                            cvss_vector=m.get("vectorString") if m else None,
                            cvss_severity=m.get("baseSeverity") if m else None,
                            cwes=_cwes(cve.get("weaknesses")),
                            references=_refs(cve.get("references")),
                            summary=_summary(cve.get("descriptions") or []),
                        )
                    )
                except Exception:
                    log.warning("nvd: skipping malformed record %r", cve_id, exc_info=True)
        return CollectorResult(cves=cves)
