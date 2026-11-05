"""FIRST EPSS collector (full current score set)."""

from __future__ import annotations

import logging
from datetime import datetime

from cvenom.collectors import base
from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
from cvenom.schemas import NormalizedCve

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
PAGE_SIZE = 10000
PAGE_DELAY = 1.0


async def _sleep(delay: float) -> None:
    # Resolved through base at call time so tests can patch either module.
    await base._sleep(delay)


@register
class EpssCollector(Collector):
    name = "epss"
    cadence_seconds = 7200
    # Updates existing CVE rows only; never creates new ones.
    enrich_only = True

    async def fetch(self, since: datetime | None = None) -> list[dict]:
        pages: list[dict] = []
        offset = 0
        while True:
            if pages:
                await _sleep(PAGE_DELAY)
            page = await http_get_json(EPSS_URL, params={"limit": PAGE_SIZE, "offset": offset})
            pages.append(page)
            data = page.get("data") or []
            if not data:
                break
            offset += len(data)
            if offset >= int(page.get("total") or 0):
                break
        return pages

    def normalize(self, raw: list[dict]) -> CollectorResult:
        cves: list[NormalizedCve] = []
        for page in raw:
            for rec in page.get("data") or []:
                cve_id = rec.get("cve")
                if not cve_id:
                    log.warning("epss: skipping record without cve id")
                    continue
                try:
                    cves.append(
                        NormalizedCve(
                            cve_id=cve_id,
                            epss=float(rec["epss"]),
                            epss_percentile=float(rec["percentile"]),
                        )
                    )
                except (KeyError, TypeError, ValueError):  # incl. ValidationError
                    log.warning("epss: skipping malformed record %s", cve_id)
        return CollectorResult(cves=cves)
