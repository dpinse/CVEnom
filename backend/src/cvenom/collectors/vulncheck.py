"""VulnCheck Community KEV collector (token-gated)."""

from __future__ import annotations

import logging
from datetime import date

from cvenom.collectors import base
from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
from cvenom.collectors.seenstate import track_new
from cvenom.config import get_settings
from cvenom.schemas import NormalizedCve

log = logging.getLogger(__name__)

VULNCHECK_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
PAGE_DELAY = 1.0
MAX_PAGES = 200  # hard stop against a misbehaving total_pages


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


@register
class VulnCheckCollector(Collector):
    name = "vulncheck_kev"
    cadence_seconds = 3600

    async def run(self) -> CollectorResult:
        if not get_settings().vulncheck_api_token:
            log.info("%s: no VULNCHECK_API_TOKEN configured; collector disabled", self.name)
            return CollectorResult()
        return await super().run()

    async def fetch(self) -> list[dict]:
        token = get_settings().vulncheck_api_token
        headers = {"Authorization": f"Bearer {token}"}
        pages: list[dict] = []
        page_no = 1
        while page_no <= MAX_PAGES:
            if page_no > 1:
                await base._sleep(PAGE_DELAY)
            page = await http_get_json(
                VULNCHECK_URL, headers=headers, params={"page": page_no}
            )
            pages.append(page)
            data = page.get("data") if isinstance(page, dict) else None
            if not data:
                break
            meta = page.get("_meta")
            total = meta.get("total_pages") if isinstance(meta, dict) else None
            if not isinstance(total, int) or page_no >= total:
                break
            page_no += 1
        return pages

    def normalize(self, raw: list[dict]) -> CollectorResult:
        cves: list[NormalizedCve] = []
        for page in raw:
            records = page.get("data") if isinstance(page, dict) else None
            for rec in records or []:
                if not isinstance(rec, dict):
                    log.warning("vulncheck: skipping non-object record")
                    continue
                ids = rec.get("cve")
                if isinstance(ids, str):
                    ids = [ids]
                if not isinstance(ids, list):
                    log.warning("vulncheck: skipping record without cve ids")
                    continue
                vendor, product = rec.get("vendorProject"), rec.get("product")
                affected = [f"{vendor} {product}"] if vendor and product else []
                added = _parse_date(rec.get("date_added"))
                for cve_id in ids:
                    try:
                        if not isinstance(cve_id, str) or not cve_id:
                            raise ValueError("bad cve id")
                        cves.append(
                            NormalizedCve(
                                cve_id=cve_id,
                                kev=True,
                                kev_source="vulncheck",
                                kev_added=added,
                                affected=affected,
                            )
                        )
                    except (TypeError, ValueError):  # incl. ValidationError
                        log.warning("vulncheck: skipping malformed cve id %r", cve_id)

        events = track_new(
            self.state,
            {c.cve_id for c in cves},
            source="vulncheck",
            collector_name=self.name,
            logger=log,
        )
        return CollectorResult(cves=cves, events=events)
