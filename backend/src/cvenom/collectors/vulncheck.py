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


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _first(rec: dict, *keys: str) -> object:
    for k in keys:
        if rec.get(k) is not None:
            return rec[k]
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
        token = get_settings().vulncheck_api_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"}
        pages: list[dict] = []
        page_no = 1
        while True:
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
            if not isinstance(total, int) or isinstance(total, bool):
                log.warning(
                    "%s: missing or non-int total_pages (%r) on page %d; feed may be truncated",
                    self.name, total, page_no,
                )
                break
            if page_no >= total:
                break
            if page_no >= MAX_PAGES:
                log.warning(
                    "%s: stopped at MAX_PAGES=%d of total_pages=%d; feed truncated",
                    self.name, MAX_PAGES, total,
                )
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
                ransom = rec.get("knownRansomwareCampaignUse")
                detail = {
                    "kev_name": _str(rec.get("vulnerabilityName")),
                    "kev_action": _str(_first(rec, "required_action", "requiredAction")),
                    "kev_due": _parse_date(_first(rec, "dueDate", "due_date")),
                    "kev_ransomware": {"Known": True, "Unknown": False}.get(ransom)
                    if isinstance(ransom, str)
                    else None,
                    "kev_notes": _str(rec.get("notes")),
                }
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
                                **detail,
                            )
                        )
                    except (TypeError, ValueError):  # incl. ValidationError
                        log.warning("vulncheck: skipping malformed cve id %r", cve_id)

        # One id can appear in several records: keep its earliest known add date.
        added_dates: dict[str, date | None] = {}
        for c in cves:
            prev = added_dates.get(c.cve_id)
            if c.kev_added is not None and (prev is None or c.kev_added < prev):
                added_dates[c.cve_id] = c.kev_added
            else:
                added_dates.setdefault(c.cve_id, prev)
        events = track_new(
            self.state,
            {c.cve_id for c in cves},
            added_dates=added_dates,
            max_age_days=get_settings().kev_alert_max_age_days,
            source="vulncheck",
            collector_name=self.name,
            logger=log,
        )
        return CollectorResult(cves=cves, events=events)
