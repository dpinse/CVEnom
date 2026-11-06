"""CISA Known Exploited Vulnerabilities collector with new-entry diffing."""

from __future__ import annotations

import logging
from datetime import date

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_json,
    parse_iso_date,
    ransomware_flag,
    register,
    str_or_none,
)
from cvenom.collectors.seenstate import track_new
from cvenom.config import get_settings
from cvenom.schemas import NormalizedCve

log = logging.getLogger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@register
class KevCollector(Collector):
    name = "cisa_kev"
    cadence_seconds = 3600

    async def fetch(self) -> dict:
        return await http_get_json(KEV_URL)

    def normalize(self, raw: dict) -> CollectorResult:
        cves: list[NormalizedCve] = []
        for rec in raw.get("vulnerabilities") or []:
            cve_id = None
            try:
                cve_id = rec["cveID"]
                if not cve_id:
                    raise ValueError("empty cveID")
                cves.append(
                    NormalizedCve(
                        cve_id=cve_id,
                        kev=True,
                        kev_added=date.fromisoformat(rec["dateAdded"]),
                        kev_source="cisa",
                        affected=[f"{rec['vendorProject']} {rec['product']}"],
                        kev_name=str_or_none(rec.get("vulnerabilityName")),
                        kev_action=str_or_none(rec.get("requiredAction")),
                        kev_due=parse_iso_date(rec.get("dueDate")),
                        kev_ransomware=ransomware_flag(rec.get("knownRansomwareCampaignUse")),
                        kev_notes=str_or_none(rec.get("notes")),
                    )
                )
            except (KeyError, TypeError, ValueError):  # incl. ValidationError
                log.warning("kev: skipping malformed entry %s", cve_id)

        events = track_new(
            self.state,
            {c.cve_id for c in cves},
            added_dates={c.cve_id: c.kev_added for c in cves},
            max_age_days=get_settings().kev_alert_max_age_days,
            source="cisa",
            collector_name=self.name,
            logger=log,
        )
        return CollectorResult(cves=cves, events=events)
