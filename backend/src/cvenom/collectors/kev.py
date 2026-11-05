"""CISA Known Exploited Vulnerabilities collector with new-entry diffing."""

from __future__ import annotations

import logging
from datetime import date

from cvenom.collectors.base import Collector, CollectorResult, http_get_json, register
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

    def diff(self, seen: set[str], current: set[str]) -> list[dict]:
        return [
            {"type": "kev_added", "cve_id": cve_id, "source": "cisa"}
            for cve_id in sorted(current - seen)
        ]

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
                    )
                )
            except (KeyError, TypeError, ValueError):  # incl. ValidationError
                log.warning("kev: skipping malformed entry %s", cve_id)

        current = {c.cve_id for c in cves}
        if "seen" not in self.state:
            events: list[dict] = []  # first run: baseline only, no alert flood
            prior: set[str] = set()
        else:
            stored = self.state["seen"]
            prior = {x for x in stored if isinstance(x, str)} if isinstance(stored, list) else set()
            events = self.diff(prior, current)
        # KEV is append-only: union so a truncated feed never shrinks the baseline.
        self.state["seen"] = sorted(prior | current)
        return CollectorResult(cves=cves, events=events)
