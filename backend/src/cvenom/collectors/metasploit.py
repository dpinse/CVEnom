"""Metasploit Framework module index: public-exploit (PoC) signal for CVEs we already track.

Fetches Rapid7's published module metadata (one fixed URL, size-capped, conditional GET). Only
``exploit/*`` modules count as a public exploit; auxiliary/post/etc. are ignored. Each CVE named
by an exploit module gets one ``poc_published`` event (source "Metasploit"); the module link
rides in ``detail["url"]`` so it is surfaced as an Exploit reference the same way Exploit-DB's is.
No stories, and unknown CVEs are never created (enrich_only).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from pydantic import ValidationError

from cvenom.collectors.base import (
    Collector,
    CollectorResult,
    http_get_conditional,
    parse_iso_date,
    register,
)
from cvenom.extract import extract_cve_ids
from cvenom.schemas import NormalizedCve, NormalizedCveEvent, validate_http_url

log = logging.getLogger(__name__)

MODULES_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)
BLOB_BASE = "https://github.com/rapid7/metasploit-framework/blob/master/"
MAX_BYTES = 120_000_000  # the real file is ~11 MB; generous headroom, hard ceiling
FETCH_TIMEOUT = 120.0
MAX_REFS_PER_MODULE = 100
SOURCE = "Metasploit"

_FULLNAME_RE = re.compile(r"exploit/[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}", re.ASCII)
_PATH_RE = re.compile(r"/?modules/exploits/[A-Za-z0-9_][A-Za-z0-9_./-]{0,250}\.rb", re.ASCII)


def _module_path(fullname: str, path: object) -> str | None:
    """Repo-relative module path: the record's own path when it is safe, else derived."""
    if isinstance(path, str) and _PATH_RE.fullmatch(path) and ".." not in path:
        return path.lstrip("/")
    derived = "modules/exploits/" + fullname.removeprefix("exploit/") + ".rb"
    if ".." not in derived and _PATH_RE.fullmatch(derived):
        return derived
    return None


def _module_time(rec: dict) -> datetime | None:
    """disclosure_date (stable across re-runs), else mod_time; None when neither parses."""
    day = parse_iso_date(rec.get("disclosure_date"))
    if day is not None and 1970 <= day.year <= 2100:
        return datetime(day.year, day.month, day.day, tzinfo=UTC)
    mod = rec.get("mod_time")
    if isinstance(mod, str):
        try:
            dt = datetime.strptime(mod.strip(), "%Y-%m-%d %H:%M:%S %z")
        except ValueError:
            return None
        if 1970 <= dt.year <= 2100:
            return dt.astimezone(UTC)
    return None


@register
class MetasploitCollector(Collector):
    name = "metasploit"
    cadence_seconds = 86400
    enrich_only = True  # only flags CVEs that already exist; never stub-creates one

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Validators are committed to self.state only once the body is accepted.
        self._pending_validators: dict[str, str] = {}

    async def fetch(self) -> bytes | None:
        self._pending_validators = {}
        # New CVE rows since the last applied run must be matched even if the file is unchanged.
        unchanged = self.state.get("cve_count") == self.state.get("last_cve_count")
        status, body, headers = await http_get_conditional(
            MODULES_URL,
            etag=self.state.get("etag") if unchanged else None,
            last_modified=self.state.get("last_modified") if unchanged else None,
            max_bytes=MAX_BYTES,
            timeout=FETCH_TIMEOUT,
        )
        if status == 304:
            return None
        if headers.get("etag"):
            self._pending_validators["etag"] = headers["etag"]
        if headers.get("last-modified"):
            self._pending_validators["last_modified"] = headers["last-modified"]
        return body

    def normalize(self, raw: bytes | None) -> CollectorResult:
        if not raw:
            return CollectorResult()
        try:
            modules = json.loads(raw)
        except (ValueError, RecursionError):
            log.warning("%s: body is not valid JSON; ignoring", self.name)
            return CollectorResult()
        del raw  # the parsed tree is all that is needed from here
        if not isinstance(modules, dict):
            log.warning("%s: module index is not an object; ignoring", self.name)
            return CollectorResult()

        now = datetime.now(UTC)
        # cve_id -> [(occurred_at, fullname, rank, path)]
        found: dict[str, list[tuple[datetime, str, int | None, str]]] = {}
        for rec in modules.values():
            try:
                if not isinstance(rec, dict) or rec.get("type") != "exploit":
                    continue
                fullname = rec.get("fullname")
                if not isinstance(fullname, str) or not _FULLNAME_RE.fullmatch(fullname):
                    log.warning("%s: skipping module with bad fullname", self.name)
                    continue
                refs = rec.get("references")
                if not isinstance(refs, list):
                    continue
                ids: set[str] = set()
                for ref in refs[:MAX_REFS_PER_MODULE]:
                    if isinstance(ref, str) and ref[:4].upper() == "CVE-":
                        ids |= extract_cve_ids(ref)
                if not ids:
                    continue
                path = _module_path(fullname, rec.get("path"))
                if path is None:
                    log.warning("%s: skipping module %s without a safe path", self.name, fullname)
                    continue
                occurred = _module_time(rec) or now
                rank = rec.get("rank")
                rank = rank if isinstance(rank, int) and not isinstance(rank, bool) else None
                for cve_id in ids:
                    found.setdefault(cve_id, []).append((occurred, fullname, rank, path))
            except (ValueError, TypeError, OverflowError, AttributeError) as exc:
                log.warning("%s: skipping bad module record: %s", self.name, exc)
        del modules

        cves: list[NormalizedCve] = []
        events: list[NormalizedCveEvent] = []
        for cve_id in sorted(found):
            try:
                mods = sorted(found[cve_id], key=lambda m: (m[0], m[1]))
                occurred, fullname, rank, path = mods[0]
                detail: dict = {"module": fullname}
                if rank is not None:
                    detail["rank"] = rank
                detail["path"] = "/" + path
                detail["url"] = validate_http_url(BLOB_BASE + path)
                if len(mods) > 1:
                    detail["module_count"] = len(mods)
                events.append(
                    NormalizedCveEvent(
                        cve_id=cve_id,
                        kind="poc_published",
                        occurred_at=occurred,
                        source=SOURCE,
                        detail=detail,
                    )
                )
                cves.append(NormalizedCve(cve_id=cve_id, poc_badge=True))
            except (ValidationError, ValueError, TypeError, OverflowError) as exc:
                log.warning("%s: skipping %s: %s", self.name, cve_id, exc)
        self.state.update(self._pending_validators)
        self.state["last_cve_count"] = self.state.get("cve_count")
        return CollectorResult(cves=cves, cve_events=events)
