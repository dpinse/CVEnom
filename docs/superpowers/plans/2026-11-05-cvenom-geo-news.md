# CVEnom Geographic & News Collectors + Velocity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed the globe and the "Loud now" lane: geographic threat events (ransomware victims, scan sources, internet outages, botnet C2s), security-news stories, and the CVE-velocity readout.

**Architecture:** Builds on Plan 1 (`feat/backend-foundation`). New collectors subclass the existing `Collector` framework and are scheduled by the existing Celery beat. Stories flow through the existing `ingest` (sanitize → dedup → CVE-link). Geographic events are a new object type, `GeoEvent`, upserted by `(source, external_id)` with Postgres `ON CONFLICT`. IP addresses are geolocated locally from an mmdb file (DB-IP Lite by default, no account needed; MaxMind GeoLite2 when credentials are set). Read-model functions (velocity, geo summary, loud stories) are pure SQL helpers; the Plan 3 API will serve them.

**Tech Stack:** Python 3.12+, SQLAlchemy 2 + Alembic, Postgres, Celery, httpx, `feedparser`, `maxminddb`, pytest + respx.

**Spec:** `docs/superpowers/specs/2026-11-04-cvenom-vuln-threat-radar-design.md` (§4 sources, §5 Loud lane + velocity, §7 security)

## Global Constraints

- Monorepo: all backend paths are relative to `backend/`. Run pytest and alembic from `backend/` with this worktree's own venv. On first use: `python -m venv .venv`, then `pip install -e ".[dev]"`.
- **Shared Postgres:** reuse the container that is already running (compose project `feat-backend-foundation`, port 5432, test DB `cvenom_test`). Do NOT run `docker compose up` from this worktree. Compose names projects by directory, so it would try to start a second Postgres on 5432 and fail. If Postgres is down, start it from this worktree's root with `docker compose -p feat-backend-foundation up -d postgres`.
- Never run `git push`, `git fetch`, `git pull`, or any other remote git operation. Commit locally only, and never stage `.superpowers/`.
- Reuse Plan 1 interfaces: `Collector` (`__init__(since=None, state=None)`, `last_error`, `enrich_only`), `CollectorResult`, `http_get_json`, `http_get_text`, `register`, `ingest`, `sanitize_text`, `NormalizedCve` (cve_id is validated), `NormalizedStory`.
- Only free sources. These optional tokens are read from env: `CF_RADAR_TOKEN`, `ABUSECH_AUTH_KEY`, `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY`. A collector whose token is missing returns an empty result, makes no HTTP call, and logs at INFO once.
- Generic User-Agent via the shared helpers. Respect rate limits. Never put secrets in URLs or logs. Use headers or basic auth only.
- Collectors emit RAW text. `ingest` is the single sanitization point, covering story title/summary, geo `label`, and `affected`.
- Story URLs must be `http`/`https`. Validate in `NormalizedStory`; reject `javascript:`, `data:`, and similar schemes.
- Country codes are ISO 3166-1 alpha-2, upper-cased and validated (`^[A-Z]{2}$`). `None` is allowed when unknown.
- Every HTTP fetch is size-capped: default 25 MB, exceeding it raises `ResponseTooLarge`.
- Default cadences: news 900s, ransomware.live 900s, DShield 3600s, Cloudflare Radar 300s, abuse.ch 3600s, GeoIP refresh 7 days, geo retention cleanup daily.
- `geo_retention_days = 30`.
- Velocity is CVEs per day by `Cve.published` over `velocity_window_days` (30). "Rising" means the last-7-day average is greater than the prior-7-day average.
- Each NEW source's response shape may be confirmed with ONE manual live request to its keyless public endpoint while building fixtures. Never send tokens, and never call live endpoints from tests.

## Review Focus

- **Hostile feed content:** a story link with a `javascript:` scheme, or HTML/script in a title or geo label, must be rejected or neutralized at ingest, never stored live. Tested in Task 1 and Task 2.
- **Malformed or oversized feeds:** XML bombs, truncated JSON, multi-GB responses. The size cap triggers, parse failures skip that feed, and the run never crashes the worker. Tested in Task 1 and Task 4.
- **Re-run idempotency for geo events:** the same victim, outage, or C2 seen again updates its row and never duplicates it (`ON CONFLICT`). Tested in Task 2.
- **Missing credentials:** CF/abuse.ch/MaxMind keys absent means those collectors are cleanly disabled and GeoIP falls back to DB-IP Lite. Tested in Tasks 3, 7, and 8.
- **Private/reserved IPs and unknown countries:** geolocation returns `None`, and such events never create bogus country aggregates. Tested in Task 3 and Task 9.

---

### Task 0: Plan 1 follow-ups (carried from Plan 1's final review)

**Files:**
- Modify: `backend/src/cvenom/schemas.py`, `backend/src/cvenom/extract.py`, `backend/src/cvenom/collectors/epss.py`, `backend/tests/collectors/test_seenstate.py`
- Test: `backend/tests/test_schemas.py`, `backend/tests/test_extract.py`, `backend/tests/collectors/test_epss.py`

**Interfaces:**
- Produces:
  - The CVE id pattern becomes `^CVE-\d{4}-\d{4,7}$` (ASCII) in BOTH the `NormalizedCve.cve_id` validator and the `extract.py` regex. The extract regex must not match a longer digit run as a truncated id. Use a negative lookahead `(?!\d)`.
  - `EpssCollector` short-circuits ONLY when the score date is unchanged AND no `Cve` rows were created since its last run.
    - Record a marker in `self.state`. The collector does no DB access, so the marker must come in through the runner. Ruling: `run_collector` passes `state["cve_count"]` = the current `Cve` row count (one `SELECT count(*)`) into EPSS state before the run, for collectors with `enrich_only = True`.
    - EPSS proceeds when either the score date or `cve_count` changed, and stores both afterwards.

- [ ] **Step 1: Write the failing tests.** Cover:
  - The validator rejects `CVE-2024-12345678` and accepts `CVE-2024-1234567`.
  - `extract_cve_ids("CVE-2024-12345678")` returns an empty set rather than `{"CVE-2024-1234567"}`.
  - EPSS with an unchanged date but a grown `cve_count` proceeds; with both unchanged it short-circuits.
  - `test_added_date_exactly_at_max_age_still_emits` computes "today" at call time (or freezes the clock), so it can't flake across midnight UTC.
- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement it** (including the small `run_collector` change).
- [ ] **Step 4: Run to verify they pass.** Run the full suite.
- [ ] **Step 5: Commit.** `git commit -m "fix: bound CVE id length, refine EPSS short-circuit, de-flake seenstate test"`

---

### Task 1: Feed-safety primitives and new schemas

**Files:**
- Modify: `backend/src/cvenom/collectors/base.py`, `backend/src/cvenom/schemas.py`
- Test: `backend/tests/collectors/test_base.py`, `backend/tests/test_schemas.py`

**Interfaces:**
- Produces:
  - `class ResponseTooLarge(Exception)`.
  - A `max_bytes: int = 25_000_000` keyword on `http_get_json` and `http_get_text`. The body is streamed and aborted past the cap.
  - `async def http_get_bytes(url, *, headers=None, params=None, retries=3, timeout=60, max_bytes=200_000_000) -> bytes`.
  - `async def http_get_conditional(url, *, etag=None, last_modified=None, headers=None, max_bytes=...) -> tuple[int, bytes, dict]`. It returns `(status, body, response_headers)`, and a 304 returns an empty body.
  - `NormalizedStory.url` validator: http/https only. Strip it, and require a scheme in `{"http","https"}` and a non-empty host.
  - `NormalizedGeoEvent` (pydantic):
    - `source: str`, `external_id: str`, `kind: Literal["scan","outage","victim","c2","bgp"]`
    - `country_code: str | None` (validated `^[A-Z]{2}$` after upper-casing)
    - `asn: int | None` (≥ 0), `observed_at: datetime` (tz-aware, normalized to UTC)
    - `magnitude: float = 1.0` (finite, ≥ 0), `label: str | None`
    - `cve_id: str | None` (same validator as `NormalizedCve`), `story_url: str | None` (http/https)
    - `details: dict = {}`

- [ ] **Step 1: Write the failing tests**
```python
def test_story_url_rejects_non_http_schemes():
    import pytest
    from pydantic import ValidationError
    from cvenom.schemas import NormalizedStory
    from datetime import datetime, timezone
    now = datetime(2026,11,4,tzinfo=timezone.utc)
    for bad in ["javascript:alert(1)", "data:text/html,x", "ftp://x/y", "//evil", ""]:
        with pytest.raises(ValidationError):
            NormalizedStory(url=bad, source="s", title="t", summary="s", published=now)
    assert NormalizedStory(url=" https://x.org/a ", source="s", title="t", summary="s", published=now).url == "https://x.org/a"

def test_geo_event_validates_country_and_magnitude():
    import pytest
    from pydantic import ValidationError
    from cvenom.schemas import NormalizedGeoEvent
    from datetime import datetime, timezone
    now = datetime(2026,11,4,tzinfo=timezone.utc)
    ev = NormalizedGeoEvent(source="x", external_id="1", kind="scan", country_code="us", observed_at=now)
    assert ev.country_code == "US"
    for bad in [dict(country_code="USA"), dict(magnitude=float("nan")), dict(magnitude=-1), dict(kind="other")]:
        with pytest.raises(ValidationError):
            NormalizedGeoEvent(**{**dict(source="x", external_id="1", kind="scan", observed_at=now), **bad})

async def test_http_get_text_aborts_past_max_bytes(respx_mock):
    import pytest
    import httpx
    from cvenom.collectors.base import http_get_text, ResponseTooLarge
    respx_mock.get("https://big.test/x").mock(return_value=httpx.Response(200, content=b"a" * 2048))
    with pytest.raises(ResponseTooLarge):
        await http_get_text("https://big.test/x", max_bytes=1024)
```
- [ ] **Step 2: Run the tests to confirm they fail.** Run `python -m pytest tests/test_schemas.py tests/collectors/test_base.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement it.** Stream bodies via `client.stream` and count bytes, sharing the existing `_request` retry/backoff internals. Add the validators and `NormalizedGeoEvent`. Add tests for `http_get_conditional`: a 304 returns `(304, b"", headers)`, and `If-None-Match`/`If-Modified-Since` are sent. Also test that `http_get_bytes` respects its cap.
- [ ] **Step 4: Run the tests to confirm they pass.** Expected: PASS, and the full suite stays green.
- [ ] **Step 5: Commit.** `git commit -m "feat: size-capped fetch helpers, story URL validation, geo event schema"`

---

### Task 2: GeoEvent storage, migration 0002, geo ingest, retention

**Files:**
- Modify: `backend/src/cvenom/models.py`, `backend/src/cvenom/collectors/base.py` (`CollectorResult.geo_events`), `backend/src/cvenom/pipeline.py`
- Create: `backend/migrations/versions/0002_geo_events.py`
- Test: `backend/tests/test_geo_pipeline.py`, `backend/tests/test_migrations.py`

**Interfaces:**
- Consumes: `NormalizedGeoEvent` (Task 1).
- Produces:
  - Model `GeoEvent` with pk `id`, `source`, `external_id` (unique together with `source`), `kind`, `country_code` (nullable), `asn`, `observed_at`, `first_seen`, `magnitude`, `label`, `cve_id` (nullable, no FK), `story_url`, `details` (JSONB). Indexes: BRIN on `observed_at`, and btree on `(country_code, kind)`.
  - Migration 0002 also adds the Plan 1-carried index on `story.content_hash`.
  - `CollectorResult.geo_events: list[NormalizedGeoEvent]` (default_factory list).
  - `ingest(...)` now also upserts `result.geo_events` with `pg insert(...).on_conflict_do_update(index_elements=[source, external_id])`. The update keeps the original `first_seen` and refreshes `observed_at`/`magnitude`/`label`/`details`. `label` goes through `sanitize_text`.
  - `def purge_old_geo_events(session, now, *, days: int) -> int` deletes rows with `observed_at < now - days` and returns the count.

- [ ] **Step 1: Write the failing tests.** Cover:
  - Ingesting the same `(source, external_id)` twice leaves one row, with an updated magnitude and an unchanged `first_seen`.
  - A label containing `<script>` is stored without a tag-starting `<`.
  - Purge removes only old rows.
  - The migration test asserts `ix_story_content_hash` and the geo indexes exist after `upgrade head`, and that `downgrade` to 0001 removes them.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.** Model, migration 0002, `CollectorResult.geo_events`, the geo upsert in `ingest`, `purge_old_geo_events`, and the setting `geo_retention_days: int = 30` in `Settings`.
- [ ] **Step 4: Run the tests to confirm they pass.** Run the full suite.
- [ ] **Step 5: Commit.** `git commit -m "feat: geo event storage, idempotent geo ingest, retention"`

---

### Task 3: Local IP geolocation

**Files:**
- Create: `backend/src/cvenom/geoip.py`
- Modify: `backend/src/cvenom/config.py` (`geoip_dir`, `maxmind_account_id`, `maxmind_license_key`); `backend/pyproject.toml` (`maxminddb`)
- Test: `backend/tests/test_geoip.py`

**Interfaces:**
- Produces:
  - `@dataclass GeoResult(country_code: str | None, asn: int | None)`.
  - `class GeoIP`:
    - `GeoIP.open(dir) -> GeoIP | None` returns None when no database file exists.
    - `lookup(ip: str) -> GeoResult | None` returns None for invalid input or non-global addresses (`ipaddress.ip_address(ip).is_global is False`) and when the IP isn't found.
  - `async def refresh_geoip(dir, settings) -> str`:
    - Default: download DB-IP Lite (`https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz` and `dbip-asn-lite-{YYYY-MM}.mmdb.gz`). If the current month 404s, fall back to the previous month.
    - When `maxmind_account_id` and `maxmind_license_key` are set, use MaxMind GeoLite2 Country/ASN via `https://download.maxmind.com/geoip/databases/<edition>/download?suffix=tar.gz` with **HTTP basic auth**, never a key in the URL.
    - Use `http_get_bytes`, gunzip/untar to a temp file, then atomically `os.replace` into `dir`.
    - Return which provider was used.

- [ ] **Step 1: Write the failing tests.** Build a tiny mmdb fixture in a tmp dir with the `mmdb_writer` package (dev dependency) or a checked-in ~1 KB fixture you generate. Assert:
  - Lookup of a fixture public IP returns `GeoResult("US", 15169)`.
  - `10.0.0.1`, `127.0.0.1`, `::1` and `"not-an-ip"` all return None.
  - `GeoIP.open(empty_dir)` is None.
  - The respx-mocked DB-IP download writes the file atomically.
  - With MaxMind creds, the request carries an `Authorization: Basic …` header and the URL has no `license_key`.
  - The previous-month fallback works on a 404.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.** Read with `maxminddb.open_database`. The country comes from `country.iso_code`; the ASN from `autonomous_system_number`.
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: local IP geolocation with DB-IP Lite default and MaxMind option"`

---

### Task 4: Security-news RSS collectors

**Files:**
- Create: `backend/src/cvenom/collectors/news.py`
- Modify: `backend/pyproject.toml` (`feedparser`)
- Test: `backend/tests/collectors/test_news.py`, with fixtures `backend/tests/fixtures/rss_*.xml`

**Interfaces:**
- Produces:
  - `class NewsFeedCollector(Collector)` with class attrs `feed_url`, `source_name`. There are four registered subclasses:
    - `news_krebs` → `https://krebsonsecurity.com/feed/` ("Krebs on Security")
    - `news_thn` → `https://feeds.feedburner.com/TheHackersNews` ("The Hacker News")
    - `news_bleeping` → `https://www.bleepingcomputer.com/feed/` ("BleepingComputer")
    - `news_securityweek` → `https://www.securityweek.com/feed/` ("SecurityWeek")
  - All four run with `cadence_seconds = 900`.
- `fetch`:
  - Calls `http_get_conditional` with the `etag`/`last_modified` stored in `self.state`.
  - On 304, returns an empty result (successful).
  - On 200, stores the new validators in state and parses the **bytes** with `feedparser.parse(body)`. Bytes only: feedparser must never fetch a URL itself.
- `normalize` handles each entry inside a per-entry try and emits `NormalizedStory(url=entry.link, source=source_name, title=entry.title, summary=entry.summary or "", published=<published_parsed or updated_parsed → UTC, else now>)`.
  - Entries whose link fails URL validation are skipped.
  - Text is emitted raw.
  - A feed that feedparser marks `bozo` with zero entries is logged as a warning and yields an empty result.

- [ ] **Step 1: Write the failing tests.** Use realistic RSS/Atom fixtures. Assert:
  - Entries map to stories with UTC `published`.
  - A `javascript:` link entry is skipped.
  - A 304 gives an empty, successful result, and the conditional headers are sent from state.
  - New ETag/Last-Modified values are saved to state.
  - A billion-laughs XML fixture is handled with no hang (assert the run returns quickly with an empty result, or that `ResponseTooLarge` / the parse is bounded).
  - Malformed XML yields empty plus a warning.
  - All four subclasses are registered.
  - End to end through `ingest`: a story whose title contains `CVE-2026-109618` creates a `StoryCveLink`, and its HTML is sanitized.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: security-news RSS collectors with conditional GET"`

---

### Task 5: ransomware.live collector

**Files:**
- Create: `backend/src/cvenom/collectors/ransomware.py`
- Test: `backend/tests/collectors/test_ransomware.py`

**Interfaces:**
- Produces: `class RansomwareLiveCollector(Collector)`, `name = "ransomware_live"`, `cadence_seconds = 900`.
- Endpoint: `https://api.ransomware.live/v2/recentvictims`. Confirm the shape with ONE live request and write the fixture from it. Treat every field defensively.
- `normalize`: each victim → one `NormalizedGeoEvent(source="ransomware_live", external_id=<stable id: group + victim name + discovered date, hashed>, kind="victim", country_code=<record country, if valid>, observed_at=<discovered>, label="<group>: <victim>", details={"group":…, "activity":…})`.
  - A victim with a valid `post_url`/website also produces a `NormalizedStory` (CVE-less) for the Loud lane.
  - Records are processed in a per-record try.

- [ ] **Step 1: Write the failing tests.** Fixture-based mapping. Also check:
  - The external_id is stable across runs, so a re-run doesn't duplicate.
  - An invalid country becomes `None`.
  - A non-http URL produces no story.
  - A malformed record is skipped.
  - Registration.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: ransomware.live victim collector"`

---

### Task 6: DShield scan-source collector

**Files:**
- Create: `backend/src/cvenom/collectors/dshield.py`
- Test: `backend/tests/collectors/test_dshield.py`

**Interfaces:**
- Consumes: `GeoIP` (Task 3).
- Produces: `class DShieldCollector(Collector)`, `name = "dshield"`, `cadence_seconds = 3600`.
- Fetch: `https://isc.sans.edu/api/sources/attacks/100/?json`. Confirm the shape with one live request. Records carry an IP plus attack/count fields.
- `normalize`:
  - Geolocate each IP.
  - Aggregate per country: `magnitude` = sum of attack counts.
  - Emit one `NormalizedGeoEvent(source="dshield", external_id=f"{country}:{YYYY-MM-DDTHH}", kind="scan", country_code=country, observed_at=<run hour, UTC>, label=f"{n} scanning sources")` per country.
  - IPs with no country are skipped.
- If `GeoIP.open()` returns None, log a warning and return an empty result. Successful, nothing to advance.

- [ ] **Step 1: Write the failing tests.** Use a fixture plus a stub `GeoIP` injected through a constructor or class attribute. Check:
  - Aggregation per country.
  - Private IPs are excluded.
  - A missing database gives empty plus a warning.
  - The hourly external_id makes a same-hour re-run update rather than duplicate.
  - Registration.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: DShield scan-source collector aggregated by country"`

---

### Task 7: Cloudflare Radar outages and BGP collector

**Files:**
- Create: `backend/src/cvenom/collectors/cfradar.py`
- Modify: `backend/src/cvenom/config.py` (`cf_radar_token`)
- Test: `backend/tests/collectors/test_cfradar.py`

**Interfaces:**
- Produces: `class CloudflareRadarCollector(Collector)`, `name = "cf_radar"`, `cadence_seconds = 300`. It is token-gated on `CF_RADAR_TOKEN`, sent as `Authorization: Bearer`.
- Endpoints:
  - `https://api.cloudflare.com/client/v4/radar/annotations/outages?dateRange=7d&format=json`
  - `https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events?dateRange=7d&format=json`
- Outages: one `NormalizedGeoEvent(kind="outage", external_id=<annotation id>, country_code=<each location>, observed_at=<startDate>, label=<cause/scope>)` per affected country.
- BGP hijacks: one `kind="bgp"` event per hijack, with the victim country if present.
- No live requests at build time (token required). Build fixtures from Cloudflare's documented response shape and note in the report that the shape is unverified live.

- [ ] **Step 1: Write the failing tests.** Check:
  - No token gives empty and zero HTTP calls.
  - The Bearer header is sent and the token never appears in logs (caplog).
  - A multi-country outage produces one event per country.
  - A Cloudflare `success: false` response is treated as a failed run (raise → `last_error`).
  - Registration.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: Cloudflare Radar outage and BGP hijack collector"`

---

### Task 8: abuse.ch botnet C2 collector

**Files:**
- Create: `backend/src/cvenom/collectors/abusech.py`
- Modify: `backend/src/cvenom/config.py` (`abusech_auth_key`)
- Test: `backend/tests/collectors/test_abusech.py`

**Interfaces:**
- Produces: `class AbuseChCollector(Collector)`, `name = "abusech"`, `cadence_seconds = 3600`.
- Feodo Tracker C2 blocklist, keyless: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`. Records include IP, port, status, malware, country and AS fields. Confirm with one live request.
  - Per C2: `NormalizedGeoEvent(source="feodo", external_id=f"{ip}:{port}", kind="c2", country_code=<record country, or GeoIP fallback>, asn=<as_number>, observed_at=<last_online or first_seen>, label=f"{malware} C2", details={"status":…})`.
- ThreatFox, only when `ABUSECH_AUTH_KEY` is set: `POST https://threatfox-api.abuse.ch/api/v1/` with `{"query":"get_iocs","days":1}` and header `Auth-Key`.
  - IP-type IOCs become `kind="c2"` events with `source="threatfox"`.
  - Without the key, skip ThreatFox silently. Feodo still runs.

- [ ] **Step 1: Write the failing tests.** Check:
  - Feodo mapping, with record country preferred over GeoIP.
  - The ThreatFox path runs only with the key, and the `Auth-Key` header is sent but never logged.
  - Non-IP IOCs are ignored.
  - Idempotent external_ids.
  - Registration.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: abuse.ch Feodo and ThreatFox C2 collector"`

---

### Task 9: Read models — velocity, geo summary, loud stories

**Files:**
- Create: `backend/src/cvenom/readmodels.py`
- Test: `backend/tests/test_readmodels.py`

**Interfaces:**
- Consumes: `Cve`, `Story`, `StoryCveLink`, `GeoEvent`, `Settings`.
- Produces:
  - `def cve_velocity(session, now, *, days: int) -> dict`: returns `{"series": [{"day": date, "count": int}, ...], "current": int, "rising": bool}`.
    - The series runs oldest to newest, with every day present (zero-filled).
    - `current` is today's count.
    - `rising` is true when the mean of the last 7 days is greater than the mean of the prior 7.
    - Grouping happens in SQL by UTC day of `published`.
  - `def geo_summary(session, now, *, window_hours: int = 24) -> list[dict]`: one row per `(country_code, kind)` that has events in the window, as `{"country_code", "kind", "magnitude": sum, "events": count, "last_seen"}`. Events with a NULL `country_code` are excluded. Rows are sorted by magnitude descending.
  - `def loud_stories(session, now, *, limit: int = 50) -> list[dict]`: stories published within `loud_window_hours`, newest first. Each is `{"title", "summary", "url", "source", "published", "cve_ids": [...]}`, and CVE-less stories are included (`cve_ids == []`).

- [ ] **Step 1: Write the failing tests.** Check:
  - Velocity zero-fills missing days, `rising` is true and false on crafted data, and the day boundary is in UTC.
  - Geo summary aggregates correctly, excludes NULL countries and out-of-window rows, and sorts correctly.
  - Loud stories include CVE-less ones, respect the window and limit, and attach the linked cve_ids.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.** No N+1: gather the cve_ids for loud stories in a single grouped query.
- [ ] **Step 4: Run the tests to confirm they pass.**
- [ ] **Step 5: Commit.** `git commit -m "feat: velocity, geo summary, and loud-stories read models"`

---

### Task 10: Schedule the new collectors and maintenance jobs

**Files:**
- Modify: `backend/src/cvenom/tasks.py`
- Test: `backend/tests/test_tasks.py`

**Interfaces:**
- Consumes: all new collectors, `refresh_geoip`, `purge_old_geo_events`.
- Produces:
  - Importing `cvenom.tasks` registers the new collectors too: `news_krebs`, `news_thn`, `news_bleeping`, `news_securityweek`, `ransomware_live`, `dshield`, `cf_radar`, `abusech`.
  - New Celery tasks `refresh_geoip_task()` and `purge_geo_task()`. Both use the Redis lock pattern; purge commits through `session_scope`.
  - Beat entries `maintenance-geoip` (every 7 days) and `maintenance-purge-geo` (daily).
- **Ruling:** the beat/REGISTRY test now asserts collector entries == `len(REGISTRY)` and that the two maintenance entries exist, instead of total equality.

- [ ] **Step 1: Write the failing tests.** Check:
  - The registry contains all 13 collectors.
  - The beat contains one collector entry per registered collector plus the two maintenance entries, with the right schedules.
  - The maintenance tasks call their functions (patched) and release their locks.
- [ ] **Step 2: Run the tests to confirm they fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run the tests to confirm they pass.** Run the full suite.
- [ ] **Step 5: Commit.** `git commit -m "feat: schedule geo/news collectors and maintenance jobs"`

---

## Self-Review

- **Spec coverage:**
  - §4 geographic sources:
    - ransomware.live → Task 5
    - DShield → Task 6
    - Cloudflare Radar → Task 7
    - abuse.ch + GeoIP → Tasks 3 and 8
  - §4 news layer → Task 4.
  - §5 Loud lane (CVE-less stories) and velocity readout → Task 9.
  - §7 hostile content and SSRF/secrets → Tasks 1, 3, 7 and 8.
  - Carried from Plan 1's final review:
    - `story.content_hash` index → Task 2
    - URL-scheme validation at ingest → Task 1
    - per-record try pattern → every collector
  - Out of scope, owned by Plan 3: API endpoints and alerting on geo/news.
- **Review Focus:** hostile content (T1, T2, T4), oversized/malformed (T1, T4), geo idempotency (T2), missing credentials (T3, T7, T8), private IPs / NULL country (T3, T9). Each one has a named test.
- **Type consistency:** `NormalizedGeoEvent` (T1) → `CollectorResult.geo_events` (T2) → collectors (T5–T8) → `GeoEvent` → `geo_summary` (T9). `GeoIP`/`GeoResult` (T3) is used by T6 and T8.
- **Proportion:** bodies appear only for tests; implementations are given as signatures and rules.
