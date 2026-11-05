# CVEnom Backend Foundation & Ingestion Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a backend that ingests authoritative vulnerability data from the free feeds and computes the four radar lanes, fully tested.

**Architecture:** Independent collectors (one per source) run on Celery-beat cadences, each `fetch → normalize → ingest`. Ingestion upserts CVEs by `cve_id` (merging signals from many feeds), stores stories with dedup, and links stories to CVEs. Lane membership is **derived at read time** by pure scoring functions from stored signals, so thresholds stay configurable without re-scoring. PostgreSQL (BRIN-indexed, append-mostly) is the store; Redis is the Celery broker.

**Tech Stack:** Python 3.12, FastAPI (app scaffold only here), SQLAlchemy 2.x + Alembic, PostgreSQL, Redis, Celery + beat, httpx, pydantic v2 / pydantic-settings, pytest + pytest-asyncio + respx, bleach.

**Spec:** `docs/superpowers/specs/2026-11-04-cvenom-vuln-threat-radar-design.md`

## Global Constraints

- Python 3.12+; Python backend only (this plan).
- PostgreSQL with **BRIN indexes** on time-ordered columns; SQLAlchemy 2.x; Alembic migrations.
- Redis as Celery broker; Celery beat for scheduling.
- Only free data sources; optional tokens: `NVD_API_KEY`, `VULNCHECK_API_TOKEN`, `GITHUB_TOKEN` (all optional, read from env).
- Respect each source's rate limits and ToS; generic client User-Agent (no personal email); backoff on 429/5xx.
- Default thresholds (configurable): EPSS **percentile** ≥ 0.95 for Likely-next; CVSS ≥ 9.0 within 48h for Fresh; Loud window 72h; velocity window 30 days; first-run backfill 90 days.
- Exploited-now = `kev` flag set by **CISA KEV or VulnCheck**; a GitHub PoC is a badge, never admission.
- Pin all dependencies with version floors in `pyproject.toml`.

## Review Focus

- **Same CVE from multiple feeds** (NVD + OSV + KEV + EPSS) must upsert-merge by `cve_id` — never duplicate rows, and never let a later feed clear a `kev=True` flag. → test in Task 2.
- **Malformed / error responses** (missing CVSS, null fields, HTTP 4xx/5xx, timeout) must log-and-skip, never crash the collector run. → test in Task 6.
- **Re-run idempotency** — re-fetching unchanged data creates no duplicate stories and emits no repeat "new KEV" events. → tests in Task 9 and Task 12.
- **Timezone handling** — the 48h Fresh window and velocity buckets compute in UTC regardless of each feed's date format. → test in Task 5.
- **Scraped text containing HTML/script** is sanitized on ingest before storage. → test in Task 4.

---

### Task 1: Project scaffold & configuration

**Files:**
- Create: `pyproject.toml`, `docker-compose.yml`, `src/cvenom/__init__.py`, `src/cvenom/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings` (pydantic-settings) with fields `database_url: str`, `redis_url: str`, `nvd_api_key: str | None`, `vulncheck_api_token: str | None`, `github_token: str | None`, `epss_percentile_threshold: float = 0.95`, `fresh_cvss_floor: float = 9.0`, `fresh_window_hours: int = 48`, `loud_window_hours: int = 72`, `velocity_window_days: int = 30`, `backfill_days: int = 90`; and `get_settings() -> Settings` (cached).

- [ ] **Step 1: Write the failing test**
```python
def test_settings_defaults_and_env_override(monkeypatch):
    from cvenom.config import Settings
    s = Settings(database_url="postgresql://x", redis_url="redis://y")
    assert s.epss_percentile_threshold == 0.95
    assert s.fresh_cvss_floor == 9.0
    assert s.fresh_window_hours == 48
    assert s.nvd_api_key is None
    monkeypatch.setenv("FRESH_WINDOW_HOURS", "24")
    assert Settings(database_url="postgresql://x", redis_url="redis://y").fresh_window_hours == 24
```
- [ ] **Step 2: Run test to verify it fails** — `pytest tests/test_config.py -v` → FAIL (import error).
- [ ] **Step 3: Implement `Settings` and `get_settings()` in `src/cvenom/config.py`**; add deps to `pyproject.toml` (sqlalchemy, alembic, psycopg[binary], celery, redis, httpx, pydantic, pydantic-settings, bleach, fastapi, uvicorn; dev: pytest, pytest-asyncio, respx); write `docker-compose.yml` with `postgres:16` and `redis:7` services.
- [ ] **Step 4: Run test to verify it passes** — `pytest tests/test_config.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat: project scaffold and configuration"`

---

### Task 2: Database models, session, and migrations

**Files:**
- Create: `src/cvenom/db.py`, `src/cvenom/models.py`, `src/cvenom/schemas.py`, `alembic.ini`, `migrations/env.py`, `migrations/versions/0001_initial.py`, `tests/conftest.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: `Settings` (Task 1).
- Produces:
  - Pydantic DTOs in `schemas.py`: `NormalizedCve` (all fields optional except `cve_id: str`: `published: datetime | None`, `cvss`, `epss`, `epss_percentile`, `kev: bool = False`, `kev_added`, `kev_source`, `poc_badge: bool = False`, `patch_available: bool | None`, `affected: list[str] = []`, `summary: str | None`) and `NormalizedStory` (`url: str`, `source: str`, `title: str`, `summary: str`, `published: datetime`).
  - SQLAlchemy models `Cve` (pk `cve_id: str`; `published: datetime(tz)`, `cvss: float | None`, `epss: float | None`, `epss_percentile: float | None`, `kev: bool = False`, `kev_added: date | None`, `kev_source: str | None`, `poc_badge: bool = False`, `patch_available: bool | None`, `affected: JSONB`, `summary: str`, `updated_at: datetime`), `Story` (pk `id`; `url: str unique`, `content_hash: str`, `source`, `title`, `summary`, `published`, `created_at`), `StoryCveLink` (composite pk `story_id`, `cve_id`), `CollectorRun` (`collector: str pk`, `last_run: datetime | None`, `state: JSONB`).
  - BRIN index on `Cve.published`, `Story.published`.
  - `session_scope() -> contextmanager[Session]` and `engine` in `db.py`.
  - `upsert_cve(session, data: NormalizedCve) -> Cve` — insert or merge by `cve_id`; merges non-null fields; **never sets `kev` from True back to False**; unions `affected`.
  - `db_session` pytest fixture (transactional, rolled back per test) in `conftest.py`.

- [ ] **Step 1: Write the failing tests**
```python
def test_upsert_merges_signals_across_feeds(db_session):
    from cvenom.models import Cve
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    from datetime import datetime, timezone
    pub = datetime(2026,10,21,tzinfo=timezone.utc)
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-109618", published=pub, cvss=9.2))
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-109618", epss=0.97, epss_percentile=0.99, kev=True, kev_source="cisa"))
    row = db_session.get(Cve, "CVE-2026-109618")
    assert row.cvss == 9.2 and row.epss == 0.97 and row.kev is True
    assert db_session.query(Cve).count() == 1  # merged, not duplicated

def test_kev_flag_is_not_cleared_by_later_feed(db_session):
    from cvenom.db import upsert_cve
    from cvenom.schemas import NormalizedCve
    from cvenom.models import Cve
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-1", kev=True))
    upsert_cve(db_session, NormalizedCve(cve_id="CVE-2026-1", kev=False))
    assert db_session.get(Cve, "CVE-2026-1").kev is True
```
- [ ] **Step 2: Run to verify it fails** — `pytest tests/test_models.py -v` → FAIL.
- [ ] **Step 3: Implement** models, `db.py`, `upsert_cve` (merge rule above), the Alembic initial migration (with BRIN indexes), and the `db_session` fixture (`conftest.py` creates schema against the compose Postgres, wraps each test in a rolled-back transaction).
- [ ] **Step 4: Run to verify it passes** — `pytest tests/test_models.py -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: data models, session, initial migration"`

---

### Task 3: CVE extraction & story linking

**Files:**
- Create: `src/cvenom/extract.py`
- Test: `tests/test_extract.py`

**Interfaces:**
- Consumes: `Story`, `StoryCveLink` (Task 2).
- Produces: `extract_cve_ids(text: str) -> set[str]` (regex `CVE-\d{4}-\d{4,}`, upper-cased, deduped); `link_story(session, story: Story, cve_ids: set[str]) -> None` (creates `StoryCveLink` rows, idempotent).

- [ ] **Step 1: Write the failing test**
```python
def test_extract_cve_ids_finds_all_and_dedupes():
    from cvenom.extract import extract_cve_ids
    txt = "PHP2Shell: cve-2026-109618 and CVE-2026-109619; again CVE-2026-109618."
    assert extract_cve_ids(txt) == {"CVE-2026-109618", "CVE-2026-109619"}

def test_extract_handles_empty_and_none():
    from cvenom.extract import extract_cve_ids
    assert extract_cve_ids("") == set()
    assert extract_cve_ids(None) == set()
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `extract_cve_ids` and `link_story`** in `src/cvenom/extract.py`.
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: CVE extraction and story linking"`

---

### Task 4: Dedup & text-sanitization utilities

**Files:**
- Create: `src/cvenom/textutil.py`
- Test: `tests/test_textutil.py`

**Interfaces:**
- Produces: `content_hash(title: str, summary: str) -> str` (stable sha256 hex of normalized text); `sanitize_text(raw: str | None) -> str` (strip all HTML/scripts to plain text via bleach, collapse whitespace); `find_existing_story(session, url: str, content_hash: str) -> Story | None`.

- [ ] **Step 1: Write the failing tests** (includes Review-Focus XSS line)
```python
def test_sanitize_strips_script_and_html():
    from cvenom.textutil import sanitize_text
    assert sanitize_text("<b>PHP</b><script>alert(1)</script> RCE") == "PHP RCE"
    assert sanitize_text(None) == ""

def test_content_hash_is_stable_and_order_sensitive():
    from cvenom.textutil import content_hash
    assert content_hash("t","s") == content_hash("t","s")
    assert content_hash("t","s") != content_hash("s","t")
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement** `content_hash`, `sanitize_text` (bleach, `tags=[]`, `strip=True`), `find_existing_story` (by `url` else `content_hash`).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: dedup and sanitization utilities"`

---

### Task 5: Lane-scoring engine

**Files:**
- Create: `src/cvenom/scoring.py`
- Test: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `Settings` (Task 1).
- Produces:
  - `class Lane(str, Enum)` = `EXPLOITED, LIKELY, LOUD, FRESH`.
  - `@dataclass CveView` with `cve_id, published: datetime, cvss: float | None, epss_percentile: float | None, kev: bool, recent_story_count: int = 0, patch_available: bool | None = None, poc_badge: bool = False`.
  - `lanes_for_cve(v: CveView, now: datetime, cfg: Settings) -> set[Lane]`.
  - `heat_rank(v: CveView, now: datetime, cfg: Settings) -> float` (ordering within lanes; KEV dominates, then epss_percentile, cvss, recency, story count; small boost when `patch_available is False`).

- [ ] **Step 1: Write the failing tests** (covers KEV pin, quiet foil, EPSS percentile, and the UTC Review-Focus line)
```python
from datetime import datetime, timezone, timedelta
def _cfg():
    from cvenom.config import Settings
    return Settings(database_url="postgresql://x", redis_url="redis://y")
NOW = datetime(2026,10,26,12,tzinfo=timezone.utc)

def test_kev_item_is_exploited_and_outranks_quiet_foil():
    from cvenom.scoring import CveView, Lane, lanes_for_cve, heat_rank
    cfg=_cfg()
    php = CveView("CVE-2026-109618", NOW-timedelta(hours=5), 9.2, 0.99, True)
    foil = CveView("CVE-2026-115560", NOW-timedelta(hours=5), 9.0, 0.30, False)
    assert Lane.EXPLOITED in lanes_for_cve(php, NOW, cfg)
    assert Lane.EXPLOITED not in lanes_for_cve(foil, NOW, cfg)
    assert heat_rank(php, NOW, cfg) > heat_rank(foil, NOW, cfg)

def test_quiet_foil_is_fresh_only_not_likely():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg=_cfg()
    foil = CveView("CVE-2026-115560", NOW-timedelta(hours=5), 9.0, 0.30, False)
    assert lanes_for_cve(foil, NOW, cfg) == {Lane.FRESH}

def test_fresh_window_uses_utc_and_expires():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg=_cfg()
    old = CveView("CVE-2026-9", NOW-timedelta(hours=72), 9.5, 0.10, False)
    assert Lane.FRESH not in lanes_for_cve(old, NOW, cfg)

def test_likely_uses_percentile_threshold():
    from cvenom.scoring import CveView, Lane, lanes_for_cve
    cfg=_cfg()
    hot = CveView("CVE-2026-2", NOW-timedelta(days=10), 7.0, 0.96, False)
    assert Lane.LIKELY in lanes_for_cve(hot, NOW, cfg)
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement** `Lane`, `CveView`, `lanes_for_cve` (EXPLOITED iff `kev`; LIKELY iff `epss_percentile >= cfg.epss_percentile_threshold`; FRESH iff `cvss >= cfg.fresh_cvss_floor and now-published <= fresh_window_hours`; LOUD iff `recent_story_count >= 1`), and `heat_rank`. All datetimes compared in UTC.
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: lane-scoring engine"`

---

### Task 6: Collector framework & resilient HTTP

**Files:**
- Create: `src/cvenom/collectors/__init__.py`, `src/cvenom/collectors/base.py`
- Test: `tests/collectors/test_base.py`

**Interfaces:**
- Consumes: `NormalizedCve`, `NormalizedStory` (schemas from Task 2/1).
- Produces:
  - `@dataclass CollectorResult` with `cves: list[NormalizedCve] = []`, `stories: list[NormalizedStory] = []`, `events: list[dict] = []`.
  - `class Collector(ABC)`: class attrs `name: str`, `cadence_seconds: int`; `async def fetch(self) -> Any`; `def normalize(self, raw: Any) -> CollectorResult`; `async def run(self) -> CollectorResult` (calls `fetch` with retry, then `normalize`; on fetch failure logs and returns empty result).
  - `async def http_get_json(url, *, headers=None, params=None, retries=3, timeout=20) -> Any` — backoff on 429/5xx/timeout, raise after retries.
  - `REGISTRY: dict[str, type[Collector]]`, `register(cls)` decorator.

- [ ] **Step 1: Write the failing tests** (covers the malformed/error Review-Focus line)
```python
import pytest
@pytest.mark.asyncio
async def test_run_returns_empty_on_fetch_failure(monkeypatch):
    from cvenom.collectors.base import Collector, CollectorResult
    class Boom(Collector):
        name="boom"; cadence_seconds=60
        async def fetch(self): raise TimeoutError()
        def normalize(self, raw): return CollectorResult(cves=[object()])
    res = await Boom().run()
    assert res.cves == [] and res.stories == []

@pytest.mark.asyncio
async def test_http_get_json_retries_then_succeeds(respx_mock):
    import httpx
    from cvenom.collectors.base import http_get_json
    route = respx_mock.get("https://api.test/x")
    route.side_effect = [httpx.Response(503), httpx.Response(200, json={"ok": True})]
    assert await http_get_json("https://api.test/x", retries=3) == {"ok": True}
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement** `CollectorResult`, `Collector` (with error-swallowing `run`), `http_get_json` (exponential backoff), and the registry.
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: collector framework and resilient HTTP"`

---

### Task 7: NVD collector (with backfill window)

**Files:**
- Create: `src/cvenom/collectors/nvd.py`
- Test: `tests/collectors/test_nvd.py`

**Interfaces:**
- Consumes: `Collector`, `http_get_json` (Task 6); `Settings` (Task 1).
- Produces: `class NvdCollector(Collector)` (`name="nvd"`, `cadence_seconds=7200`); `async def fetch(self, since: datetime | None = None)` (uses `pubStartDate`/`pubEndDate`; `since` defaults to now − `backfill_days` on first run, else last window; sends `apiKey` header when set); `normalize` → `CollectorResult(cves=[NormalizedCve...])` reading CVSS 3.1 base score and published date.

- [ ] **Step 1: Write the failing test** — feed a recorded NVD 2.0 JSON fixture via `respx`; assert one `NormalizedCve` with `cve_id`, `cvss`, tz-aware `published`.
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `NvdCollector`** (map NVD 2.0 `vulnerabilities[].cve`; prefer CVSS v3.1 metric; parse dates to UTC; `since` window from `settings.backfill_days`).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: NVD collector with backfill window"`

---

### Task 8: EPSS collector

**Files:**
- Create: `src/cvenom/collectors/epss.py`
- Test: `tests/collectors/test_epss.py`

**Interfaces:**
- Produces: `class EpssCollector(Collector)` (`name="epss"`, `cadence_seconds=7200`); `normalize` → `CollectorResult(cves=[NormalizedCve(cve_id, epss, epss_percentile)...])` from the FIRST EPSS API JSON.

- [ ] **Step 1: Write the failing test** — respx fixture of EPSS JSON (`data: [{cve, epss, percentile}]`); assert `NormalizedCve` carries `epss` and `epss_percentile` as floats.
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `EpssCollector`.**
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: EPSS collector"`

---

### Task 9: CISA KEV collector with diff detection

**Files:**
- Create: `src/cvenom/collectors/kev.py`
- Test: `tests/collectors/test_kev.py`

**Interfaces:**
- Consumes: `Collector` (Task 6); `CollectorRun` (Task 2).
- Produces: `class KevCollector(Collector)` (`name="cisa_kev"`, `cadence_seconds=3600`); `normalize` → `CollectorResult` with `cves=[NormalizedCve(cve_id, kev=True, kev_added, kev_source="cisa")...]`; `def diff(self, seen: set[str], current: set[str]) -> list[dict]` returning `[{"type":"kev_added","cve_id":...}]` for newly-seen entries. Run persists the seen set in `CollectorRun.state`.

- [ ] **Step 1: Write the failing tests** (covers the re-run idempotency Review-Focus line)
```python
def test_diff_emits_only_new_entries():
    from cvenom.collectors.kev import KevCollector
    k = KevCollector()
    first = k.diff(seen=set(), current={"CVE-2026-109618","CVE-2026-109619"})
    assert {e["cve_id"] for e in first} == {"CVE-2026-109618","CVE-2026-109619"}
    second = k.diff(seen={"CVE-2026-109618","CVE-2026-109619"}, current={"CVE-2026-109618","CVE-2026-109619"})
    assert second == []
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `KevCollector`** (parse KEV catalog JSON; `diff`; event emission).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: CISA KEV collector with diff detection"`

---

### Task 10: VulnCheck Community KEV collector

**Files:**
- Create: `src/cvenom/collectors/vulncheck.py`
- Test: `tests/collectors/test_vulncheck.py`

**Interfaces:**
- Produces: `class VulnCheckCollector(Collector)` (`name="vulncheck_kev"`, `cadence_seconds=3600`); sends token when `settings.vulncheck_api_token` set, and **returns an empty result (no error) when the token is absent**; `normalize` → `CollectorResult` with `cves=[NormalizedCve(cve_id, kev=True, kev_source="vulncheck")...]`.

- [ ] **Step 1: Write the failing tests** — (a) with token, respx fixture → KEV-flagged `NormalizedCve`s; (b) without token → `run()` returns empty result and makes no HTTP call.
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `VulnCheckCollector`** (token-gated).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: VulnCheck Community KEV collector"`

---

### Task 11: OSV + GHSA collector (patch-availability)

**Files:**
- Create: `src/cvenom/collectors/osv.py`
- Test: `tests/collectors/test_osv.py`

**Interfaces:**
- Produces: `class OsvCollector(Collector)` (`name="osv"`, `cadence_seconds=7200`); `normalize` → `CollectorResult` with `cves=[NormalizedCve(cve_id, patch_available, affected)...]`, where `patch_available` is `True` when the OSV/GHSA record carries a `ranges[].events[].fixed` version, else `False`; `affected` captures package names.

- [ ] **Step 1: Write the failing tests** — respx fixtures: one record with a `fixed` event → `patch_available is True`; one without → `patch_available is False`.
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `OsvCollector`** (map OSV aliases to `CVE-...`; derive `patch_available` from fixed-version events).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: OSV and GHSA collector with patch-availability"`

---

### Task 12: Ingestion pipeline

**Files:**
- Create: `src/cvenom/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `upsert_cve` (Task 2), `extract_cve_ids`/`link_story` (Task 3), `content_hash`/`sanitize_text`/`find_existing_story` (Task 4), `CollectorResult` (Task 6).
- Produces: `def ingest(session, result: CollectorResult) -> None` — within one transaction: upsert every `cve`; for each story, sanitize title/summary, skip if `find_existing_story` matches, else insert and `link_story` to `extract_cve_ids(title+summary)`; persist `events` is out of scope here (Plan 3 alert engine consumes them). `def lane_views(session, now: datetime) -> dict[Lane, list[CveView]]` — build `CveView`s (with `recent_story_count` from `StoryCveLink` within `loud_window_hours`) and bucket by `lanes_for_cve`, ordered by `heat_rank`.

- [ ] **Step 1: Write the failing tests** (covers idempotency + end-to-end lane assignment)
```python
def test_ingest_is_idempotent_and_links_stories(db_session):
    from cvenom.pipeline import ingest
    from cvenom.collectors.base import CollectorResult
    from cvenom.schemas import NormalizedCve, NormalizedStory
    from datetime import datetime, timezone
    pub = datetime(2026,10,21,tzinfo=timezone.utc)
    r = CollectorResult(
        cves=[NormalizedCve(cve_id="CVE-2026-109618", published=pub, cvss=9.2, kev=True)],
        stories=[NormalizedStory(url="https://x/a", source="THN", title="PHP2Shell CVE-2026-109618", summary="rce", published=pub)])
    ingest(db_session, r); ingest(db_session, r)  # twice
    from cvenom.models import Story, StoryCveLink
    assert db_session.query(Story).count() == 1
    assert db_session.query(StoryCveLink).count() == 1

def test_lane_views_place_kev_in_exploited(db_session):
    from cvenom.pipeline import ingest, lane_views
    from cvenom.collectors.base import CollectorResult
    from cvenom.schemas import NormalizedCve
    from cvenom.scoring import Lane
    from datetime import datetime, timezone
    now = datetime(2026,10,21,12,tzinfo=timezone.utc)
    ingest(db_session, CollectorResult(cves=[NormalizedCve(cve_id="CVE-2026-109618", published=now, cvss=9.2, kev=True)]))
    views = lane_views(db_session, now)
    assert any(v.cve_id=="CVE-2026-109618" for v in views[Lane.EXPLOITED])
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement `ingest` and `lane_views`** (single transaction; dedup; sanitize; link; bucket).
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: ingestion pipeline and lane views"`

---

### Task 13: Celery app, tasks, and beat schedule

**Files:**
- Create: `src/cvenom/tasks.py`
- Test: `tests/test_tasks.py`

**Interfaces:**
- Consumes: `REGISTRY` (Task 6), all collectors (Tasks 7–11), `ingest` (Task 12), `Settings` (Task 1).
- Produces: `celery_app` (broker = `settings.redis_url`); `run_collector(name: str) -> dict` (sync helper: instantiate collector, `asyncio.run(collector.run())`, open a session, `ingest`, update `CollectorRun.last_run`, return a small summary); `run_collector_task` (Celery task wrapping it); `beat_schedule` built from each registered collector's `cadence_seconds`.

- [ ] **Step 1: Write the failing tests**
```python
def test_registry_contains_all_core_collectors():
    import cvenom.tasks  # triggers collector imports/registration
    from cvenom.collectors.base import REGISTRY
    assert {"nvd","epss","cisa_kev","vulncheck_kev","osv"} <= set(REGISTRY)

def test_beat_schedule_has_entry_per_collector():
    from cvenom.tasks import beat_schedule
    from cvenom.collectors.base import REGISTRY
    assert len(beat_schedule) == len(REGISTRY)
```
- [ ] **Step 2: Run to verify it fails** → FAIL.
- [ ] **Step 3: Implement** `celery_app`, `run_collector`, `run_collector_task`, and `beat_schedule`; ensure importing `tasks` registers every collector.
- [ ] **Step 4: Run to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat: Celery app, collector tasks, and beat schedule"`

---

## Self-Review

- **Spec coverage:** authoritative sources (NVD/EPSS/KEV/VulnCheck/OSV+GHSA) → Tasks 7–11; unified schema + BRIN + merge-upsert → Task 2; CVE extraction/linking → Task 3; dedup + sanitize → Task 4; lane model incl. quiet-foil/KEV-pin/percentile → Task 5; scheduling/cadences → Task 13; backfill → Task 7. Geographic/news collectors, velocity readout, API, auth, alerts, and frontend are **out of scope by design** (Plans 2–4).
- **Review Focus:** merge-upsert (T2), malformed/error responses (T6), re-run idempotency (T9, T12), UTC windows (T5), ingest sanitization (T4) — each has a named test.
- **Type consistency:** `NormalizedCve`/`NormalizedStory` (defined with the schemas in Task 2) flow through collectors → `CollectorResult` → `ingest` → `upsert_cve`; `CveView`/`Lane` shared by Task 5 and Task 12; `REGISTRY` shared by Tasks 6 and 13.
- **Proportion:** bodies are shown only for tests and a few merge rules; implementations are specified by signature. Plan is close to the size of the decisions it fixes.
