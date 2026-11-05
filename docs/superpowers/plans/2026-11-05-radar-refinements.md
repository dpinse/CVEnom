# Radar Refinements (A–E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the radar show what matters *now* (30-day lane windows, a recalibrated Situation readout), put older items one click away on a History page, explain globe hotspots in a country drawer, enrich the CVE and story drawers, and remove every `.onion` link.

**Scope:** spec sections **A–E** only, on branch `feat/radar-refinements`. Section F (instant scrape) and G (dev environment) are built on `feat/dev-env`, and H (mandatory MFA) on `feat/mfa`. This plan does not touch `tasks.py` worker hooks, compose files, the Dockerfile, `vite.config.ts`, auth code or the MFA migration.

**Architecture:**
- Backend first, frontend consumers second.
- The lane windows live in SQL (`pipeline.lane_views`) and in the pure scorer (`scoring.lanes_for_cve`), so `/api/lanes`, `/api/cves?lane=` and Situation all agree.
- One migration, **0006** (`down_revision = "0005"`). It holds the new `cve` columns, `story.details`, and the `.onion` / non-permalink ransomware cleanup, and ships in Task 2. The MFA branch's 0007 will be relinked onto it later, so 0006 must not depend on anything from that branch.
- New read endpoints (`/api/stories`, `/api/story`, `/api/geo/{cc}`) sit on the existing read router, so they inherit `_utf8_query`, `rate_limit("read")` and `public_or_user` in that order.

**Tech Stack:** Python 3.14, FastAPI, SQLAlchemy 2, Alembic, Postgres 16, Redis. Vite + React 19 + TypeScript strict, TanStack Query, MapLibre, Vitest + MSW, Playwright (chromium + firefox). No new dependencies on either side.

**Spec:** `docs/superpowers/specs/2026-11-05-radar-refinements-design.md`, sections A–E. The house constraints come from `docs/superpowers/plans/2026-11-05-cvenom-frontend.md`.

## Global Constraints

- **Backend tests on this branch** use the test Postgres on port 5434. Run them from `backend/` as `CVENOM_TEST_PG_PORT=5434 pytest ...` (see `backend/tests/conftest.py`), with Redis on `localhost:6379`. Every `pytest` command below assumes that variable is exported.
- **Frontend checks** run from `frontend/`: `npm test`, `npm run lint`, `npm run typecheck`, `npm run build`, `npm run e2e`.
- Commit locally only. Never `git push`, `git fetch` or `git pull`. Never stage `.superpowers/`.
- **Lane windows:** `EXPLOITED_WINDOW_DAYS=30` and `LIKELY_WINDOW_DAYS=30` are new. `LOUD_WINDOW_HOURS=72`, `FRESH_WINDOW_HOURS=48` and `EPSS_PERCENTILE_THRESHOLD=0.95` stay as they are. `kev_added` is a date, so "today" is the UTC date.
- **Settings have NO env prefix.** Every new `Settings` field gets a `# NAME=` line in `.env.example` (`test_env_example_covers_settings` enforces this).
- **`SessionDep` is function-scoped.** Use the shared `SessionDep` object and never a second session per request.
- **`rate_limit` runs before auth** on every `/api` route (`test_every_api_route_rate_limits_before_auth`).
- **`restricted_sources`:** anonymous callers never see individual `ransomware.live` / `ransomware_live` records. Apply the filter in SQL, in the `WHERE` before `LIMIT`/`OFFSET` and in the `count`. Aggregates (counts by kind, top sources) stay public.
- **Sanitise at ingest.**
  - Every stored text field goes through `sanitize_text`, and every string inside a JSON column goes through `_sanitize_details` / `sanitize_text`.
  - Raw URL *columns* (`story.url`, `geo_event.story_url`) are stored exactly as `validate_http_url` accepted them.
  - A link built from a JSON-column string is `safeHref(decodeEntities(s))`, which decodes exactly once.
- **Frontend XSS contract:** no `dangerouslySetInnerHTML`; render API text only through `<Text>` / `decodeEntities` (decode once); every link goes through `safeHref` / `<ExternalLink>` with `target="_blank" rel="noopener noreferrer"`.
- **No `.onion` links anywhere.** `safeHref` returns `null` for a host that is `onion` or ends in `.onion` (case-insensitive, trailing dots ignored). The backend's `validate_http_url` rejects the same hosts.
- **Dist and source URL allow-list** (`frontend/src/test/project.test.ts`). The only new remote URLs are the NVD, CISA KEV catalog, cve.org and cwe.mitre.org link prefixes. Each is an exact `{ literal: ... }` entry with a one-line justification, defined once as a complete string constant in `lib/refLinks.ts`.
- **The token stays in memory only** (unchanged). The CSP stays exactly as it is, with no `unsafe-*`. nginx `add_header` lines stay at server level. The drawers never render `<img>`.
- **Dependencies:** npm deps stay exact-pinned with `package-lock.json` committed, and the backend lockfile stays hash-pinned. This plan adds no dependency. If one ever becomes necessary, regenerate `backend/requirements.lock` per its header (`uv pip compile ... --generate-hashes --python-platform linux --python-version 3.14`).

## Review Focus

- **A quiet month.** When nothing was KEV-listed in 30 days, the Exploited lane must read as calm, not broken: it shows an explanatory empty state with a link to History, and Situation shows Calm. A KEV row with a NULL `kev_added` (VulnCheck without a date) is excluded from the lane but still found in History. Tests in Tasks 1 and 8.
- **The UTC day boundary.** At 23:30 UTC, or for a viewer in UTC−5 at 21:00 local, the lane window and Situation must use the UTC date, not local time. A listing dated exactly `today − 30` is in; one dated `today − 31` is out. Tests in Tasks 1 and 7.
- **Legacy rows and links after migration 0006.** Existing CVEs have NULL new fields and `[]` lists, so the drawer omits those sections instead of showing empty headers. A shared `?story=<old .onion url>` link shows "not found" and never echoes the URL. Tests in Task 9.
- **Paging past the end of History.** A shared link with `page=40` after the data shrank must show an empty page that reports the real total and offers "first page", not an error or a spinner. Tests in Tasks 5 and 8: the API returns `items: []` with the true `total`, and the UI renders the "No results on this page" state with a link back to page 1.
- **Back and forward between drawers.** Moving CVE → country → story through chips and hotspots, then pressing Back, must show the previous drawer: one dialog at a time, with focus inside it. Selections are single-valued URL params, so Back restores the previous one. Test in Task 10 (e2e: open the CVE, select the country from the hotspot list, Back gives the CVE dialog again and exactly one `[role=dialog]` exists).

---

### Task 1: Lane recency windows (spec A, backend)

**Files:**
- Modify:
  - `backend/src/cvenom/config.py`
  - `backend/src/cvenom/scoring.py`
  - `backend/src/cvenom/pipeline.py` (`lane_views`)
  - `.env.example`
- Test:
  - `backend/tests/test_scoring.py`
  - `backend/tests/test_pipeline.py`
  - `backend/tests/api/test_read_api.py`

**Interfaces:**
- Produces:
  - `Settings.exploited_window_days: int = 30` and `Settings.likely_window_days: int = 30`.
  - `CveView` gains `kev_added: date | None = None`.
  - `lanes_for_cve(v, now, cfg)`:
    - **EXPLOITED** iff `v.kev and v.kev_added is not None and v.kev_added >= _utc(now).date() - timedelta(days=cfg.exploited_window_days)`.
    - **LIKELY** iff `epss_percentile >= threshold and v.published is not None and _utc(now) - _utc(v.published) <= timedelta(days=cfg.likely_window_days)`.
    - LOUD and FRESH are unchanged.
  - `lane_views(session, now)`:
    - The candidate `or_` uses `and_(Cve.kev.is_(True), Cve.kev_added >= kev_cutoff_date)` and `and_(Cve.epss_percentile >= thr, Cve.published >= likely_cutoff)`.
    - It fills `CveView.kev_added`.
    - EXPLOITED sorts by `(-kev_added.toordinal(), -heat_rank, cve_id)`. The other lanes keep `(-heat_rank, cve_id)`.
  - `/api/cves?lane=` follows automatically, because it calls `lane_views`.

- [ ] **Step 1: Write the failing tests.**
  - `test_exploited_window_boundary`: with `now = 2026-11-05T23:30Z`, `kev_added = 2026-10-06` (today − 30) is EXPLOITED and `2026-10-05` is not.
  - `test_kev_without_date_not_exploited`.
  - `test_likely_requires_publish_within_window`: EPSS 0.99 published 29 days ago is LIKELY; 31 days ago is not; `published=None` is not.
  - `test_lane_views_exploited_newest_listing_first`: an older listing with EPSS 0.99 sorts after a newer listing with EPSS 0.10.
  - `test_lane_filter_follows_windows` (read API): `/api/cves?lane=EXPLOITED` excludes a KEV listed 40 days ago, but `/api/cves?kev=true` still returns it (the History path).
  - Update existing fixtures that build KEV rows or views without `kev_added` so they keep their intent.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/test_scoring.py tests/test_pipeline.py tests/api/test_read_api.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Add `# EXPLOITED_WINDOW_DAYS=30` and `# LIKELY_WINDOW_DAYS=30` to `.env.example` next to `LOUD_WINDOW_HOURS`.
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest tests/test_scoring.py tests/test_pipeline.py tests/api/ tests/test_packaging.py -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(lanes): 30-day windows for Exploited and Likely, newest KEV listing first`
---

### Task 2: Migration 0006, new CVE/story fields, and backend `.onion` rejection (spec D, E)

**Files:**
- Create: `backend/migrations/versions/0006_cve_details_onion_cleanup.py`
- Modify:
  - `backend/src/cvenom/models.py` (`Cve`, `Story`)
  - `backend/src/cvenom/schemas.py`
  - `backend/src/cvenom/db.py` (`upsert_cve`)
  - `backend/src/cvenom/pipeline.py` (`_sanitized`, `_ingest_story`)
- Test:
  - `backend/tests/test_schemas.py`
  - `backend/tests/test_models.py`
  - `backend/tests/test_pipeline.py`
  - `backend/tests/test_migrations.py`

**Interfaces:**
- Produces: these `Cve` columns, all nullable unless stated.

  | Column | Type | Constraint |
  | --- | --- | --- |
  | `kev_name` | Text | |
  | `kev_action` | Text | |
  | `kev_due` | Date | |
  | `kev_ransomware` | Boolean | |
  | `kev_notes` | Text | |
  | `cvss_vector` | String(255) | |
  | `cvss_severity` | String(16) | |
  | `cwes` | JSONB | NOT NULL, server default `'[]'` |
  | `references` | JSONB | NOT NULL, server default `'[]'` |
  | `last_modified` | timestamptz | |

  `references` is a Postgres reserved word: SQLAlchemy quotes it, and any raw SQL must write `"references"`.
- Produces: `Story.details`, JSONB, NOT NULL, server default `'{}'`. It holds the ransomware.live context (Task 4) and outlives the 30-day geo retention.
- Produces: new `NormalizedCve` fields.
  - `kev_name`, `kev_action`, `kev_notes`: `str | None`.
  - `kev_due: date | None`.
  - `kev_ransomware: bool | None`.
  - `cvss_vector: str | None` (≤ 255).
  - `cvss_severity: Literal["NONE","LOW","MEDIUM","HIGH","CRITICAL"] | None`: an unknown value becomes `None`; it never fails the record.
  - `cwes: list[str] | None = None`: keep only `^CWE-\d{1,6}$`, dedupe in order, cap at 20.
  - `references: list[CveReference] | None = None`:
    - `CveReference(url: str, tags: list[str])`. The url passes `validate_http_url`. Tags: at most 10, each a str of 64 chars or fewer.
    - The validator runs `mode="before"`: it drops invalid entries and caps at 20, and never fails the record.
  - `last_modified: datetime | None`, passed through `bound_datetime`.
  - `None` means "not provided", which is how a KEV record avoids wiping NVD lists.
- Produces: `NormalizedStory.details: dict = Field(default_factory=dict)`.
- Produces: `validate_http_url` raises `ValueError("onion urls are not allowed")` when `parts.hostname.rstrip(".").lower()` is `onion` or ends with `.onion`.
- Produces: `upsert_cve` merge rules.
  - Add `cvss_vector`, `cvss_severity` and `last_modified` to `_MERGE_FIELDS`, so a non-null value overwrites.
  - `kev_name`, `kev_action`, `kev_due` and `kev_notes`: a non-null incoming value overwrites iff `data.kev_source == "cisa"` or the stored value is NULL. CISA beats VulnCheck, as with `kev_source`.
  - `kev_ransomware`: an incoming non-null value gives `row.kev_ransomware = (row.kev_ransomware is True) or data.kev_ransomware`, so True is sticky.
  - `cwes` and `references`: overwrite when the incoming value is not `None`.
- Produces: `_sanitized` also sanitises `kev_name`, `kev_action`, `kev_notes`, `cvss_vector`, each reference's `url` and `tags`, and each CWE. `_ingest_story` stores `_sanitize_details(story.details)`.
- Migration 0006 (`revision = "0006"`, `down_revision = "0005"`; the MFA branch's 0007 is relinked onto it later):
  - `upgrade` adds the columns, then runs the data cleanup. `ONION` is the Postgres regex `'^[a-z][a-z0-9+.-]*://([^/?#@]*@)?[^/?#:@]*\.onion\.?(:[0-9]*)?([/?#]|$)'`.
    ```sql
    DELETE FROM story WHERE source = 'ransomware.live' AND url NOT LIKE 'https://www.ransomware.live/%';
    DELETE FROM story WHERE url ~* ONION;
    UPDATE geo_event SET story_url = NULL
      WHERE story_url ~* ONION
         OR (source = 'ransomware_live' AND story_url NOT LIKE 'https://www.ransomware.live/%');
    ```
    The first statement deletes every non-permalink ransomware.live story, not only `.onion` ones. A legacy row keyed on the victim's website would otherwise block the permalink re-ingest forever through the `content_hash` dedupe (same title and summary).
  - `downgrade` drops the columns. The deleted rows are not restored; say so in the docstring.

- [ ] **Step 1: Write the failing tests.** Reproduce the `.onion` bug first:
```python
@pytest.mark.parametrize("url", [
    "http://abcdef.onion/", "https://ABC.ONION/x", "http://abc.onion.:80/p", "http://sub.abc.onion",
])
def test_validate_http_url_rejects_onion(url):
    with pytest.raises(ValueError):
        validate_http_url(url)

@pytest.mark.parametrize("url", ["https://onion.example.com/", "https://example.com/x.onion"])
def test_validate_http_url_allows_onion_lookalikes(url):
    assert validate_http_url(url) == url
```
  Also add:
  - `test_normalized_cve_drops_bad_references_and_caps_20`: 25 references, including one `javascript:` and one `.onion`, give 20 valid entries, and the record is still created.
  - `test_cwes_filtered_and_capped`: `NVD-CWE-Other` is dropped.
  - `test_unknown_severity_is_none`.
  - `test_upsert_kev_details_cisa_wins_over_vulncheck`: VulnCheck first then CISA gives CISA values; CISA first then VulnCheck keeps the CISA values.
  - `test_upsert_kev_ransomware_sticky_true`.
  - `test_upsert_kev_record_does_not_wipe_nvd_lists`.
  - `test_ingest_sanitizes_new_text_and_story_details`: `<script>` in `kev_name` and in `details["victim"]` is stored entity-escaped with no tag.
  - `test_migration_0006_cleanup`, in a scratch DB:
    - Upgrade to `0005` and insert, via SQL:
      - a ransomware.live story on `.onion`;
      - one on the victim website;
      - one on a permalink;
      - a news story on `.onion`;
      - a news story on clearnet;
      - geo events with a `.onion`, a website and a permalink `story_url`.
    - Upgrade to `0006` and assert that only the permalink ransomware story and the clearnet news story remain, and that only the permalink `story_url` survives.
    - Downgrade to `0005` and assert that it succeeds.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/test_schemas.py tests/test_pipeline.py tests/test_migrations.py -v`. Expected: the `.onion` tests FAIL (URLs are accepted today), and the field and migration tests FAIL.
- [ ] **Step 3: Implement** the model, schema, merge, sanitisation and migration.
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest -v` (the full backend suite, because the URL validator is shared). Expected: PASS.
- [ ] **Step 5: Commit.** `feat(data): migration 0006 for KEV/NVD detail columns, story details and .onion cleanup`
---

### Task 3: KEV, VulnCheck and NVD collect the new fields (spec D)

**Files:**
- Modify:
  - `backend/src/cvenom/collectors/kev.py`
  - `backend/src/cvenom/collectors/vulncheck.py`
  - `backend/src/cvenom/collectors/nvd.py`
- Test:
  - `backend/tests/collectors/test_kev.py`
  - `backend/tests/collectors/test_vulncheck.py`
  - `backend/tests/collectors/test_nvd.py`

**Interfaces:**
- Consumes: the `NormalizedCve` fields from Task 2.
- Produces:
  - **CISA KEV** maps `vulnerabilityName`→`kev_name`, `requiredAction`→`kev_action`, `dueDate`→`kev_due` (an unparseable date gives `None`, never a skipped record), `knownRansomwareCampaignUse`→`kev_ransomware` (`"Known"`→True, `"Unknown"`→False, else None) and `notes`→`kev_notes`. A non-str value gives `None`.
  - **VulnCheck** (field names unverified, so parse aliases defensively): `vulnerabilityName`; `required_action` | `requiredAction`; `dueDate` | `due_date`; `knownRansomwareCampaignUse`; `notes`. An absent field gives `None`.
  - **NVD:**
    - `_metric(metrics) -> dict | None` returns the chosen `cvssData` (V3.1, then V3.0; Primary preferred, as `_cvss` does today).
    - `cvss` (unchanged), `cvss_vector` = `vectorString` and `cvss_severity` = `baseSeverity` all come from that one entry.
    - `cwes` comes from `cve.weaknesses[*].description[*].value`.
    - `references` comes from `cve.references[*]` as `{url, tags}`.
    - `last_modified` comes from `cve.lastModified`.
    - All of this stays inside the existing per-record `try`.

- [ ] **Step 1: Write the failing tests.**
  - `test_kev_maps_detail_fields`.
  - `test_kev_bad_due_date_keeps_record`.
  - `test_kev_rerun_backfills_existing_row` (db): a `Cve` row with `kev=True`, `kev_name=None`, then `ingest(normalize(feed))`, gives `kev_name` set.
  - `test_vulncheck_maps_aliases_and_tolerates_absence`.
  - `test_nvd_maps_vector_severity_cwes_refs_last_modified`: inline record with V3.1 Primary plus Secondary, two CWEs (one `NVD-CWE-noinfo`), and 25 references, one `.onion`. It gives the Primary vector, 1 CWE and 20 references with no `.onion`.
  - `test_nvd_record_without_metrics_or_weaknesses`: lists come out `None` and the record is kept.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/collectors/test_kev.py tests/collectors/test_vulncheck.py tests/collectors/test_nvd.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the mappings.
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest tests/collectors -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(collectors): keep KEV name/action/due/ransomware/notes and NVD vector/CWEs/references`
---

### Task 4: ransomware.live permalinks, never `post_url` (spec E)

**Files:**
- Modify: `backend/src/cvenom/collectors/ransomware.py` (rewrite `_one` / `_with_urls`; update the docstring: field names confirmed by the user on 2026-11-05)
- Test: `backend/tests/collectors/test_ransomware.py`

**Interfaces:**
- Consumes: `NormalizedStory.details` (Task 2); `validate_http_url` with `.onion` rejection.
- Produces:
  - `PERMALINK_PREFIX = "https://www.ransomware.live/"`.
  - `permalink_for(rec: dict) -> str | None`:
    - It returns `rec["permalink"]` when that is a str that starts with `PERMALINK_PREFIX` and passes `validate_http_url`.
    - Otherwise, when `rec["id"]` is a non-empty str or int that isn't a bool, it returns `PERMALINK_PREFIX + "id/" + urllib.parse.quote(str(id), safe="")`.
    - Otherwise it returns `None`.
  - A record whose `permalink_for` is `None` is skipped entirely: no story and no geo event.
  - **Story:**
    - `url` = permalink; `title` = `f"{victim} listed by {group}"` (unchanged); `summary` = `description`; `published` = observed.
    - `details` holds: `group`, `victim`, `country`, `activity`, `website` (text, never a link), `attackdate`, `discovered` (as given), and `press`.
    - `press` is a list. It accepts a str or a list of str, keeps only values that pass `validate_http_url`, caps at 5, and is `[]` when null.
  - **Geo event:** `story_url` = permalink. `external_id` and `details` are unchanged.
  - `post_url`, `screenshot`, `ransom`, `data_size` and `infostealer` are never read into any output.

- [ ] **Step 1: Write the failing tests.** The reproduction goes first:
  - `test_story_url_is_permalink_not_post_url`: a record with `permalink=https://www.ransomware.live/id/abc`, `post_url=http://leak.onion/x` and `website=https://victim.example`. The story URL must equal the permalink. Today it is the website or `post_url`.

  Then add:
  - `test_foreign_permalink_falls_back_to_id` (`permalink=https://evil.example/id/1`).
  - `test_id_is_url_quoted` (`id="a/../b c"` gives `https://www.ransomware.live/id/a%2F..%2Fb%20c`).
  - `test_record_without_permalink_or_id_is_skipped`.
  - `test_post_url_and_screenshot_never_stored`: the `repr` of the whole `CollectorResult` contains neither `.onion` nor the screenshot URL.
  - `test_details_fields_and_press_filtering`: press is `["https://news.example/a", "javascript:x", "http://p.onion/"]`, giving one entry, and website is plain text.
  - `test_geo_event_story_url_is_permalink`.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/collectors/test_ransomware.py -v`. Expected: the reproduction FAILS.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest tests/collectors/test_ransomware.py tests/test_geo_pipeline.py -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `fix(ransomware): key stories on ransomware.live permalinks; never store post_url`
---

### Task 5: Read API for CVE detail fields, History search and story lookup (spec B, D)

**Files:**
- Modify:
  - `backend/src/cvenom/api/routes_read.py`
  - `backend/src/cvenom/api/schemas_api.py`
  - `backend/src/cvenom/readmodels.py`
- Test: `backend/tests/api/test_history_api.py` (create), `backend/tests/api/test_read_api.py`

**Interfaces:**
- Consumes: the Task 2 columns.
- Produces: `CveDetail` gains these fields. `CveItem` and the lanes stay lean.
  - `kev_name`, `kev_action`, `kev_notes`: `str | None`.
  - `kev_due: date | None`.
  - `kev_ransomware: bool | None`.
  - `cvss_vector`, `cvss_severity`: `str | None`.
  - `cwes: list[str]`.
  - `references: list[CveReferenceOut{url: str, tags: list[str]}]`. The reader keeps only dict entries with a str `url`.
  - `last_modified: UtcDatetime | None`.
- Produces: `GET /api/cves` additions.
  - `kev_from: date | None` and `kev_to: date | None` filter on `Cve.kev_added`, with `kev_to` inclusive.
  - `sort: Literal["kev_added","published","cvss"] | None`. The default is `kev_added` when `kev=true`, else `published`.
  - Orders, each with `nulls_last`:
    - `kev_added` → `kev_added desc, cve_id`;
    - `published` → `published desc, cve_id`;
    - `cvss` → `cvss desc, published desc, cve_id`.
- Produces: `readmodels._story_dicts(session, stories) -> list[dict]`, the link aggregation shared with `loud_stories`, which is refactored to use it.
- Produces: `readmodels.search_stories(session, *, q, source, start, end, page, page_size, exclude_sources) -> tuple[list[dict], int]`.
  - `q` matches `Story.title` or `Story.summary` with `ILIKE` and the shared `_escape_like` (moved to readmodels and imported by routes_read).
  - `source` is an exact match.
  - Order: `published desc, id desc`.
  - `exclude_sources` applies in `WHERE` for both the page and the count.
- Produces: `GET /api/stories?q=&source=&from=&to=&page=&page_size=` → `StoryListOut{items: list[StoryItem], page, page_size, total}`.
  - `StoryItem` has the `LoudStory` fields; keep `LoudStory` as an alias.
  - Parameters: `q` ≤ 200; `source` ≤ 64; `page` 1..10000; `page_size` 1..100, default 25.
- Produces: `readmodels.story_detail(session, url, exclude_sources) -> dict | None` and `GET /api/story?url=` (url ≤ 2048) → `StoryDetailOut(StoryItem){details: dict}`.
  - It returns 404 `{"error":"not_found"}` for a missing story and for a restricted source when anonymous. The two 404s are identical.
  - It is not cached.
- Produces: `CACHE_PATHS["/api/stories"] = frozenset({"source","from","to","page","page_size"})`. Free-text `q` bypasses the anonymous cache, so arbitrary search strings cannot fill Redis. `/api/stories/loud` keeps its own longer-prefix entry.

- [ ] **Step 1: Write the failing tests** in `test_history_api.py`.
  - `test_detail_includes_new_fields`: NULL and `[]` defaults serialise.
  - `test_kev_date_range_filter`.
  - `test_sort_default_kev_added_when_kev_only`.
  - `test_sort_cvss_and_invalid_sort_422`.
  - `test_stories_q_matches_title_and_summary_with_like_escaping`: `%`, `_` and `\` are literal.
  - `test_stories_nul_is_422`.
  - `test_stories_newest_first_and_total`.
  - `test_stories_anon_restricted_filtered_before_limit`: 30 ransomware.live stories newer than 1 news story. Anonymous with `page_size=25` returns the news story and `total == 1`; authed returns `total == 31`.
  - `test_stories_anon_cached_without_q_bypassed_with_q` (`x-cache` HIT on the second plain call; absent with `q`).
  - `test_story_detail_found_with_details_for_authed`.
  - `test_story_detail_restricted_anon_404_identical_to_missing`.
  - `test_story_url_too_long_422`.
  - `test_page_past_end_returns_empty_items_with_true_total`: both `/api/cves` and `/api/stories`.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/api/test_history_api.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest tests/api -v`. Expected: PASS, including `test_limiter_order.py`.
- [ ] **Step 5: Commit.** `feat(api): CVE detail fields, KEV-date filter and sort, stories search and story lookup`
---

### Task 6: Country activity endpoint (spec C, backend)

**Files:**
- Modify:
  - `backend/src/cvenom/readmodels.py`
  - `backend/src/cvenom/api/routes_read.py`
  - `backend/src/cvenom/api/schemas_api.py`
- Test: `backend/tests/api/test_geo_country_api.py` (create)

**Interfaces:**
- Produces: `readmodels.country_activity(session, now, cc: str, *, window_hours: int, include_events: bool) -> dict`, returning:
  - `country_code`, `window_hours`.
  - `counts: list[{kind, events, magnitude}]`: only the kinds present, ordered by events desc.
  - `top_sources: list[{source, events}]`: at most 5.
  - `trend: list[{bucket: datetime, events: int}]`: hourly UTC buckets (`date_trunc('hour', timezone('UTC', observed_at))`), zero-filled, with exactly `window_hours` points, oldest first.
  - `events`: when `include_events`, at most 50, newest first, as `CountryEventOut{source, kind, label, magnitude, observed_at, asn, story_url, details}`; otherwise `None`.
- Produces: `GET /api/geo/{cc}?window_hours=24`.
  - `cc` is `Path(pattern="^[A-Z]{2}$")`, so anything else gets a 422. A well-formed code with no data gets 200 with empty counts.
  - `window_hours` is 1..168.
  - `include_events=user is not None`. Anonymous callers get `events: null` for every source, so the cached anonymous body never carries individual events. Signed-in users get every source, ransomware victims included.
  - The existing `CACHE_PATHS["/api/geo"]` prefix already caches the anonymous response (allowed param `window_hours`). Keep it.
- Produces: the `CountryActivityOut` response model.

- [ ] **Step 1: Write the failing tests.**
  - `test_country_invalid_codes_422`: parametrise over `de`, `DEU`, `D1` and `%00`.
  - `test_country_unknown_but_wellformed_is_empty_200` (`ZZ`).
  - `test_country_counts_and_top_sources`: 6 sources give 5.
  - `test_country_trend_zero_filled_length`: `window_hours=24` gives 24 points.
  - `test_country_anon_events_null_but_victim_count_public`.
  - `test_country_authed_events_capped_50_newest_first_include_ransomware`.
  - `test_country_anon_second_call_cache_hit_and_authed_bypasses`.
  - `test_country_window_bounds_422` (0 and 169).
- [ ] **Step 2: Run the tests and confirm they fail.** Run `pytest tests/api/test_geo_country_api.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `pytest tests/api -v`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(api): GET /api/geo/{cc} country activity`
---

### Task 7: Frontend foundations: `.onion` guard, reference links, Situation, types and hooks (spec A, C, D, E)

**Files:**
- Create: `frontend/src/lib/refLinks.ts`, `frontend/src/lib/iso3166.ts`
- Modify:
  - `frontend/src/lib/text.tsx`
  - `frontend/src/lib/situation.ts`
  - `frontend/src/lib/types.ts`
  - `frontend/src/lib/queries.ts`
  - `frontend/src/lib/live.ts`
  - `frontend/src/lib/selection.ts`
  - `frontend/src/test/project.test.ts`
- Test:
  - `frontend/src/lib/text.test.tsx`
  - `frontend/src/lib/situation.test.ts`
  - `frontend/src/lib/queries.test.tsx`
  - `frontend/src/lib/refLinks.test.ts` (create)
  - `frontend/src/lib/selection.test.ts` (create)

**Interfaces:**
- Consumes: the Task 5 and Task 6 response shapes.
- Produces:
  - `safeHref` rejects `.onion` hosts, as described in Global Constraints.
  - `refLinks.ts`:
    - Four complete string-literal constants:
      - `NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"`
      - `KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="`
      - `CVE_ORG = "https://www.cve.org/CVERecord?id="`
      - `CWE_DEF = "https://cwe.mitre.org/data/definitions/"`
    - `nvdUrl(id)`, `kevUrl(id)` and `cveOrgUrl(id)` each return `string | null`; `null` unless `CVE_ID_RE` matches.
    - `cweUrl(cwe: string): string | null` returns `CWE_DEF + n + ".html"` for `^CWE-(\d{1,6})$`.
    - Add the four as `{ literal }` entries in `ALLOWED` (`project.test.ts`), each with a one-line justification ("drawer reference link, `<a href>` only").
  - `iso3166.ts`: `ISO_ALPHA2: ReadonlySet<string>`, the 249 officially assigned codes plus `XK` (Kosovo, used by Cloudflare Radar), and `isIso3166Alpha2(cc: string): boolean`.
  - `situationLevel(exploited: CveItem[], now: Date): Situation`, by `kev_added` UTC date:
    - **Severe**, `lit` 4: any listing with `isRecentKevDate` (today or yesterday UTC, unchanged), OR ≥ 6 listings with `kev_added >= isoDate(now − 7 days)`.
    - **High**, `lit` 3: ≥ 3 listings in that 7-day span.
    - **Elevated**, `lit` 2: ≥ 1 listing.
    - **Calm**, `lit` 1: none.
  - `types.ts`:
    - `CveDetail` gains the Task 5 fields and `CveReference`.
    - `CveQuery` gains `kev_from`, `kev_to` and `sort`.
    - New: `StoryItem`, `StoryListOut`, `StoryQuery {q, source, from, to, page, page_size}`, `StoryDetailOut`, `CountryActivity` and `CountryEvent`.
  - `queries.ts`:
    - Query keys: `qk.stories(params)` → `["stories", params]`, `qk.story(url)` → `["story", url]`, `qk.country(cc, h)` → `["geo", "country", cc, h]`.
    - Hooks: `useStorySearch(params: StoryQuery)` (keepPreviousData), `useStory(url: string | undefined)` and `useCountry(cc: string | undefined, windowHours = 24)`.
    - `storySearchPath(params): string`.
  - `live.ts` `INVALIDATES`: `stories` → `["loud", "stories", "story"]`. `geo` already covers country through the `"geo"` root.
  - `selection.ts`:
    - `Selection` gains `{ kind: "country"; cc: string }`, parsed from `?country=` only when `isIso3166Alpha2`.
    - `select()` clears `cve`, `story` and `country` before setting one.

- [ ] **Step 1: Write the failing tests.** The `.onion` reproduction goes first:
```ts
test("safeHref rejects .onion hosts", () => {
  for (const bad of ["http://abcdef.onion/", "https://ABC.ONION/x", "http://abc.onion.:80/", "http://a.b.onion"])
    expect(safeHref(bad)).toBeNull();
  expect(safeHref("https://onion.example.com/")).toBe("https://onion.example.com/");
  expect(safeHref("https://example.com/x.onion")).toBe("https://example.com/x.onion");
});
```
  Then add:
  - **Situation:** 0 → Calm; one listing 20 days old → Elevated; 3 in 7 days → High; 6 in 7 days → Severe; one listed today → Severe; 2 in 7 days plus 10 older → Elevated; at `now = 2026-11-05T23:30Z`, a listing dated `2026-10-29` counts inside 7 days.
  - **refLinks:** `nvdUrl("CVE-2026-1001")`; `nvdUrl("x")` is null; `cweUrl("CWE-79")` gives `https://cwe.mitre.org/data/definitions/79.html`; `cweUrl("NVD-CWE-Other")` is null.
  - **selection:** `?country=DE` parses; `de`, `QQ` and `DEU` are ignored; selecting a CVE clears `country`.
  - **queries:** `useStory` requests `/api/story?url=<encoded>`; a `stories` live message invalidates `stories` and `story`.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `npx vitest run src/lib src/test/project.test.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `npm test && npm run lint && npm run typecheck`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(frontend): .onion-safe links, reference link builders, new Situation rule, history/country hooks`
---

### Task 8: History page (spec B, frontend)

**Files:**
- Rename: `frontend/src/pages/Search.tsx` → `frontend/src/pages/History.tsx` and `Search.test.tsx` → `History.test.tsx` (use `git mv`)
- Create: `frontend/src/pages/HistoryStories.tsx`
- Modify:
  - `frontend/src/routes.tsx`
  - `frontend/src/routes.test.tsx`
  - `frontend/src/components/CommandBar.tsx` (nav link)
  - `frontend/src/components/Lanes.tsx` (lane subtitles and empty states)
  - `frontend/src/styles/search.css`
- Test:
  - `frontend/src/pages/History.test.tsx`
  - `frontend/src/routes.test.tsx`
  - `frontend/src/components/Lanes.test.tsx`
  - `frontend/e2e/smoke.spec.ts`

**Interfaces:**
- Consumes: `useCveSearch`, `useStorySearch`, `useSelection`, and the types (Task 7).
- Produces:
  - **Routes and nav:**
    - Route `history` (inside `PublicOrUser`). `<h1>History</h1>`, with tabs "CVEs" / "Stories" chosen by `?tab=stories`; the default is CVEs.
    - The tabs are buttons in a `role="tablist"`, keyboard operable.
    - Switching tab clears all filter params.
    - Route `search` renders `<Navigate to={{ pathname: "/history", search: loc.search }} replace />`.
    - CommandBar gains a `NavLink` "History" to `/history`.
  - **CVEs tab:**
    - `parseFilters` additionally reads `kev_from` and `kev_to` (with `validDate`) and `sort` (`kev_added` | `published` | `cvss`; anything else is dropped).
    - The UI adds a KEV-added date range and a sort select labelled "Newest KEV listing" / "Newest published" / "Highest CVSS".
    - The default shown is "Newest KEV listing" when "KEV only" is on, else "Newest published".
    - `sort` goes into the URL only when it differs from that default.
  - **Stories tab (`HistoryStories`):**
    - `parseStoryFilters(sp): StoryQuery & { page: number }` reads `q` (≤ 200, the same trim and slice as CVEs), `source` (free text ≤ 64), `from`, `to` and `page`.
    - Debounce: 300 ms.
    - Rows show the decoded title, the source, the relative time and CVE chips.
    - Clicking a row calls `select({ kind: "story", url })`. Pages are 50 items with prev/next.
  - **Lanes:**
    - Exploited subtitle: "KEV-listed, last 30 days". Likely subtitle: "published ≤ 30 days, high EPSS".
    - The Exploited empty state reads "No new KEV listings in the last 30 days", followed by a `Link` "Browse History" to `/history?kev=true`.

- [ ] **Step 1: Write the failing tests.**
  - `/search?q=log4j&kev=true` lands on `/history?q=log4j&kev=true`.
  - `?tab=stories` renders the Stories tab, and switching tabs clears `q`.
  - `kev_from`, `kev_to` and `sort` round-trip through the URL, and `sort=bogus` is dropped.
  - With KEV only on, the sort select shows "Newest KEV listing" and no `sort` param is written.
  - Stories typing debounces to one `/api/stories` request.
  - A story row click sets `?story=<url>`.
  - A 201-character `q` is truncated.
  - `page=40` beyond the total shows "No results on this page" with a link to page 1, for both tabs.
  - An empty Exploited lane shows the copy and a History link to `/history?kev=true`.
  - e2e (`smoke.spec.ts`): visiting `/search?q=x` ends at `/history?q=x`, and the "History" nav link is visible. Add `/api/cves` and `/api/stories` fixtures to `e2e/harness.ts`.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `npx vitest run src/pages src/routes.test.tsx src/components/Lanes.test.tsx`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `npm test && npm run lint && npm run typecheck && npm run build && npm run e2e`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(frontend): History page with CVE and story tabs; /search redirects`
---

### Task 9: Richer CVE and story drawers, and the overflow fix (spec D, E)

**Files:**
- Create: `frontend/e2e/drawer-overflow.spec.ts`, `frontend/e2e/fixtures/story.json`
- Modify:
  - `frontend/src/components/CveDetail.tsx`
  - `frontend/src/components/StoryDetail.tsx`
  - `frontend/src/styles/drawer.css`
  - `frontend/e2e/harness.ts`
  - `frontend/e2e/fixtures/cve-CVE-2026-1001.json`
- Test: `frontend/src/components/Drawer.test.tsx`, `frontend/e2e/drawer-overflow.spec.ts`

**Interfaces:**
- Consumes: `useCve`, `useStory`, `refLinks`, `safeHref`, `ExternalLink`, `<Text>`, `decodeEntities` (Task 7).
- Produces: a `CveDetailView` that renders spec D's ten sections in order.
  1. **Header:** the vulnerability name, plus chips for severity (`cvss_severity`, else derived with `severityOf(cvss)`), KEV and "ransomware use" (only when `kev_ransomware === true`).
  2. **Summary.**
  3. **Scores:** CVSS with the vector in mono, then EPSS score and percentile.
  4. **Key dates:** published, last modified, KEV added and CISA due date. Show only the dates present.
  5. **Required action.**
  6. **Affected products, then Weaknesses:** CWE ids through `ExternalLink href={cweUrl(c)}`.
  7. **References:** each one is the hostname of `safeHref(decodeEntities(url))` linked through `ExternalLink`, plus tags as chips. An unsafe URL shows plain decoded text.
  8. **Related stories.**
  9. **Geo activity**, as today.
  10. **Standard links:** NVD, CISA KEV (only when `kev`) and cve.org.

  A section whose data is NULL or empty is omitted entirely, heading included.
- Produces: a `StoryDetail` that reads `useStory(url)` and no longer reads the loud feed.
  - For every story: the title, source, published time, summary, linked CVE chips (each selects that CVE) and the article link (`ExternalLink`).
  - **When `source` is `ransomware.live`:**
    - a details block with victim, group, sector (`details.activity`), country (`countryName`), attack date and discovered date;
    - the website as `<Text>` (never an anchor);
    - the description;
    - press links via `ExternalLink href={decodeEntities(p)}`;
    - `RansomwareCredit`;
    - an article link labelled "View on ransomware.live".
  - No `<img>` is ever rendered.
  - On a 404: "Story not found (it may have been removed)". The URL is never echoed.
- Produces: `drawer.css` wrapping fixes, decided by the reproduction. Candidates are `min-width: 0` on flex and grid children, `overflow-wrap: anywhere` on the title, summary, references and kv values, and `max-width: 100%` on chips.

- [ ] **Step 1: Write the failing e2e reproduction** in `drawer-overflow.spec.ts`. Override `/api/cves/CVE-2026-1001` with a 600-character unbroken summary, a 300-character unbroken reference URL and a long vector. Do the same for `/api/story` with a long unbroken title and summary.
  - Run at 1280×800 and at 400×800.
  - Open each drawer and assert `scrollWidth <= clientWidth` for `[role=dialog]` and `.dbody`, and `document.documentElement.scrollWidth <= innerWidth`.
- [ ] **Step 2: Run it and confirm it fails.**
  - Run `npx playwright test e2e/drawer-overflow.spec.ts`. Expected: FAIL on at least one case.
  - If every case passes on the current code, widen the reproduction (story drawer, chips row, kv rows, Firefox) until one fails. Do not change any CSS without a red test.
  - Record which element overflowed; it goes in the commit message.
- [ ] **Step 3: Write the failing unit tests** in `Drawer.test.tsx`.
  - Every new section renders from a full fixture, and a fixture with NULLs and `[]` renders no empty section headings.
  - A CWE links to `cwe.mitre.org`.
  - A reference shows its hostname and tags.
  - A `javascript:` reference and a `.onion` reference render no `<a>`.
  - The NVD and cve.org links are always present; the CISA KEV link only when `kev`. All of them have `rel="noopener noreferrer"`.
  - A story outside the loud feed loads through `/api/story`.
  - The ransomware details render; the website is not a link; a `.onion` press link renders no `<a>`; the drawer contains no `<img>`.
  - A story 404 shows the not-found copy without the URL text.
- [ ] **Step 4: Implement** both views and the CSS fix. Update the e2e fixtures and harness routes (`/api/story`).
- [ ] **Step 5: Run everything and confirm it passes.** Run `npm test && npm run lint && npm run typecheck && npm run build && npm run e2e`. Expected: PASS on chromium and firefox.
- [ ] **Step 6: Commit.** `feat(frontend): richer CVE and story drawers; fix drawer overflow (<element>)`
---

### Task 10: Country drawer from the globe (spec C, frontend)

**Files:**
- Create: `frontend/src/components/CountryDetail.tsx`, `frontend/e2e/fixtures/geo-DE.json`
- Modify:
  - `frontend/src/components/globeMap.ts` (click handler)
  - `frontend/src/components/Globe.tsx`
  - `frontend/src/components/GlobeChrome.tsx` (`HotspotList` buttons)
  - `frontend/src/components/DrawerHost.tsx`
  - `frontend/src/styles/globe.css`
  - `frontend/src/styles/drawer.css`
  - `frontend/e2e/harness.ts`
- Test:
  - `frontend/src/components/Globe.test.tsx`
  - `frontend/src/components/Drawer.test.tsx`
  - `frontend/e2e/smoke.spec.ts`

**Interfaces:**
- Consumes: `useCountry`, `Selection` `country`, `isIso3166Alpha2` (Task 7); `countryName`, `KIND_LABEL`, `KindSwatch`, `useGlobe().flyTo`.
- Produces:
  - **The map:**
    - `MountOptions.onHotspotClick?: (iso2: string) => void`.
    - `mountGlobe` registers `map.on("click", "hotspots", ...)`, reading `features[0].properties.iso2`, and a pointer cursor on `mouseenter`/`mouseleave` of `hotspots`.
    - A drag never fires a click (MapLibre semantics).
    - `Globe` passes `(cc) => select({ kind: "country", cc })` when `isIso3166Alpha2(cc)`.
  - **`HotspotList`:**
    - Each item becomes a `<button type="button">` that selects the country; Enter and Space work natively.
    - The list is visually hidden until it has focus: a `.hotspot-list` panel shows on `:focus-within` with a visible focus ring.
  - **`DrawerHost`:** renders `<Drawer heading={countryName(cc)}>` with `<CountryDetail cc={cc} />` for a country selection.
  - **`CountryDetail`:**
    - On load it calls `flyTo(cc)`.
    - Counts by kind, each with a `KindSwatch` and `KIND_LABEL`.
    - Top sources.
    - An inline-SVG `CountryTrend`. It renders only when the total events are ≥ 3 and at least 2 buckets are non-zero; otherwise the section is omitted.
    - **Signed-in users:** the event list shows the kind, the decoded label, the source, the relative time, `ExternalLink` to `story_url`, and `RansomwareCredit` when any event's source is `ransomware_live`.
    - **Anonymous users:** "Sign in to see individual events".
    - Empty counts: "No activity recorded for this country in the last 24 hours".

- [ ] **Step 1: Write the failing tests.**
  - A mocked-maplibre click on `hotspots` with `iso2: "DE"` sets `?country=DE`, and `iso2: "QQ"` does nothing.
  - A `HotspotList` button pressed with Enter sets `?country=DE`.
  - `?country=de` opens no drawer.
  - `CountryDetail`:
    - anonymous: counts and no event list;
    - authed: events plus the ransomware credit;
    - a sparse trend is not rendered;
    - a `.onion` `story_url` renders no `<a>`;
    - a label containing `&lt;script&gt;` renders literally.
  - e2e:
    - Tab to the first hotspot button and press Enter. The dialog shows "Germany" and the URL has `country=DE`.
    - Esc closes the drawer.
    - At 400 px the drawer has no horizontal overflow.
    - Back and forward: open the CVE drawer, then the country from the hotspot list. Back shows the CVE dialog again, and there is exactly one `[role=dialog]`.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `npx vitest run src/components` and `npx playwright test e2e/smoke.spec.ts`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.** Run `npm test && npm run lint && npm run typecheck && npm run build && npm run e2e`. Expected: PASS, including the firefox globe pixel check.
- [ ] **Step 5: Commit.** `feat(frontend): country drawer from globe hotspots and the keyboard hotspot list`

---

## Self-Review

- **Spec coverage (A–E):**
  - A lane windows and settings: Task 1. Situation: Task 7. The lane filter in search: Task 1, through `lane_views`.
  - B History, backend: Task 5. Frontend, with the redirect and nav label: Task 8.
  - C country drawer API: Task 6. Globe click, keyboard hotspot list and drawer: Task 10.
  - D new columns and migration 0006: Task 2. Collectors: Task 3. Detail API: Task 5. CVE and story drawer layouts and the overflow e2e: Task 9. Standard-link hosts on the allow-list: Task 7.
  - E `safeHref` `.onion`: Task 7. Backend URL guard and migration cleanup: Task 2. Permalink collector, `post_url` never stored: Task 4. Ransomware story drawer with no screenshot: Task 9.
  - F, G and H are out of scope; they are built on other branches.
- **Type consistency:**
  - `CveView.kev_added` (T1) is filled by `lane_views` (T1).
  - The `NormalizedCve` and `NormalizedStory.details` fields (T2) are used by T3 and T4.
  - The `CveDetail` and `StoryDetailOut` fields (T5) are mirrored in `types.ts` (T7) and consumed in T9.
  - `CountryActivity` (T6) is consumed by `useCountry` (T7) and `CountryDetail` (T10).
  - `Selection` `country` (T7) is used by T10.
- **Review Focus:** each of the five lines has a named test in its owning task (T1, T5, T7, T8, T9, T10).
- **Proportion:** code bodies appear only for the `.onion` guard tests and the migration's cleanup SQL. Everything else is signatures, values and assertions.
