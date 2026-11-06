# Radar refinements security review (`feat/radar-refinements`, fb4ade7..4517256)

**Result: 0 High, 1 Medium, 2 Low, 5 Info.** Access control, cache isolation, SSRF and the frontend XSS contract all hold. The one Medium is an ingest-ordering gap: tag or comment markup inside a URL or `website` value splits `.onion` past every backend onion check, and `sanitize_text` then strips the markup *after* validation. The result is a `.onion` string in stored JSON columns, and as plain text in the ransomware drawer's Website row. No `.onion` **link** is ever rendered, because the frontend `safeHref` (WHATWG host) is a working second layer.

Method: I read the full diff by area. I probed with scratchpad Python in the backend venv (`validate_http_url`, `sanitize_text`, `_story_details`, `permalink_for`, NFKC timing, FastAPI `Path(pattern=)` anchoring through TestClient) and with Node (`new URL()` host normalisation for default-ignorable code points, `%2e`, trailing dots, a bare `onion` host). No DB tests, nginx or containers were run. The CSP was confirmed unchanged by its absence from the diff (`nginx.conf` and `vite.config.ts` are untouched).

## Findings

### High
None.

### Medium

**M1. Markup inside a URL or `website` defeats the backend `.onion` checks; the stored value is a `.onion` string, and `website` is shown as text.**
- **Where:**
  - `backend/src/cvenom/schemas.py:80-133` (`_check_http_url` / `validate_http_url`): validates the raw string and its entity-decoded form.
  - `backend/src/cvenom/pipeline.py:137` (`url = sanitize_text(ref.url)`) and `pipeline.py:169` (`_sanitize_details`, used for `story.details.press` and `website`): sanitise the value after validation.
  - `backend/src/cvenom/collectors/ransomware.py:128-134`: the `website` guard runs `contains_onion` on the raw text.
  - `frontend/src/components/StoryDetail.tsx:25,45`: renders `website` through `<Text>`.
- **Probed** (each value accepted, then shown as it is stored):

  | Input | Stored as |
  | --- | --- |
  | `https://x.on<b>ion/a` | `https://x.onion/a` |
  | `https://x.on<!---->ion/a` | `https://x.onion/a` |
  | `https://x.onion<x>/a` | `https://x.onion/a` |
  | `https://x.oni&lt;b&gt;on/` | `https://x.onion/` (the entity-decoded check sees host `x.oni<b>on`) |
  | website `x.on<b>ion` | kept by the R3 guard, stored and rendered as `x.onion` |
  | `NormalizedCve(references=[{"url": "https://x.on<b>ion/"}])` | accepted |

  The cause is that bleach `strip=True` removes tags and comments after the onion checks have already passed.
- **Impact:**
  - A leak-site address reaches storage in `cve.references[*].url` and `story.details.press[*]`. It also reaches output as plain text in the ransomware story drawer's **Website** row, which signed-in users see. This breaks the R3 intent ("a leak-site address must never reach any output") and the fix wave's goal for entity-obfuscated onions.
  - Press and reference **links** are still safe. `safeHref(decodeEntities(...))` sees host `x.onion` and renders `LinkRemoved`, never the URL text. The R7 / `?story=` path is unaffected.
- **Exploitability:** an attacker needs control of an upstream field: the ransomware.live victim `website`/`press` (gang-authored leak posts are the original source), an NVD reference URL (CNA-submitted), or an RSS item. That is low effort for a gang, but the reward is limited to a text display.
- **Fix:** validate the form that is actually stored. Either:
  - in `validate_http_url`, reject any URL containing `<`, `>`, `"` or a backtick, in the raw or the entity-decoded form (none is legal unescaped in a URL, and WHATWG forbids `<`/`>` in hosts). This closes every variant above in one line; or
  - run the checks on `html.unescape(sanitize_text(url))` as well.

  For `website`, call `contains_onion(html.unescape(sanitize_text(website)))` (or apply the same `<>` reject). Add regression tests for the three `<b>`, `<!---->` and `&lt;b&gt;` forms on press, reference and website.

### Low

**L1. `validate_http_url` has no length cap; NFKC on expanding compatibility characters is super-linear, so one long URL stalls the worker.**
- **Where:** `backend/src/cvenom/schemas.py:49-77` (`normalize_onion_text` via `_is_onion_host`) and `schemas.py:106`. It is reached from every `NormalizedStory.url` (all news collectors), each `CveReference` (NVD), each ransomware `press` item (`ransomware.py:117`; invalid items are iterated with no bound) and `geo story_url`.
- **Probed** with a host made of U+FDFA:

  | Host length | `normalize_onion_text` | stdlib `urlsplit` | `validate_http_url` total |
  | --- | --- | --- | --- |
  | 100k chars | | | 2.2 s |
  | 200k chars | ~5 s | ~4.7 s | |
  | 1M chars (3 MB, fits in the 25 MB cap) | | | **211 s** |

  The stdlib share (`urlsplit`'s `_checknetloc` NFKC) is pre-existing. This branch roughly doubles the per-URL cost and adds new call sites. The 2048 cap added in the fix wave covers only `website` and `permalink`.
- **Impact:** an availability problem only. One poisoned upstream record costs minutes of worker CPU, and it recurs every run while the record stays in the fetch window. A related, unverified risk: `story.url` is a unique btree column. A very long URL (for example a ransomware permalink built from an unbounded `id`, `ransomware.py:110`) could exceed the btree row limit. That raises a non-IntegrityError that `_retry_unique` re-raises, which would fail the whole ingest run.
- **Fix:** at the top of `validate_http_url`, reject `len(url) > 2048` before `urlsplit` or any normalisation. Cap `str(rid)` in `permalink_for` as well, or rely on the same validator by calling `_valid_url` on the built permalink.

**L2. Default-ignorable code points inside a `website` value display as a `.onion` name.**
- **Where:** `schemas.py:49-67` and `ransomware.py:131`. NFKC keeps U+00AD, U+200B, U+034F and the variation selectors, so `contains_onion("x.on­ion")` is False, and the drawer renders text that reads as `x.onion` (soft hyphen invisible).
- **Impact:** text only, signed-in only. URLs carrying these code points are already stopped at the link layer: in Node, `new URL("https://x.on­ion/").hostname` is `x.onion` (the same holds for ZWSP, CGJ and VS16), so `safeHref` returns null.
- **Fix:** in `normalize_onion_text`, strip Unicode Default_Ignorable_Code_Point characters (at minimum U+00AD, U+034F, U+180B-180F, U+200B-200F, U+2060-206F, U+FE00-FE0F, U+FEFF, U+E0000-E0FFF) before the check. This also closes the backend side of the `validate_http_url` residual.

### Info

- **I1. Raw URL column decoded as if escaped.** `frontend/src/components/CountryDetail.tsx:49` calls `safeHref(decodeEntities(e.story_url))`, but `geo_event.story_url` is a raw column (hard rule: stored exactly as validated, not entity-escaped). A legitimate `&amp;` in a raw URL would be altered. There is no security effect: the backend already validates the entity-decoded form, and only ransomware permalinks populate the column today. Use `safeHref(e.story_url)` for consistency with `StoryDetail`'s `story.url`.
- **I2. OSV backlog can become permanent.** `osv.py:93-112, 129-147`. If the owed span lies beyond the 25 MB index budget, every run streams the full 25 MB, re-truncates and rewrites `[floor, cursor]`. State is two ISO timestamps (bounded), and the per-id fetches stay capped at `MAX_IDS=1000`. There is no unbounded growth; this is a correctness and staleness issue only.
- **I3. No total deadline on the stream.** `http_stream_lines` (`base.py:208`) has only the per-read httpx timeout (20 s), so a slow-drip upstream can hold a worker for a long time within 25 MB. The same holds for the existing `_request`. Redirects are off, 3xx/4xx raise, retries stop once any body byte is read (`started`), `Retry-After` is capped, and the budget counts decoded bytes, which bounds gzip bombs. All verified.
- **I4. Unindexed story search.** `/api/stories` runs an unindexed `ILIKE` over title and summary plus a `count(*)`, which is 2 sequential scans per request. A `q` request bypasses the cache, and `page` can reach 10000 with `OFFSET` up to 999,900. This is bounded by the per-IP `read` limit and the current table size. Add a `pg_trgm` GIN index (deferred minor 4) if the story table grows.
- **I5. `id` of `..` normalises to the site root.** A ransomware `id` of `..` yields `https://www.ransomware.live/id/..`, which browsers normalise to the site root. It stays on the same host and is harmless; `quote(safe="")` stops `/`, `?` and `#` injection.

## Residual-risk rulings

| Residual | Ruling | Reason |
| --- | --- | --- |
| **R2**: migration 0006 regex misses a bare `onion` host | **Acceptable** | It also misses multiple trailing dots, `%2e`, entity-encoded or fullwidth dots and soft hyphens, but this only matters for *non-ransomware* legacy story rows and non-ransomware `geo_event.story_url`. Every legacy ransomware.live story or geo URL is removed by the permalink clause whatever its host. Clearnet news collectors are very unlikely to have stored such URLs. The frontend `safeHref` (WHATWG) blocks every variant as a link, and `StoryDetail` never echoes `story.url` text. Widening an irreversible DELETE is the larger risk. |
| Default-ignorable code points in `validate_http_url` | **Acceptable for URLs**; see L2 for the `website` text | `safeHref` (WHATWG/UTS46) maps them away and rejects the host (probed in Node). Unsafe URLs render as `LinkRemoved` or the fixed label, never as text. |
| `.onion` prose in description, summary, title, victim/group label or `kev_notes` | **Acceptable** | Text only, never linked: there is no linkifier, and all of it goes through `<Text>`. Ransomware text is signed-in only. It is the upstream's own narrative, and stripping prose would corrupt legitimate reporting about onion services. Document it as an accepted residual. M1 differs because `website` and press/reference values are *address* fields that the design explicitly promised to filter. |
| R4 (free-text `source` in the `/api/stories` cache allow-list) | **Acceptable** | Each key is created only after the anonymous per-IP `read` limit is counted (in the cache middleware itself), with a 30 s TTL and small bodies. Growth is bounded by the request rate. |
| R7 (unsafe `?story=` opens a not-found drawer with no fetch and no echo) | **Agree** | Verified in `selection.ts` and `StoryDetail.tsx`. |

## Verified clean

- **Access control**
  - The router-level dependencies run `_utf8_query`, then `rate_limit("read")`, then `public_or_user`. That covers all new routes, and `test_every_api_route_rate_limits_before_auth` enforces the order.
  - `restricted_sources` is applied in SQL:
    - `search_stories` puts it in the `WHERE` used by both `count` and the paged `SELECT`, before `LIMIT`/`OFFSET` (`readmodels.py:207-239`);
    - `story_detail` uses the same `WHERE ... LIMIT 1`.
  - `/api/story` returns one byte-identical `{"error":"not_found"}` 404 for a missing story and for a restricted one (the same query shape, so there is no status, body or meaningful timing oracle).
  - `/api/geo/{cc}` gives anonymous callers `events=None`, plus counts, top sources and trend (aggregates are public by rule).
  - `/api/cves` adds no individual-record exposure.
- **Cache**
  - `/api/geo/{cc}` is covered by the `/api/geo` prefix with only `window_hours` allowed. The keyspace is ≤ 676 country codes × 168.
  - Any `Authorization` header bypasses both lookup and store, and an invalid token returns 401 with no anonymous fallback.
  - An anonymous cached body never contains events or restricted stories.
  - `/api/story` is not cached, and `/api/stories/loud` wins the longest-prefix match over `/api/stories`.
- **Input validation**
  - **`cc`:** the pydantic-core (Rust) regex is fully anchored (`DE\n` gives 422, probed), and lowercase, Greek or fullwidth input is rejected.
  - **`q`:** ILIKE uses `_escape_like` with `escape="\\"` and bound parameters, and NUL is rejected for every query string by `_utf8_query`.
  - **Bounds:** `url` ≤ 2048, `source` ≤ 64, `q` ≤ 200, `page` 1-10000, `page_size` 1-100.
  - **Typed parameters:** `kev_from`/`kev_to` are typed `date`, and `sort` is a `Literal`.
- **SSRF**
  - All new fetch hosts are constants (OSV index, `api.osv.dev`, `api-pro.ransomware.live`), with `follow_redirects=False` everywhere.
  - The OSV id passes the `[A-Za-z0-9._:-]+` fullmatch, is not dot-only, and is `quote(safe="")`'d into the path.
  - The ransomware permalink is either a prefix-checked `https://www.ransomware.live/` URL (the trailing slash pins the host, `@` userinfo is rejected, ≤ 2048, no onion) or is built from a quoted `id`.
  - Nothing from a record is ever fetched.
- **Leak-site fields**
  - `post_url`, `url`, `screenshot`, `ransom`, `data_size` and `infostealer` are never read (`ransomware.py`).
  - Story `details` is an explicit allow-list, and the geo details hold only group and activity (and country), with `story_url` set to the permalink.
  - `?story=`, the story drawer, the press list, CVE references and country event rows all render unsafe URLs as `LinkRemoved`, a fixed label or nothing, never as URL text (fix 3d19dcf verified).
- **XSS contract**
  - Non-test `src` has no `dangerouslySetInnerHTML`, `innerHTML` or `<img>`.
  - All new API text goes through `<Text>` (decoded once). The CVE detail dates come from `fmtDate` or a raw date string as a React text node.
  - Every new anchor is an `ExternalLink` with `rel="noopener noreferrer"`. The hostname link text comes from `new URL(safe)` only after `safeHref`.
  - The refLinks prefixes are built only for `CVE_ID_RE`/`CWE-\d{1,6}` ids.
  - The dist allow-list gains exactly the 4 literals (NVD, CISA KEV, cve.org, CWE), and the CSP, nginx and Vite config are untouched.
- **URL parameters**
  - `page` is `^\d+$` within 1-10000.
  - The dates must be real calendar dates.
  - `sort`, `lane` and `source` (CVEs) are allow-listed, and `tab` is limited to `stories` or `cves`.
  - `country` must be in the ISO 3166 set and is also checked in the selection writer and the hotspot handler.
  - The Stories `source` is trimmed, sliced and URL-encoded.
- **Sanitisation at ingest**
  - `kev_name`, `kev_action`, `kev_notes`, `cvss_vector` (re-capped after escaping), the `cwes` strings, the reference URLs and tags, and all of `story.details` (recursively, keys included) go through `sanitize_text`.
  - `cvss_severity` is a `Literal`, `kev_due` is a date, and `last_modified` goes through `bound_datetime`.
  - The raw `story.url` is stored exactly as validated.
- **Migration 0006**
  - It runs inside alembic's `begin_transaction()`, so on PG the DDL and the deletes are atomic.
  - It deletes only:
    - `story` rows with `source='ransomware.live'` whose URL is not a `https://www.ransomware.live/` URL (`LIKE` has no wildcard characters in the prefix);
    - `story` rows whose `url` matches `ONION` (`~*`).
  - The only FK to `story` is `story_cve_link` (`ON DELETE CASCADE`).
  - It nulls `geo_event.story_url` for onion URLs and for non-permalink ransomware_live URLs.
  - `ONION` has no quote character (asserted). The downgrade drops columns only, and the irreversibility is documented in the docstring.
- **DoS bounds**
  - `contains_onion` on `website` and `permalink` runs only at ≤ 2048 chars.
  - The OSV state is 2 timestamps, and the stream budget is 25 MB of decoded bytes with a carried partial line bounded by the same budget.
  - The country trend has exactly `window_hours` (≤ 168) points.

## Addendum: resolution (commit 4517256, ruling R10)

The review above was run at 3d19dcf. Its Medium and both Lows were fixed in one targeted hardening commit, **4517256** `fix(security): reject markup and over-long URLs before the .onion check; strip ignorables in website text`:

- **M1 (fixed):**
  - `validate_http_url` rejects `<`, `>`, `"` and the backtick in the raw form and in the entity-decoded form.
  - The ransomware `website` guard runs `contains_onion(sanitize_text(website))`, so the check sees exactly what ingest stores.
- **L1 (fixed):** `validate_http_url` rejects any value over 2048 characters before any normalisation. A 1M-character U+FDFA host is now rejected in about 1 ms; it took 211 s before. A ransomware `id` long enough to push the permalink over 2048 characters now skips the record.
- **L2 (fixed for the required set):** `normalize_onion_text` strips category Cf, U+034F, U+180B–180F and U+FE00–FE0F before the check.

**Scoped re-review (opus):** all three ADDRESSED, with no new breakage.
- **Bypass variants:** every draft probe was re-run, plus about 30 new variants. All are rejected or dropped. The variants covered:
  - numeric and named entities for `<`;
  - nested entities;
  - markup in userinfo or port;
  - unterminated tags;
  - CDATA and processing instructions;
  - quote and backtick entities.
- **Legitimate inputs still accepted:** the lookalike hosts and paths, `&amp;` queries, and IDN hosts, including ZWNJ in Persian.
- **Call-site check:** no legitimate data is lost in practice.
- **Gates at 4517256:** backend 1336 passed. The frontend is unchanged since 3d19dcf: vitest 698 passed, 3 skipped; e2e 26 chromium + 26 firefox; lint, typecheck, format:check and build clean.

**Accepted residual (ruling R11, a follow-up):** a few invisible or bidi characters can still make the signed-in-only ransomware **Website text** read visually as `.onion`. This is text only and never a link: `safeHref` UTS46-maps these URL forms away and rejects them. The characters are:
- the variation-selector supplement U+E0100–E01EF (category Mn, not stripped);
- the Hangul and Khmer fillers U+115F, U+1160, U+17B4, U+17B5, U+3164 and U+FFA0;
- bidi controls U+202A–202E and U+2066–2069 (an RLO can display `x.noino` as `x.onion`).

The follow-up is about 3 lines: extend `_IGNORABLE_EXTRA`, and reject or strip bidi controls in `website`.

**Info items left as-is:** I1 (CountryDetail decodes the raw `story_url` column; no security effect), I2 (an OSV backlog beyond the budget can persist, though bounded), I3 (no total stream deadline), I4 (unindexed story search), I5 (an `id` of `..` normalises to the same-host root).

**Final result: 0 High, 0 Medium open, 0 Low open, 1 accepted Low residual (R11), 5 Info.**
