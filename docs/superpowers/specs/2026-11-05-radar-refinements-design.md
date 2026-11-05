# Radar refinements: design

**Date:** 2026-11-05
**Branch:** `feat/radar-refinements` (from `main` @ 6c27b9f)
**Why:** this is the first real run of CVEnom after the four plans merged. The board fills with CVEs from 2002 onwards, Situation is always "Severe", the drawers are thin, ransomware.live links point at `.onion` leak sites, and every code change means a manual Docker rebuild. This batch makes the radar mean "what matters *now*", with history one click away.

## Goals
1. Each lane shows recent items only, newest or most relevant first. Older items can be reached through a History page.
2. Clicking a globe hotspot explains what is happening in that country.
3. The CVE and story drawers carry real context, not just a link and the affected products.
4. No `.onion` links appear anywhere.
5. A fresh deploy or restart fills the radar within minutes, not hours.
6. A dev setup where code changes show up in seconds without rebuilding images.

## Non-goals
- No new data sources, no breach or watchlist features (Plan 5 stays parked), and no changes to alert-rule semantics. Alerts are already event-triggered and unaffected by the lane windows.

## Anti-goals
- Don't hide exploited CVEs so aggressively that a quiet month looks empty and the radar feels broken.
- Don't loosen the anonymous visibility rules: ransomware victim records stay signed-in only.

## Decisions (made by the user, 2026-11-05)
| Topic | Decision |
| --- | --- |
| Exploited now | KEV listings from the **last 30 days**, newest listing first |
| Likely next | CVEs **published in the last 30 days** with EPSS percentile ≥ the threshold (default 0.95) |
| Loud now | Stories from the **last 72 h**. This is unchanged. |
| Past items | A **History page** for everyone who can view the radar |
| Globe click | Opens a **country drawer** that you can share with `?country=DE` |

## The changes

### A. Lane recency windows (backend)
- **New settings:** `EXPLOITED_WINDOW_DAYS=30` and `LIKELY_WINDOW_DAYS=30`. `LOUD_WINDOW_HOURS=72` and `FRESH_WINDOW_HOURS=48` stay as they are.
- **Exploited:** `kev = true AND kev_added >= today - 30 days`. `kev_added` is a date, so "today" is in UTC. Sort by `kev_added` descending, then by heat.
- **Likely:** `epss_percentile >= threshold AND published >= now - 30 days`. Sort by heat.
- **Lane filter in search:** `lane_views` drives both `/api/lanes` and the `lane=` filter on search, so the search filter follows the windows automatically.
- **Situation readout** *(my call; please check).* Count KEV listings in the Exploited lane:

  | Level | Rule |
  | --- | --- |
  | Severe | any listing in the last 24 h, or 6 or more in the last 7 days |
  | High | 3 or more in the last 7 days |
  | Elevated | at least 1 in the 30-day window |
  | Calm | none |

  Today "Severe" fires whenever there are 6 or more items, which is always true once the lane holds every KEV.

### B. History page (frontend + backend)
- `/history` replaces `/search`, and `/search` redirects there (my call). The nav label changes to "History". It has two tabs.
- **CVEs tab:** keeps today's search box and filters (lane, KEV source, minimum CVSS, KEV only, published date range). New additions:
  - a **KEV-added date range**;
  - a **sort** order: newest KEV listing (the default when "KEV only" is on), newest published, or highest CVSS.

  The backend adds `kev_from`, `kev_to` and `sort` to `/api/cves`.
- **Stories tab:** a new `GET /api/stories?q=&source=&from=&to=&page=&page_size=`.
  - The search box matches titles and summaries. LIKE wildcards are escaped and NUL bytes rejected, the same as CVE search.
  - Results are newest first.
  - Anonymous callers never see restricted sources (ransomware.live), and the filter is applied in SQL.
  - The endpoint has the usual rate limits and the anonymous cache.
- Every row opens the existing drawer.

### C. Country drawer (globe click)
- Clicking a hotspot, or pressing Enter on it in the keyboard-accessible hotspot list, sets `?country=XX` and opens the drawer. The code must be a validated ISO-3166 alpha-2.
- **New endpoint `GET /api/geo/{cc}?window_hours=24`:**
  - **For everyone:** counts by kind (scanning, botnet C2, outage, BGP, ransomware) and the top sources, aggregated.
  - **For signed-in users only:** up to 50 recent individual events, ransomware victims included, following the fair-use rule.
- **The drawer shows:** the country name, the counts, a mini trend if the data supports it, and the event list for signed-in users.

### D. Richer CVE and story detail
Collect and store data the collectors currently throw away.

**New `cve` columns (migration 0006):**
- From the CISA and VulnCheck KEV feeds: `kev_name` (the vulnerability name), `kev_action` (required action), `kev_due` (due date), `kev_ransomware` (known ransomware campaign use) and `kev_notes`.
- From NVD: `cvss_vector`, `cvss_severity`, `cwes` (a JSON list), `references` (a JSON list of `{url, tags}`, capped at 20), `last_modified`.
- All text is sanitised at ingest, as now.
- KEV re-reads its full catalog on every run, so existing rows backfill on the next KEV run. NVD fills in through its normal backfill window.

**CVE drawer layout:**
1. **Header:** the CVE id, the vulnerability name, and severity, KEV and ransomware-use chips.
2. **Summary.**
3. **Scores:** the CVSS score with its vector, plus the EPSS score and percentile.
4. **Key dates:** published, last modified, KEV added, CISA due date.
5. **Required action**, from CISA.
6. **Affected products** and **weaknesses** (CWE ids, linked to cwe.mitre.org).
7. **References**, showing the hostname and tags.
8. **Related stories.**
9. **Geo activity.**
10. **Standard links:** NVD, CISA KEV and MITRE CVE. These are built from the CVE id; their hosts are added to the dist URL allow-list.

**Story drawer:**
- **Every story:** the title, source, published time, summary, the linked CVEs (each opens its CVE), and the article link.
- **ransomware.live stories** (signed-in only): the group, victim, country, sector and discovered date. The link follows section E.

**Overflow bug:** a long summary currently runs off the screen when the drawer opens. Reproduce it on desktop and at 400 px, fix the wrapping, and add an e2e check that the drawer has no horizontal overflow when it holds a long, unbroken summary.

### E. No `.onion` links
- `safeHref` rejects any host ending in `.onion`, everywhere.
- **ransomware.live record shape:** the user supplied the field names of a live record on 2026-11-05. Each record carries:
  - **Identity and timing:** `id`, `victim`, `group`, `discovered`, `attackdate`.
  - **Context:** `country`, `activity` (the sector), `website`, `description`, `press` (nullable), `ransom` (nullable), `data_size` (nullable), `infostealer`.
  - **Links and media:** `screenshot`, `post_url` (a `.onion` leak-site URL), and `permalink`, e.g. `https://www.ransomware.live/id/<id>`.
- **The story URL** (which is also the dedupe key) is the `permalink`, and it must start with `https://www.ransomware.live/`.
  - If a record has no valid permalink, the collector builds one from `id`: `https://www.ransomware.live/id/<url-quoted id>`.
  - A record with neither is skipped. `post_url` is never stored or shown.
- **Migration 0006** deletes existing ransomware.live stories whose URL is a `.onion` URL, and clears `story_url` on geo events that point at one. The `/victims/recent` feed re-ingests those victims under their permalinks on the next run *(my call; the cost is that a victim already gone from the recent feed drops off the history)*.
- **ransomware.live story drawer:** shows the victim, group, sector (`activity`), country, attack and discovered dates, the website as plain text, the description, and press links if present (through `safeHref`). The link goes to the ransomware.live page.
  - The `screenshot` is never embedded. It is a remote image, so the CSP blocks it, and it can show leaked data.

### F. Instant first scrape
- When the worker starts, it queues one run of every registered collector, the same way GeoIP already bootstraps.
- The per-collector Redis lock and row lock prevent double runs, and collectors without a key skip as they do today.
- `README.md` and `docs/deploy.md` document both this and the manual trigger command.

### G. Dev environment with live reload
- **`docker-compose.dev.yml`** (root): Postgres and Redis, as now, plus these services.
  - **api:** `uvicorn --reload`, with `backend/src` bind-mounted.
  - **worker and beat:** run under `watchfiles`, so they restart when the Python code changes.
  - **frontend:** the Vite dev server with HMR on `localhost:5173`, with `frontend/` bind-mounted and its own `node_modules` volume. It proxies `/api` and the WebSocket to `api:8000`.
- **Images:** reuse the backend image's Python with dev dependencies, plus a Node image for the frontend. Rebuild only when a dependency changes.
- **Windows and OneDrive bind mounts:** file events are unreliable there, so the watchers poll (`WATCHFILES_FORCE_POLLING`, Vite `server.watch.usePolling`).
- **Ports and secrets:** every published port is localhost-only. Dev secrets come from an untracked `.env.dev`, and an example file is committed.
- **Docs:** one command, `docker compose -f docker-compose.dev.yml up`, documented in the README.

## Approaches considered
- **Lane windows: SQL filter vs a UI-only filter.** The SQL filter keeps payloads small and makes every consumer agree: lanes, the search `lane=` filter, and Situation. A UI-only filter would still ship 1,500 rows. **Chose SQL.**
- **History: a new page vs extending Search.** Search already has most of the filters, so extending it and renaming it avoids two near-duplicate pages. **Chose to extend and rename.**
- **Dev environment: compose with bind mounts vs host-only (venv plus `npm run dev`).** Host-only is faster on Windows, but it needs Python, Node and Celery set up on the host. Compose gives a one-command setup that matches production images. **Chose compose.** The host-only route stays documented.

## Left to the builder
- Exact drawer styling, matched to the existing tokens and mockup.
- Mini-trend rendering in the country drawer (skip it if the data is too sparse).
- Exact CWE and reference parsing from NVD 2.0 JSON.

## Open
- None. The ransomware.live record shape was confirmed by the user (section E).
