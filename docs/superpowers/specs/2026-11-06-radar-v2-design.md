# CVEnom Radar v2 — design

**Date:** 2026-11-06 · **Branch:** `feat/radar-v2` (local only; the user pushes and opens PRs)
**Visual reference (binding for layout and behaviour):** `docs/superpowers/design/cvenom-radar-v2-mockup.html`
(published at https://claude.ai/artifact/DPFTwGq2tccWc7kZuPUpQw). Open it in a browser; it is clickable.
Inspiration: radar.offseq.com — take ideas, never copy its copy, branding or layout verbatim.

## Why

User feedback on the current radar:
1. "Exploited now" lane is overcrowded (up to 100 rows).
2. Wants a 24h / 7d / 14d / 30d time filter.
3. Wants a top-nav split: **Dashboard** (main page) and **Threats** (replaces History).
4. Globe circles are cluttered, Europe nearly unclickable → flat map, country outlines, **choropleth shading
   (darker = more alerts)**, with a toggle back to the globe. No dots/circles.
5. Bug: KEV-listed CVEs (e.g. CVE-2026-109619, -109618) appear in "Likely next".
6. Bug: the clicked-threat summary in the drawer is cut off and runs off screen.
7. Wants a richer per-threat page: timeline, affected versions, more detail.
8. More intel sources (user picked: vendor research blogs, gov/CERT advisories, exploit signals).
9. No LLM. Everything here is structured data. (LLM enrichment is an explicit non-goal.)

## 1. Lane rules (backend `scoring.py` + `pipeline.lane_views`)

Lanes take a **range** `R ∈ {24h, 7d, 14d, 30d}` (default `7d`).

| Lane | Rule |
|---|---|
| EXPLOITED | `kev` and `kev_added` within R (date compare, UTC) |
| LIKELY | **not `kev`**, `epss_percentile ≥ epss_percentile_threshold`, `published` within `likely_window_days` (30, unchanged — independent of R) |
| LOUD | ≥1 linked story published within R (stories-only rows also within R) |
| FRESH | **not `kev`**, `cvss ≥ fresh_cvss_floor`, `published` within R |

- A KEV CVE is never "likely" and never "fresh". LOUD may still overlap with EXPLOITED by design.
- `GET /api/lanes?range=7d` returns, per lane, `total` (full count) and the top `limit` items (default 5,
  max 100) in the existing sort order. Invalid `range` → 422. Cache keys must include range and limit.
- The WebSocket/live invalidation keeps working for all ranges.
- `/api/stories/loud` accepts the same `range`.

## 2. Global time range

- Segmented control `24h | 7d | 14d | 30d` in the top bar, right side, on Dashboard and Threats (and the
  threat page, where it only affects the "where it's seen" box).
- Source of truth: URL query `?range=` (so links share it), falling back to localStorage
  (`cvenom.range`, try/catch), then `7d`. Changing it updates the URL with `replace`.
- All dashboard widgets and the Threats page refetch for the chosen range.

## 3. Navigation and routes

- Top nav: **Dashboard** (`/`) and **Threats** (`/threats`). Active item marked (`aria-current="page"`).
  Admin/account menus unchanged.
- `/threats` replaces `/history`. `/history` and `/search` redirect to `/threats`, preserving the query string
  (map old params: `kev=true` → `lane=exploited`).
- `/threats/:cveId` is the full threat page (CVE ID validated client-side with the existing CVE regex; bad
  id → not-found view without fetching).
- The existing drawer stays as a **quick view** (lane rows, map side panel, news tab chips) with an
  "Open threat page →" link. The Threats table rows navigate straight to the threat page.

## 4. Dashboard (`/`)

Top to bottom (see mockup):
1. **Summary line** — `Last 7 days` heading, then four links with counts for R:
   new KEV listings (→ Threats lane=exploited), KEV deadlines in the next 7 days (`kev_due` between today and
   today+7, → Threats lane=exploited sort=due), new critical CVEs (CVSS ≥ 9 published in R → lane=fresh),
   public exploits published in R (`poc_published` events in R → Threats poc=1). One backend endpoint
   `GET /api/summary?range=`.
2. **Map panel** — map on the left, side panel (300px) on the right; stacks under 820px.
   - Default **Flat** (MapLibre `mercator` projection), toggle **Globe** (`globe` projection). Choice persisted
     in localStorage (`cvenom.mapMode`). The existing MapLibre map is reused; switch with `setProjection`.
   - **Choropleth**: countries with activity are filled in **5 buckets**, bucket = `min(4, floor(sqrt(n/max)*5))`,
     colour = the alert colour mixed into the land colour at 16/32/50/70/90 %. Countries with no activity keep
     the land colour. Thin country outlines on every country. **Remove the circle/hotspot layer.**
   - Hover: outline highlight + tooltip `Country · N events`. Click/Enter selects a country.
   - Legend bottom-left: `fewer [5 swatches] more alerts · N countries · <range>`.
   - Side panel: default "Top countries" (8 rows: ISO code, name, bar, count). With a country selected: its
     breakdown (attack sources, ransomware victims, botnet C2, BGP hijacks — the existing `/api/geo/{cc}`
     data, filtered by R) and linked CVEs, plus "All countries" back button. The existing keyboard hotspot list
     becomes this list (keep it keyboard-accessible).
   - Geo data respects R (`/api/geo?range=`, `/api/geo/{cc}?range=`). Anonymous viewers still see only aggregated
     ransomware counts (existing rule).
3. **Lanes** — 4 columns (2 under 1100px, 1 under 560px). Each lane: tick, title, total, one-line subtitle
   (Exploited: "Added to CISA KEV or VulnCheck KEV"; Likely: "Not yet exploited, EPSS ≥ p95"; Loud: "CVEs the
   news is covering"; Fresh: "New, CVSS ≥ 9, not yet exploited"), **5 compact rows**, footer link
   "View all N in Threats →" (or "Open in Threats →" when total ≤ 5) to `/threats?lane=<k>&range=<R>`.
   - Compact row = severity dot · CVE ID · CVSS (right); one line "Vendor Product: issue" with ellipsis
     (product from `kev_name`/affected, issue from summary; full text in `title`); one meta line of at most
     three signals (lane-specific first: "KEV 1d ago" / "EPSS p98" / "7 stories" / "published 7h ago", then
     PoC, no patch). No chip wrapping. Loud lane story-only rows: title (one line) + source · age.
   - Empty lane: "Nothing in the last <range>."
4. **Volume chart** — replaces the Velocity sparkline: "New CVEs per day" (per hour for 24h), bars stacked
   by severity (crit/high/med/low from CVSS; unscored excluded and counted in a footnote), total for R.
   `GET /api/volume?range=` returns buckets. SVG, theme tokens, accessible label, table fallback for SR.

## 5. Threats page (`/threats`)

- Heading "Threats", short sentence naming the range. Tabs: **CVEs** | **News** (`?tab=news`).
- CVE filters (all in the URL): text search (CVE id, vendor, product, summary), lane chips
  (All / Exploited now / Likely next / Loud now / Fresh criticals), Public exploit, No patch, severity
  (any / critical / high and up). Sort: Severity (CVSS), EPSS, Seen (default, newest), KEV due.
- Table columns: Severity (dot, score, label) · CVE (link) · Product and issue (product line + issue line) ·
  Signals (tags KEV / PoC / no patch / news ×N) · EPSS (pN) · Seen (relative). Paginated (existing cursor or
  offset pattern from History). Count line under the table.
- "All" lane = union of the four lanes for R. Backed by extending `GET /api/cves` with `range`, `lane`,
  `poc`, `nopatch`, `sev_min`, and sort keys; keep existing params working.
- News tab: the existing stories search, filtered by R, columns Story · Source · CVEs · Published.

## 6. Threat page (`/threats/:cveId`)

Two columns (main + 300px aside; single column under 1100px). Sections in order:
1. Breadcrumb `Threats / CVE-…`; ID line (severity pill, CVE ID, CWE); H1 "Product: issue".
2. **Status line**: Exploited in the wild / Not known to be exploited · KEV due date · Public exploit / none ·
   EPSS % · Fix available / No patch yet · "Data as of <updated_at> UTC".
3. **Metrics row** (4): CVSS (version, source, severity) · EPSS (score, percentile) · KEV due date · Patch.
4. **Exploitation evidence ladder** (5 stages): Disclosed (published) · Detectable (Nuclei template exists —
   from references/`cve_event` kind `detection`; else not reached) · Public exploit (`poc_badge`/events) ·
   Exploited in the wild (KEV) · Ransomware use (`kev_ransomware`). Each stage: name + evidence/date.
5. **What to do**: CISA required action box when `kev_action` (with due date); **affected versions table**
   (Product · Affected versions · Fixed in · Source). Empty → "No version data yet. See the vendor advisory."
6. **Timeline**: chronological `cve_event` rows: date, offset from publication (`t = 0`, `+3d`, `−9d`),
   event, source. Key events bold (published, fix released, PoC, KEV added).
7. **Description**: NVD text verbatim, wrapping (`overflow-wrap:anywhere`), "Source: NVD".
8. **CVSS vector**: raw vector string + decoded metric grid (CVSS 3.x and 4.0 vectors; unknown → raw only).
9. **Weakness**: CWE id + name from a bundled MITRE CWE name map; link to cwe.mitre.org.
10. **References**: existing reference links (already safe-link-checked), labelled by kind.
11. Aside: In the news (linked stories), Related threats (same product first, then same CWE; max 4),
    Where it's seen (geo events naming this CVE in R, top 3 countries; hidden when none).
- One endpoint: extend `GET /api/cves/{id}` with `events`, `affected_versions`, `related`, `geo` (or add
  sub-resources if cleaner). Public-read rules unchanged.

## 7. Drawer fix

The CVE and story drawers must never clip or overflow horizontally: body scrolls vertically, flex/grid children
`min-width: 0`, long text/URLs wrap (`overflow-wrap: anywhere`), drawer width `min(440px, 100vw)`. Add an e2e
or component test with a very long summary and a long unbroken URL.

## 8. New data

### 8.1 `cve_event` table (migration 0008)
`id`, `cve_id` (FK cve, cascade), `kind` (enum-like string: `reserved`, `published`, `nvd_modified`,
`fix_released`, `poc_published`, `detection`, `first_news`, `kev_added`, `epss_crossed`), `occurred_at`
(timestamptz), `source` (short text), `detail` (JSONB, small), `created_at`. Unique `(cve_id, kind, source)`;
index `(kind, occurred_at)` for range counts. Written idempotently (insert … on conflict do nothing) by the
pipeline when a signal is **first** seen: publish/KEV/news/PoC/EPSS crossing threshold. Migration backfills
`published`, `kev_added`, and `first_news` (earliest linked story) from existing data. Retain forever (small).

### 8.2 Affected versions
New `cve.affected_versions` JSONB list (max 50 entries) of
`{product, vendor|null, ecosystem|null, introduced|null, fixed|null, last_affected|null, source: "OSV"|"NVD"}`.
- **OSV**: from `affected[].ranges[].events` (`introduced`/`fixed`/`last_affected`) per package
  (ecosystem + name). Also `affected[].versions` is ignored (too long).
- **NVD**: from `configurations[].nodes[].cpeMatch[]` where `vulnerable` is true:
  `versionStartIncluding/Excluding`, `versionEndIncluding/Excluding`, vendor/product parsed from the CPE 2.3 URI.
  Display "through X" for EndIncluding, "before X" for EndExcluding.
- Merge: replace entries per source on each update; dedupe; all strings sanitized with the existing
  `sanitize_text`, each ≤ 128 chars.

### 8.3 CWE names
Bundle a static `cwe-names.json` (id → name) generated from MITRE's CWE CSV (research view 1000) by a
committed script; served with the frontend bundle (no runtime fetch to MITRE).

### 8.4 New collectors (keyless)
RSS/Atom via the existing `NewsFeedCollector` (verify each URL responds with a feed before adding; drop dead
ones and note it in the ledger):
- Vendor research: Cisco Talos `https://blog.talosintelligence.com/rss/`, Palo Alto Unit 42
  `https://unit42.paloaltonetworks.com/feed/`, Check Point Research `https://research.checkpoint.com/feed/`,
  Kaspersky Securelist `https://securelist.com/feed/`, Microsoft Security Blog
  `https://www.microsoft.com/en-us/security/blog/feed/`, Google Project Zero
  `https://googleprojectzero.blogspot.com/feeds/posts/default`, Zero Day Initiative
  `https://www.zerodayinitiative.com/blog?format=rss`, Tenable Research `https://www.tenable.com/blog/feed`.
- Gov / CERT: CERT/CC `https://kb.cert.org/vuls/atomfeed/`, NCSC UK
  `https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml`, JVN `https://jvn.jp/en/rss/jvn.rdf`,
  SANS ISC `https://isc.sans.edu/rssfeed_full.xml`.
- Exploit signals:
  - **Exploit-DB** `https://www.exploit-db.com/rss.xml`: entries mentioning CVE IDs set `poc_badge`, write a
    `poc_published` event (source "Exploit-DB") and add the entry as a reference. Not shown as a news story.
  - **CIRCL OSINT MISP feed** `https://www.circl.lu/doc/misp/feed-osint/manifest.json`: poll manifest, fetch
    only events newer than the last seen timestamp (cap per run), extract `vulnerability`-type attributes →
    stories (title = event `info`, url = the event's CIRCL feed URL, source "CIRCL OSINT") linked to CVEs.
    Size caps per response; never follow attribute URLs.
- Polling cadence and politeness match existing news collectors. All titles/summaries sanitized; .onion and
  markup rules unchanged.

## 9. Constraints

- Generic product; nothing company-specific. Public exposure is a real threat model: new endpoints obey
  `public_read`; anonymous rate limits apply; individual ransomware victims stay signed-in only.
- No new external origins for the browser (CSP unchanged); map geometry stays bundled (world-atlas).
- Keep the existing look: tokens in `frontend/src/styles/tokens.css`, IBM Plex fonts, both themes. Follow
  the mockup's layout, spacing and copy. No colored `border-left` stripes > 1px on rows; no eyebrows.
- Respect `prefers-reduced-motion`; keyboard focus visible; map selectable by keyboard via the side list.
- Tests: pytest for backend (rules, endpoints, collectors with recorded fixtures — no live network in tests),
  vitest for frontend, Playwright e2e updated for the new routes. Existing suites stay green.
- `ruff` clean, Prettier formatted.

## Non-goals
LLM summaries/analysis; Telegram; per-user watchlists; HIBP; paid feeds; Reddit (API terms); AlienVault OTX (key).
