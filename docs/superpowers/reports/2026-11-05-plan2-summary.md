# Plan 2 summary: geo and news collectors, plus velocity

**Branch:** `feat/geo-news`. It is stacked on `feat/backend-foundation` (7510824) and has been pushed to GitHub. Nothing is merged, and `main` is untouched.

**Result:**
- All 11 tasks are done (Task 0 for follow-ups, then Tasks 1–10), and each passed its own task review.
- The whole-branch final review (opus) found no Critical issues, 4 Important and 6 Minor. One fix wave addressed 9 of the 10. The remaining one is parked (see "Parked" below), and the scoped re-review of the fix wave was clean.
- See `2026-11-05-plan2-security-review.md` for the security review.

**Tests:** 497 passed, 0 warnings. Plan 1 ended at 233.

**Security review:** no high-confidence vulnerabilities. One hardening item has been applied: feedparser now gets `io.BytesIO`, because it used to try `open()` on a raw body as a local path.

**Full decision record:** `2026-11-05-plan2-ledger.md` has every ruling and what each one costs if it turns out wrong.

## What exists now
- **HTTP helpers**
  - `http_get_text`, `http_get_bytes`, `http_get_conditional` (ETag / If-Modified-Since) and `http_post_json`.
  - All of them share one retrying `_request` with a streaming size cap measured on *decoded* bytes, which defends against gzip bombs.
  - Redirects are off by default and enabled only for the fixed GeoIP hosts. httpx strips `Authorization` when it follows a cross-origin redirect, and a test covers that.
- **Schemas, in one central validation point**
  - CVE ids are `\d{4,7}`.
  - Story URLs must be http/https with no userinfo.
  - Every story and geo timestamp is aware UTC. Years outside 1970–2100 are rejected, and anything more than 1h in the future is clamped to now.
  - Geo `external_id` is 1–256 printable characters, and `asn` must be ≤ 2³²−1.
- **GeoEvent table**
  - Added in migration 0002, with BRIN on `observed_at` and a unique `(source, external_id)`.
  - It has an idempotent upsert that keeps `first_seen`. Batches are deduped last-wins and written in chunks of 500.
  - `details` is sanitized recursively, keys included, and non-finite floats become null.
  - `purge_old_geo_events` removes old rows after a 30-day retention.
- **GeoIP lookup**
  - Defaults to DB-IP Lite, with MaxMind GeoLite2 as an option (license key is a SecretStr).
  - Tar extraction is safe, with a 100 MB cap and a `database_type` check before an atomic replace.
  - Readers use in-memory mode, so a refresh never fights an open file handle on Windows.
  - Private and reserved IPs are excluded.
- **Collectors** (13 registered):
  - **Four news RSS feeds:** Krebs, The Hacker News, BleepingComputer and SecurityWeek. Each feed has a 5 MB cap and conditional GET. A feed is refused if it declares `<!ENTITY` (the check also catches UTF-16 and UTF-32 encodings), and feeds are parsed from bytes only.
  - **ransomware.live Pro:** key-gated and off by default.
  - **DShield top attackers:** aggregated by country using GeoIP.
  - **Cloudflare Radar outages and BGP hijacks:** token-gated. An ongoing outage stays current until it ends.
  - **abuse.ch:** the Feodo C2 blocklist needs no key; ThreatFox is key-gated.
- **Read models:** `cve_velocity` (UTC-day series, zero-filled, with a `rising` flag), `geo_summary` and `loud_stories` (no N+1 queries).
- **Scheduling:**
  - Beat runs one entry per collector.
  - GeoIP refresh is on a wall-clock crontab every 6h and skips when the DB is under 7 days old. The worker also bootstraps the GeoIP DB on startup.
  - Geo purge runs hourly. Both maintenance jobs are Redis-locked, and failures are logged without secrets.

## Decisions that need you
1. **ransomware.live retired its free API.** The v2 endpoint returns 404. The collector targets the Pro API (`api-pro.ransomware.live/victims/recent`, `X-API-KEY`) and is **disabled until you set `CVENOM_RANSOMWARE_LIVE_API_KEY`**. The swagger doesn't document the record field names, so the parser uses defensive aliases. Once you have a key, compare one real response against `ransomware.py`.
2. **Cloudflare Radar and ThreatFox need free tokens:** `CVENOM_CF_RADAR_TOKEN` and `CVENOM_ABUSECH_AUTH_KEY`. Without them those layers are cleanly disabled. Once the CF token exists, check whether the hijack query (`per_page=100`, 7 days) returns the newest events. That item is parked.
3. **Carried over from Plan 1:** the CISA-after-VulnCheck alert rule. Still awaiting your call.

## Parked or deferred (details in the ledger)
- **UTF-7 `<!ENTITY` bypass in news (parked).** A probe confirmed that feedparser's fallback does not expand entities. The risk is low: there are 4 fixed feeds, a 5 MB cap, and expat's limits.
- **Cloudflare hijack sort order (parked):** unverifiable without a token.
- **Carried to Plan 3:**
  - the API validates read-model ranges (`days` 1–30, `window_hours` 1–168, `limit` ≤ 100);
  - the remaining plain-`str` tokens (`nvd_api_key`, `vulncheck_api_token`, `github_token`) become SecretStr.
- **Carried to Plan 4:** DB-IP CC-BY attribution on the globe.
