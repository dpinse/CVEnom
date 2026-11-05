# CVEnom — Vulnerability Threat Radar

**Design document**
Date: 2026-11-04
Status: Draft for approval

---

## 1. Intent and why

CVEnom is a self-hosted **vulnerability threat radar**: a situational-awareness tool that tells a security practitioner what the security world is *buzzing about right now* — what is newly critical, what is likely to blow up next, and what is already being exploited in the wild — regardless of whether they personally run the affected software.

It is a riff on the "monitor the situation" meme, built as a genuinely useful operations instrument. The centerpiece is an interactive globe showing threat geography; beneath it, a four-lane radar ranks and sorts live vulnerability signal; a drill-down view explains any item; and email alerts fire the moment something crosses into active exploitation.

**Why now / what success looks like.** Authoritative vulnerability data (NVD, EPSS, CISA KEV) and the news/social chatter around it are scattered across many feeds, and a raw CVE firehose is hundreds of items a day — noise. CVEnom's job is to collapse those signals into one glanceable picture of *what actually matters this week*, and to page the operator by email when a vulnerability turns from theoretical to real. Success is: the operator opens CVEnom (or reads an alert email) and immediately knows what is on fire and what is heating up, with a trustworthy path from "a headline" to "the hard facts."

The worked example that shaped this design is the real late-October 2026 "Black October" wave: the PHP2Shell pair (CVE-2026-109618 / 109619) climbing from fresh disclosure to public PoC to CISA KEV in days, alongside a cluster of breaches (Quest Diagnostics, Capcom, Railway) that had *no* attributed CVE. CVEnom must handle both, and link them where a link exists.

## 2. Goals, non-goals, anti-goals

### Goals
- Near-real-time (minutes-to-hours) awareness of what is being weaponized and discussed.
- A **globe-centric** situational view (threat geography) as the centerpiece, with a **four-lane radar** beneath it and a **drill-down** detail view.
- **Trustworthy severity**: authoritative data from NVD / EPSS / CISA KEV; news and social used as *early-warning signal*, never as the source of truth for severity.
- Model **two object types** — CVEs (structured, scorable) and Stories/incidents (news and breaches, which may carry no CVE) — and **link** a story to a CVE when attribution exists.
- **Email alerts** when an item crosses into active exploitation or meets operator-defined criteria, with a pluggable path to SMS/webhook later.
- **Always-on** background collection, independent of whether the dashboard is open.
- **Hardened from the first commit**, and self-hostable.

### Non-goals (for this build)
- Per-user asset/stack correlation ("does this affect *my* software?"). We deliberately chose "what's buzzing regardless of whether you run it." This is a plausible later addition, not now.
- The full SOC wall: threat-actor / APT leaderboard, animated attack-arc eye-candy beyond country-level outage shading.
- The non-cyber **"situation strip"** (earthquakes, space weather, ISS, crypto ticks) — parked as a clearly-isolated, future meme-garnish module. It must never entangle the core.
- SMS alert channel (design the sink interface for it; v1 ships email **and webhook**).
- Paid/gated feeds (Shodan, GreyNoise). Optional free-tier tokens only.

### Anti-goals (would make this a failure even if it technically works)
- Becoming a **firehose** where the genuinely urgent is buried under theoretical criticals. A naive "sort by CVSS" is the failure mode we are explicitly designing against (see the quiet-foil case, §5).
- Presenting scraped or unverified data **as if it were authoritative** severity.
- Treating breach/incident news that has **no CVE** as invisible.

## 3. Constraints

- **Fixed by the operator:** Python backend, React frontend.
- **Chosen stack (see §6):** FastAPI + PostgreSQL + Redis + Celery + WebSockets.
- Self-hosted; **small-team multi-user**; **internet-facing** (behind Cloudflare) and always-on.
- Prefer **free** data sources. Optional tokens raise limits or add feeds: `NVD_API_KEY` (optional, higher NVD rate limit), `CF_RADAR_TOKEN` (Cloudflare Radar), `ABUSEIPDB_API_KEY` (optional IP enrichment).
- Respect every source's robots.txt, terms of service, and rate limits; identify with a generic client string.

## 4. Data sources

**Authoritative vulnerability data (source of truth):**
- **NVD CVE 2.0 API** — CVE records, CVSS 3.1. Poll ~2h.
- **FIRST EPSS** — exploitation-probability scores. Poll ~2h.
- **CISA KEV** catalog — vulnerabilities known exploited in the wild; the single strongest "act now" signal. Poll ~1h, with **diff detection** so a new KEV entry is an event.
- **VulnCheck Community** (free, registration) — a broader, faster KEV-style feed that often flags in-the-wild exploitation before CISA KEV. Augments the Exploited-now lane. Poll ~1h with diff detection.
- **OSV.dev** (free) and **GitHub Advisory Database** (free; token raises rate limit) — open-source package vulnerabilities across ecosystems, often ahead of NVD, and carrying **fixed-version data** used to derive patch availability (see §5). Poll ~2h.

**Threat landscape / geographic (feed the globe):**
- **ransomware.live** — active ransomware victims. Poll ~15m.
- **DShield / SANS ISC** — mass-scan firehose; a scan spike is often the earliest sign a fresh CVE is being weaponized. Poll ~1h.
- **Cloudflare Radar** — internet outages and BGP anomalies for country-level shading (requires `CF_RADAR_TOKEN`). Poll ~5m.
- **abuse.ch — ThreatFox / URLhaus / Feodo Tracker** (free, optional key) — live IOCs and botnet C2 IPs; geolocating the C2s populates the globe. Poll ~15–60m.
- **MaxMind GeoLite2** (free account) — IP→country/ASN geolocation for placing scan origins and C2s on the globe.
- **AbuseIPDB** — optional, on-demand IP/ASN enrichment.

**News / story layer (early-warning chatter; RSS preferred over HTML scraping):**
- Krebs on Security, The Hacker News, Bleeping Computer, SecurityWeek (RSS). Poll ~5–15m.

**Backlog (free, ready to add — the collector architecture makes each cheap):** Shadowserver stats, AlienVault/LevelBlue OTX pulses, CISA advisories RSS, oss-security / Full Disclosure lists, Mastodon (infosec.exchange) and Reddit r/netsec feeds.

**Future (isolated modules, not in this build):** Shodan, GreyNoise, Exploit-DB / Metasploit / nuclei (exploit-availability timeline), the non-cyber "situation strip."

## 5. Product model and lane scoring

### Two object types
- **CVE** — structured and scorable (CVSS, EPSS, KEV membership, PoC availability, affected products).
- **Story** — a news item or breach. May or may not carry a CVE. Stories with no CVE are first-class and live only in the news lane. When a CVE is mentioned or attributed, CVEnom **links** the story to it (regex `CVE-\d{4}-\d{4,}` extraction on ingest, plus enrichment of that CVE from NVD/EPSS/KEV).

### Lanes, not a single ranking
CVEnom deliberately refuses to force one ranking, because the signals disagree. It presents four parallel lanes; a CVE may appear in several at once.

| Lane | Admission rule | Instinct it serves |
|---|---|---|
| **Exploited now** | In CISA KEV **or VulnCheck Community KEV** (v1). PoC/Metasploit-based admission is a later module (§4); a GitHub PoC shows as a *badge*, not an admission ticket. | Reactive — real danger today |
| **Likely next** | EPSS at/above the 95th percentile, boosted by rising news volume | Forward-looking — what blows up next |
| **Loud now** | News/story volume (≥1 reputable source in last 72h); **holds CVE-less items** (breaches) | What the world is shouting about |
| **Fresh criticals** | New CVSS ≥ 9.0 within the last 48h | Just-landed, not yet triaged |

**Default thresholds (configurable):** Likely-next uses EPSS **percentile** (top ~5%), not absolute score, because raw EPSS drifts; Fresh-criticals uses CVSS ≥ 9.0 over a 48h window; the velocity readout is a 30-day line with "rising" = last-7-day average above the prior 7. A GitHub repo naming a CVE is treated as an unverified PoC badge only. The "no-patch-available" boost **is** computed for the open-source subset using fixed-version data from OSV.dev / GitHub Advisory Database; for CVEs lacking that data it is simply not applied (no false signal).

- **KEV items are pinned/flagged "in the wild"** wherever they appear.
- The **quiet-foil** case is the design test: a fresh CVSS 9.0 with low EPSS, no PoC, and no chatter (e.g. CVE-2026-115560) must sit quietly in *Fresh criticals* and never rise into Likely-next/Exploited-now — so it cannot bury the genuinely urgent.
- A **CVE-velocity** readout (CVEs published/day, trend) sits with the globe as an instrument reading.

### Alerts
- Rule-based: KEV crossing (an item newly entering "Exploited now"), minimum severity threshold (e.g. CVSS ≥ 7, or EPSS ≥ X), and custom keywords.
- **Email and webhook channels in v1**, behind a pluggable sink interface (SMS later). Webhook secrets are encrypted at rest and webhook URLs pass SSRF validation (§7).

## 6. Approaches considered

Three ways to build it were weighed. The operator's fixed constraints are Python + React; the open axes were database, scheduler/queue, live-update transport, and backend language.

**Approach A — Lean single service.** One FastAPI process, APScheduler running collectors in-process, SQLite, email on KEV crossing, React polling for refresh.
*Rejected:* SQLite is weak for the append-mostly time-series analytics the velocity view and history want; no live push; a slow collector can stall the process.

**Approach B — Full operational stack. → CHOSEN.** FastAPI + PostgreSQL (BRIN-indexed, tuned for append-mostly event streams) + Redis + Celery (beat-scheduled collectors) + WebSockets for live updates.
*Chosen* because the operator wants Postgres and Redis from the start, it scales cleanly to many sources and real history, isolates a failing collector, and gives the globe/lanes live push. The extra operational parts are an accepted cost.

**Approach C — Lean now, upgrade path kept open.** Approach A's simplicity but with a storage-abstraction layer and modular collectors so SQLite→Postgres is a later swap; SSE instead of WebSockets.
*Rejected* by operator preference for Postgres/Redis up front; the "defer the heavy stack" trade-off is not wanted here.

**Backend language — Python (decisive), not Go.** CVEnom's center of gravity is ingestion, parsing, CVE extraction/NLP, and gluing to threat-intel sources — overwhelmingly Python territory (feedparser, BeautifulSoup, mature NVD/EPSS clients). FastAPI gives async WebSockets and ample throughput for an I/O-bound polling workload; Celery+Redis is a paved road. Go's edges (single-binary deploy, high-concurrency fan-out) would only dominate if pushing live updates to thousands of simultaneous viewers, which a self-hosted radar is not. If that ever changes, a small Go WebSocket gateway beside the Python collectors is the escape hatch — but not now.

**Frontend globe — MapLibre GL JS.** The real app renders a globe-projection map with country outlines, a **choropleth** for country-level outage shading, and hotspot markers/layers for exploit-scanning origins and victim geography, with WebSocket-driven updates and a click-to-drill-down interaction. (The throwaway mockup used a d3-orthographic canvas globe only because the artifact sandbox blocks map tiles; that constraint does not apply to the real app. A globe rendering quirk seen in the mockup under Firefox is a mockup-only issue to verify, not a design decision.)

## 7. Security / hardening (first-class)

CVEnom **fetches untrusted content from the internet and renders it in a browser**, so the threat surface is larger than auth alone:

- **Stored XSS** — scraped titles/summaries rendered in React. Sanitize on ingest *and* escape on render. This is the crown-jewel risk because of the public read-only mode (untrusted content reaches anonymous viewers).
- **SSRF** — both the collectors and any operator-supplied **webhook URL** can be aimed at internal or cloud-metadata endpoints. Allowlist hosts, block private/link-local/metadata IP ranges, and resolve-then-validate.
- **Supply chain** — collectors pull a large dependency tree. Pin dependencies and scan them in CI.
- **Outbound manners** — rate-limit and back off per source; honor robots.txt and ToS; generic client identity.

**Exposure (internet-facing, behind Cloudflare — defense in depth):** Cloudflare fronts the app but is treated as one layer, not the only one. The origin enforces its own anonymous **rate limiting**, **DoS/abuse** protection, a **caching tier** for public read-only endpoints, and strict **CSP / security headers**, so it stays safe if requests reach it directly (origin-IP leak, CF bypass, or misconfiguration).

**Authentication and secrets (operator's requirements):**
- JWT auth with **auto-rotating Ed25519 keys**.
- **Public read-only mode** for the dashboard; writes/config require auth.
- **Multi-device session management**.
- **AES-256 encryption of webhook secrets at rest.**

**Baseline:** TLS everywhere, security headers / CSP, least-privilege DB role, strict input validation, no secrets in source.

## 8. Architecture (the "how" that is decided)

- **Collectors** are independent Celery tasks, one per source, each on its own cadence (§4), scheduled by Celery beat; Redis is the broker.
- **Pipeline:** `ingest → normalize (unified schema) → extract & link CVEs → score lanes → store → emit`. Emit = WebSocket push to connected dashboards + alert-rule evaluation.
- **Storage:** PostgreSQL, BRIN indexes on time-ordered event columns (append-mostly). CVEs upserted by CVE-ID; stories deduplicated by URL and content hash. Transactions so an interrupted collection leaves consistent data.
- **Alert engine:** evaluates rules on new/changed items; **email and webhook sinks** implemented behind a pluggable sink interface (SMS later). Webhook delivery validates target URLs for SSRF and stores secrets encrypted.
- **Users & auth:** small-team multi-user. A seeded admin on first run provisions further accounts by invite; Ed25519 JWT with rotation; multi-device sessions; public read-only dashboard, auth required for writes/config. Alert rules are **shared**, each with its own recipient list.
- **API:** FastAPI REST for search/filter (by date range, keyword, CVE-ID, source, severity/lane) and historical queries; WebSocket for live updates and drill-down.
- **Frontend:** React dashboard — globe centerpiece (MapLibre), four-lane radar, CVE-velocity readout, drill-down drawer, dark + light themes, search/filter UI. Color is reserved for signal (severity ramp + "in the wild" red); chrome is neutral.
- **Packaging:** containerized (API, worker, beat, Postgres, Redis) for self-hosting.

## 9. Left to the builder

- Exact lane-scoring weights and thresholds (what EPSS counts as "likely," the "fresh" time window, keyword sets) — make them configurable.
- Full database schema and migrations (Alembic).
- MapLibre globe style, country-polygon source, and the outage-level → shade mapping.
- CVE-extraction/linking precision (regex plus any light NLP for attribution).
- Deployment specifics (docker-compose / env handling) and the testing strategy.
- The later, isolated modules: exploit-availability timeline, the non-cyber situation strip, asset/stack correlation.

## 10. Builder-check resolutions (calls made during review)

- **Exploited-now data source.** For v1 this lane is driven by **CISA KEV and VulnCheck Community KEV**. Exploit-availability feeds (Metasploit / nuclei / Exploit-DB) remain a later module (§4); a GitHub PoC is a badge, not an admission ticket. This keeps the lane authoritative rather than noisy and is consistent with the exploit-availability non-goal.
- **Globe model.** The globe is an always-on **ambient threat-geography** panel fed by the geo sources (Cloudflare Radar outages, DShield scan origins, ransomware.live victims). Selecting a **geo-tagged** story/incident focuses the globe on its location. CVEs have no inherent geography, so a plain CVE selection does not drive the globe.
- **First-run history.** History accumulates from install forward, plus a **bounded ~90-day NVD/EPSS backfill** on first run so the velocity readout and Fresh-criticals are meaningful on day one. Backfill is rate-limit aware; `NVD_API_KEY` recommended.
- **"Likely next" inputs.** Keep the rising-news-volume boost. The no-patch boost was initially dropped (not derivable from NVD) but is **reinstated for the open-source subset** once OSV.dev / GitHub Advisory Database were added as sources (their fixed-version data makes it derivable); see §5. For CVEs without that data it is not applied.
- **Email transport.** The operator supplies SMTP credentials or a transactional-email provider via config. Direct-from-host sending is discouraged (deliverability); a relay/provider is recommended.
- **Alert channels (v1).** Email **and webhook** both ship in v1 behind a pluggable sink interface; SMS is later. Webhook URLs are SSRF-validated and secrets encrypted at rest.
- **Exposure.** Internet-facing behind Cloudflare, with app-level defense-in-depth — Cloudflare is not relied on alone (see §7).
- **User model.** Small-team multi-user: seeded admin on first run provisions accounts by invite; alert rules are shared with per-rule recipient lists.

## 11. Status

All operator decisions resolved. Ready for approval.
