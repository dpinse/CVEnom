# Plan 1: Backend foundation & ingestion core (summary)

**Branch:** `feat/backend-foundation`, pushed to GitHub at `7510824`. Not merged; `main` is untouched.
**Result:** All 13 tasks are complete and each passed its own task review. The whole-branch final review (opus) required one fix wave, and its scoped re-review was clean. The security review found no high-confidence vulnerabilities (see `2026-11-05-plan1-security-review.md`).
**Tests:** 233 passed, 0 warnings.
**Full decision record:** `2026-11-05-plan1-ledger.md` is the controller's complete ledger. Every ruling is listed there with what it costs if wrong.

## What exists now

- **Config and schema:** pydantic Settings; SQLAlchemy models (CVE, Story, StoryCveLink, CollectorRun) with BRIN time indexes; Alembic migration 0001; and validated schemas. CVE ids are normalized, and scores must be finite and in range.
- **Ingest-time XSS defense:** `sanitize_text` returns entity-escaped plain text with no tag-starting `<`. This is the single sanitization point at ingest.
- **Scoring:** the lane engine (EXPLOITED / LIKELY / LOUD / FRESH plus `heat_rank`), with the KEV tier as a strict gate.
- **Collectors:** a resilient framework, plus NVD (lastMod windows with a 1h overlap), EPSS (enrich-only, chunked, date short-circuit), CISA KEV, VulnCheck KEV (token-gated), and OSV/GHSA (enrich-only, patch availability).
- **KEV alert safety:**
  - first-run baseline;
  - recency gate (14 days);
  - corrupt-state guards;
  - the DB `kev=True` flag doubles as a second seen-set, so there is one `kev_added` per CVE across both feeds.
- **Ingestion pipeline:** savepoint retry on unique violations only, enrich-only fast path, and SQL-prefiltered lane views.
- **Celery tasks and beat schedule:** a failed run never advances its window. Redis lock with atomic release (2× TTL) plus `SELECT … FOR UPDATE`.

## Decisions that need YOU (flagged during execution)

1. **CISA alert after VulnCheck absorbed a CVE.** When VulnCheck's baseline or the 14-day recency gate silently marks a CVE as KEV, a later CISA listing of that CVE does **not** alert. Under the current rule, a CVE alerts once per CVE, not once per source. The alternative is to let a CISA listing always alert once. Say which you want.
2. **Subagents pushed to GitHub unprompted** (four times). You chose "keep going as-is". The feature branch was the only one affected, and `main` was never touched.

## Carried forward

- **Plan 2, Task 0:**
  - bound CVE id digits (`\d{4,7}`);
  - EPSS short-circuit also checks for new CVE rows;
  - fix a midnight-UTC test flake.
- **Plan 2:**
  - `story.content_hash` index;
  - http/https-only story URLs;
  - per-record try in every new collector.
- **Plan 3:**
  - persist events in the collector's transaction (outbox), plus per-CVE alert dedupe;
  - validate webhook URLs at alert time;
  - production compose: no published DB/Redis ports, credentials from env/secrets, non-superuser DB role, Redis auth;
  - dependency lock file;
  - Celery `worker_process_init` engine dispose.
- **Follow-up:** an alembic `compare_metadata` drift test; streaming the OSV index.
