# Security review: Plan 1 (`feat/backend-foundation`)

**Requested by:** the user, via `/security-review` ("after all the tasks are complete do a security review")
**Range:** `fb0b04e..7510824` (merge-base with `main` to the Plan 1 head)
**Method:** the `/security-review` procedure. An identification pass ran first (opus). Each candidate then got an independent false-positive filter (sonnet), and only candidates scoring ≥ 8/10 were kept.

## Result

No high-confidence vulnerabilities.

## Candidates considered

| # | Candidate | Filter score | Outcome |
|---|---|---|---|
| 1 | `docker-compose.yml`: hardcoded `postgres:postgres` superuser, Postgres/Redis ports published on all interfaces, no Redis auth | 2/10 | Filtered. It is dev/test scaffolding: there is no app service and no deploy docs, and the spec defers packaging. Falls under hard exclusion 7 (lack of hardening). |

**Follow-up regardless (scheduled for Plan 3 packaging):** the production compose must bind Postgres and Redis to the internal network or loopback, read credentials from env/secrets, use a non-superuser app DB role, and enable Redis auth. The dev compose should be bound to `127.0.0.1` as well.

## Areas reviewed with no reportable findings

- **SSRF.** Every collector URL is a hardcoded constant. OSV ids are validated (`[A-Za-z0-9._:-]+`, with `.`/`..` rejected) and URL-quoted. httpx does not follow redirects by default, so the NVD `apiKey` and VulnCheck `Bearer` headers cannot be redirected to another host.
- **Injection.** All DB access goes through the SQLAlchemy ORM or bound parameters, and CVE ids are validated with an anchored ASCII regex.
- **Deserialization.** Celery is restricted to the JSON serializer and `accept_content`, so there is no pickle path.
- **Stored XSS at ingest.** `sanitize_text` decodes entities to a fixed point, removes closed script/style blocks, then runs `bleach.clean(tags=[], strip=True)`. It never decodes after that. Its output is entity-escaped plain text with no tag-starting `<` (tested invariant). It is applied to `title`, `summary`, cve `summary`, and `affected`.
- **Secrets in logs.** No secrets appear in URLs or log messages, and both tokens travel only in headers.

## Note below the reporting bar

- `Story.url` has no scheme allowlist on this branch. No story collector exists yet, so it is not exploitable here. **Addressed in Plan 2, Task 1** (an http/https-only validator on `NormalizedStory`).
