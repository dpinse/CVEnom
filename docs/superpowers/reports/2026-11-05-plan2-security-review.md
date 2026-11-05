# Plan 2 security review (`feat/geo-news`, 7510824..30d798a)

**Result: no high-confidence vulnerabilities.** That means no finding with more than 80% confidence of real exploitability.

**Scope:** every changed source file under `backend/src/cvenom/`, with each feed's data traced from the network to the database. The reviewer also checked behaviour against the installed libraries, httpx 0.28.1 and feedparser 6.0.14.

## Verified safe
- **Credentials on redirects.**
  - MaxMind Basic auth: httpx drops `Authorization` whenever the origin changes, so the presigned R2 redirect never sees the key.
  - Custom headers (`X-API-KEY`, `Auth-Key`, CF `Bearer`): these go only through helpers that set `follow_redirects=False`.
- **TLS:** there is no `verify=False` anywhere, and every endpoint is a hardcoded `https://` constant.
- **SSRF:** no value that comes from a feed is ever fetched. GeoIP URLs are built only from constants and the date.
- **Tar extraction:** there is no `extractall`. The code takes only the first regular `.mmdb` member and skips links. Size is capped, and absolute, `..` and drive-letter paths are rejected.
- **`geoip_dir` writes:** files are written with `mkstemp` under fixed final names. Each one is validated as mmdb with the expected `database_type`, then moved into place with an atomic `os.replace`.
- **XXE and billion laughs:** a `<!entity` check runs on the body with NUL bytes stripped first. On top of that, feedparser sets `feature_external_ges=0` and expat does not resolve external entities.
- **Stored XSS:**
  - `title`, `summary`, geo `label` and every key and value inside `details` pass through `sanitize_text`.
  - URLs must be http(s), have a host, and contain no userinfo or control characters.
  - Country codes, ASNs, magnitudes, dates and `kind` are all validated.
- **SQL injection:** all queries use SQLAlchemy Core/ORM bound parameters. There is no raw `text()`.
- **Deserialization:** Celery accepts JSON only. There is no pickle, yaml or eval.
- **Secrets in logs:** all keys are `SecretStr` and travel only in headers. The GeoIP failure log records the exception type and HTTP status, never the URL.
- **Header injection through stored ETag / Last-Modified:** h11 rejects CR/LF.

## Hardening applied after review
- **`news.py`: feedparser opened local paths.** When `feedparser.parse()` is given bytes or a str, it first tries `open()` on them as a local path. A feed body that was just a filesystem path would therefore have been read from disk, and the `<!entity` guard would have run on the path string instead of the file. The reviewer rated this about 3/10 exploitable, since it needs one of four hardcoded HTTPS publishers to be compromised. It is now fixed by parsing `io.BytesIO(raw)`. A regression test plants a real feed file and checks that a body naming its path yields no stories; before the fix, the test failed with 2 stories.

## Notes carried forward
- **`external_id` is stored without `sanitize_text` (about 2/10).** It is control-character filtered, capped at 256 characters, and used only as an upsert key. If Plan 3 ever exposes it, sanitize it or restrict it to `[A-Za-z0-9:._\-\[\]]`. React text rendering would neutralise it in any case.
