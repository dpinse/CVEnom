# CVEnom roadmap

CVEnom is a **generic** vulnerability and threat news aggregator. It is meant to be offered to any company, so nothing in it is tailored to one organisation.

The items below are proposals, not commitments. None of them is designed or built yet. Each one goes through a design discussion first.

## Next up (after the current build is tested)

### 1. Breaches and personal watchlists
Users choose what they care about, and the radar tells them when it shows up in a breach or in the news.
- **Breach feed (generic):**
  - Ingest the Have I Been Pwned breach catalog. This uses the free endpoint and needs no key.
  - Each new breach becomes an item on the radar, showing the breached site, the breach and added dates, the account count and the data classes exposed.
  - HIBP's breach data is CC BY 4.0, so attribution is required.
  - Link these entries to the breach news the existing feeds already ingest, rather than duplicating them.
- **Personal watch terms:** in their profile, each user defines terms such as vendor names, domains, products or keywords.
  - New breaches whose domain matches, and news stories that mention or link to a watched term, alert that user through email or webhook.
  - Name matching needs care to avoid false positives. Short or common words such as "Box" or "Square" are the hard cases.
  - Today's alert rules are team-wide and admin-managed. Watchlists add a per-user "My alerts" layer on top of the same matching and delivery pipeline.
- **Breached-password check:** reject passwords found in HIBP Pwned Passwords at every place a password gets set: the admin CLI, invite or reset acceptance, and change password.
  - It uses k-anonymity, so only a 5-character hash prefix leaves the server.
  - Open: whether to fail open or fail closed when HIBP can't be reached.
- **Optional, per deployment:** HIBP paid domain search, for a company's own employee accounts. It needs a paid key and proof that the company owns the domain. This is an add-on, not core.
- **Open question that blocks the design:** will many companies share **one CVEnom instance** (multi-tenant), or will each company get **its own deployment**?
  - With one shared instance, CVEnom needs real separation between companies: users, rules, watchlists, invites and delivery logs. That is a sizeable project on its own.
  - With one deployment per company, the current single-team model already works.

## Later

- **Passkeys (WebAuthn).** Let users sign in with a passkey: Windows Hello, Touch ID, Android, or a security key such as a YubiKey. This would sit alongside the mandatory TOTP MFA and could eventually replace passwords.
  - A passkey covers both factors on its own, so signing in with one skips the TOTP step.
  - Needs work on: registration and management in the account page, attestation policy, and how a lost passkey is recovered (TOTP or recovery codes as the fallback).

- **Telegram alerts.** This needs a bot token plus a chat id, which is a different payload from generic webhooks. It is deferred because the current users don't use Telegram.
- **SMS alerts.** These were mentioned in the original vision.
- **"Situation" strip.** This is the playful "meme garnish" status strip from the early brainstorm, and it remains a TODO.
- **Re-evaluate alerts after enrichment.** Today, rules are evaluated when a CVE joins KEV, and unknown CVSS or EPSS scores count as a match. A later pass could re-check those CVEs once their scores arrive.
- **`SECRETS_KEY` re-encryption tool.** Rotating the key currently requires re-adding webhook recipients. A CLI could re-encrypt the stored secrets instead.
- **Story search.** Search and filter across all stories, not only "Loud now".
- **CI pipeline.** Run the test suites, lint and a dependency audit (`pip-audit`, `npm audit`) on every push.
- **Cloudflare Radar hijack ordering.** Once a token exists, verify that `per_page` and the sort order return the newest events.
