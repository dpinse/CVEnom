"""Header "Situation" gauge: how loud the last week is relative to this install's own normal.

One place for the rules. `classify` is pure (integers in, level and reason out) so it is unit
testable; `situation_for` gathers the integers. The reason is built only from fixed templates
plus integers, never DB free text, so the response stays safe for the public cache.

Volume level: new_kev_7d (KEV added in the last 7 days) against the weekly average of the
90 days before that window (days 8..97 back), floored at 3.0 per week so a quiet install does
not flip on one or two additions. Fewer than 28 days of KEV history means the floor is the
baseline. Fewer than 3 additions in the week is always Calm.

Spike triggers (24h) can only raise the level. `kev_added` is a DATE, so "24h" means today or
yesterday in UTC (same rule as the frontend's isRecentKevDate). "First seen" for a CVE is
`Cve.published`: the Cve model carries no first-seen column of its own.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select

from cvenom.models import Cve

LEVELS = ("Calm", "Elevated", "High", "Severe")
FLOOR_PER_WEEK = 3.0
BASELINE_DAYS = 90
MIN_HISTORY_DAYS = 28
EPSS_TOP_PCT = 0.99


@dataclass(frozen=True)
class SituationFacts:
    new_kev_7d: int
    baseline_kev_90d: int  # additions in days 8..97 back
    history_days: int  # days since the oldest KEV addition (0 if none)
    ransomware_24h: int
    ransomware_epss_24h: bool  # a ransomware-linked recent addition with EPSS pct >= 0.99
    poc_unpatched_24h: bool
    new_cve_epss_top_24h: bool


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def volume_level(facts: SituationFacts) -> tuple[int, float]:
    """(level index, ratio against the 90-day norm)."""
    if facts.history_days >= MIN_HISTORY_DAYS:
        baseline = facts.baseline_kev_90d * 7 / BASELINE_DAYS
    else:
        baseline = FLOOR_PER_WEEK
    ratio = facts.new_kev_7d / max(baseline, FLOOR_PER_WEEK)
    if facts.new_kev_7d < 3 or ratio <= 1.0:
        return 0, ratio
    if ratio <= 1.5:
        return 1, ratio
    if ratio <= 2.5:
        return 2, ratio
    return 3, ratio


def classify(facts: SituationFacts) -> dict:
    vol, ratio = volume_level(facts)
    n = facts.new_kev_7d
    if vol == 0:
        vol_reason = (
            f"{n} KEV {_plural(n, 'addition', 'additions')} this week, within the usual range"
        )
    else:
        vol_reason = (
            f"{n} KEV {_plural(n, 'addition', 'additions')} this week, {ratio:.1f}x the 90-day norm"
        )

    # (level, reason), strongest first on ties
    triggers: list[tuple[int, str]] = []
    r = facts.ransomware_24h
    if r >= 2 or facts.ransomware_epss_24h:
        triggers.append(
            (3, f"{r} ransomware-linked KEV {_plural(r, 'addition', 'additions')} in 24h")
        )
    if r >= 1:
        triggers.append(
            (2, f"{r} ransomware-linked KEV {_plural(r, 'addition', 'additions')} in 24h")
        )
    if facts.poc_unpatched_24h:
        triggers.append((2, "KEV addition with a public exploit and no patch in 24h"))
    if facts.new_cve_epss_top_24h:
        triggers.append((1, "New CVE in the top 1% for EPSS in 24h"))

    level, reason = vol, vol_reason
    if triggers:
        top = max(triggers, key=lambda t: t[0])  # max keeps the first of equals
        if top[0] >= vol:
            level, reason = top
    return {"level": LEVELS[level], "lit": level + 1, "reason": reason}


def gather_facts(session, now: datetime) -> SituationFacts:
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)

    def count(*preds) -> int:
        return int(session.scalar(select(func.count()).select_from(Cve).where(*preds)) or 0)

    kev = Cve.kev.is_(True)
    new_kev = count(kev, Cve.kev_added >= today - timedelta(days=7))
    baseline = count(
        kev,
        Cve.kev_added >= today - timedelta(days=7 + BASELINE_DAYS),
        Cve.kev_added < today - timedelta(days=7),
    )
    oldest = session.scalar(select(func.min(Cve.kev_added)).where(kev))
    history = (today - oldest).days if oldest else 0

    recent = and_(kev, Cve.kev_added >= yesterday, Cve.kev_added <= today)
    ransom = and_(recent, Cve.kev_ransomware.is_(True))
    return SituationFacts(
        new_kev_7d=new_kev,
        baseline_kev_90d=baseline,
        history_days=history,
        ransomware_24h=count(ransom),
        ransomware_epss_24h=count(ransom, Cve.epss_percentile >= EPSS_TOP_PCT) > 0,
        poc_unpatched_24h=count(recent, Cve.poc_badge.is_(True), Cve.patch_available.is_(False))
        > 0,
        new_cve_epss_top_24h=count(
            Cve.kev.is_not(True),
            Cve.published >= now - timedelta(hours=24),
            Cve.epss_percentile >= EPSS_TOP_PCT,
        )
        > 0,
    )


def situation_for(session, now: datetime) -> dict:
    return classify(gather_facts(session, now))
