"""Header "Situation" gauge: how loud the last week is relative to this install's own normal.

One place for the rules. `classify` is pure (integers in, level and reason out) so it is unit
testable; `situation_for` gathers the integers. The reason is built only from fixed templates
plus integers, never DB free text, so the response stays safe for the public cache.

Volume level: new_kev_7d against the weekly average of the 90 days before that window,
floored at 3.0 per week so a quiet install does not flip on one or two additions. Fewer than
28 days of KEV history means the floor is the baseline. Fewer than 3 additions in the week is
always Calm. Bands on ratio = new_kev_7d / baseline: Calm <= 1.25, Elevated <= 1.75,
High <= 2.5, Severe above. Comparisons are done in integers (cross-multiplied), never floats.

Windows are UTC calendar dates (`kev_added` is a DATE). The "7d" window is `kev_added >=
today - 7`, i.e. 8 calendar dates (today plus the 7 before). The baseline is the 90 dates
`today - 97 .. today - 8`, so the two never overlap and nothing is counted twice.

Spike triggers can only raise the level. `kev_added` is a DATE, so the KEV triggers cover
today and yesterday in UTC ("since yesterday"; same rule as the frontend's isRecentKevDate). "First seen" for a CVE is
`Cve.published`: the Cve model carries no first-seen column of its own.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select

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


def _scaled_baseline(facts: SituationFacts) -> tuple[int, bool]:
    """(weekly baseline x 90, is it a real 90-day baseline).

    weekly = baseline_kev_90d * 7 / 90, so weekly * 90 = baseline_kev_90d * 7; the floor is
    3.0 * 90 = 270. A baseline is "real" only with enough history and above the floor.
    """
    floor = int(FLOOR_PER_WEEK * BASELINE_DAYS)
    if facts.history_days < MIN_HISTORY_DAYS:
        return floor, False
    scaled = facts.baseline_kev_90d * 7
    return max(scaled, floor), scaled > floor


def volume_level(facts: SituationFacts) -> tuple[int, float, bool]:
    """(level index, ratio against the baseline, baseline is real)."""
    d, real = _scaled_baseline(facts)
    n = facts.new_kev_7d
    ratio = n * BASELINE_DAYS / d
    # ratio <= p/q  <=>  n * 90 * q <= p * d
    if n < 3 or n * BASELINE_DAYS * 4 <= 5 * d:
        return 0, ratio, real
    if n * BASELINE_DAYS * 4 <= 7 * d:
        return 1, ratio, real
    if n * BASELINE_DAYS * 2 <= 5 * d:
        return 2, ratio, real
    return 3, ratio, real


def classify(facts: SituationFacts) -> dict:
    vol, ratio, real = volume_level(facts)
    n = facts.new_kev_7d
    noun = _plural(n, "addition", "additions")
    if vol == 0:
        vol_reason = f"{n} KEV {noun} this week, within the usual range"
    elif real:
        vol_reason = f"{n} KEV {noun} this week, {ratio:.2f}x the 90-day norm"
    else:
        vol_reason = f"{n} KEV {noun} this week, above the usual range"

    # (level, reason), strongest first on ties
    triggers: list[tuple[int, str]] = []
    r = facts.ransomware_24h
    rn = f"{r} ransomware-linked KEV {_plural(r, 'addition', 'additions')} since yesterday"
    if r >= 2:
        triggers.append((3, rn))
    if r >= 1 and facts.ransomware_epss_24h:
        triggers.append((3, "Ransomware-linked KEV addition with EPSS in the top 1%"))
    if r >= 1:
        triggers.append((2, rn))
    if facts.poc_unpatched_24h:
        triggers.append((2, "KEV addition with a public exploit and no patch since yesterday"))
    if facts.new_cve_epss_top_24h:
        triggers.append((1, "New CVE in the top 1% for EPSS since yesterday"))

    level, reason = vol, vol_reason
    if triggers:
        top = max(triggers, key=lambda t: t[0])  # max keeps the first of equals
        if top[0] >= vol:
            level, reason = top
    return {"level": LEVELS[level], "lit": level + 1, "reason": reason}


def gather_facts(session, now: datetime) -> SituationFacts:
    """One aggregate query over the KEV rows plus the last day of publications."""
    now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)

    kev = Cve.kev.is_(True)
    recent = kev & (Cve.kev_added >= yesterday) & (Cve.kev_added <= today)
    ransom = recent & Cve.kev_ransomware.is_(True)
    top_epss = Cve.epss_percentile >= EPSS_TOP_PCT
    fresh = (
        Cve.kev.is_not(True)
        & (Cve.published >= now - timedelta(hours=24))
        & (Cve.published <= now)
        & top_epss
    )
    row = session.execute(
        select(
            func.count().filter(kev & (Cve.kev_added >= today - timedelta(days=7))),
            func.count().filter(
                kev
                & (Cve.kev_added >= today - timedelta(days=7 + BASELINE_DAYS))
                & (Cve.kev_added < today - timedelta(days=7))
            ),
            func.min(Cve.kev_added).filter(kev),
            func.count().filter(ransom),
            func.count().filter(ransom & top_epss),
            func.count().filter(recent & Cve.poc_badge.is_(True) & Cve.patch_available.is_(False)),
            func.count().filter(fresh),
        ).where(or_(kev, fresh))
    ).one()
    oldest = row[2]
    return SituationFacts(
        new_kev_7d=int(row[0]),
        baseline_kev_90d=int(row[1]),
        history_days=(today - oldest).days if oldest else 0,
        ransomware_24h=int(row[3]),
        ransomware_epss_24h=row[4] > 0,
        poc_unpatched_24h=row[5] > 0,
        new_cve_epss_top_24h=row[6] > 0,
    )


def situation_for(session, now: datetime) -> dict:
    return classify(gather_facts(session, now))
