from datetime import datetime, timedelta, timezone

import pytest

from cvenom.models import Cve
from cvenom.readmodels import summary_counts
from cvenom.situation import SituationFacts, classify, gather_facts, situation_for

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
TODAY = NOW.date()


def facts(**kw):
    base = dict(
        new_kev_7d=0, baseline_kev_90d=0, history_days=90, ransomware_24h=0,
        ransomware_epss_24h=False, poc_unpatched_24h=False, new_cve_epss_top_24h=False,
    )
    base.update(kw)
    return SituationFacts(**base)


# ---- pure rules ----
@pytest.mark.parametrize(
    "n,baseline90,level",
    [
        (0, 0, "Calm"),
        (2, 0, "Calm"),  # floor: < 3 is always Calm
        (3, 0, "Calm"),  # ratio 1.0
        # at the 3.0/week floor: <=3 Calm, 4-5 Elevated, 6-7 High, 8+ Severe
        (4, 0, "Elevated"),
        (5, 0, "Elevated"),  # 1.67
        (6, 0, "High"),  # 2.0
        (7, 0, "High"),  # 2.33
        (8, 0, "Severe"),  # 2.67
        # baseline 14/week (180 in 90d): edges 1.25 / 1.75 / 2.5 are exact (17.5, 24.5, 35)
        (17, 180, "Calm"),
        (18, 180, "Elevated"),
        (24, 180, "Elevated"),
        (25, 180, "High"),
        (35, 180, "High"),
        (36, 180, "Severe"),
        # baseline 60/week exactly (771.43 is not an integer; 90 days of 60 = 771.4, use 770/780)
        (62, 780, "Calm"),
        (75, 780, "Calm"),  # 75 / 60.67 = 1.236
        (76, 780, "Elevated"),
    ],
)
def test_volume_levels_and_boundaries(n, baseline90, level):
    assert classify(facts(new_kev_7d=n, baseline_kev_90d=baseline90))["level"] == level


def test_integer_boundaries_are_exact():
    # baseline 90d = 360 -> 28/week: 1.25x = 35 (Calm), 36 Elevated; 1.75x = 49, 50 High; 2.5x = 70, 71.
    f = lambda n: classify(facts(new_kev_7d=n, baseline_kev_90d=360))["level"]  # noqa: E731
    assert [f(35), f(36), f(49), f(50), f(70), f(71)] == [
        "Calm", "Elevated", "Elevated", "High", "High", "Severe"]


def test_short_history_uses_floor_baseline():
    # a big baseline count is ignored when there are < 28 days of history
    assert classify(facts(new_kev_7d=8, baseline_kev_90d=900, history_days=27))["level"] == "Severe"
    assert classify(facts(new_kev_7d=8, baseline_kev_90d=900, history_days=28))["level"] == "Calm"


@pytest.mark.parametrize(
    "n,lit,level",
    [(0, 1, "Calm"), (4, 2, "Elevated"), (6, 3, "High"), (9, 4, "Severe")],
)
def test_lit_matches_level(n, lit, level):
    r = classify(facts(new_kev_7d=n))
    assert (r["level"], r["lit"]) == (level, lit)


def test_realistic_steady_state_is_calm_and_spike_is_not():
    assert classify(facts(new_kev_7d=62, baseline_kev_90d=780))["level"] == "Calm"
    assert classify(facts(new_kev_7d=100, baseline_kev_90d=780))["level"] == "Elevated"
    assert classify(facts(new_kev_7d=125, baseline_kev_90d=780))["level"] == "High"
    assert classify(facts(new_kev_7d=160, baseline_kev_90d=780))["level"] == "Severe"


def test_reason_templates():
    assert classify(facts(new_kev_7d=1))["reason"] == "1 KEV addition this week, within the usual range"
    assert classify(facts(new_kev_7d=0))["reason"] == "0 KEV additions this week, within the usual range"
    # real 90-day baseline: multiplier shown with 2 decimals (never "1.0x" for a non-Calm level)
    r = classify(facts(new_kev_7d=76, baseline_kev_90d=780))
    assert r["reason"] == "76 KEV additions this week, 1.25x the 90-day norm"
    assert classify(facts(new_kev_7d=100, baseline_kev_90d=780))["reason"] == (
        "100 KEV additions this week, 1.65x the 90-day norm")


def test_no_multiplier_when_baseline_is_not_a_real_90_day_one():
    # floor baseline (quiet install) and short history both say "above the usual range"
    assert classify(facts(new_kev_7d=4))["reason"] == "4 KEV additions this week, above the usual range"
    r = classify(facts(new_kev_7d=8, baseline_kev_90d=900, history_days=27))
    assert r["reason"] == "8 KEV additions this week, above the usual range"


def test_multiplier_never_reads_one_point_zero_when_not_calm():
    for n in range(3, 400):
        r = classify(facts(new_kev_7d=n, baseline_kev_90d=780))
        if r["level"] != "Calm":
            assert "1.0x" not in r["reason"] and "1.00x" not in r["reason"]


@pytest.mark.parametrize(
    "kw,level,reason",
    [
        (dict(ransomware_24h=1), "High", "1 ransomware-linked KEV addition since yesterday"),
        (dict(ransomware_24h=2), "Severe", "2 ransomware-linked KEV additions since yesterday"),
        (dict(ransomware_24h=1, ransomware_epss_24h=True), "Severe",
         "Ransomware-linked KEV addition with EPSS in the top 1%"),
        (dict(poc_unpatched_24h=True), "High",
         "KEV addition with a public exploit and no patch since yesterday"),
        (dict(new_cve_epss_top_24h=True), "Elevated",
         "New CVE in the top 1% for EPSS since yesterday"),
    ],
)
def test_triggers_raise_a_calm_week(kw, level, reason):
    r = classify(facts(**kw))
    assert (r["level"], r["reason"]) == (level, reason)


def test_triggers_never_lower_the_level():
    r = classify(facts(new_kev_7d=9, new_cve_epss_top_24h=True))  # Severe volume, Elevated trigger
    assert r["level"] == "Severe" and "KEV additions this week" in r["reason"]
    r = classify(facts(new_kev_7d=9, ransomware_24h=1))  # Severe volume beats High trigger
    assert r["level"] == "Severe" and "KEV additions this week" in r["reason"]


def test_strongest_trigger_names_the_reason():
    r = classify(facts(ransomware_24h=1, poc_unpatched_24h=True, new_cve_epss_top_24h=True))
    assert r["level"] == "High" and "ransomware" in r["reason"]
    r = classify(facts(poc_unpatched_24h=True, new_cve_epss_top_24h=True))
    assert "public exploit" in r["reason"]


# ---- DB gathering ----
def kev(db, cid, ago, **kw):
    db.add(Cve(cve_id=cid, published=NOW - timedelta(days=60), kev=True,
               kev_added=TODAY - timedelta(days=ago), **kw))


def test_new_cve_with_future_published_does_not_trigger(db_session):
    db_session.add(Cve(cve_id="CVE-2026-6201", published=NOW + timedelta(hours=2),
                       epss_percentile=0.999))
    db_session.flush()
    assert situation_for(db_session, NOW)["level"] == "Calm"


def test_gather_counts_windows(db_session):
    db = db_session
    kev(db, "CVE-2026-0001", 7)  # in the week (same predicate as new_kev)
    kev(db, "CVE-2026-0002", 8)  # baseline edge: day 8
    kev(db, "CVE-2026-0003", 97)  # baseline edge: day 97
    kev(db, "CVE-2026-0004", 98)  # outside baseline, still history
    db.flush()
    f = gather_facts(db, NOW)
    assert (f.new_kev_7d, f.baseline_kev_90d, f.history_days) == (1, 2, 98)


def test_db_volume_spike_with_enough_history(db_session):
    db = db_session
    for i in range(30):  # ~2.3/wk baseline, floored to 3
        kev(db, f"CVE-2026-1{i:03d}", 8 + i * 3)
    for i in range(8):
        kev(db, f"CVE-2026-2{i:03d}", 1 + i % 5)
    db.flush()
    r = situation_for(db, NOW)
    assert r["level"] == "Severe" and r["lit"] == 4


def test_db_short_history_ignores_baseline(db_session):
    db = db_session
    for i in range(8):
        kev(db, f"CVE-2026-3{i:03d}", i % 5)  # all within 7 days, history < 28d
    db.flush()
    assert situation_for(db, NOW)["level"] == "Severe"


def test_db_ransomware_recent_window(db_session):
    db = db_session
    kev(db, "CVE-2026-4001", 2, kev_ransomware=True)  # two days ago: not recent
    kev(db, "CVE-2026-4002", 0, kev_ransomware=False)
    db.flush()
    assert situation_for(db, NOW)["level"] == "Calm"
    kev(db, "CVE-2026-4003", 1, kev_ransomware=True)  # yesterday counts
    db.flush()
    r = situation_for(db, NOW)
    assert (r["level"], r["reason"]) == ("High", "1 ransomware-linked KEV addition since yesterday")
    kev(db, "CVE-2026-4004", 0, kev_ransomware=True)
    db.flush()
    assert situation_for(db, NOW)["level"] == "Severe"


def test_db_ransomware_with_top_epss_is_severe(db_session):
    kev(db_session, "CVE-2026-4101", 0, kev_ransomware=True, epss_percentile=0.99)
    db_session.flush()
    assert situation_for(db_session, NOW)["level"] == "Severe"


def test_db_ransomware_epss_below_threshold_is_high(db_session):
    kev(db_session, "CVE-2026-4201", 0, kev_ransomware=True, epss_percentile=0.989)
    db_session.flush()
    assert situation_for(db_session, NOW)["level"] == "High"


def test_db_poc_and_no_patch(db_session):
    db = db_session
    kev(db, "CVE-2026-5001", 0, poc_badge=True, patch_available=True)
    kev(db, "CVE-2026-5002", 0, poc_badge=True, patch_available=None)  # unknown patch: no
    kev(db, "CVE-2026-5003", 0, poc_badge=False, patch_available=False)
    kev(db, "CVE-2026-5004", 8, poc_badge=True, patch_available=False)  # not recent
    db.flush()
    assert situation_for(db, NOW)["level"] == "Calm"
    kev(db, "CVE-2026-5005", 1, poc_badge=True, patch_available=False)
    db.flush()
    r = situation_for(db, NOW)
    assert (r["level"], r["reason"]) == (
        "High", "KEV addition with a public exploit and no patch since yesterday")


@pytest.mark.parametrize("cvss", [None, 5.0, 9.8])
def test_db_new_top_epss_cve_scored_or_not(db_session, cvss):
    db_session.add(Cve(cve_id="CVE-2026-6001", published=NOW - timedelta(hours=23),
                       cvss=cvss, epss_percentile=0.995))
    db_session.flush()
    r = situation_for(db_session, NOW)
    assert (r["level"], r["reason"]) == ("Elevated", "New CVE in the top 1% for EPSS since yesterday")


def test_db_new_top_epss_cve_exclusions(db_session):
    db = db_session
    db.add(Cve(cve_id="CVE-2026-6101", published=NOW - timedelta(hours=25), epss_percentile=0.999))
    db.add(Cve(cve_id="CVE-2026-6102", published=NOW - timedelta(hours=1), epss_percentile=0.98))
    db.add(Cve(cve_id="CVE-2026-6103", published=NOW - timedelta(hours=1), epss_percentile=0.999,
               kev=True, kev_added=TODAY - timedelta(days=30)))  # in KEV: not this trigger
    db.flush()
    assert situation_for(db, NOW)["level"] == "Calm"


def test_db_trigger_does_not_lower_volume_level(db_session):
    db = db_session
    for i in range(8):
        kev(db, f"CVE-2026-7{i:03d}", 3)
    db.add(Cve(cve_id="CVE-2026-7900", published=NOW, epss_percentile=0.999))
    db.flush()
    assert situation_for(db, NOW)["level"] == "Severe"


def test_summary_situation_independent_of_range(db_session):
    db = db_session
    for i in range(5):
        kev(db, f"CVE-2026-8{i:03d}", 10 + i)  # outside 7d, inside 14d/30d
    db.flush()
    sits = [summary_counts(db, NOW, rng)["situation"] for rng in ("24h", "7d", "14d", "30d")]
    assert all(s == sits[0] for s in sits)
    assert sits[0]["level"] == "Calm"


def test_reason_is_template_only_even_with_hostile_db_text(db_session):
    evil = "<script>alert(1)</script> secret@example.com"
    kev(db_session, "CVE-2026-9001", 0, kev_ransomware=True, kev_name=evil, kev_notes=evil,
        summary=evil)
    db_session.flush()
    r = situation_for(db_session, NOW)
    assert r["reason"] == "1 ransomware-linked KEV addition since yesterday"
