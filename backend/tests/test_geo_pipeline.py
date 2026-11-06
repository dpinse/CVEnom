import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from cvenom.collectors.base import CollectorResult
from cvenom.models import GeoEvent
from cvenom.pipeline import ingest, purge_old_geo_events
from cvenom.schemas import NormalizedGeoEvent

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def ev(external_id="e1", **kw):
    base = dict(source="s", external_id=external_id, kind="scan", observed_at=NOW)
    base.update(kw)
    return NormalizedGeoEvent(**base)


def run(session, *events, **kw):
    ingest(session, CollectorResult(geo_events=list(events)), **kw)


def rows(session):
    return session.scalars(select(GeoEvent).order_by(GeoEvent.id)).all()


def test_upsert_idempotent_keeps_first_seen(db_session):
    old = NOW - timedelta(days=5)
    # now() is the outer-transaction start, so seed an explicitly old first_seen.
    db_session.add(GeoEvent(source="s", external_id="e1", kind="scan", observed_at=NOW,
                            first_seen=old, magnitude=1.0, label="a", details={}))
    db_session.flush()
    db_session.expunge_all()
    run(db_session, ev(magnitude=5.0, label="b", observed_at=NOW + timedelta(hours=1)))
    db_session.expunge_all()
    got = rows(db_session)
    assert len(got) == 1
    assert got[0].magnitude == 5.0 and got[0].label == "b"
    assert got[0].first_seen == old
    assert got[0].observed_at == NOW + timedelta(hours=1)


def test_label_sanitized(db_session):
    run(db_session, ev(label="<script>alert(1)</script>x"))
    label = rows(db_session)[0].label
    assert label is not None and re.search(r"<[A-Za-z/!?]", label) is None


def test_enrich_only_still_ingests_geo(db_session):
    run(db_session, ev(), enrich_only=True)
    assert len(rows(db_session)) == 1


def test_cve_id_has_no_fk(db_session):
    run(db_session, ev(cve_id="CVE-2099-0001"))
    assert rows(db_session)[0].cve_id == "CVE-2099-0001"


def test_batch_with_duplicates_and_many(db_session):
    run(db_session, *[ev(f"e{i}") for i in range(50)], ev("e0", magnitude=9.0))
    got = rows(db_session)
    assert len(got) == 50
    assert next(r for r in got if r.external_id == "e0").magnitude == 9.0


def test_purge_only_old(db_session):
    run(
        db_session,
        ev("old", observed_at=NOW - timedelta(days=31)),
        ev("edge", observed_at=NOW - timedelta(days=29)),
        ev("new"),
    )
    assert purge_old_geo_events(db_session, NOW, days=30) == 1
    assert {r.external_id for r in rows(db_session)} == {"edge", "new"}


def test_purge_naive_now_treated_as_utc(db_session):
    run(db_session, ev("old", observed_at=NOW - timedelta(days=31)), ev("new"))
    assert purge_old_geo_events(db_session, NOW.replace(tzinfo=None), days=30) == 1
    assert {r.external_id for r in rows(db_session)} == {"new"}


def test_batch_over_chunk_size_with_duplicate_across_chunks(db_session):
    events = [ev(f"e{i}", magnitude=1.0) for i in range(600)]
    events.append(ev("e0", magnitude=7.0))  # key first seen in chunk 1, repeated at the end
    run(db_session, *events)
    got = rows(db_session)
    assert len(got) == 600
    assert next(r for r in got if r.external_id == "e0").magnitude == 7.0


def test_details_strings_sanitized_recursively(db_session):
    details = {
        "group": "<script>alert(1)</script>evil",
        "n": 5,
        "flag": True,
        "nested": {"a": ["<b>x</b>", {"b": "<img src=x onerror=1>y"}], "k": 1.5},
        "none": None,
    }
    run(db_session, ev(details=details))
    row = rows(db_session)[0]
    assert "<" not in str(row.details)
    assert row.details["n"] == 5 and row.details["flag"] is True
    assert row.details["nested"]["k"] == 1.5 and row.details["none"] is None
    assert row.details["nested"]["a"][0] == "x"


def test_non_finite_floats_in_details_stored_as_null(db_session):
    nan, inf = float("nan"), float("inf")
    details = {"a": nan, "b": inf, "c": -inf, "ok": 1.5, "n": {"x": [nan, 2, {"y": inf}]}}
    run(db_session, ev(details=details))
    row = rows(db_session)[0]
    assert row.details["a"] is None and row.details["b"] is None and row.details["c"] is None
    assert row.details["ok"] == 1.5
    assert row.details["n"]["x"] == [None, 2, {"y": None}]


def test_details_keys_sanitized_and_upsert_succeeds(db_session):
    run(db_session, ev(details={"<b>x</b>\x00": 1, 5: "v", "n": {"<i>k</i>": 2}}))
    row = rows(db_session)[0]
    assert "<" not in str(row.details) and "\x00" not in str(row.details)
    assert row.details["5"] == "v"
    assert list(row.details["n"].values()) == [2]
