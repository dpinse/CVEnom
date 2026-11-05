import logging
from datetime import UTC, datetime, timedelta

import pytest

from cvenom.collectors.seenstate import track_new

log = logging.getLogger("test")

TODAY = datetime.now(UTC).date()


def _t(state, current, added_dates=None, max_age_days=14):
    return track_new(
        state,
        set(current),
        added_dates=added_dates or {},
        max_age_days=max_age_days,
        source="src",
        collector_name="coll",
        logger=log,
    )


def test_first_run_baselines_without_events():
    state = {}
    assert _t(state, {"B", "A"}) == []
    assert state["seen"] == ["A", "B"]


def test_new_ids_emit_sorted_events():
    state = {"seen": ["A"]}
    assert _t(state, {"A", "C", "B"}) == [
        {"type": "kev_added", "cve_id": "B", "source": "src"},
        {"type": "kev_added", "cve_id": "C", "source": "src"},
    ]
    assert state["seen"] == ["A", "B", "C"]


def test_union_never_shrinks():
    state = {"seen": ["A", "B"]}
    assert _t(state, set()) == []
    assert state["seen"] == ["A", "B"]


@pytest.mark.parametrize(
    "bad", [None, "A", 7, {"a": 1}, ["A", 5], ["A", None], [["A"]], [b"A"]]
)
def test_corrupt_rebaselines_with_warning(bad, caplog):
    # A non-list, or a list with ANY non-str element, is corrupt: warn, no events, re-baseline.
    state = {"seen": bad}
    with caplog.at_level("WARNING"):
        assert _t(state, {"A", "B"}) == []
    assert "corrupt" in caplog.text and "coll" in caplog.text
    assert state["seen"] == ["A", "B"]


def test_corrupt_with_empty_current_leaves_seen_absent(caplog):
    state = {"seen": ["A", 5]}
    with caplog.at_level("WARNING"):
        assert _t(state, set()) == []
    assert "seen" not in state


# --- first-run flood guards (#2) ---


def test_empty_first_run_leaves_seen_absent_then_full_run_baselines_silently():
    state = {}
    assert _t(state, set()) == []
    assert "seen" not in state
    # The next (full) run is still a first run: baseline, no flood.
    assert _t(state, {"A", "B", "C"}, {"A": TODAY, "B": TODAY, "C": TODAY}) == []
    assert state["seen"] == ["A", "B", "C"]


def test_truncated_first_baseline_then_full_feed_emits_only_recent():
    old = TODAY - timedelta(days=400)
    recent = TODAY - timedelta(days=2)
    state = {}
    assert _t(state, {"A", "B"}, {"A": old, "B": old}) == []  # truncated baseline
    full = {"A": old, "B": old, "C": old, "D": recent, "E": old}
    events = _t(state, set(full), full)
    assert [e["cve_id"] for e in events] == ["D"]
    assert state["seen"] == ["A", "B", "C", "D", "E"]  # old ids absorbed silently


def test_old_added_date_suppresses_event_but_is_recorded_seen():
    state = {"seen": ["A"]}
    assert _t(state, {"A", "B"}, {"B": TODAY - timedelta(days=15)}) == []
    assert state["seen"] == ["A", "B"]


def test_added_date_exactly_at_max_age_still_emits():
    state = {"seen": ["A"]}
    events = _t(state, {"A", "B"}, {"B": TODAY - timedelta(days=14)}, max_age_days=14)
    assert [e["cve_id"] for e in events] == ["B"]


def test_none_added_date_still_emits():
    state = {"seen": ["A"]}
    events = _t(state, {"A", "B", "C"}, {"B": None})  # C absent from the map: also unknown
    assert [e["cve_id"] for e in events] == ["B", "C"]
