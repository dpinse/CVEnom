import logging

import pytest

from cvenom.collectors.seenstate import track_new

log = logging.getLogger("test")


def _t(state, current):
    return track_new(state, set(current), source="src", collector_name="coll", logger=log)


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


@pytest.mark.parametrize("bad", [None, "A", 7, {"a": 1}])
def test_corrupt_rebaselines_with_warning(bad, caplog):
    state = {"seen": bad}
    with caplog.at_level("WARNING"):
        assert _t(state, {"A"}) == []
    assert "corrupt" in caplog.text and "coll" in caplog.text
    assert state["seen"] == ["A"]


def test_non_string_prior_entries_ignored():
    state = {"seen": ["A", 5, None]}
    assert _t(state, {"A", "B"}) == [{"type": "kev_added", "cve_id": "B", "source": "src"}]
    assert state["seen"] == ["A", "B"]
