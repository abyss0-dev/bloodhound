"""Unit coverage for the USDT E2E readiness helper.

These tests use in-memory readers only.  They guard the distinction between a
bounded observed condition and the old fixed-delay approach.
"""

import pytest


def test_wait_for_matching_events_retries_until_the_predicate_matches(
    wait_for_matching_events,
):
    snapshots = [[], [{"event": {"type": "DIAGNOSTIC"}}]]

    def read_events():
        return snapshots.pop(0)

    events = wait_for_matching_events(
        read_events,
        lambda candidate: bool(candidate),
        "an in-memory diagnostic",
        timeout=1,
        interval=0,
    )

    assert events == [{"event": {"type": "DIAGNOSTIC"}}]


def test_wait_for_matching_events_fails_when_no_observed_condition_arrives(
    wait_for_matching_events,
):
    with pytest.raises(pytest.fail.Exception, match="missing diagnostic"):
        wait_for_matching_events(
            lambda: [],
            lambda candidate: bool(candidate),
            "missing diagnostic",
            timeout=0,
            interval=0,
        )
