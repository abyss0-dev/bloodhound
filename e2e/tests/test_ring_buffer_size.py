"""Verify configured ring capacity against the live kernel map readiness report."""

import pytest


def ready_events(events):
    return [
        event for event in events
        if event.get("event", {}).get("type") == "META"
        and event.get("event", {}).get("name") == "bloodhound_ready"
    ]


def test_configured_ring_buffer_size(foreground_bloodhound, wait_for_matching_events):
    with foreground_bloodhound("--ring-buffer-size", "8388608") as daemon:
        events = wait_for_matching_events(
            daemon.events,
            lambda events: bool(ready_events(events)),
            "8 MiB kernel ring buffer readiness",
            timeout=30,
        )
        ready = ready_events(events)
        assert len(ready) == 1, ready
        assert ready[0]["args"]["ring_buffer_size"] == 8388608


@pytest.mark.parametrize("size", [0, 2048, 3_000_000, 4097])
def test_invalid_ring_buffer_size(size, foreground_bloodhound):
    with foreground_bloodhound("--ring-buffer-size", str(size)) as daemon:
        assert daemon.wait() != 0
        assert f"invalid --ring-buffer-size {size}" in daemon.stderr()
        assert not ready_events(daemon.events())
        # Validation must precede output setup and BPF attachment, not merely
        # rely on the kernel rejecting map creation later in startup.
        assert daemon.events() == []
        assert "Bloodhound starting" not in daemon.stderr()
