"""Final accounting is an ordinary HEARTBEAT, last after a clean shutdown."""
import pytest


def assert_final_accounting(events):
    assert events
    assert events[-1]["event"]["type"] == "HEARTBEAT"
    heartbeats = [e["args"] for e in events if e["event"]["type"] == "HEARTBEAT"]
    assert sum(h["drop_count_delta"] for h in heartbeats) == heartbeats[-1]["drop_count_total"]
    assert sum(h["events_emitted_delta"] for h in heartbeats) == len(events) - 1
    previous = 0
    for h in heartbeats:
        assert h["drop_count_delta"] == h["drop_count_total"] - previous
        assert h.get("gap_detected", False) == (h["drop_count_delta"] > 0)
        assert h.get("run_prefix_incomplete", False) == (h["drop_count_total"] > 0)
        if h["drop_count_total"]:
            assert h["reason_code"] == "ring_buffer_overflow"
        assert "final" not in h
        previous = h["drop_count_total"]
    return heartbeats


@pytest.mark.parametrize("signal,iteration", [("INT", i) for i in range(5)] + [("TERM", 0)])
def test_final_heartbeat(signal, iteration, foreground_bloodhound, wait_until, ssh_cmd):
    with foreground_bloodhound("--heartbeat-interval", "0.1") as daemon:
        wait_until(lambda: len(daemon.events()) > 0, "ready", timeout=30)
        ssh_cmd("for i in $(seq 1 30); do /bin/true; done")
        wait_until(lambda: any(e["event"]["type"] == "HEARTBEAT" for e in daemon.events()), "periodic heartbeat")
        daemon.signal(signal)
        assert daemon.wait() == 0, daemon.stderr()
        assert "Shutdown complete" in daemon.stderr()
        assert_final_accounting(daemon.events())


@pytest.mark.parametrize("interval", ["0", "3600"])
def test_disabled_or_long_interval(interval, foreground_bloodhound, wait_until):
    with foreground_bloodhound("--heartbeat-interval", interval) as daemon:
        wait_until(lambda: bool(daemon.events()), "ready", timeout=30)
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        assert "Shutdown complete" in daemon.stderr()
        heartbeats = [e for e in daemon.events() if e["event"]["type"] == "HEARTBEAT"]
        if interval == "0":
            assert heartbeats == []
        else:
            assert len(assert_final_accounting(daemon.events())) == 1


def test_tiny_ring_final_drop_accounting(foreground_bloodhound, wait_until, ssh_cmd):
    with foreground_bloodhound("--ring-buffer-size", "4096", "--heartbeat-interval", "3600") as daemon:
        wait_until(lambda: bool(daemon.events()), "ready", timeout=30)
        # Freeze userspace only: attached kernel probes keep producing into 4K.
        daemon.signal("STOP")
        try:
            result = ssh_cmd("for i in $(seq 1 300); do /bin/true; done")
            assert result.returncode == 0, result.stderr
        finally:
            daemon.signal("CONT")
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        assert "Shutdown complete" in daemon.stderr()
        heartbeats = assert_final_accounting(daemon.events())
        assert len(heartbeats) == 1
        assert heartbeats[-1]["drop_count_total"] > 0
