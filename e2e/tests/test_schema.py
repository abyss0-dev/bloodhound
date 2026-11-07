"""Schema validation tests."""
from helpers import validate_all_events, validate_event


class TestSchemaValidation:
    """Validate all events against docs/schema.json."""

    def test_all_events_conform_to_schema(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """Every event in the output should conform to the BehaviorEvent schema."""
        # Generate some diverse activity
        ssh_cmd("ls /tmp")
        ssh_cmd("cat /etc/hostname")
        ssh_cmd("mkdir /tmp/schema_test && rmdir /tmp/schema_test")
        ssh_cmd("echo hello > /tmp/schema_out && rm /tmp/schema_out")
        wait_for_events()

        events = bloodhound_events()
        assert len(events) > 0, "No events captured"

        validate_all_events(events)

    def test_bpf_and_heartbeat_timestamps_share_monotonic_domain(
        self, ssh_cmd, bloodhound_events, wait_for_matching_events
    ):
        """BPF and userspace records expose comparable integer nanoseconds."""
        ssh_cmd("true")
        events = wait_for_matching_events(
            bloodhound_events,
            lambda observed: (
                any(e.get("event", {}).get("type") == "TRACEPOINT" for e in observed)
                and any(e.get("event", {}).get("type") == "HEARTBEAT" for e in observed)
            ),
            "a BPF tracepoint and HEARTBEAT in one observation stream",
        )
        bpf_event = next(
            event for event in events
            if event.get("event", {}).get("type") == "TRACEPOINT"
        )
        heartbeat = next(
            event for event in events
            if event.get("event", {}).get("type") == "HEARTBEAT"
        )
        bpf_timestamp = bpf_event["header"]["timestamp"]
        heartbeat_timestamp = heartbeat["header"]["timestamp"]
        assert isinstance(bpf_timestamp, int)
        assert isinstance(heartbeat_timestamp, int)
        # Both values are VM-uptime-scale nanoseconds. A mixed Unix timestamp
        # would differ by decades, while scheduling jitter is bounded here.
        assert abs(heartbeat_timestamp - bpf_timestamp) < 60_000_000_000


class TestAuidFilter:
    """Test that only target user's events appear."""

    def test_only_target_auid_events(
        self, ssh_cmd, bloodhound_events, wait_for_events, ssh_config
    ):
        """All events should have the target user's auid."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        target_auid = 1000  # testuser uid

        from helpers import assert_auid_filter
        assert_auid_filter(events, target_auid)


class TestShutdown:
    """Test graceful shutdown."""

    def test_sigterm_produces_clean_exit(
        self, ssh_cmd, bloodhound_events, wait_for_events,
        wait_for_bloodhound_attachment,
    ):
        """Check the stopped invocation, not a restarted daemon or old journal."""
        wait_for_bloodhound_attachment()
        invocation = ssh_cmd(
            "systemctl show --property=InvocationID --value bloodhound", user="root"
        ).stdout.strip()
        assert invocation
        ssh_cmd("echo shutdown_test")
        wait_for_events()
        try:
            # systemctl stop sends SIGTERM and suppresses Restart=always.
            stopped = ssh_cmd("systemctl stop bloodhound", user="root")
            assert stopped.returncode == 0, stopped.stderr
            status = ssh_cmd(
                "systemctl show -p Result -p ExecMainStatus bloodhound", user="root"
            )
            assert "Result=success" in status.stdout
            assert "ExecMainStatus=0" in status.stdout
            journal = ssh_cmd(
                f"journalctl _SYSTEMD_INVOCATION_ID={invocation} --no-pager -o cat",
                user="root",
            )
            assert "Shutdown complete" in journal.stdout
            assert "SIGKILL" not in journal.stdout
            events = bloodhound_events()
            assert events, "No events found after shutdown"
            assert events[-1]["event"]["type"] == "HEARTBEAT"
        finally:
            restored = ssh_cmd("systemctl start bloodhound", user="root")
            assert restored.returncode == 0, restored.stderr
            wait_for_bloodhound_attachment()
