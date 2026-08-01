"""Privileged USDT end-to-end tests.

The fixtures exercise the normal uprobe -> shared ring buffer -> deserializer
-> NDJSON path.  Restarting Bloodhound is synchronized by observable NDJSON
records, never by a fixed post-restart delay.
"""

from contextlib import contextmanager

import pytest

from helpers import assert_event_exists, validate_all_events


SHELL_TARGET = "/opt/bloodhound/usdt-fixtures/training-shell-v3"
SHELL_EVENT = {
    "type": "USDT",
    "name": "abyss0_shell.simple_command_completed",
    "layer": "behavior",
}
COLLECTOR_DIAGNOSTIC = {
    "type": "DIAGNOSTIC",
    "name": "usdt.collector",
    "layer": "behavior",
}


def _diagnostics(events, collector_id, reason_code):
    return [
        event
        for event in events
        if event.get("event") == COLLECTOR_DIAGNOSTIC
        and event.get("args", {}).get("collector_id") == collector_id
        and event.get("args", {}).get("reason_code") == reason_code
    ]


def _assert_collector_attached(ssh_cmd, collector_id):
    """Fail with the loader's real error when a collector did not attach.

    The guest kernel deliberately disables BPF run statistics, so ``run_cnt``
    is not portable evidence.  The fixture -> NDJSON assertion below is the
    acceptance proof; this guard only makes a loader failure unambiguous.
    """

    journal = ssh_cmd(
        "journalctl -u bloodhound -b --no-pager -o cat",
        user="root",
    )
    assert journal.returncode == 0, journal.stderr
    assert f"USDT collector {collector_id} failed to attach" not in journal.stdout, (
        f"{collector_id} attachment failed before the fixture executed:\n"
        f"{journal.stdout}"
    )


@pytest.fixture
def replace_usdt_target(ssh_cmd, fresh_bloodhound_events):
    """Temporarily replace the fixed collector target and recover the VM.

    The daemon is stopped before its file output is recreated, so the fresh
    NDJSON reader has no stale line-count baseline or open-file hole.  The
    recovery command is deliberately safe even when setup fails partway
    through; it restores the target whenever its backup exists.
    """

    @contextmanager
    def replace(replacement):
        backup = f"{SHELL_TARGET}.test-backup"
        prepare = ssh_cmd(
            "set -eu; "
            f"target={SHELL_TARGET}; backup={backup}; "
            "test ! -e \"$backup\"; "
            "systemctl stop bloodhound; "
            "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson; "
            "cp \"$target\" \"$backup\"; "
            f"cp {replacement} \"$target\"; "
            "systemctl start bloodhound",
            user="root",
        )
        try:
            assert prepare.returncode == 0, prepare.stderr
            yield fresh_bloodhound_events
        finally:
            restore = ssh_cmd(
                "set -eu; "
                f"target={SHELL_TARGET}; backup={backup}; "
                "systemctl stop bloodhound || true; "
                "if test -e \"$backup\"; then mv \"$backup\" \"$target\"; fi; "
                "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson; "
                "systemctl start bloodhound; "
                "systemctl is-active --quiet bloodhound; "
                "test ! -e \"$backup\"",
                user="root",
            )
            assert restore.returncode == 0, restore.stderr

    return replace


@pytest.fixture
def wait_for_usdt_daemon(ssh_cmd, wait_until):
    """Wait for this daemon instance to finish its compiled attach sequence.

    ``systemctl is-active`` only says that Type=simple has spawned the process.
    The journal marker is emitted after loader attachment returns.  It is a
    synchronization boundary before running a fixture, not evidence for the
    USDT assertion itself; each test still proves its result from NDJSON.
    """

    def wait():
        def attached():
            result = ssh_cmd(
                "set -eu; "
                "pid=$(systemctl show --property=MainPID --value bloodhound); "
                "test \"$pid\" -gt 0; "
                "journalctl _PID=\"$pid\" --no-pager -o cat | "
                "grep -Fx 'BPF programs loaded and attached' >/dev/null",
                user="root",
            )
            return result.returncode == 0

        wait_until(attached, "Bloodhound loader attachment for the current daemon")

    return wait


class TestTrustedUsdtCollectors:
    @staticmethod
    def _rejected_target_events(
        ssh_cmd,
        replace_usdt_target,
        wait_for_matching_events,
        replacement,
        reason_code,
        run_replaced_target=True,
    ):
        """Reject a target only after its startup diagnostic is observable."""
        with replace_usdt_target(replacement) as fresh_events:
            events = wait_for_matching_events(
                fresh_events,
                lambda candidate: bool(
                    _diagnostics(candidate, "training-shell-v3", reason_code)
                ),
                f"training-shell-v3 {reason_code} diagnostic",
            )
            if run_replaced_target:
                result = ssh_cmd(SHELL_TARGET)
                assert result.returncode == 0, result.stderr
            validate_all_events(events)
            diagnostics = _diagnostics(events, "training-shell-v3", reason_code)
            assert len(diagnostics) == 1, diagnostics
            assert not any(event.get("event") == SHELL_EVENT for event in events)
            return events

    def test_training_shell_v3_emits_a_semantic_usdt_event(
        self,
        ssh_cmd,
        bloodhound_events,
        wait_for_matching_events,
        wait_for_usdt_daemon,
    ):
        wait_for_usdt_daemon()
        result = ssh_cmd(f"{SHELL_TARGET} & {SHELL_TARGET} & wait")
        assert result.returncode == 0, result.stderr

        events = wait_for_matching_events(
            bloodhound_events,
            lambda candidate: sum(event.get("event") == SHELL_EVENT for event in candidate)
            >= 2,
            "two concurrent training-shell-v3 USDT events",
        )
        validate_all_events(events)
        matches = [event for event in events if event.get("event") == SHELL_EVENT]
        assert len(matches) == 2, f"Expected two concurrent fixture events, got {matches}"
        assert len({event["header"]["pid"] for event in matches}) == 2
        event = matches[0]
        assert event["args"]["attach_point_id"] == 0
        assert event["args"]["shell_pid"] == 412
        assert event["args"]["command_id"] == 17
        assert event["args"]["command_kind"] == "builtin"
        assert event["args"]["command_name"]["value"] == "echo"
        assert event["args"]["command_name_bytes"] == {
            "base64": "ZWNobw==",
            "capture_limit": 64,
            "observed_length": 4,
            "truncated": False,
        }
        assert event["args"]["semantic_flags"] == ["SELF_PID_EXPANDED"]
        assert event["args"]["exit_status"] == 0

    def test_independent_peer_collector_emits_its_own_event_shape(
        self,
        ssh_cmd,
        bloodhound_events,
        wait_for_matching_events,
        wait_for_usdt_daemon,
    ):
        wait_for_usdt_daemon()
        _assert_collector_attached(ssh_cmd, "training-peer-v1")
        result = ssh_cmd("/opt/bloodhound/usdt-fixtures/training-peer-v1")
        assert result.returncode == 0, result.stderr

        events = wait_for_matching_events(
            bloodhound_events,
            lambda candidate: any(
                event.get("event")
                == {
                    "type": "USDT",
                    "name": "abyss0_peer.task_finished",
                    "layer": "behavior",
                }
                for event in candidate
            ),
            "training-peer-v1 USDT event",
        )
        validate_all_events(events)
        event = assert_event_exists(
            events,
            event_type="USDT",
            name="abyss0_peer.task_finished",
            layer="behavior",
        )
        assert event["args"] == {
            "attach_point_id": 0,
            "task_id": 99,
            "result": "ok",
        }

    def test_unreadable_required_argument_is_a_diagnostic_not_a_partial_event(
        self,
        ssh_cmd,
        replace_usdt_target,
        wait_for_matching_events,
        wait_for_usdt_daemon,
    ):
        """A required pointer read fails closed without exposing its value."""
        with replace_usdt_target(
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-unreadable"
        ) as fresh_events:
            wait_for_usdt_daemon()
            result = ssh_cmd(SHELL_TARGET)
            assert result.returncode == 0, result.stderr
            events = wait_for_matching_events(
                fresh_events,
                lambda candidate: bool(
                    _diagnostics(candidate, "training-shell-v3", "abi_incompatible")
                ),
                "unreadable command_name diagnostic",
            )
            validate_all_events(events)
            diagnostics = _diagnostics(events, "training-shell-v3", "abi_incompatible")
            assert len(diagnostics) == 1, diagnostics
            assert diagnostics[0]["args"] == {
                "collector_id": "training-shell-v3",
                "reason_code": "abi_incompatible",
                "attach_point_id": 0,
                "argument": "command_name",
                "read_error_code": "unreadable_user_memory",
            }
            assert not any(event.get("event") == SHELL_EVENT for event in events)

    def test_non_allowlisted_build_id_is_rejected_before_attachment(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events
    ):
        self._rejected_target_events(
            ssh_cmd,
            replace_usdt_target,
            wait_for_matching_events,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-build-id-mismatch",
            "target_build_id_mismatch",
        )

    def test_missing_provider_probe_is_rejected_before_attachment(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events
    ):
        self._rejected_target_events(
            ssh_cmd,
            replace_usdt_target,
            wait_for_matching_events,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-no-probe",
            "probe_not_found",
        )

    def test_unsupported_note_operand_form_is_rejected_before_attachment(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events
    ):
        self._rejected_target_events(
            ssh_cmd,
            replace_usdt_target,
            wait_for_matching_events,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-wrong-abi",
            "abi_incompatible",
        )

    def test_unsupported_architecture_is_rejected_before_attachment(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events
    ):
        self._rejected_target_events(
            ssh_cmd,
            replace_usdt_target,
            wait_for_matching_events,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-unsupported-architecture",
            "unsupported_architecture",
            run_replaced_target=False,
        )

    def test_semaphore_backed_collector_attaches_and_emits(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events, wait_for_usdt_daemon
    ):
        with replace_usdt_target(
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-semaphore"
        ) as fresh_events:
            wait_for_usdt_daemon()
            _assert_collector_attached(ssh_cmd, "training-shell-v3")
            result = ssh_cmd(SHELL_TARGET)
            assert result.returncode == 0, result.stderr
            events = wait_for_matching_events(
                fresh_events,
                lambda candidate: any(event.get("event") == SHELL_EVENT for event in candidate),
                "semaphore-backed training-shell-v3 USDT event",
            )
            validate_all_events(events)
            assert_event_exists(
                events,
                event_type="USDT",
                name="abyss0_shell.simple_command_completed",
                layer="behavior",
            )

    def test_every_matching_static_location_emits_its_attach_point(
        self, ssh_cmd, replace_usdt_target, wait_for_matching_events, wait_for_usdt_daemon
    ):
        with replace_usdt_target(
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-multi"
        ) as fresh_events:
            wait_for_usdt_daemon()
            result = ssh_cmd(SHELL_TARGET)
            assert result.returncode == 0, result.stderr
            events = wait_for_matching_events(
                fresh_events,
                lambda candidate: {
                    event.get("args", {}).get("attach_point_id")
                    for event in candidate
                    if event.get("event") == SHELL_EVENT
                } >= {0, 1},
                "USDT events from both static locations",
            )
            validate_all_events(events)
            assert {
                event["args"]["attach_point_id"]
                for event in events
                if event.get("event") == SHELL_EVENT
            } >= {0, 1}
