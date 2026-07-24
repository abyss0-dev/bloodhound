"""Privileged USDT end-to-end tests.

The fixture is an independent static executable shipped with the test rootfs.
It exercises the normal uprobe -> shared ring buffer -> deserializer -> NDJSON
path; this test intentionally never calls a collector decoder directly.
"""

import json

from helpers import assert_event_exists, validate_all_events


class TestTrustedUsdtCollectors:
    @staticmethod
    def _rejected_target_events(ssh_cmd, replacement, reason_code):
        """Replace only the fixed target and collect its fresh daemon stream."""
        target = "/opt/bloodhound/usdt-fixtures/training-shell-v3"
        backup = f"{target}.test-backup"
        prepare = ssh_cmd(
            "systemctl stop bloodhound && "
            "mv /var/log/bloodhound.ndjson /var/log/bloodhound.ndjson.before-usdt-rejection && "
            "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson && "
            f"cp {target} {backup} && cp {replacement} {target} && "
            "systemctl start bloodhound && sleep 12",
            user="root",
        )
        assert prepare.returncode == 0, prepare.stderr
        try:
            result = ssh_cmd(target)
            assert result.returncode == 0, result.stderr
            output = ssh_cmd("cat /var/log/bloodhound.ndjson", user="root")
            assert output.returncode == 0, output.stderr
            events = [json.loads(line) for line in output.stdout.splitlines() if line.strip()]
            validate_all_events(events)
            diagnostics = [
                event for event in events
                if event.get("event") == {
                    "type": "DIAGNOSTIC",
                    "name": "usdt.collector",
                    "layer": "behavior",
                }
                and event.get("args", {}).get("collector_id") == "training-shell-v3"
                and event.get("args", {}).get("reason_code") == reason_code
            ]
            assert len(diagnostics) == 1, diagnostics
            assert not any(
                event.get("event", {}).get("name")
                == "abyss0_shell.simple_command_completed"
                for event in events
            )
            return events
        finally:
            restore = ssh_cmd(
                "systemctl stop bloodhound && "
                f"mv {backup} {target} && "
                "mv /var/log/bloodhound.ndjson /var/log/bloodhound.ndjson.after-usdt-rejection && "
                "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson && "
                "systemctl start bloodhound && sleep 12",
                user="root",
            )
            assert restore.returncode == 0, restore.stderr

    def test_training_shell_v3_emits_a_semantic_usdt_event(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        result = ssh_cmd(
            "/opt/bloodhound/usdt-fixtures/training-shell-v3 & "
            "/opt/bloodhound/usdt-fixtures/training-shell-v3 & wait"
        )
        assert result.returncode == 0, result.stderr
        wait_for_events(seconds=2)

        events = bloodhound_events()
        validate_all_events(events)
        matches = [
            event for event in events
            if event.get("event") == {
                "type": "USDT",
                "name": "abyss0_shell.simple_command_completed",
                "layer": "behavior",
            }
        ]
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
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        result = ssh_cmd("/opt/bloodhound/usdt-fixtures/training-peer-v1")
        assert result.returncode == 0, result.stderr
        wait_for_events(seconds=2)

        events = bloodhound_events()
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
        self, ssh_cmd, wait_for_events
    ):
        """The collector must fail closed without exposing the pointer value."""
        target = "/opt/bloodhound/usdt-fixtures/training-shell-v3"
        replacement = "/opt/bloodhound/usdt-fixtures/training-shell-v3-unreadable"
        backup = f"{target}.test-backup"
        prepare = ssh_cmd(
            "systemctl stop bloodhound && "
            "mv /var/log/bloodhound.ndjson /var/log/bloodhound.ndjson.before-usdt-error && "
            "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson && "
            f"cp {target} {backup} && cp {replacement} {target} && "
            "systemctl start bloodhound && sleep 12",
            user="root",
        )
        assert prepare.returncode == 0, prepare.stderr
        try:
            result = ssh_cmd(target)
            assert result.returncode == 0, result.stderr
            wait_for_events(seconds=2)
            # `StandardOutput=file:` reopens a restarted service's stream at
            # offset zero. Read this intentionally rotated file directly
            # rather than the session-wide line-count baseline fixture.
            output = ssh_cmd("cat /var/log/bloodhound.ndjson", user="root")
            assert output.returncode == 0, output.stderr
            events = [
                json.loads(line)
                for line in output.stdout.splitlines()
                if line.strip()
            ]
            validate_all_events(events)
            diagnostics = [
                event for event in events
                if event.get("event") == {
                    "type": "DIAGNOSTIC",
                    "name": "usdt.collector",
                    "layer": "behavior",
                }
                and event.get("args", {}).get("collector_id") == "training-shell-v3"
                and event.get("args", {}).get("reason_code") == "abi_incompatible"
            ]
            assert len(diagnostics) == 1, diagnostics
            assert diagnostics[0]["args"] == {
                "collector_id": "training-shell-v3",
                "reason_code": "abi_incompatible",
                "attach_point_id": 0,
                "argument": "command_name",
                "read_error_code": "unreadable_user_memory",
            }
            assert not any(
                event.get("event", {}).get("name")
                == "abyss0_shell.simple_command_completed"
                for event in events
            )
        finally:
            restore = ssh_cmd(
                "systemctl stop bloodhound && "
                f"mv {backup} {target} && "
                "mv /var/log/bloodhound.ndjson /var/log/bloodhound.ndjson.after-usdt-error && "
                "install -m 0644 -o root -g root /dev/null /var/log/bloodhound.ndjson && "
                "systemctl start bloodhound && sleep 12",
                user="root",
            )
            assert restore.returncode == 0, restore.stderr

    def test_non_allowlisted_build_id_is_rejected_before_attachment(self, ssh_cmd):
        self._rejected_target_events(
            ssh_cmd,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-build-id-mismatch",
            "target_build_id_mismatch",
        )

    def test_missing_provider_probe_is_rejected_before_attachment(self, ssh_cmd):
        self._rejected_target_events(
            ssh_cmd,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-no-probe",
            "probe_not_found",
        )

    def test_unsupported_note_operand_form_is_rejected_before_attachment(self, ssh_cmd):
        self._rejected_target_events(
            ssh_cmd,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-wrong-abi",
            "abi_incompatible",
        )

    def test_unsupported_semaphore_is_reported_without_attachment(self, ssh_cmd):
        self._rejected_target_events(
            ssh_cmd,
            "/opt/bloodhound/usdt-fixtures/training-shell-v3-semaphore",
            "semaphore_unavailable",
        )
