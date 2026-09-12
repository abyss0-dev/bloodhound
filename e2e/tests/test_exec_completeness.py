"""#33 argv completeness for both execve and execveat, consumed by #52."""
import json
from pathlib import Path
import subprocess


def test_exec_capture_completeness(ssh_config, ssh_cmd, bloodhound_events, wait_for_events):
    fixture = Path(__file__).resolve().parents[1] / "fixtures/exec-completeness.c"
    remote = "/tmp/bh-exec-completeness"
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(fixture),
                    f"root@{ssh_config['host']}:{remote}.c"], check=True)
    result = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote} && {remote}",
                     user="root")
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 20
    wait_for_events()
    events = bloodhound_events()
    for record in records:
        name = "execveat" if record["execveat"] else "execve"
        matches = [e for e in events if e["header"]["pid"] == record["pid"]
                   and e["event"]["name"] == name]
        assert len(matches) == 1, (record, matches)
        event = matches[0]
        args = event["args"]
        case = record["case"]
        expected = "complete"
        if case in ("twenty_one", "long_arg", "total_limit"):
            expected = "truncated"
        if case in ("bad_vector", "bad_string"):
            expected = "read_error"
        if case == "invalid_utf8":
            expected = "invalid_encoding"
        assert args["exec_capture_version"] == 1
        assert args["argv_status"] == expected, (record, args)
        assert args["filename_status"] == "complete"
        assert args["filename"] == "/usr/bin/true"
        assert event["return_code"] == (-14 if expected == "read_error" else 0)
        assert record["status"] == (100 << 8 if expected == "read_error" else 0)
        if case == "empty":
            assert args["argv"] == ["empty", "", "last", ""]
        if case == "twenty":
            assert len(args["argv"]) == 20
        if case in ("long_arg", "exact_arg_limit"):
            assert args["argv"][1] == "x" * 255
