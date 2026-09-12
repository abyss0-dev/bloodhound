"""Collector facts for #52, without implementing downstream Evidence gates."""
import json
import shlex
from pathlib import Path
import subprocess


def test_ptrace_hook_still_protects_daemon(
        ssh_cmd, bloodhound_events, wait_for_events):
    result = ssh_cmd("systemctl show bloodhound -p MainPID --value", user="root")
    assert result.returncode == 0
    daemon = int(result.stdout.strip())
    assert daemon > 0
    # Root has CAP_SYS_PTRACE, so DAC alone cannot make this test pass.
    script = ('import os; from pathlib import Path; '
              'Path("/proc/self/loginuid").write_text("1000"); '
              f'os.readlink("/proc/{daemon}/root")')
    result = ssh_cmd("python3 -c " + shlex.quote(script), user="root")
    assert result.returncode != 0 and "PermissionError" in result.stderr
    wait_for_events()
    matches = [e for e in bloodhound_events() if e["event"]["name"] == "ptrace_access_check"
               and e.get("args", {}).get("target_pid") == daemon]
    assert matches and all(e["return_code"] == -1 for e in matches)
    result = ssh_cmd("systemctl show bloodhound -p MainPID --value", user="root")
    assert int(result.stdout.strip()) == daemon


def test_openat_path_failures_and_relative_dirfd(
        ssh_config, ssh_cmd, bloodhound_events, wait_for_events):
    fixture = Path(__file__).resolve().parents[1] / "fixtures/openat-errors.c"
    remote = "/tmp/bh-openat-errors"
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(fixture),
                    f"root@{ssh_config['host']}:{remote}.c"], check=True)
    result = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote} && {remote}",
                     user="root")
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 5
    wait_for_events()
    events = bloodhound_events()
    for record in records:
        matches = [e for e in events if e["header"]["pid"] == record["pid"]
                   and e["event"]["name"] == "openat"
                   and e.get("return_code") == record["ret"]
                   and e.get("args", {}).get("dirfd") == record["dirfd"]]
        assert len(matches) == 1, (record, matches)
        args = matches[0]["args"]
        if record["case"] == "relative":
            assert record["ret"] >= 0 and args["filename"] == "hostname"
            assert args["file_identity_status"] == "complete"
            assert (args["dev_major"], args["dev_minor"], args["ino"]) == (
                record["major"], record["minor"], record["ino"])
        else:
            assert args["file_identity_status"] == "not_attempted"
            assert "dev" not in args and "ino" not in args
        expected = {"bad_pointer": ("read_error", -14), "long_path": ("truncated", -36),
                    "empty": ("complete", -2), "bad_dirfd": ("complete", -9)}
        if record["case"] in expected:
            status, ret = expected[record["case"]]
            assert args["filename_status"] == status and record["ret"] == ret


def test_openat_map_pressure_is_not_silent(
        ssh_config, ssh_cmd, bloodhound_events, wait_for_events):
    result = ssh_cmd("bpftool -j map show", user="root")
    assert result.returncode == 0, result.stderr
    maps = [m for m in json.loads(result.stdout) if m.get("name") == "OPENAT_ENTRY_MA"]
    assert len(maps) == 1, "fault injection requires exactly one isolated collector"
    fixture = Path(__file__).resolve().parents[1] / "fixtures/openat-map-pressure.c"
    remote = "/tmp/bh-openat-map-pressure"
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(fixture),
                    f"root@{ssh_config['host']}:{remote}.c"], check=True)
    result = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote} && "
                     f"{remote} {maps[0]['id']}", user="root")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["inserted"] > 0 and report["map_errno"] != 0
    assert report["child_status"] == report["cleanup_failed"] == 0
    wait_for_events()
    diagnostics = [e for e in bloodhound_events()
                   if e["event"]["name"] == "openat.collection"
                   and e.get("args", {}).get("reason_code") == "entry_save_failed"]
    assert diagnostics, "successful open with unrecorded entry must invalidate the run prefix"
    assert all(e["args"]["failure_count_delta"] > 0
               and e["args"]["run_prefix_incomplete"] is True for e in diagnostics)
    assert all(e["header"].get("process_ref") is None for e in diagnostics)


def test_concurrent_openat_across_cpu_migration(
        ssh_config, ssh_cmd, bloodhound_events, wait_for_events):
    fixture = Path(__file__).resolve().parents[1] / "fixtures/openat-concurrency.c"
    remote = "/tmp/bh-openat-concurrency"
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(fixture),
                    f"root@{ssh_config['host']}:{remote}.c"], check=True)
    result = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote} && {remote}",
                     user="root")
    assert result.returncode == 0, result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 32
    assert all(r["before_cpu"] == 0 for r in records)
    assert sum(r["after_cpu"] == 1 for r in records) == 16
    wait_for_events()
    events = bloodhound_events()
    for record in records:
        matches = [e for e in events if e["header"]["pid"] == record["pid"]
                   and e["event"]["name"] == "openat"
                   and e.get("args", {}).get("filename") == record["path"]]
        assert len(matches) == 1, (record, matches)
        event = matches[0]
        args = event["args"]
        assert event["return_code"] == record["fd"]
        assert event["header"]["auid"] == 1000
        ref = event["header"]["process_ref"]
        assert ref["tgid"] == record["pid"] and ref["start_boottime_ns"] > 0
        assert args["filename_status"] == args["file_identity_status"] == "complete"
        assert (args["dev_major"], args["dev_minor"], args["ino"]) == (
            record["major"], record["minor"], record["ino"])
        assert any(e["event"]["name"] == "process_exit"
                   and e["header"].get("process_ref") == ref for e in events)


def test_two_namespace_methods(ssh_config, ssh_cmd, bloodhound_events, wait_for_events):
    fixture = Path(__file__).resolve().parents[1] / "fixtures/filesystem-observation.py"
    remote = "/tmp/bh-filesystem-observation.py"
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(fixture),
                    f"root@{ssh_config['host']}:{remote}"], check=True)
    result = ssh_cmd(f"python3 {remote}", user="root")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    host, service = report["initial"]
    assert (host["major"], host["minor"], host["ino"]) != (
        service["major"], service["minor"], service["ino"])
    assert host["sha256"] != service["sha256"]
    methods = {m["name"]: m for m in report["methods"]}
    changes = report["changes"]
    assert changes["host_after"]["ino"] != host["ino"]
    assert changes["service_after"]["ino"] != service["ino"]
    assert changes["namespace_before"] == changes["namespace_after"]
    assert changes["mountinfo_changed"] is True
    assert methods["namespace_self"]["stdout"] != methods["namespace_target"]["stdout"]
    assert methods["copy_old"]["destination"]["sha256"] == host["sha256"]
    for name in ("copy_service", "recopy_service"):
        assert methods[name]["destination"]["sha256"] == service["sha256"]
    wait_for_events()
    events = bloodhound_events()
    for method in report["methods"]:
        assert method["returncode"] == (1 if method["name"] in ("missing", "target_exited") else 0)
        actor = [e for e in events if e["header"]["pid"] == method["pid"]]
        execs = [e for e in actor if e["event"]["name"] == "execve"
                 and e.get("args", {}).get("filename") == method["executable"]]
        assert len(execs) == 1, (method, actor)
        execution = execs[0]
        assert execution["args"]["argv"] == method["argv"]
        assert execution["args"]["argv_status"] == "complete"
        assert execution["args"]["filename_status"] == "complete"
        assert execution["return_code"] == 0
        assert execution["header"]["auid"] == 1000
        ref = execution["header"]["process_ref"]
        assert ref["tgid"] == method["pid"] and ref["start_boottime_ns"] > 0
        exits = [e for e in actor if e["event"]["name"] == "process_exit"
                 and e["header"].get("process_ref") == ref]
        assert len(exits) == 1, (method, actor)
        assert exits[0]["args"]["exit_code"] == method["returncode"]

    for name, observation in (("cat_host", host), ("cat_service", service),
                              ("cat_replaced_host", changes["host_after"]),
                              ("cat_remounted_service", changes["service_after"])):
        matches = [e for e in events if e["header"]["pid"] == methods[name]["pid"]
                   and e["event"]["name"] == "openat"
                   and e.get("args", {}).get("filename") == observation["path"]]
        assert len(matches) == 1
        event = matches[0]
        args = event["args"]
        assert event["return_code"] >= 0
        assert args["filename_status"] == args["file_identity_status"] == "complete"
        assert (args["dev_major"], args["dev_minor"], args["ino"]) == (
            observation["major"], observation["minor"], observation["ino"])
    missing = [e for e in events if e["header"]["pid"] == methods["missing"]["pid"]
               and e["event"]["name"] == "openat" and e.get("return_code") == -2]
    assert missing
    assert all(e["args"]["file_identity_status"] == "not_attempted" for e in missing)
