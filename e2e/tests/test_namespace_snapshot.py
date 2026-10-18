"""#57 header tid / namespace snapshot and META bloodhound_ready."""
import json
import shlex

from helpers import python_command, validate_event

SLOTS = ("mnt", "net", "uts", "ipc", "cgroup", "user", "pid")
# Prints this task's tid, pid and namespace identities as /proc reports them,
# then execs a marker process in the same task.
REPORT = (
    "import json,os,sys,threading; "
    f"s={{n: os.stat(f'/proc/self/ns/{{n}}') for n in {SLOTS!r}}}; "
    "print(json.dumps({'pid': os.getpid(), 'tid': threading.get_native_id(), "
    "'dev': {n: v.st_dev for n,v in s.items()}, 'ino': {n: v.st_ino for n,v in s.items()}}), flush=True); "
    "os.execv('/usr/bin/true', ['/usr/bin/true', sys.argv[1]])"
)


def _report(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _marker_exec(events, marker):
    return [e for e in events if e["event"]["name"] == "execve"
            and e.get("args", {}).get("argv") == ["/usr/bin/true", marker]]


def _ready(ssh_cmd):
    result = ssh_cmd("cat /var/log/bloodhound.ndjson", user="root")
    assert result.returncode == 0, result.stderr
    first = json.loads(result.stdout.splitlines()[0])
    return first, [json.loads(line) for line in result.stdout.splitlines() if "bloodhound_ready" in line]


def test_ready_is_first_record_and_reports_nsfs_dev(ssh_cmd):
    first, readies = _ready(ssh_cmd)
    assert first["event"] == {"type": "META", "name": "bloodhound_ready", "layer": "behavior"}, first
    validate_event(first)
    assert "tid" not in first["header"] and "ns" not in first["header"], first
    args = first["args"]
    assert args["probes_attached"] > 0, args
    assert args["ring_buffer_size"] == 4 * 1024 * 1024, args
    stat = ssh_cmd(python_command("import os; print(os.stat('/proc/self/ns/net').st_dev)"), user="root")
    assert stat.returncode == 0, stat.stderr
    assert args["nsfs_dev"] == int(stat.stdout), args
    assert all(r["args"]["nsfs_dev"] == args["nsfs_dev"] for r in readies), readies


def _assert_header_matches(record, report, nsfs_dev):
    validate_event(record)
    ns = record["header"]["ns"]
    assert set(ns) == set(SLOTS), ns
    for slot in SLOTS:
        assert ns[slot] == {"status": "complete", "inode": report["ino"][slot]}, (slot, ns)
        assert report["dev"][slot] == nsfs_dev, (slot, report)


def test_exec_header_snapshot_equals_procfs(ssh_cmd, bloodhound_events, wait_for_matching_events):
    first, _ = _ready(ssh_cmd)
    marker = "bh-ns-initial"
    report = _report(ssh_cmd(f"python3 -c {shlex.quote(REPORT)} {marker}"))
    events = wait_for_matching_events(
        bloodhound_events, lambda observed: _marker_exec(observed, marker), "marker exec", timeout=30)
    [record] = _marker_exec(events, marker)
    assert record["header"]["tid"] == report["tid"] == report["pid"], (record["header"], report)
    _assert_header_matches(record, report, first["args"]["nsfs_dev"])


def test_unshared_namespaces_appear_in_exec_and_child_start(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    first, _ = _ready(ssh_cmd)
    initial = _report(ssh_cmd(f"python3 -c {shlex.quote(REPORT)} bh-ns-before"))
    marker = "bh-ns-unshared"
    # sudo keeps the audit login UID, so the namespaced child stays traced.
    report = _report(ssh_cmd(
        "sudo unshare --net --uts --ipc --fork --pid --mount-proc "
        f"python3 -c {shlex.quote(REPORT)} {marker}"
    ))
    assert report["pid"] == 1, report
    changed = {"mnt", "net", "uts", "ipc", "pid"}
    for slot in SLOTS:
        assert (report["ino"][slot] != initial["ino"][slot]) == (slot in changed), (slot, initial, report)

    events = wait_for_matching_events(
        bloodhound_events, lambda observed: _marker_exec(observed, marker), "namespaced exec", timeout=30)
    [record] = _marker_exec(events, marker)
    _assert_header_matches(record, report, first["args"]["nsfs_dev"])
    # tid is reported in the producer's PID namespace, not the child's.
    assert record["header"]["tid"] != 1, record["header"]

    ref = record["header"]["process_ref"]
    starts = [e for e in events if e["event"] == {"type": "LIFECYCLE", "name": "process_start", "layer": "behavior"}
              and e["header"].get("process_ref") == ref]
    assert len(starts) == 1, starts
    start = starts[0]
    # The kernel-observed start describes the child at fork: it already
    # belongs to the new namespaces created by unshare before the fork.
    assert start["header"]["tid"] == record["header"]["tid"], (start["header"], record["header"])
    _assert_header_matches(start, report, first["args"]["nsfs_dev"])


def test_task_context_records_carry_tid_and_ns_together(ssh_cmd, bloodhound_events, wait_for_matching_events):
    marker = "bh-ns-coverage"
    _report(ssh_cmd(f"python3 -c {shlex.quote(REPORT)} {marker}"))
    events = wait_for_matching_events(
        bloodhound_events, lambda observed: _marker_exec(observed, marker), "marker exec", timeout=30)
    synthesized = {"HEARTBEAT", "DIAGNOSTIC", "META", "PACKET"}
    for event in events:
        header = event["header"]
        assert ("tid" in header) == ("ns" in header), event
        if event["event"]["type"] in synthesized:
            assert "tid" not in header, event
    kernel = [e for e in events if e["event"]["type"] not in synthesized]
    assert kernel and all("tid" in e["header"] or e["event"]["name"] == "process_start" for e in kernel), [
        e for e in kernel if "tid" not in e["header"]][:5]
