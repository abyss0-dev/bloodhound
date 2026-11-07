"""Phase 2 startup facts and default observation-only boundary."""
import json
import shlex
import uuid

import pytest

REQUIRED = {"lifecycle", "signal", "exec.execve", "raw_syscalls"}
NON_TIER2_KEYS = REQUIRED | {"exec.execveat", "tty.write", "tty.read", "tty.read_ret"}


def assert_attached_matches_loader(daemon, attached):
    reports = [
        json.loads(line.split("BPF attachment report: ", 1)[1])
        for line in daemon.stderr().splitlines()
        if line.startswith("BPF attachment report: ")
    ]
    assert len(reports) == 1, daemon.stderr()
    assert set(attached) == set(reports[0])
    assert attached == reports[0]
    tier2 = {key for key in attached if key.startswith("tier2.")}
    assert tier2
    assert all(attached[key] is True for key in tier2)
    assert set(attached) - tier2 == NON_TIER2_KEYS


def tc_state(ssh_cmd):
    """Snapshot qdiscs and filters; unsupported inspection is an explicit failure."""
    def query(command):
        result = ssh_cmd(command, user="root")
        assert result.returncode == 0, (
            f"TC state inspection failed (unsupported is not a passing no-TC check): "
            f"{command}: {result.stderr}"
        )
        return json.loads(result.stdout)

    qdiscs = query("tc -j qdisc show")
    links = query("ip -j link show")
    filters = {}
    for link in links:
        device = link["ifname"]
        # clsact ingress/egress plus root and every existing qdisc parent.
        parents = {"root", "ingress", "egress"}
        parents.update(
            f"parent {qdisc['handle']}" for qdisc in qdiscs
            if qdisc.get("dev") == device and qdisc.get("handle") not in {None, "0:"}
        )
        for parent in sorted(parents):
            command = f"tc -j filter show dev {shlex.quote(device)} {parent}"
            filters[(device, parent)] = query(command)
    return qdiscs, filters


@pytest.mark.parametrize("seconds,millis", [("0", 0), ("0.0006", 1), ("1", 1000)])
def test_first_record_is_ready_with_exact_startup_facts(
    ssh_cmd, foreground_bloodhound, wait_until, seconds, millis,
):
    boot = ssh_cmd("cat /proc/sys/kernel/random/boot_id", user="root")
    assert boot.returncode == 0, boot.stderr
    before_qdiscs, before_filters = tc_state(ssh_cmd)
    with foreground_bloodhound("--heartbeat-interval", seconds) as daemon:
        wait_until(lambda: daemon.events(), "first stdout readiness record")
        event = daemon.events()[0]
        assert event["event"]["type"] == "META"
        assert event["event"]["name"] == "bloodhound_ready"
        args = event["args"]
        assert str(uuid.UUID(args["boot_id"])) == boot.stdout.strip()
        assert args["auid"] == 1000
        assert args["heartbeat_interval_ms"] == millis
        assert args["ring_buffer_size"] == 4 * 1024 * 1024
        assert isinstance(args["probes_attached"], int) and args["probes_attached"] > 0
        assert len(args["excluded"]) == 1
        pid = args["excluded"][0]
        assert isinstance(pid, int) and pid > 0
        actual = ssh_cmd(f"cat /proc/{pid}/comm", user="root")
        assert actual.returncode == 0 and actual.stdout.strip() == "bloodhound"
        assert_attached_matches_loader(daemon, args["attached"])
        assert "tier2.sendfile" not in args["attached"]
        assert "tier2.splice" not in args["attached"]
        assert all(args["attached"][key] is True for key in REQUIRED)
        assert all(isinstance(value, bool) for value in args["attached"].values())
        after_qdiscs, after_filters = tc_state(ssh_cmd)
        assert after_qdiscs == before_qdiscs, "startup changed qdiscs"
        assert after_filters == before_filters, "startup changed TC filters"
        ssh_cmd("cat /etc/hostname")
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        events = daemon.events()
        assert not any(e["event"]["type"] in {"LSM", "PACKET"} for e in events)
        if millis == 0:
            assert not any(e["event"]["type"] == "HEARTBEAT" for e in events)
        else:
            assert events[-1]["event"]["type"] == "HEARTBEAT"


def test_unprivileged_umount2_is_tier2_without_raw_duplicate(
    ssh_cmd, foreground_bloodhound, wait_until,
):
    script = '''
import ctypes, errno, json, os
assert os.geteuid() == 1000
libc = ctypes.CDLL(None, use_errno=True)
result = libc.umount2(b"/nonexistent", 0)
error = ctypes.get_errno()
assert result == -1 and error in {errno.EPERM, errno.ENOENT}, (result, error)
print(json.dumps({"pid": os.getpid(), "error": error}))
'''
    with foreground_bloodhound() as daemon:
        wait_until(lambda: daemon.events(), "readiness before umount2")
        result = ssh_cmd("python3 -c " + shlex.quote(script))
        assert result.returncode == 0, result.stderr
        call = json.loads(result.stdout)
        pid = call["pid"]
        wait_until(
            lambda: any(e["header"]["pid"] == pid
                        and e["event"]["name"] == "umount2"
                        for e in daemon.events()),
            "Tier-2 umount2 event for unprivileged caller",
        )
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        records = [e for e in daemon.events() if e["header"]["pid"] == pid]
        rich = [e for e in records if e["event"]["name"] == "umount2"
                and e["event"]["type"] == "TRACEPOINT"]
        assert len(rich) == 1, records
        assert rich[0]["return_code"] == -call["error"]
        assert not any(e["event"]["type"] == "SYSCALL"
                       and e["args"].get("syscall_nr") == 166 for e in records)


def test_live_process_records_are_not_procfs_enriched(ssh_cmd, foreground_bloodhound, wait_until):
    with foreground_bloodhound() as daemon:
        wait_until(lambda: daemon.events(), "readiness before alive-process test")
        started = ssh_cmd("nohup sleep 20 >/dev/null 2>&1 & echo $!")
        assert started.returncode == 0, started.stderr
        pid = int(started.stdout.strip())
        try:
            assert ssh_cmd(f"test -e /proc/{pid}/exe", user="root").returncode == 0
            wait_until(
                lambda: any(event["header"]["pid"] == pid for event in daemon.events()),
                "records for a process that is still alive",
            )
            records = [event for event in daemon.events() if event["header"]["pid"] == pid]
            assert records
            for event in records:
                assert "proc" not in event
                if event["event"]["name"] != "process_start":
                    assert "ppid" not in event["header"]
        finally:
            ssh_cmd(f"kill {pid} 2>/dev/null || true", user="root")


def test_selected_rich_pairs_have_readiness_keys(foreground_bloodhound, wait_until):
    with foreground_bloodhound("--enable-rich-sendfile") as daemon:
        wait_until(lambda: daemon.events(), "readiness with selected rich pairs")
        attached = daemon.events()[0]["args"]["attached"]
        assert_attached_matches_loader(daemon, attached)
        assert attached["tier2.sendfile"] is True
        assert attached["tier2.splice"] is True
