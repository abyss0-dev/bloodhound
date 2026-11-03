"""Phase 2 startup facts and default observation-only boundary."""
import json
import uuid

import pytest

REQUIRED = {"lifecycle", "signal", "exec.execve", "raw_syscalls"}
TIER2 = {
    "openat", "read", "write", "connect", "bind", "listen", "socket",
    "clone", "clone3", "chdir", "fchdir", "unlink", "unlinkat", "rename",
    "renameat2", "mkdir", "mkdirat", "rmdir", "symlink", "symlinkat", "link",
    "linkat", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat",
    "truncate", "ftruncate", "mount", "umount2", "sendto", "recvfrom", "dup",
    "dup2", "dup3", "pread64", "pwrite64", "readv", "writev", "mmap", "fcntl",
}
DEFAULT_KEYS = REQUIRED | {f"tier2.{name}" for name in TIER2} | {
    "exec.execveat", "tty.write", "tty.read", "tty.read_ret",
}


@pytest.mark.parametrize("seconds,millis", [("0", 0), ("0.0006", 1), ("1", 1000)])
def test_first_record_is_ready_with_exact_startup_facts(
    ssh_cmd, foreground_bloodhound, wait_until, seconds, millis,
):
    boot = ssh_cmd("cat /proc/sys/kernel/random/boot_id", user="root")
    assert boot.returncode == 0, boot.stderr
    before = ssh_cmd("tc -j qdisc show", user="root")
    assert before.returncode == 0, before.stderr
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
        assert set(args["attached"]) == DEFAULT_KEYS
        assert all(args["attached"][key] is True for key in REQUIRED)
        assert all(isinstance(value, bool) for value in args["attached"].values())
        after = ssh_cmd("tc -j qdisc show", user="root")
        assert after.returncode == 0, after.stderr
        assert json.loads(after.stdout) == json.loads(before.stdout), "startup changed qdiscs"
        ssh_cmd("cat /etc/hostname")
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        events = daemon.events()
        assert not any(e["event"]["type"] in {"LSM", "PACKET"} for e in events)
        if millis == 0:
            assert not any(e["event"]["type"] == "HEARTBEAT" for e in events)
        else:
            assert events[-1]["event"]["type"] == "HEARTBEAT"


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
        assert set(attached) == DEFAULT_KEYS | {"tier2.sendfile", "tier2.splice"}
        assert isinstance(attached["tier2.sendfile"], bool)
        assert isinstance(attached["tier2.splice"], bool)
