"""Opt-in enforcement tests; DAC failure alone is never LSM evidence."""
import errno
import json
import shlex

import pytest

from helpers import filter_events

LSM_KEYS = {
    "lsm.task_kill", "lsm.bpf", "lsm.ptrace_access_check", "lsm.file_open",
    "lsm.inode_unlink", "lsm.inode_rename", "lsm.task_fix_setuid",
}


def principal_root(ssh_cmd, code):
    """Keep root capabilities (DAC permits), but join the observed AUID."""
    command = (
        "echo 1000 > /proc/self/loginuid; "
        "test \"$(cat /proc/self/loginuid)\" = 1000 || exit 97; "
        f"exec python3 -c {shlex.quote(code)}"
    )
    result = ssh_cmd(f"sh -ec {shlex.quote(command)}", user="root")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def opt_in_ready(daemon, wait_until, hook):
    wait_until(lambda: daemon.events(), "opt-in readiness")
    ready = daemon.events()[0]
    assert ready["event"]["name"] == "bloodhound_ready"
    attached = ready["args"]["attached"]
    assert {key for key in attached if key.startswith("lsm.")} == LSM_KEYS
    assert all(isinstance(attached[key], bool) for key in LSM_KEYS)
    if not attached[hook]:
        pytest.skip(f"optional hook {hook} failed to attach (reported unavailable)")
    return ready


class TestLsmTaskKill:
    def test_kill_daemon_blocked(self, ssh_cmd, foreground_bloodhound, wait_until):
        # SIGCONT is harmless if enforcement regresses; unlike SIGKILL it
        # cannot destroy the daemon before the assertion explains the failure.
        with foreground_bloodhound("--enable-lsm") as daemon:
            ready = opt_in_ready(daemon, wait_until, "lsm.task_kill")
            pid = ready["args"]["excluded"][0]
            result = principal_root(ssh_cmd, f"""
import json, os, signal
try:
    os.kill({pid}, signal.SIGCONT)
    error = 0
except OSError as exc:
    error = exc.errno
print(json.dumps({{"errno": error}}))
""")
            assert result["errno"] == errno.EPERM
            wait_until(
                lambda: any(
                    event.get("args", {}).get("target_pid") == pid
                    and event.get("return_code") == -1
                    for event in filter_events(daemon.events(), event_type="LSM", name="task_kill")
                ),
                "actual task_kill denial event (not DAC denial)",
            )
            assert ssh_cmd(f"kill -0 {pid}", user="root").returncode == 0


class TestLsmBpf:
    def test_bpf_is_observe_only(self, ssh_cmd, foreground_bloodhound, wait_until):
        with foreground_bloodhound("--enable-lsm") as daemon:
            opt_in_ready(daemon, wait_until, "lsm.bpf")
            result = principal_root(ssh_cmd, """
import ctypes, json, os, struct
libc = ctypes.CDLL(None, use_errno=True)
# x86_64 BPF_MAP_CREATE, BPF_MAP_TYPE_HASH; a valid map, not /dev/null.
attr = ctypes.create_string_buffer(struct.pack("IIIII", 1, 4, 4, 1, 0) + bytes(124))
fd = libc.syscall(321, 0, ctypes.byref(attr), 144)
error = ctypes.get_errno() if fd < 0 else 0
if fd >= 0:
    os.close(fd)
print(json.dumps({"fd": fd, "errno": error}))
""")
            assert result["fd"] >= 0, f"privileged principal bpf() failed: {result}"
            wait_until(
                lambda: filter_events(daemon.events(), event_type="LSM", name="bpf"),
                "observe-only BPF hook event",
            )
            for event in filter_events(daemon.events(), event_type="LSM", name="bpf"):
                assert event["return_code"] == 0
