"""clone/clone3 process-versus-thread lifecycle classification."""


def _lifecycle(events, name, pid):
    return [
        event for event in events
        if event.get("event", {}).get("type") == "LIFECYCLE"
        and event.get("event", {}).get("name") == name
        and event.get("header", {}).get("pid") == pid
    ]


def test_pthread_clone3_does_not_create_a_process_instance(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    script = (
        "import os,threading; "
        "print(os.getpid(),flush=True); "
        "t=threading.Thread(target=lambda: print(threading.get_native_id(),flush=True)); "
        "t.start(); t.join()"
    )
    result = ssh_cmd(f"python3 -c {script!r}")
    ids = [int(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(ids) == 2, result.stderr
    parent_pid, thread_tid = ids
    events = wait_for_matching_events(
        bloodhound_events,
        lambda current: any(
            event.get("event", {}).get("name") in ("clone", "clone3")
            and event.get("header", {}).get("pid") == parent_pid
            and "CLONE_THREAD" in event.get("args", {}).get("flags", [])
            for event in current
        ),
        f"thread clone event for parent pid={parent_pid}",
    )
    assert _lifecycle(events, "process_start", thread_tid) == []
    assert all(
        event.get("args", {}).get("child_ref", {}).get("tgid") != thread_tid
        for event in events
        if event.get("event", {}).get("name") == "process_fork"
    )


def test_libc_fork_clone_creates_one_process_instance(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    script = (
        "import os; child=os.fork(); "
        "os._exit(0) if child == 0 else "
        "(print(os.getpid(),child,flush=True),os.waitpid(child,0))"
    )
    result = ssh_cmd(f"python3 -c {script!r}")
    ids = [int(value) for value in result.stdout.split() if value.strip()]
    assert len(ids) == 2, result.stderr
    parent_pid, child_pid = ids
    events = wait_for_matching_events(
        bloodhound_events,
        lambda current: len(_lifecycle(current, "process_exit", child_pid)) == 1,
        f"clone child exit for pid={child_pid}",
    )
    starts = _lifecycle(events, "process_start", child_pid)
    assert len(starts) == 1
    child_ref = starts[0]["header"]["process_ref"]
    forks = [
        event for event in events
        if event.get("event", {}).get("name") == "process_fork"
        and event.get("args", {}).get("child_ref") == child_ref
    ]
    assert len(forks) == 1
    assert forks[0]["args"]["parent_ref"]["tgid"] == parent_pid


def test_clone3_process_has_start_then_fork_with_matching_reference(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    script = r'''
import ctypes, os
class CloneArgs(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_ulonglong),
                ("pidfd", ctypes.c_ulonglong),
                ("child_tid", ctypes.c_ulonglong),
                ("parent_tid", ctypes.c_ulonglong),
                ("exit_signal", ctypes.c_ulonglong),
                ("stack", ctypes.c_ulonglong),
                ("stack_size", ctypes.c_ulonglong),
                ("tls", ctypes.c_ulonglong),
                ("set_tid", ctypes.c_ulonglong),
                ("set_tid_size", ctypes.c_ulonglong),
                ("cgroup", ctypes.c_ulonglong)]
args = CloneArgs()
args.exit_signal = 17
rc = ctypes.CDLL(None, use_errno=True).syscall(435, ctypes.byref(args), ctypes.sizeof(args))
if rc == 0:
    os._exit(0)
if rc < 0:
    raise OSError(ctypes.get_errno(), "clone3")
print(os.getpid(), rc, flush=True)
os.waitpid(rc, 0)
'''
    result = ssh_cmd(f"python3 -c {script!r}")
    ids = [int(value) for value in result.stdout.split() if value.strip()]
    assert len(ids) == 2, f"rc={result.returncode} stderr={result.stderr!r}"
    parent_pid, child_pid = ids
    events = wait_for_matching_events(
        bloodhound_events,
        lambda current: len(_lifecycle(current, "process_exit", child_pid)) == 1,
        f"clone3 child exit for pid={child_pid}",
    )
    starts = _lifecycle(events, "process_start", child_pid)
    assert len(starts) == 1
    child_ref = starts[0]["header"]["process_ref"]
    forks = [
        event for event in events
        if event.get("event", {}).get("name") == "process_fork"
        and event.get("args", {}).get("child_ref") == child_ref
    ]
    assert len(forks) == 1
    assert forks[0]["args"]["parent_ref"]["tgid"] == parent_pid
    assert forks[0]["args"]["clone_flags"] == ["0x0"]
    assert events.index(starts[0]) < events.index(forks[0])
