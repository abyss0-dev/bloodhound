"""Kernel-observed process lifecycle contract tests for issue #43."""

import signal

import pytest

from helpers import python_command


def _pid_from(result) -> int:
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines, f"missing fixture pid: rc={result.returncode} stderr={result.stderr!r}"
    return int(lines[0])


def _exits(events, pid: int) -> list[dict]:
    return [
        event for event in events
        if event.get("event", {}).get("type") == "LIFECYCLE"
        and event.get("event", {}).get("name") == "process_exit"
        and event.get("header", {}).get("pid") == pid
    ]


def _starts(events, pid: int) -> list[dict]:
    return [
        event for event in events
        if event.get("event", {}).get("type") == "LIFECYCLE"
        and event.get("event", {}).get("name") == "process_start"
        and event.get("header", {}).get("pid") == pid
    ]


def _wait_for_one_exit(wait_for_matching_events, bloodhound_events, pid: int):
    return wait_for_matching_events(
        bloodhound_events,
        lambda events: len(_exits(events, pid)) == 1,
        f"one process_exit for pid={pid}",
    )


@pytest.mark.parametrize(
    ("script", "expected_code"),
    [
        ("import os; print(os.getpid(), flush=True)", 0),
        ("import os; print(os.getpid(), flush=True); os._exit(42)", 42),
        (
            "import os,threading,time; "
            "threading.Thread(target=lambda: time.sleep(30),daemon=True).start(); "
            "print(os.getpid(),flush=True); os._exit(7)",
            7,
        ),
    ],
)
def test_normal_exit_group_and_multithread_teardown_emit_once(
    script,
    expected_code,
    ssh_cmd,
    bloodhound_events,
    wait_for_matching_events,
):
    pid = _pid_from(ssh_cmd(python_command(script)))
    events = _wait_for_one_exit(wait_for_matching_events, bloodhound_events, pid)
    exits = _exits(events, pid)
    assert len(exits) == 1
    assert exits[0]["args"]["exit_kind"] == "code"
    assert exits[0]["args"]["exit_code"] == expected_code

    starts = _starts(events, pid)
    assert len(starts) == 1
    stable_ref = exits[0]["header"]["process_ref"]
    assert stable_ref == starts[0]["header"]["process_ref"]
    assert stable_ref["tgid"] == pid
    assert stable_ref["start_boottime_ns"] > 0


def test_fatal_signal_emits_one_signal_exit(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    script = (
        "import os,signal; print(os.getpid(),flush=True); "
        "os.kill(os.getpid(),signal.SIGTERM)"
    )
    pid = _pid_from(ssh_cmd(python_command(script)))
    events = _wait_for_one_exit(wait_for_matching_events, bloodhound_events, pid)
    exits = _exits(events, pid)
    assert len(exits) == 1
    assert exits[0]["args"]["exit_kind"] == "signal"
    assert exits[0]["args"]["signal"] == signal.SIGTERM


def test_last_worker_reports_the_group_leader_exit_status(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    # SYS_exit terminates only the calling thread. The worker therefore emits
    # the last sched_process_exit after the leader (and its exit_code) is gone.
    script = (
        "import ctypes,os,threading,time; "
        "threading.Thread(target=lambda: time.sleep(0.2)).start(); "
        "print(os.getpid(),flush=True); ctypes.CDLL(None).syscall(60,42)"
    )
    pid = _pid_from(ssh_cmd(python_command(script)))
    events = _wait_for_one_exit(wait_for_matching_events, bloodhound_events, pid)
    exits = _exits(events, pid)
    assert len(exits) == 1
    assert exits[0]["args"]["exit_kind"] == "code"
    assert exits[0]["args"]["exit_code"] == 42


def test_short_lived_process_has_complete_identity_and_ordering(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    pid = _pid_from(ssh_cmd("sh -c 'echo $$; exec /bin/true'"))
    events = _wait_for_one_exit(wait_for_matching_events, bloodhound_events, pid)
    starts = _starts(events, pid)
    assert len(starts) == 1
    process_ref = starts[0]["args"]["process_ref"]
    assert process_ref == starts[0]["header"]["process_ref"]
    assert process_ref["start_boottime_ns"] > 0
    assert "partial" not in starts[0].get("args", {})

    start_index = events.index(starts[0])
    child_behavior = [
        i for i, event in enumerate(events)
        if event.get("header", {}).get("process_ref") == process_ref
        and event.get("event", {}).get("type") != "LIFECYCLE"
    ]
    assert child_behavior
    assert start_index < min(child_behavior)


def test_rapid_pid_reuse_produces_two_process_references(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    script = r'''
import os
candidate = 30000
pids = []
for _ in range(2):
    with open("/proc/sys/kernel/ns_last_pid", "w") as f:
        f.write(str(candidate))
    child = os.fork()
    if child == 0:
        os.execl("/bin/true", "true")
    pids.append(child)
    os.waitpid(child, 0)
print(*pids, flush=True)
'''
    result = ssh_cmd(python_command(script, sudo=True))
    pids = [int(value) for value in result.stdout.split() if value.strip()]
    assert len(pids) == 2, result.stderr
    assert pids[0] == pids[1], f"fixture did not reuse a pid: {pids}"
    pid = pids[0]
    events = wait_for_matching_events(
        bloodhound_events,
        lambda current: len(_exits(current, pid)) == 2,
        f"two exits for reused pid={pid}",
    )
    refs = [
        tuple(sorted(event["header"]["process_ref"].items()))
        for event in _starts(events, pid)
    ]
    assert len(refs) == 2
    assert len(set(refs)) == 2


def test_task_kill_identifies_target_without_synthesizing_exit(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    pid = _pid_from(ssh_cmd("nohup sleep 30 >/dev/null 2>&1 & echo $!"))
    try:
        probe = ssh_cmd(f"kill -0 {pid}")
        assert probe.returncode == 0
        events = wait_for_matching_events(
            bloodhound_events,
            lambda current: any(
                event.get("event", {}).get("name") == "task_kill"
                and event.get("args", {}).get("target_pid") == pid
                and event.get("args", {}).get("signal") == 0
                for event in current
            ),
            f"task_kill signal probe for pid={pid}",
        )
        task_kill = next(
            event for event in events
            if event.get("event", {}).get("name") == "task_kill"
            and event.get("args", {}).get("target_pid") == pid
            and event.get("args", {}).get("signal") == 0
        )
        assert task_kill["args"]["target_ref"]["tgid"] == pid
        assert task_kill["args"]["target_ref"]["start_boottime_ns"] > 0
        assert _exits(events, pid) == []
    finally:
        ssh_cmd(f"kill -TERM {pid}")


def test_signal_generate_identifies_sender_and_target_without_lsm_authority(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    pid = _pid_from(ssh_cmd("nohup sleep 30 >/dev/null 2>&1 & echo $!"))
    try:
        sent = ssh_cmd(f"kill -TERM {pid}")
        assert sent.returncode == 0
        events = wait_for_matching_events(
            bloodhound_events,
            lambda current: any(
                event.get("event", {}).get("type") == "TRACEPOINT"
                and event.get("event", {}).get("name") == "signal_generate"
                and event.get("args", {}).get("target_pid") == pid
                and event.get("args", {}).get("signal") == 15
                and event.get("args", {}).get("result") == "delivered"
                for event in current
            ) and len(_exits(current, pid)) == 1,
            f"signal_generate and process_exit for pid={pid}",
        )
        generated_index, generated = next(
            (index, event)
            for index, event in enumerate(events)
            if event.get("event", {}).get("type") == "TRACEPOINT"
            and event.get("event", {}).get("name") == "signal_generate"
            and event.get("args", {}).get("target_pid") == pid
            and event.get("args", {}).get("signal") == 15
            and event.get("args", {}).get("result") == "delivered"
        )
        exit_index = next(
            index
            for index, event in enumerate(events)
            if event.get("event", {}).get("name") == "process_exit"
            and event.get("header", {}).get("pid") == pid
        )
        assert generated["header"]["process_ref"]["tgid"] > 0
        assert generated["header"]["process_ref"]["start_boottime_ns"] > 0
        assert generated["args"]["target_ref"]["tgid"] == pid
        assert generated["args"]["target_ref"]["start_boottime_ns"] > 0
        assert "return_code" not in generated
        assert generated_index < exit_index
    finally:
        ssh_cmd(f"kill -KILL {pid} 2>/dev/null || true")
