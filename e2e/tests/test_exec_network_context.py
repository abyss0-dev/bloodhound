"""Real kernel producer acceptance for exec-entry network context."""
import json
import os
import shlex
from pathlib import Path


def _exec_events(events, marker):
    return [
        event for event in events
        if event.get("event", {}).get("name") == "execve"
        and marker in " ".join(event.get("args", {}).get("argv", []))
    ]


def _context_for_exec(events, exec_event):
    actor = (
        exec_event["header"]["pid"],
        exec_event["header"]["process_ref"]["start_boottime_ns"],
    )
    return [
        event for event in events
        if event.get("event", {}).get("name") == "exec_entry_network_context"
        and event.get("header", {}).get("pid") == actor[0]
        and event.get("header", {}).get("timestamp") == exec_event["header"]["timestamp"]
        and event.get("args", {}).get("actor", {}).get("start_boottime_ns") == actor[1]
        and event.get("args", {}).get("entry_timestamp_ns") == exec_event["header"]["timestamp"]
    ]


def _record_evidence(entry):
    path = os.environ.get("T2_ACCEPTANCE_EVIDENCE")
    if path:
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")


def _management_netns_fstat(ssh_cmd):
    result = ssh_cmd(
        "python3 -c 'import os; f=os.open(\"/proc/self/ns/net\", os.O_RDONLY); "
        "s=os.fstat(f); os.close(f); print(s.st_dev, s.st_ino)'",
        user="root",
    )
    assert result.returncode == 0, result.stderr
    device, inode = map(int, result.stdout.strip().split())
    return {"device": device, "inode": inode}


def _run_in_distinct_netns(ssh_cmd, source):
    command = (
        "sudo timeout --signal=TERM --kill-after=2s 20s "
        "unshare --net -- setpriv --reuid=1000 --regid=1000 --init-groups "
        f"/usr/bin/python3 -c {shlex.quote(source)}"
    )
    result = ssh_cmd(command)
    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip().split()
    assert len(fields) == 3, result.stdout
    _, device, inode = fields
    learner = {"device": int(device), "inode": int(inode)}
    management = _management_netns_fstat(ssh_cmd)
    return result, learner, management


def _assert_distinct_netns(learner, management):
    assert learner["device"] == management["device"], (
        "net namespaces must share the guest nsfs superblock device"
    )
    assert learner["inode"] != management["inode"], (
        "exec must report the distinct learner net namespace, not the manager namespace"
    )


def test_exec_context_uses_entry_actor_time_and_nsfs_fstat(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    marker = "t2-netctx-unique-acceptance"
    source = (
        "import os; "
        "fd=os.open('/proc/self/ns/net', os.O_RDONLY); a=os.fstat(fd); os.close(fd); "
        f"print('{marker}', a.st_dev, a.st_ino)"
    )
    result, learner_ns, management_ns = _run_in_distinct_netns(ssh_cmd, source)
    assert result.stdout.strip().split()[0] == marker, result.stdout
    _assert_distinct_netns(learner_ns, management_ns)

    events = wait_for_matching_events(
        bloodhound_events,
        lambda observed: any(
            event.get("event", {}).get("name") == "execve"
            and event.get("args", {}).get("filename", "").endswith("/python3")
            and marker in " ".join(event.get("args", {}).get("argv", []))
            for event in observed
        ),
        "matching exec event",
        timeout=30,
    )
    execs = [event for event in _exec_events(events, marker)
             if event.get("args", {}).get("filename", "").endswith("/python3")]
    assert len(execs) == 1, execs
    exec_event = execs[0]
    assert exec_event.get("return_code") == 0, exec_event
    assert exec_event["header"]["auid"] == 1000, exec_event
    matching = _context_for_exec(events, exec_event)
    assert len(matching) == 1, matching
    context = matching[0]
    assert context["args"]["status"] == "complete", context
    assert context["args"]["netns"] == learner_ns
    assert events.index(context) < events.index(exec_event), "context must retain exec-pair FIFO admission order"
    assert set(context["args"]) == {
        "actor", "entry_timestamp_ns", "netns", "record_version", "status"
    }
    diagnostics = [
        event for event in events
        if event.get("event", {}).get("name") == "exec.collection"
        or event.get("args", {}).get("reason_code") == "ring_buffer_overflow"
    ]
    assert not diagnostics, diagnostics
    kernel = ssh_cmd("uname -a", user="root")
    assert kernel.returncode == 0, kernel.stderr
    _record_evidence({
        "case": "leader_exec",
        "kernel": kernel.stdout.strip(),
        "entry_actor": context["args"]["actor"],
        "entry_timestamp_ns": context["args"]["entry_timestamp_ns"],
        "netns": context["args"]["netns"],
        "fd_fstat": learner_ns,
        "management_fd_fstat": management_ns,
        "status": context["args"]["status"],
        "exec_return_code": exec_event["return_code"],
        "diagnostics": diagnostics,
    })


def test_nonleader_exec_keeps_exact_entry_pairing(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    marker = "t2-nonleader-netctx-acceptance"
    target_source = (
        "import os; fd=os.open('/proc/self/ns/net', os.O_RDONLY); "
        "s=os.fstat(fd); os.close(fd); "
        f"print('{marker}', s.st_dev, s.st_ino)"
    )
    source = (
        "import os,threading; "
        f"target={target_source!r}; "
        "f=lambda: os.execv('/usr/bin/python3', ['/usr/bin/python3', '-c', target]); "
        "t=threading.Thread(target=f); t.start(); t.join()"
    )
    result, learner_ns, management_ns = _run_in_distinct_netns(ssh_cmd, source)
    assert result.stdout.strip().split()[0] == marker, result.stdout
    _assert_distinct_netns(learner_ns, management_ns)
    events = wait_for_matching_events(
        bloodhound_events,
        lambda observed: any(
            event.get("event", {}).get("name") == "execve"
            and event.get("args", {}).get("filename") == "/usr/bin/python3"
            and event.get("args", {}).get("argv", [None, None, None])[2] == target_source
            for event in observed
        ),
        "non-leader thread successful exec",
        timeout=30,
    )
    execs = [
        event for event in _exec_events(events, marker)
        if event.get("args", {}).get("filename") == "/usr/bin/python3"
        and event.get("args", {}).get("argv", [None, None, None])[2] == target_source
    ]
    assert len(execs) == 1, execs
    exec_event = execs[0]
    assert exec_event.get("return_code") == 0, exec_event
    assert exec_event["header"]["auid"] == 1000, exec_event
    contexts = _context_for_exec(events, exec_event)
    assert len(contexts) == 1, contexts
    context = contexts[0]
    assert context["args"]["status"] == "complete", context
    assert context["args"]["netns"] == learner_ns
    assert context["header"]["pid"] == exec_event["header"]["pid"]
    assert context["header"]["timestamp"] == exec_event["header"]["timestamp"]
    assert events.index(context) < events.index(exec_event)
    _record_evidence({
        "case": "nonleader_exec",
        "entry_actor": context["args"]["actor"],
        "entry_timestamp_ns": context["args"]["entry_timestamp_ns"],
        "netns": context["args"]["netns"],
        "fd_fstat": learner_ns,
        "management_fd_fstat": management_ns,
        "status": context["args"]["status"],
        "exec_return_code": exec_event["return_code"],
    })


def test_failed_exec_has_no_success_context(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    marker = "t2-failed-netctx-acceptance"
    source = (
        "import os; "
        f"os.execve('/t2-no-such-executable-{marker}', ['{marker}'], os.environ)"
    )
    result = ssh_cmd(f"python3 -c {shlex.quote(source)}")
    assert result.returncode != 0
    events = wait_for_matching_events(
        bloodhound_events,
        lambda observed: any(
            event.get("event", {}).get("name") == "execve"
            and marker in " ".join(event.get("args", {}).get("argv", []))
            for event in observed
        ),
        "failed exec attempt",
        timeout=30,
    )
    failures = [
        event for event in _exec_events(events, marker)
        if event.get("args", {}).get("filename")
        == f"/t2-no-such-executable-{marker}"
    ]
    assert len(failures) == 1, failures
    failed_exec = failures[0]
    assert failed_exec.get("return_code", 0) < 0, failed_exec
    assert not _context_for_exec(events, failed_exec), "failed exec must not receive a success context"
    _record_evidence({
        "case": "failed_exec",
        "entry_actor": failed_exec["header"].get("process_ref"),
        "entry_timestamp_ns": failed_exec["header"]["timestamp"],
        "exec_return_code": failed_exec["return_code"],
        "matching_contexts": 0,
    })
