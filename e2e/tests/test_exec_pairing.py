"""#58 exec entry/exit pairing across a non-leader thread exec."""
import shlex

RUNS = 20
TARGET = "import sys; print('bh-nonleader-exec', sys.argv[1])"
LAUNCHER = (
    "import os,sys,threading; "
    f"a=['/usr/bin/python3','-c',{TARGET!r},sys.argv[1]]; "
    "t=threading.Thread(target=lambda: os.execv(a[0], a)); t.start(); t.join()"
)


def _target_argv(run):
    return ["/usr/bin/python3", "-c", TARGET, str(run)]


def test_nonleader_exec_emits_exactly_one_paired_record(
    ssh_cmd, bloodhound_events, wait_for_matching_events
):
    # de_thread() hands the leader PID to the execing thread before
    # sys_exit; every run must still produce its successful exec record.
    result = ssh_cmd(
        f"for i in $(seq {RUNS}); do python3 -c {shlex.quote(LAUNCHER)} $i || exit 1; done"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        word for run in range(1, RUNS + 1) for word in ("bh-nonleader-exec", str(run))
    ]

    def execs(events, run):
        return [e for e in events if e["event"]["name"] == "execve"
                and e.get("args", {}).get("argv") == _target_argv(run)]

    events = wait_for_matching_events(
        bloodhound_events,
        lambda observed: all(execs(observed, run) for run in range(1, RUNS + 1)),
        "successful non-leader exec records",
        timeout=30,
    )
    for run in range(1, RUNS + 1):
        matches = execs(events, run)
        assert len(matches) == 1, (run, matches)
        record = matches[0]
        assert record["return_code"] == 0, record
        assert record["header"]["auid"] == 1000, record
        ref = record["header"]["process_ref"]
        views = [e for e in events if e["event"]["name"] == "exec_view"
                 and e["header"].get("process_ref") == ref
                 and e["header"]["timestamp"] == record["header"]["timestamp"]]
        assert len(views) == 1, (run, views)

    diagnostics = [e for e in events if e["event"]["name"] == "exec.collection"]
    assert not diagnostics, diagnostics
