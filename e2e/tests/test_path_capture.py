import json
from pathlib import Path
import shlex
import subprocess

import pytest


@pytest.fixture(autouse=True)
def attached(wait_for_bloodhound_attachment):
    wait_for_bloodhound_attachment()


def run_fixture(ssh_config, ssh_cmd, name):
    source = Path(__file__).resolve().parents[1] / "fixtures" / name
    remote = "/tmp/bh-" + source.stem
    subprocess.run(["sshpass", "-p", "root", "scp", "-o", "StrictHostKeyChecking=no",
                    "-P", ssh_config["port"], str(source),
                    f"root@{ssh_config['host']}:{remote}.c"], check=True)
    result = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote} && {remote}",
                     user="root")
    assert result.returncode == 0, (result.stdout, result.stderr)
    return [json.loads(line) for line in result.stdout.splitlines()]


@pytest.mark.parametrize("name,number,args", [
    ("rename", 82, "old, new"),
    ("renameat2", 316, "-100, old, -100, new, 0"),
    ("link", 86, "old, new"),
    ("linkat", 265, "-100, old, -100, new, 0"),
    ("symlink", 88, "old, new"),
    ("symlinkat", 266, "old, -100, new"),
])
def test_two_path_contents(name, number, args, ssh_cmd, bloodhound_events,
                           wait_for_matching_events):
    script = f'''
import ctypes, json, os, tempfile
libc = ctypes.CDLL(None, use_errno=True)
with tempfile.TemporaryDirectory(prefix="bh-{name}-") as root:
    oldpath, newpath = root + "/source", root + "/destination"
    with open(oldpath, "w") as f:
        f.write("source")
    old, new = ctypes.c_char_p(os.fsencode(oldpath)), ctypes.c_char_p(os.fsencode(newpath))
    ret = libc.syscall({number}, {args})
    assert ret == 0, ctypes.get_errno()
    print(json.dumps(dict(pid=os.getpid(), oldpath=oldpath, newpath=newpath)))
'''
    result = ssh_cmd("python3 -c " + shlex.quote(script))
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    events = wait_for_matching_events(
        bloodhound_events,
        lambda events: any(e["header"]["pid"] == record["pid"]
                           and e["event"]["name"] == name for e in events),
        f"{name} event for PID {record['pid']}",
    )
    matches = [e for e in events if e["header"]["pid"] == record["pid"]
               and e["event"]["name"] == name]
    assert len(matches) == 1, (record, matches)
    assert matches[0]["return_code"] == 0
    assert matches[0]["args"]["oldpath"] == record["oldpath"]
    assert matches[0]["args"]["newpath"] == record["newpath"]


@pytest.mark.parametrize("two,first,second,expected", [
    (False, "normal", "normal", ("complete",)),
    (False, "long", "normal", ("truncated",)),
    (False, "bad", "normal", ("read_error",)),
    (False, "null", "normal", ("read_error",)),
    (True, "long", "bad", ("truncated", "read_error")),
    (True, "bad", "long", ("read_error", "truncated")),
    (True, "normal", "normal", ("complete", "complete")),
])
def test_path_capture_status(two, first, second, expected, ssh_cmd,
                             bloodhound_events, wait_for_matching_events):
    name = "rename" if two else "chdir"
    script = f'''
import ctypes, json, os
libc = ctypes.CDLL(None, use_errno=True)
normal = ctypes.c_char_p(b"/tmp")
long = ctypes.c_char_p(b"/" + b"x" * 8192)
paths = dict(normal=normal, long=long, bad=ctypes.c_void_p(1), null=ctypes.c_void_p(0))
ret = libc.syscall({82 if two else 80}, paths[{first!r}], paths[{second!r}])
print(json.dumps(dict(pid=os.getpid(), ret=ret)))
'''
    result = ssh_cmd("python3 -c " + shlex.quote(script))
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    events = wait_for_matching_events(
        bloodhound_events,
        lambda events: any(e["header"]["pid"] == record["pid"]
                           and e["event"]["name"] == name for e in events),
        f"{name} capture status for PID {record['pid']}",
    )
    matches = [e for e in events if e["header"]["pid"] == record["pid"]
               and e["event"]["name"] == name]
    assert len(matches) == 1, matches
    args = matches[0]["args"]
    assert args["path_capture_version"] == 1
    keys = ("path1_status", "path2_status") if two else ("path_status",)
    assert tuple(args[key] for key in keys) == expected, matches
    path_keys = ("oldpath", "newpath") if two else ("filename",)
    for key, source in zip(path_keys, (first, second)):
        if source == "long":
            assert args[key] == "/" + "x" * 4094, matches
        elif source == "normal":
            assert args[key] == "/tmp", matches
        else:
            assert args[key] == "", matches


def test_single_path_across_cpu_migration(ssh_config, ssh_cmd, bloodhound_events,
                                          wait_for_matching_events):
    records = run_fixture(ssh_config, ssh_cmd, "path-concurrency.c")
    assert len(records) == 32
    assert all(r["before_cpu"] == 0 for r in records)
    assert sum(r["after_cpu"] == 1 for r in records) == 16
    pids = {r["pid"] for r in records}
    events = wait_for_matching_events(
        bloodhound_events,
        lambda events: pids <= {e["header"]["pid"] for e in events
                               if e["event"]["name"] == "truncate"},
        "truncate events from all workers",
    )
    for record in records:
        matches = [e for e in events if e["header"]["pid"] == record["pid"]
                   and e["event"]["name"] == record["name"]]
        assert len(matches) == 1, (record, matches)
        assert matches[0]["return_code"] == 0
        assert matches[0]["args"]["filename"] == record["path"], (record, matches)
