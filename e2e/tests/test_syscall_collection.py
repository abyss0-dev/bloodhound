"""Normal rich/path/raw collection must not report collection loss."""

import json
import shlex


def test_rich_and_path_workload_has_no_syscall_collection_loss(
    ssh_cmd, foreground_bloodhound, wait_until,
):
    script = '''
import ctypes, json, os, tempfile
libc = ctypes.CDLL(None, use_errno=True)
assert libc.syscall(186) == os.getpid()  # gettid: Tier 1, main thread
child = os.fork()
if child == 0:
    libc.syscall(60, 0)  # exit (not exit_group) has no sys_exit
    os._exit(99)
assert os.waitpid(child, 0)[1] == 0
with tempfile.TemporaryDirectory(prefix="bh-syscall-collection-") as root:
    oldpath, newpath = root + "/source", root + "/destination"
    with open(oldpath, "wb+") as source, tempfile.TemporaryFile() as target:
        source.write(b"bloodhound collection fixture")
        source.flush()
        copied = os.sendfile(target.fileno(), source.fileno(), 0, 13)
        assert copied == 13
        target.seek(0)
        assert target.read() == b"bloodhound co"
        assert libc.syscall(76, ctypes.c_char_p(os.fsencode(oldpath)), 5) == 0
        assert libc.syscall(82, ctypes.c_char_p(os.fsencode(oldpath)),
                            ctypes.c_char_p(os.fsencode(newpath))) == 0
    print(json.dumps({"pid": os.getpid(), "oldpath": oldpath, "newpath": newpath}))
'''
    with foreground_bloodhound("--enable-rich-sendfile") as daemon:
        wait_until(lambda: daemon.events(), "readiness before collection workload")
        assert daemon.events()[0]["args"]["attached"]["tier2.sendfile"] is True
        result = ssh_cmd("python3 -c " + shlex.quote(script))
        assert result.returncode == 0, (result.stdout, result.stderr)
        call = json.loads(result.stdout)

        def workload_events():
            return [e for e in daemon.events() if e["header"]["pid"] == call["pid"]]

        wait_until(
            lambda: {"sendfile", "truncate", "rename"}
            <= {e["event"]["name"] for e in workload_events()},
            "rich sendfile and single/two-path workload events",
        )
        # Shutdown forces the health monitor's final sample; absence of loss
        # before the first polling tick alone would be a vacuous assertion.
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        events = daemon.events()
        records = workload_events()
        for name in ("sendfile", "truncate", "rename"):
            matches = [e for e in records if e["event"]["name"] == name]
            assert len(matches) == 1, (name, records)
            assert matches[0]["event"]["type"] == "TRACEPOINT"
            assert matches[0]["return_code"] == (13 if name == "sendfile" else 0)
        assert any(e["event"]["type"] == "SYSCALL"
                   and e["args"].get("syscall_nr") == 186
                   and e["return_code"] == call["pid"] for e in records), records
        truncate = next(e for e in records if e["event"]["name"] == "truncate")
        assert truncate["args"]["filename"] == call["oldpath"]
        rename = next(e for e in records if e["event"]["name"] == "rename")
        assert rename["args"]["oldpath"] == call["oldpath"]
        assert rename["args"]["newpath"] == call["newpath"]
        assert any(e["header"]["pid"] != call["pid"]
                   and e["event"]["type"] == "SYSCALL"
                   and e["args"].get("syscall_nr") == 60 for e in events), events
        assert not any(e["event"]["name"] in {"syscall.collection", "raw_syscall.collection"}
                       for e in events), events
