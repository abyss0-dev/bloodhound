"""Rich collectors suppress raw records only when they preserve the arguments."""

import json
import shlex


def test_execve_dedup_keeps_execveat_fd_arguments(
    ssh_cmd, foreground_bloodhound, wait_until,
):
    script = '''
import ctypes, errno, json, os, tempfile
libc = ctypes.CDLL(None, use_errno=True)
with tempfile.TemporaryFile() as file:
    fd = file.fileno()
    result = libc.syscall(322, fd, ctypes.c_char_p(b""), 0, 0, 0x1000)
    assert result == -1
    execveat_error = ctypes.get_errno()
    result = libc.syscall(59, ctypes.c_char_p(b"/bloodhound-no-such-executable"), 0, 0)
    assert result == -1 and ctypes.get_errno() == errno.ENOENT
    print(json.dumps({"pid": os.getpid(), "fd": fd, "error": execveat_error}))
'''
    with foreground_bloodhound() as daemon:
        wait_until(lambda: daemon.events(), "readiness before exec dedup")
        result = ssh_cmd("python3 -c " + shlex.quote(script))
        assert result.returncode == 0, result.stderr
        call = json.loads(result.stdout)
        pid = call["pid"]
        wait_until(
            lambda: any(e["header"]["pid"] == pid
                        and e["event"]["name"] == "execve"
                        and e.get("return_code") == -2
                        for e in daemon.events()),
            "failed rich execve",
        )
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        records = [e for e in daemon.events() if e["header"]["pid"] == pid]
        raw = [e for e in records if e["event"]["type"] == "SYSCALL"]
        execveat = [e for e in raw if e["args"]["syscall_nr"] == 322]
        assert len(execveat) == 1, records
        assert execveat[0]["args"]["raw_args"][0] == call["fd"]
        assert execveat[0]["args"]["raw_args"][4] == 0x1000
        assert execveat[0]["return_code"] == -call["error"]
        assert not any(e["args"]["syscall_nr"] == 59 for e in raw), records


def test_opt_in_sendfile_arguments_return_and_no_raw_duplicate(
    ssh_cmd, foreground_bloodhound, wait_until,
):
    script = '''
import json, os, tempfile
with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
    source.write(b"bloodhound sendfile fixture")
    source.flush()
    count = 13
    copied = os.sendfile(target.fileno(), source.fileno(), 0, count)
    assert copied == count
    target.seek(0)
    assert target.read() == b"bloodhound se"
    print(json.dumps({"pid": os.getpid(), "in_fd": source.fileno(),
                      "out_fd": target.fileno(), "size": count, "copied": copied}))
'''
    with foreground_bloodhound("--enable-rich-sendfile") as daemon:
        wait_until(lambda: daemon.events(), "readiness before sendfile")
        assert daemon.events()[0]["args"]["attached"]["tier2.sendfile"] is True
        result = ssh_cmd("python3 -c " + shlex.quote(script))
        assert result.returncode == 0, result.stderr
        call = json.loads(result.stdout)
        pid = call["pid"]
        wait_until(
            lambda: any(e["header"]["pid"] == pid
                        and e["event"]["name"] == "sendfile"
                        for e in daemon.events()),
            "rich sendfile event",
        )
        daemon.signal()
        assert daemon.wait() == 0, daemon.stderr()
        records = [e for e in daemon.events() if e["header"]["pid"] == pid]
        rich = [e for e in records if e["event"]["type"] == "TRACEPOINT"
                and e["event"]["name"] == "sendfile"]
        assert len(rich) == 1, records
        for key in ("in_fd", "out_fd", "size"):
            assert rich[0]["args"][key] == call[key]
        assert rich[0]["return_code"] == call["copied"]
        assert not any(e["event"]["type"] == "SYSCALL"
                       and e["args"].get("syscall_nr") == 40 for e in records), records
