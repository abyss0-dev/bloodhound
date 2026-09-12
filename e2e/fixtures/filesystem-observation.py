#!/usr/bin/env python3
"""Managed two-view workload; emits facts, never Story/Evidence decisions."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def observe(path):
    path = Path(path)
    st = path.stat()
    return dict(path=str(path), major=os.major(st.st_dev), minor=os.minor(st.st_dev),
                ino=st.st_ino, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def namespace(root):
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "--bind", f"{root}/service", f"{root}/view"], check=True)
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    os.execl("/usr/bin/sleep", "sleep", "120")


def main():
    # Explicit test actor audit identity, inherited by every method process.
    Path("/proc/self/loginuid").write_text("1000")
    root = Path(tempfile.mkdtemp(prefix="bh-fs-"))
    root.chmod(0o755)
    for name in ("view", "service", "backup"):
        (root / name).mkdir()
    os.chown(root / "backup", 1000, 1000)
    (root / "view/current.chk").write_text("shell-view\n")
    (root / "service/current.chk").write_text("service-view\n")
    child = subprocess.Popen(["unshare", "--mount", sys.executable, __file__,
                              "--namespace", str(root)])
    try:
        host = str(root / "view/current.chk")
        source = f"/proc/{child.pid}/root{host}"
        dest = str(root / "backup/copied.chk")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("namespace process exited during setup")
            try:
                if Path(source).read_text() == "service-view\n":
                    break
            except PermissionError:
                # setuid temporarily clears dumpability before exec restores it.
                pass
            time.sleep(0.02)
        else:
            raise RuntimeError("namespace fixture did not become ready")
        report = dict(kernel=os.uname().release, target_pid=child.pid,
                      root=str(root), initial=[observe(host), observe(source)], methods=[])
        workloads = [
            ("process", ["ps", "-p", str(child.pid), "-o", "pid=,comm="]),
            ("stat_host", ["stat", "--", host]),
            ("stat_service", ["stat", "--", source]),
            ("namespace_self", ["readlink", "/proc/self/ns/mnt"]),
            ("namespace_target", ["readlink", f"/proc/{child.pid}/ns/mnt"]),
            ("mount_self", ["cat", "/proc/self/mountinfo"]),
            ("mount_target", ["cat", f"/proc/{child.pid}/mountinfo"]),
            ("cat_host", ["cat", "--", host]),
            ("cat_service", ["cat", "--", source]),
            ("copy_old", ["cp", "--", host, dest]),
            ("stat_old_destination", ["stat", "--", dest]),
            ("cat_old_destination", ["cat", "--", dest]),
            ("copy_service", ["cp", "--", source, dest]),
            ("stat_destination", ["stat", "--", dest]),
            ("cat_destination", ["cat", "--", dest]),
            ("recopy_service", ["cp", "--", source, dest]),
            ("missing", ["cat", "--", str(root / "missing")]),
        ]
        for name, argv in workloads:
            executable = os.path.realpath(shutil.which(argv[0]))
            process = subprocess.Popen(argv, executable=executable, user=1000, group=1000,
                                       extra_groups=[], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=10)
            report["methods"].append(dict(name=name, argv=argv, executable=executable,
                pid=process.pid, returncode=process.returncode, stdout=stdout, stderr=stderr,
                destination=observe(dest) if Path(dest).exists() else None))
        print(json.dumps(report))
    finally:
        child.terminate()
        child.wait(timeout=10)
        shutil.rmtree(root)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--namespace":
        namespace(sys.argv[2])
    else:
        main()
