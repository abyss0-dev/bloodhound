"""Exact QEMU ownership checks used by the task-owned VM harness."""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path


class ProcessIdentityError(RuntimeError):
    pass


def parse_proc_stat(text: str) -> tuple[int, int]:
    """Return (threads, start_ticks); comm may itself contain right parens."""
    _, separator, rest = text.rpartition(")")
    if not separator:
        raise ValueError("malformed proc stat: missing comm terminator")
    fields = rest.strip().split()  # starts with field 3 (state)
    if len(fields) <= 19:
        raise ValueError("malformed proc stat: missing starttime")
    return int(fields[17]), int(fields[19])  # proc fields 20 and 22


def is_owned_process(pid: int, start_ticks: int, disk: str, proc_root: Path = Path("/proc")) -> bool:
    proc = proc_root / str(pid)
    try:
        _, current_start = parse_proc_stat((proc / "stat").read_text())
        argv = (proc / "cmdline").read_bytes().decode(errors="replace").split("\0")
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return False
    return current_start == start_ticks and any(disk in argument for argument in argv)


def terminate_owned_process(
    pid: int,
    start_ticks: int,
    disk: str,
    *,
    grace: float = 10.0,
    proc_root: Path = Path("/proc"),
    kill=os.kill,
    sleep=time.sleep,
) -> bool:
    """TERM then bounded KILL only an exact pid/start/image owner; never waits on mismatch."""
    if not is_owned_process(pid, start_ticks, disk, proc_root):
        return False
    kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not is_owned_process(pid, start_ticks, disk, proc_root):
            return True
        sleep(0.05)
    if not is_owned_process(pid, start_ticks, disk, proc_root):
        return True
    kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + min(grace, 5.0)
    while time.monotonic() < deadline:
        if not is_owned_process(pid, start_ticks, disk, proc_root):
            return True
        sleep(0.05)
    raise ProcessIdentityError(f"owned QEMU pid {pid} did not stop within bounded cleanup")


def disk_is_referenced(disk: str, proc_root: Path = Path("/proc")) -> bool:
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().decode(errors="replace").split("\0")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if any(disk in argument for argument in argv):
            return True
    return False


def main() -> int:
    import sys
    mode, pid, ticks, disk = sys.argv[1:5]
    pid, ticks = int(pid), int(ticks)
    if mode == "start":
        print(parse_proc_stat(Path(f"/proc/{pid}/stat").read_text())[1])
        return 0
    if mode == "stop":
        return 0 if terminate_owned_process(pid, ticks, disk) else 2
    if mode == "in-use":
        return 0 if disk_is_referenced(disk) else 1
    raise ValueError(f"unknown mode: {mode}")


def run_bounded(argv: list[str], timeout: float, **kwargs):
    """Run a helper command with a mandatory finite timeout."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    return subprocess.run(argv, timeout=timeout, **kwargs)


if __name__ == "__main__":
    raise SystemExit(main())
