"""Ownership parser, PID reuse, bounded stop and timeout regressions."""
import os
import signal
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from t2_process_identity import (  # noqa: E402
    is_owned_process,
    parse_proc_stat,
    run_bounded,
    terminate_owned_process,
)


def stat_line(threads, start, comm="qemu ) test"):
    # State then numeric fields 4..52. Offsets 17 (field20) and 19 (field22).
    fields = ["S"] + ["0"] * 49
    fields[17] = str(threads)
    fields[19] = str(start)
    return f"42 ({comm}) " + " ".join(fields)


def test_proc_stat_uses_start_ticks_not_changing_thread_count():
    assert parse_proc_stat(stat_line(8, 123456)) == (8, 123456)
    assert parse_proc_stat(stat_line(12, 123456)) == (12, 123456)


def test_pid_reuse_and_image_mismatch_never_signal_foreign_process(tmp_path):
    proc = tmp_path / "42"
    proc.mkdir()
    (proc / "stat").write_text(stat_line(4, 999))
    (proc / "cmdline").write_bytes(b"qemu\0-drive\0file=/owned/disk.img\0")
    signalled = []
    assert not terminate_owned_process(42, 1000, "/owned/disk.img", proc_root=tmp_path,
                                       kill=lambda *args: signalled.append(args))
    assert not terminate_owned_process(42, 999, "/different/disk.img", proc_root=tmp_path,
                                       kill=lambda *args: signalled.append(args))
    assert signalled == []


def test_exact_child_stops_and_is_reaped():
    disk = "/tmp/t2-process-identity-owned-image"
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", disk])
    try:
        _, start = parse_proc_stat(Path(f"/proc/{child.pid}/stat").read_text())
        assert is_owned_process(child.pid, start, disk)
        assert terminate_owned_process(child.pid, start, disk, grace=2)
        child.wait(timeout=3)
        assert child.returncode is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)


def test_external_command_timeout_is_finite():
    try:
        run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], 0.05)
    except subprocess.TimeoutExpired:
        return
    raise AssertionError("bounded command unexpectedly completed")
