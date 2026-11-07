"""Syscall pairing must not manufacture collection loss during attachment."""
from pathlib import Path
import shlex
import subprocess
import uuid


def test_openat_loop_across_daemon_startup(
        ssh_config, ssh_cmd, foreground_bloodhound, wait_until):
    fixture = Path(__file__).resolve().parents[1] / "fixtures/openat-startup.c"
    remote = f"/tmp/bh-openat-startup-{uuid.uuid4().hex}"
    subprocess.run([
        "sshpass", "-p", ssh_config["password"], "scp",
        "-o", "StrictHostKeyChecking=no", "-P", ssh_config["port"],
        str(fixture), f"{ssh_config['user']}@{ssh_config['host']}:{remote}.c",
    ], check=True)
    built = ssh_cmd(f"gcc -O2 -Wall -Wextra -Werror {remote}.c -o {remote}")
    assert built.returncode == 0, built.stderr
    command = (
        f"nohup sh -c {shlex.quote(f'{remote} {remote}.stop {remote}.ready; echo $? > {remote}.done')} "
        f">{remote}.log 2>&1 </dev/null &")
    started = ssh_cmd(command)
    assert started.returncode == 0, started.stderr
    try:
        wait_until(lambda: ssh_cmd(f"test -s {remote}.ready").returncode == 0,
                   "openat workload running before daemon startup")
        for attempt in range(3):
            with foreground_bloodhound("--heartbeat-interval", "0.1") as daemon:
                wait_until(lambda: any(e["event"]["name"] == "bloodhound_ready"
                                      for e in daemon.events()), "daemon readiness")
                assert daemon.events()[0]["args"]["attached"]["tier2.openat"] is True
                wait_until(lambda: any(e["event"]["name"] == "openat"
                                      for e in daemon.events()), "live openat capture")
                assert ssh_cmd(f"test ! -e {remote}.done").returncode == 0
                # Quiesce before detachment: object destruction has no paired
                # hook ordering guarantee and is not the startup window tested.
                # Every single-open child must exit while both hooks are live,
                # so startup orphans still reach lifecycle cleanup and counters.
                assert ssh_cmd(f"touch {remote}.stop").returncode == 0
                wait_until(lambda: ssh_cmd(f"test -s {remote}.done").returncode == 0,
                           "graceful workload completion")
                result = ssh_cmd(f"cat {remote}.done")
                assert result.stdout.strip() == "0", result.stderr
                daemon.signal()
                assert daemon.wait() == 0, daemon.stderr()
                diagnostics = [e for e in daemon.events()
                               if e["event"]["type"] == "DIAGNOSTIC"
                               and e["event"]["name"] == "openat.collection"
                               and e.get("args", {}).get("reason_code") == "invocation_interrupted"]
                assert not diagnostics, (attempt, diagnostics)
            if attempt < 2:
                reset = ssh_cmd(f"rm -f {remote}.stop {remote}.ready {remote}.done")
                assert reset.returncode == 0, reset.stderr
                started = ssh_cmd(command)
                assert started.returncode == 0, started.stderr
                wait_until(lambda: ssh_cmd(f"test -s {remote}.ready").returncode == 0,
                           "openat workload running before daemon restart")
    finally:
        ssh_cmd(f"touch {remote}.stop")
        wait_until(lambda: ssh_cmd(f"test -s {remote}.done").returncode == 0,
                   "openat workload cleanup")
        ssh_cmd(f"rm -f {remote} {remote}.*")
