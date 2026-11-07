"""Test-initiated restarts must not consume the service's crash-loop budget."""


def test_consecutive_service_starts(ssh_cmd, start_bloodhound):
    drop_in = "/run/systemd/system/bloodhound.service.d/99-e2e-start-limit.conf"
    # Keep all cycles in one rate-limit window even on slow CI hosts; leave
    # StartLimitBurst at the unit/manager default and restore policy afterward.
    configured = ssh_cmd(
        "mkdir -p /run/systemd/system/bloodhound.service.d && "
        f"printf '[Unit]\\nStartLimitIntervalSec=5min\\n' > {drop_in} && "
        "systemctl daemon-reload",
        user="root",
    )
    try:
        assert configured.returncode == 0, configured.stderr
        burst = ssh_cmd(
            "systemctl show bloodhound --property=StartLimitBurst --value",
            user="root",
        )
        assert burst.returncode == 0, burst.stderr
        cycles = int(burst.stdout.strip()) + 1
        assert cycles > 1, "The regression requires an enabled start rate limit"
        for cycle in range(cycles):
            print(f"Service stop/start cycle {cycle + 1}/{cycles}")
            stopped = ssh_cmd("systemctl stop bloodhound", user="root")
            assert stopped.returncode == 0, stopped.stderr
            start_bloodhound()
    finally:
        restored = ssh_cmd(
            f"rm -f {drop_in} && systemctl daemon-reload && "
            "systemctl reset-failed bloodhound",
            user="root",
        )
        assert restored.returncode == 0, restored.stderr
        start_bloodhound()
