import json
import os
import shlex
import subprocess
import time

import pexpect
import pytest


def pytest_addoption(parser):
    parser.addoption("--ssh-port", default="2222", help="SSH port for VM")
    parser.addoption("--ssh-host", default="localhost", help="SSH host for VM")
    parser.addoption("--ssh-user", default="testuser", help="SSH user")
    parser.addoption("--ssh-pass", default="testpass", help="SSH password")
    parser.addoption(
        "--bloodhound-output",
        default="/var/log/bloodhound.ndjson",
        help="Path to bloodhound output file in VM",
    )


@pytest.fixture(scope="session")
def ssh_config(request):
    return {
        "host": request.config.getoption("--ssh-host"),
        "port": request.config.getoption("--ssh-port"),
        "user": request.config.getoption("--ssh-user"),
        "password": request.config.getoption("--ssh-pass"),
        "output_path": request.config.getoption("--bloodhound-output"),
    }


@pytest.fixture(scope="session")
def ssh_cmd(ssh_config):
    """Build an SSH command prefix for non-interactive commands."""

    def run(cmd, user=None):
        u = user or ssh_config["user"]
        # Use matching password: root uses "root", others use the configured password
        password = "root" if u == "root" else ssh_config["password"]
        full_cmd = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            ssh_config["port"],
            f"{u}@{ssh_config['host']}",
            cmd,
        ]
        print(f"  [SSH {u}] {cmd}")
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=30
        )
        return result

    return run


@pytest.fixture
def interactive_ssh(ssh_config):
    """Create an interactive SSH session via pexpect (allocates PTY)."""

    def create_session():
        cmd = (
            f"sshpass -p {ssh_config['password']} "
            f"ssh -o StrictHostKeyChecking=no "
            f"-p {ssh_config['port']} "
            f"{ssh_config['user']}@{ssh_config['host']}"
        )
        child = pexpect.spawn(cmd, timeout=30)
        # Wait for shell prompt
        child.expect(r"[\$#] ", timeout=15)
        return child

    return create_session


@pytest.fixture(autouse=True)
def _event_baseline(ssh_config, request):
    """Record the current NDJSON line count before each test.

    Since we cannot safely truncate the NDJSON file (the daemon holds it open
    via systemd StandardOutput=append: and truncating creates NUL-byte gaps),
    we instead record how many lines exist BEFORE the test starts and only
    return events generated after that point.
    """
    result = subprocess.run(
        [
            "sshpass", "-p", "root",
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-p", ssh_config["port"],
            f"root@{ssh_config['host']}",
            f"wc -l < {ssh_config['output_path']}",
        ],
        capture_output=True, text=True, timeout=10,
    )
    try:
        request.node._baseline = int(result.stdout.strip())
    except (ValueError, AttributeError):
        request.node._baseline = 0


@pytest.fixture
def bloodhound_events(ssh_config, ssh_cmd, request):
    """Retrieve and parse bloodhound NDJSON output from the VM.

    Only returns events generated AFTER the test started (using the baseline
    line count recorded by the _event_baseline fixture).
    """

    def get_events():
        baseline = getattr(request.node, "_baseline", 0)
        output_path = shlex.quote(ssh_config["output_path"])
        result = ssh_cmd(
            f"tail -n +{baseline + 1} -- {output_path}",
            user="root",
        )
        assert result.returncode == 0, result.stderr

        events = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # The daemon can be appending while tail reads the file.
                    # A polling caller retries a partial final line.
                    continue
        return events

    return get_events


@pytest.fixture
def fresh_bloodhound_events(ssh_config, ssh_cmd):
    """Read the complete current NDJSON file without a session baseline.

    This reader is for tests that stop Bloodhound, create a new output file,
    and then restart it.  The ordinary ``bloodhound_events`` fixture is not
    safe for that use because its line-count baseline predates the restart.
    Incomplete writes are retried by the polling helper below.
    """

    def get_events():
        output_path = shlex.quote(ssh_config["output_path"])
        result = ssh_cmd(f"cat -- {output_path}", user="root")
        assert result.returncode == 0, result.stderr

        events = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # The daemon can be appending while the file is read.  A
                # polling caller will retry; never treat a partial final line
                # as a malformed event from Bloodhound.
                continue
        return events

    return get_events


@pytest.fixture
def wait_until():
    """Poll a bounded readiness predicate without using a fixed delay."""

    def wait(predicate, description, timeout=15.0, interval=0.1):
        deadline = time.monotonic() + timeout
        while True:
            if predicate():
                return
            if time.monotonic() >= deadline:
                pytest.fail(f"Timed out waiting for {description}")
            time.sleep(interval)

    return wait


@pytest.fixture
def wait_for_matching_events(wait_until):
    """Poll an event reader until an observable NDJSON condition is true.

    The timeout bounds a real readiness protocol; it is not a delay chosen to
    make a race less likely.  Callers must provide a predicate over actual
    NDJSON records, such as the expected collector diagnostic or USDT event.
    """

    def wait(read_events, predicate, description, timeout=15.0, interval=0.1):
        latest_events = []

        def is_ready():
            nonlocal latest_events
            latest_events = read_events()
            if predicate(latest_events):
                return True
            return False

        wait_until(is_ready, description, timeout=timeout, interval=interval)
        return latest_events

    return wait


@pytest.fixture
def wait_for_events():
    """Wait a brief period for events to be processed and flushed."""

    def wait(seconds=2):
        time.sleep(seconds)

    return wait
