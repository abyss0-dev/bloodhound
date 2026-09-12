"""Opt-in verified Bash entry/return observations, before FD redirection."""
import pytest


def test_bash_launch_rejects_other_images_before_attachment(request, ssh_cmd):
    if not request.config.getoption('--bash-launch-enabled'):
        pytest.skip('requires the opt-in verified Bash collector binary')
    result = ssh_cmd('/opt/bloodhound/bloodhound --uid 1000 --bash-launch /usr/bin/true', user='root')
    assert result.returncode != 0
    assert 'unsupported Bash launch image digest' in result.stderr


@pytest.mark.parametrize('command,pipeline', [
    ('true', False),
    ('stat -- /etc/hostname > /dev/null', False),
    ('stat -- /etc/hostname > /dev/null | cat', True),
    ('cat /etc/hostname | stat -- /etc/hostname < /dev/null > /dev/null', True),
])
def test_verified_bash_launch_preserves_pipeline_arguments(
        command, pipeline, request, interactive_ssh, ssh_cmd, bloodhound_events,
        wait_for_events):
    if not request.config.getoption('--bash-launch-enabled'):
        pytest.skip('requires explicitly enabled verified Bash launch collector')
    shell = interactive_ssh()
    try:
        shell.sendline("printf 'SHELL_PID=%s\\n' \"$BASHPID\"")
        shell.expect(r'SHELL_PID=(\d+)')
        pid = int(shell.match.group(1))
        shell.expect(r'[\$#] ')
        clock = ssh_cmd("python3 -c 'import time; print(time.monotonic_ns())'", user="root")
        assert clock.returncode == 0, clock.stderr
        after = int(clock.stdout.strip())
        shell.sendline(command)
        shell.expect(r'[\$#] ')
        wait_for_events()
        events = [e for e in bloodhound_events()
                  if e.get('header', {}).get('pid') == pid
                  and e.get('event', {}).get('type') == 'UPROBE'
                  and e['header']['timestamp'] > after]
        entries = [e for e in events if e['event']['name'] == 'bash_command_entry']
        returns = [e for e in events if e['event']['name'] == 'bash_command_return']
        assert entries and returns
        for e in entries + returns:
            assert e['header']['process_ref']['start_boottime_ns'] > 0
            assert e['args']['launch_capture_version'] == 1
            assert e['args']['launch_status'] == 'complete'
        simple = [e['args'] for e in entries if e['args']['command_type'] == 4]
        assert simple
        observed = any(e['pipe_in'] != -1 or e['pipe_out'] != -1 for e in simple)
        assert observed == pipeline, simple
        assert all('pipe_in' not in e['args'] for e in returns)
    finally:
        shell.sendline('exit')
        shell.close()
