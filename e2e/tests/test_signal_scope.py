"""O-11: real-kernel sender-or-target selection, with an unchanged sender header.

Requires an owned E2E guest and root's ability to set audit loginuid. These are
live observations, not raw fixtures. The foreground daemon uses default
observation mode (no opt-in enforcement).
"""

import json

import pytest

from helpers import python_command


# The target inherits the original root loginuid, then sets its own. Only after
# that fork does the sender set its loginuid, so the two scopes are independent.
# Pipe synchronization keeps the target alive and avoids cleanup kill events.
SIGNAL_PAIR = r'''
import json, os, signal, sys
sender_auid, target_auid = map(int, sys.argv[1:])
ready_r, ready_w = os.pipe()
done_r, done_w = os.pipe()
target = os.fork()
if target == 0:
    os.close(ready_r)
    os.close(done_w)
    try:
        with open('/proc/self/loginuid', 'w') as f:
            f.write(str(target_auid))
        assert int(open('/proc/self/loginuid').read()) == target_auid
        signal.signal(signal.SIGUSR1, signal.SIG_IGN)
        os.write(ready_w, b'1')
        os.read(done_r, 1)
    finally:
        os._exit(0)
os.close(ready_w)
os.close(done_r)
try:
    assert os.read(ready_r, 1) == b'1', 'target loginuid setup failed'
    with open('/proc/self/loginuid', 'w') as f:
        f.write(str(sender_auid))
    assert int(open('/proc/self/loginuid').read()) == sender_auid
    def start_ticks(pid):
        # The comm field may contain spaces, so split after its closing ')'.
        return int(open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()[19])
    report = {
        'sender': os.getpid(), 'target': target,
        'sender_ticks': start_ticks(os.getpid()),
        'target_ticks': start_ticks(target),
        'hz': os.sysconf('SC_CLK_TCK'),
        'sessionid': int(open('/proc/self/sessionid').read()),
        'ns': {n: os.stat(f'/proc/self/ns/{n}').st_ino
               for n in ('mnt', 'net', 'uts', 'ipc', 'cgroup', 'user', 'pid')},
    }
    os.kill(target, signal.SIGUSR1)
    print(json.dumps(report), flush=True)
finally:
    os.close(done_w)
    os.waitpid(target, 0)
'''


@pytest.mark.parametrize(
    'sender_auid,target_auid,expected',
    [(1000, 0, 1), (0, 1000, 1), (0, 0, 0), (1000, 1000, 1)],
    ids=['sender-only', 'target-only', 'neither', 'both-once'],
)
def test_signal_sender_or_target_scope(
    ssh_cmd, foreground_bloodhound, wait_until,
    sender_auid, target_auid, expected,
):
    with foreground_bloodhound('--heartbeat-interval', '0.1') as daemon:
        wait_until(
            lambda: any(e.get('event', {}).get('name') == 'bloodhound_ready'
                        for e in daemon.events()),
            'foreground signal collector readiness',
        )
        command = python_command(SIGNAL_PAIR) + f' {sender_auid} {target_auid}'
        result = ssh_cmd(command, user='root')
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        # Clean shutdown drains ring-buffer records before final assertions,
        # including the negative and exactly-once cases.
        daemon.signal('INT')
        assert daemon.wait() == 0, daemon.stderr()
        events = daemon.events()
        assert events[-1]['event']['type'] == 'HEARTBEAT', events[-1:]
        assert events[-1]['args']['drop_count_total'] == 0, events[-1]

    matches = [
        e for e in events
        if e.get('event', {}).get('name') == 'signal_generate'
        and e.get('header', {}).get('pid') == report['sender']
        and e.get('args', {}).get('target_pid') == report['target']
        and e.get('args', {}).get('signal') == 10  # SIGUSR1 on the supported guest
    ]
    assert len(matches) == expected, matches
    if not expected:
        return

    [event] = matches
    header, args = event['header'], event['args']
    assert header['auid'] == sender_auid  # Never relabel the target-only sender.
    assert header['pid'] == header['tid'] == report['sender']
    assert header['sessionid'] == report['sessionid']
    for name, inode in report['ns'].items():
        assert header['ns'][name] == {'status': 'complete', 'inode': inode}
    for ref, pid_key, ticks_key in (
        (header['process_ref'], 'sender', 'sender_ticks'),
        (args['target_ref'], 'target', 'target_ticks'),
    ):
        assert ref['tgid'] == report[pid_key]
        assert ref['start_boottime_ns'] > 0
        assert ref['start_boottime_ns'] * report['hz'] // 1_000_000_000 == report[ticks_key]
    assert args['result'] == 'ignored'
    if sender_auid != 1000:
        # An outside sender observed only through this signal must not acquire
        # a synthetic lifecycle start: signals are non-authoritative seeds.
        assert not [
            e for e in events
            if e.get('event', {}).get('name') == 'process_start'
            and e.get('header', {}).get('process_ref') == header['process_ref']
        ]
