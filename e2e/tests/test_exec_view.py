"""Exec-entry view facts must match the invoking task, including changed roots."""
import json
import shlex

import pytest


def test_exec_view_matches_same_invocation_in_distinct_roots(
        ssh_cmd, bloodhound_events, wait_for_events):
    reports = []
    for changed in [False, True]:
        script = '''import json, os, tempfile, subprocess
from pathlib import Path
binary_fd, binary = tempfile.mkstemp(prefix='exec-view-bin-')
os.close(binary_fd)
subprocess.run(['gcc', '-static', '-x', 'c', '-', '-o', binary],
    input='int main(void) { return 0; }', text=True, check=True)
fd = os.open(binary, os.O_RDONLY)
os.unlink(binary)
Path('/proc/self/loginuid').write_text('1000')
changed = CHANGED
if changed:
    os.unshare(os.CLONE_NEWNS)
root = tempfile.mkdtemp(prefix='exec-view-') if changed else '/'
st = os.stat(root)
ns = os.stat('/proc/self/ns/mnt').st_ino
# The new empty root is on the same root filesystem in this fixture.
mount = next(int(line.split()[0]) for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == '/')
print(json.dumps(dict(pid=os.getpid(), root_inode=st.st_ino,
    root_dev_major=os.major(st.st_dev), root_dev_minor=os.minor(st.st_dev),
    mount_namespace=ns, root_mount_id=mount)), flush=True)
if changed:
    os.chroot(root)
    os.chdir('/')
os.execve(fd, ['true'], {})
'''.replace('CHANGED', repr(changed))
        result = ssh_cmd('python3 -c ' + shlex.quote(script), user='root')
        assert result.returncode == 0, result.stderr
        reports.append(json.loads(result.stdout))
    wait_for_events()
    events = bloodhound_events()
    assert reports[0]['mount_namespace'] != reports[1]['mount_namespace']
    assert reports[0]['root_inode'] != reports[1]['root_inode']
    for report in reports:
        views = [e for e in events if e['event']['name'] == 'exec_view'
                 and e['header']['pid'] == report['pid']]
        assert len(views) == 1, views
        view = views[0]
        assert view['args']['view_status'] == 'complete'
        for field, value in report.items():
            if field != 'pid':
                assert view['args'][field] == value, (report, view)
        executions = [e for e in events if e['event']['name'] in ('execve', 'execveat')
                      and e['header']['process_ref'] == view['header']['process_ref']
                      and e['header']['timestamp'] == view['header']['timestamp']]
        assert len(executions) == 1, executions
        assert executions[0]['return_code'] == 0


def test_exec_view_pairs_failed_and_successful_attempts_across_concurrent_actors(
        ssh_cmd, bloodhound_events, wait_for_events):
    script = '''import json, os
from pathlib import Path
Path('/proc/self/loginuid').write_text('1000')
children = []
for index in range(16):
    pid = os.fork()
    if pid == 0:
        for attempt in range(2):
            try:
                os.execv('/exec-view-nonexistent/program', ['missing'])
            except FileNotFoundError:
                pass
        os.execv('/usr/bin/true', ['true'])
    children.append(pid)
for pid in children:
    _, status = os.waitpid(pid, 0)
    assert status == 0
print(json.dumps(children))
'''
    result = ssh_cmd('python3 -c ' + shlex.quote(script), user='root')
    assert result.returncode == 0, result.stderr
    pids = json.loads(result.stdout)
    wait_for_events()
    events = bloodhound_events()
    for pid in pids:
        records = [e for e in events if e['header']['pid'] == pid]
        executions = [e for e in records if e['event']['name'] == 'execve']
        views = [e for e in records if e['event']['name'] == 'exec_view']
        assert len(executions) == len(views) == 3
        assert [e['return_code'] for e in executions] == [-2, -2, 0]
        assert len({e['header']['timestamp'] for e in executions}) == 3
        for execution in executions:
            pairs = [e for e in views
                     if e['header']['process_ref'] == execution['header']['process_ref']
                     and e['header']['timestamp'] == execution['header']['timestamp']]
            assert len(pairs) == 1
            assert pairs[0]['args']['view_status'] == 'complete'


@pytest.mark.parametrize('command', [
    'stat -- /etc/hostname',
    'stat -- /etc/hostname > /dev/null',
    'stat -- /etc/hostname > /dev/null | cat',
    'cat /etc/hostname | stat -- /etc/hostname < /dev/null > /dev/null',
])
def test_exec_view_observes_commands_independently_of_shell_connections(
        command, ssh_cmd, bloodhound_events, wait_for_events):
    # Use sh without any semantic collector or dependency on a Bash image.
    result = ssh_cmd('/bin/sh -c ' + shlex.quote(command))
    assert result.returncode == 0, result.stderr
    wait_for_events()
    events = bloodhound_events()
    executions = [e for e in events if e['event']['name'] == 'execve'
                  and e.get('args', {}).get('filename') == '/usr/bin/stat'
                  and e['args'].get('argv') == ['stat', '--', '/etc/hostname']
                  and e.get('return_code') == 0]
    assert len(executions) == 1, executions
    execution = executions[0]
    assert execution['args']['argv_status'] == 'complete'
    views = [e for e in events if e['event']['name'] == 'exec_view'
             and e['header']['process_ref'] == execution['header']['process_ref']
             and e['header']['timestamp'] == execution['header']['timestamp']]
    assert len(views) == 1 and views[0]['args']['view_status'] == 'complete'
    exits = [e for e in events if e['event']['name'] == 'process_exit'
             and e['header']['process_ref'] == execution['header']['process_ref']]
    assert len(exits) == 1 and exits[0]['args']['exit_code'] == 0
