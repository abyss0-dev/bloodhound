"""Child FD-table observation before post-fork descriptor redirection."""
import json
import shlex
import uuid

import pytest


@pytest.mark.parametrize('case', ['no_pipe', 'inherited_pipe', 'above_limit'])
def test_fork_files_observes_inherited_pipe_before_child_closes_it(
        case, ssh_cmd, bloodhound_events, wait_for_events):
    report_path = '/tmp/fork-files-' + uuid.uuid4().hex + '.json'
    script = f'''import fcntl, json, os
from pathlib import Path
Path('/proc/self/loginuid').write_text('1000')
null = os.open('/dev/null', os.O_RDWR)
for fd in range(3):
    os.dup2(null, fd)
os.closerange(3, 4096)
owned = []
case = {case!r}
if case == 'inherited_pipe':
    owned = list(os.pipe())
if case == 'above_limit':
    owned = [fcntl.fcntl(0, fcntl.F_DUPFD, 512)]
pid = os.fork()
if pid == 0:
    for fd in owned:
        os.close(fd)
    os.execv('/usr/bin/true', ['true'])
_, status = os.waitpid(pid, 0)
Path({report_path!r}).write_text(json.dumps(dict(pid=pid, status=status)))
'''
    command = ('python3 -c ' + shlex.quote(script) + ' && cat ' +
               shlex.quote(report_path) + ' && rm ' + shlex.quote(report_path))
    result = ssh_cmd(command, user='root')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['status'] == 0
    wait_for_events()
    events = bloodhound_events()
    records = [e for e in events if e['event']['name'] == 'fork_files'
               and e['header']['pid'] == report['pid']]
    assert len(records) == 1, (report, records)
    record = records[0]
    args = record['args']
    assert args['files_capture_version'] == 1
    if case == 'above_limit':
        assert args['files_status'] == 'limit_exceeded'
        assert 'has_pipe' not in args and 'scanned_slots' not in args
    else:
        assert args['files_status'] == 'complete'
        assert args['has_pipe'] == (case == 'inherited_pipe')
        assert 0 < args['scanned_slots'] <= 256
    forks = [e for e in events if e['event']['name'] == 'process_fork'
             and e['args'].get('child_ref') == record['header']['process_ref']
             and e['header']['timestamp'] == record['header']['timestamp']]
    assert len(forks) == 1
    stdio = [e for e in events if e['event']['name'] == 'exec_stdio'
             and e['header']['process_ref'] == record['header']['process_ref']]
    assert len(stdio) == 1
    assert stdio[0]['args']['stdin_kind'] == 'character'
    assert stdio[0]['args']['stdout_kind'] == 'character'
