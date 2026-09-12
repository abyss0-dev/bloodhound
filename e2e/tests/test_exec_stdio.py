"""Descriptor kinds at exec entry, independently of downstream method grammar."""
import json
import shlex


def test_exec_stdio_distinguishes_pipes_sockets_closed_and_regular(
        ssh_cmd, bloodhound_events, wait_for_events):
    script = '''import json, os, socket, tempfile
from pathlib import Path
Path('/proc/self/loginuid').write_text('1000')
for case in ['character', 'pipe_in', 'pipe_out', 'socket_in', 'closed_in', 'regular_out']:
    owned = []
    stdin = os.open('/dev/null', os.O_RDONLY)
    stdout = os.open('/dev/null', os.O_WRONLY)
    owned += [stdin, stdout]
    if case == 'pipe_in':
        stdin, peer = os.pipe()
        owned += [stdin, peer]
    if case == 'pipe_out':
        peer, stdout = os.pipe()
        owned += [peer, stdout]
    if case == 'socket_in':
        left, right = socket.socketpair()
        stdin, peer = left.detach(), right.detach()
        owned += [stdin, peer]
    if case == 'regular_out':
        stdout, path = tempfile.mkstemp(prefix='exec-stdio-')
        os.unlink(path)
        owned.append(stdout)
    pid = os.fork()
    if pid == 0:
        os.dup2(stdin, 0)
        os.dup2(stdout, 1)
        if case == 'closed_in':
            os.close(0)
        os.execv('/usr/bin/true', ['true'])
    _, status = os.waitpid(pid, 0)
    for fd in owned:
        os.close(fd)
    print(json.dumps(dict(case=case, pid=pid, status=status)), flush=True)
'''
    result = ssh_cmd('python3 -c ' + shlex.quote(script), user='root')
    assert result.returncode == 0, result.stderr
    reports = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(reports) == 6
    wait_for_events()
    events = bloodhound_events()
    for report in reports:
        assert report['status'] == 0
        records = [e for e in events if e['event']['name'] == 'exec_stdio'
                   and e['header']['pid'] == report['pid']]
        assert len(records) == 1, (report, records)
        record = records[0]
        args = record['args']
        assert args['stdio_capture_version'] == 1
        assert args['stdio_status'] == 'complete'
        expected_in = {'pipe_in': 'fifo', 'socket_in': 'socket', 'closed_in': 'closed'}.get(report['case'], 'character')
        expected_out = {'pipe_out': 'fifo', 'regular_out': 'regular'}.get(report['case'], 'character')
        assert (args['stdin_kind'], args['stdout_kind']) == (expected_in, expected_out)
        pairs = [e for e in events if e['event']['name'] == 'execve'
                 and e['header']['process_ref'] == record['header']['process_ref']
                 and e['header']['timestamp'] == record['header']['timestamp']]
        assert len(pairs) == 1 and pairs[0]['return_code'] == 0
