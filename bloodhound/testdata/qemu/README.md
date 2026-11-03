# QEMU raw event fixtures

These files are base64-encoded ring-buffer records captured from real eBPF
programs executing against the Linux kernel, not synthetic records assembled
by Rust test helpers or repaired by hand.

## Provenance and Environment

The 16 process, filesystem, syscall, and LSM fixtures were recaptured on
2026-11-03 in the QEMU/KVM test environment from base commit
`66f302272ce5da8783b6d128ccb016cb181e8977` (merged PR #61).

- **Guest kernel**: Linux 6.8.0-49-generic (`Linux 6.8.0-49-generic #49~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`)
- **Root filesystem**: Ubuntu 22.04 LTS (`e2e/rootfs.ext4`) booted via QEMU with virtio disk and NIC under `-snapshot`
- **Collector build**: Built from source (`Dockerfile.build --target build`) with temporary userspace logging added to `sequencer.rs` (`accept_raw`) to print raw ring-buffer bytes as hex on stderr when matching `BH_CAPTURE_KIND`. All instrumentation was removed after capture; no eBPF code or raw ring-buffer bytes were modified or synthesized.
- **Older provenance preserved**: `packet_ingress.b64` (and its golden snapshot) was not recaptured in this batch; it preserves its original capture provenance from 2026-08-20.

## Capture and Correlation Procedure

1. **Isolation**: Each trigger was executed in an independent collector invocation started inside the guest VM with `BH_CAPTURE_KIND=<kind> --uid 1000 --heartbeat-interval 0`. Any previous collector instance was cleanly terminated before starting.
2. **Readiness**: The harness waited for the `bloodhound_ready` line in collector stdout before initiating the trigger.
3. **Correlation**: Emitted NDJSON events were correlated with raw hex records from collector stderr. The 64-bit kernel timestamp (offset 8 in raw record) and `EventKind` byte (offset 0) were matched between the deserialized event and the raw ring-buffer record.
4. **Validation**: A fixture was accepted only when exactly one emitted event matched the distinctive trigger criteria and exactly one raw record matched that kernel timestamp and kind. The raw bytes were base64-encoded directly into `<fixture>.b64`.

## Header and Status Evolution

Relative to the historical 2026-08-20 baseline, the 2026-11-03 fixtures reflect schema and kernel probe updates:

- **Thread ID (`tid`)**: Populated across all event headers.
- **Namespace snapshot (`ns`)**: Full 7-namespace snapshots (`cgroup`, `ipc`, `mnt`, `net`, `pid`, `user`, `uts`) with inode numbers and `"status": "complete"` in every event header (#61).
- **Execution identities**: Fresh `pid`, `tid`, `sessionid`, `timestamp`, and `process_ref.start_boottime_ns`.
- **`execve`**: Includes `exec_capture_version: 1`, `argv_status: "complete"`, and `filename_status: "complete"` (#59).
- **`openat`**: Includes `capture_version: 1`, `file_identity_status: "complete"`, `filename_status: "complete"`, `dirfd: -100`, `dev: 265289728` (`dev_major: 253`, `dev_minor: 0`), and `ino: 22773` (#54).
- **`raw_syscall`**: Captures real register arguments and return PID for x86_64 syscall 39 (`getpid`).
- **Target and child identities**: Updated child PID in `clone`, `target_pid` and `target_ref` in `lsm_task_kill`, and `target_pid` in `lsm_ptrace`.

## Special Trigger Prerequisites and Known Limitations

- **`lsm_ptrace` guest capability requirement**: The collector runs as root (UID 0), while test triggers run as UID 1000 (`testuser`). Because the eBPF `lsm_ptrace` hook specifically filters for daemon-targeted ptrace attempts, the test process had to target the root collector PID. To prevent early kernel DAC checks from rejecting the attach call before reaching the LSM `ptrace_access_check` hook, the guest Python binary was provisioned with `CAP_SYS_PTRACE` (`setcap cap_sys_ptrace+ep $(readlink -f /usr/bin/python3)`). The trigger executed as UID 1000 with this capability, and the LSM hook intercepted and denied the attach with `-EPERM` (-1). This is a guest-only capability prerequisite, not an unprivileged attempt.
- **`rename` path truncation**: Decoded `oldpath` shows `"!"` and `newpath` shows `""`. This fixture was isolated by Python execution and verified through the preceding `openat` for `/tmp/bh-golden-old` in the same PID.
- **`read` return code**: Decoded `return_code` is 0 with `requested_size: 7`.
- **No byte synthesis**: These `rename` and `read` payload characteristics reflect genuine kernel probe acquisition behaviors on Linux 6.8; they were not manually edited, synthesized, or altered.

## Fixture Inventory

| Fixture | EventKind | Trigger / selection | Notes |
| --- | --- | --- | --- |
| `tty_write` | 1 | `script -q -c "bash --noprofile --norc -c 'printf BH_TTY_WRITE_GOLDEN'"` | PTY write matched distinctive string |
| `tty_read` | 0 | `printf 'BH_TTY_READ_GOLDEN\n' \| script -q -c "bash --noprofile --norc -c 'read x'"` | PTY read matched distinctive string |
| `execve` | 2 | `/usr/bin/true` | Complete argv and filename status |
| `raw_syscall` | 10 | `python3 -c 'import ctypes; ctypes.CDLL(None).syscall(39)'` | Syscall 39 (`getpid`), captured raw register args |
| `openat` | 20 | `python3 -c 'open("/tmp/bh-golden-openat","w").close()'` | Complete file identity and filename status |
| `read` | 21 | `python3 -c 'import os; f=os.open("/etc/hostname",os.O_RDONLY); os.read(f,7)'` | Requested size 7; return code 0 limitation retained |
| `connect_ipv4` | 23 | `python3 -c 'import socket; s=socket.socket(); s.setblocking(False); s.connect_ex(("127.0.0.1",18443))'` | Nonblocking connect to 127.0.0.1:18443 (errno -115 EINPROGRESS) |
| `connect_ipv6` | 23 | `python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.setblocking(False); s.connect_ex(("::1",18444))'` | Nonblocking connect to [::1]:18444 (errno -115 EINPROGRESS) |
| `clone` | 27 | `python3 -c 'import os; p=os.fork(); os._exit(0) if p==0 else os.waitpid(p,0)'` | Fork returning child PID |
| `mkdir` | 35 | `python3 -c 'import os; os.mkdir("/tmp/bh-golden-mkdir")'` | Created `/tmp/bh-golden-mkdir` |
| `rename` | 33 | `python3 -c 'import os; open("/tmp/bh-golden-old","w").close(); os.rename("/tmp/bh-golden-old","/tmp/bh-golden-new")'` | Known path payload limitation retained |
| `sendto` | 52 | `python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"GOLDEN",("127.0.0.1",19090))'` | Sent 6 UDP bytes to 127.0.0.1:19090 |
| `lsm_task_kill` | 201 | `python3 -c 'import os,time; p=os.fork(); time.sleep(1) if p==0 else (os.kill(p,0),os.waitpid(p,0))'` | Sent signal 0 to child process |
| `lsm_bpf` | 202 | `bpftool prog show` | Unprivileged command, returned -1 |
| `lsm_setuid` | 206 | `python3 -c 'import os; os.setuid(os.getuid())'` | Target UID/GID matches process UID/GID |
| `lsm_ptrace` | 203 | `python3 -c 'import ctypes; print(ctypes.CDLL(None).ptrace(16,<collector_pid>,0,0))'` | Guest Python with `CAP_SYS_PTRACE`; denied (-1) |
| `packet_ingress` | 50 | UDP loopback datagram (44-byte IPv4 packet) | Preserved 2026-08-20 provenance |
