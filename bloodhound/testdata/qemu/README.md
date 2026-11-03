# QEMU raw event fixtures

These files are base64-encoded ring-buffer records captured from real eBPF
programs executing against the Linux kernel, not synthetic records assembled
by Rust test helpers or repaired by hand.

## Provenance and Environment

The test suite contains 17 golden raw fixtures: 16 process, filesystem,
network, and LSM fixtures recaptured on 2026-11-03, and 1 network packet fixture
retaining its original 2026-08-20 provenance.

### 2026-11-03 Recaptured Fixtures (16 non-packet fixtures)

- **Source base**: Commit `66f302272ce5da8783b6d128ccb016cb181e8977` (merged PR #61).
- **Guest kernel**: Linux 6.8.0-49-generic (`Linux 6.8.0-49-generic #49~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, boot image `e2e/vmlinuz`). Note that the `#49~22.04.1-Ubuntu` suffix is the Ubuntu kernel package build identifier and does not represent the guest userland distribution.
- **Guest userland**: Ubuntu 24.04.5 LTS (`noble`, `PRETTY_NAME="Ubuntu 24.04.5 LTS"`, verified from `/etc/os-release` in `rootfs.tar`).
- **Virtualization**: QEMU/KVM with 2 vCPUs, 2048 MiB RAM, virtio disk, virtio NIC, `-snapshot`, and loopback SSH forwarding on host port 2262.
- **Empty rootfs repair**: The local `e2e/rootfs.ext4` build output had been an empty ext4 filesystem containing only `lost+found`, which caused a "No working init found" kernel panic. It was populated from the pre-existing `bloodhound-e2e` Docker image (containing the Ubuntu 24.04.5 rootfs tree) using `mkfs.ext4 -F -d <tree>` into `e2e/rootfs.ext4` without requiring root or sudo. Configuration was applied matching `e2e/scripts/build-rootfs.sh`: systemd-networkd for virtio DHCP and DNS, and OpenSSH socket activation for root and testuser (UID 1000).
- **Deployment**: No collector service was installed in the guest rootfs. The collector binary was built inside a Docker container using `Dockerfile.build --target build` (musl target) and copied over SSH to `/tmp/bloodhound-capture` for each run.

### 2026-08-20 Preserved Fixture (`packet_ingress`)

- **Provenance**: `packet_ingress.b64` (and its snapshot `bloodhound__deserializer__golden_tests__packet_ingress.snap`) was not recaptured in this batch. It preserves its original capture from 2026-08-20 under QEMU/KVM Linux 6.8.0-49-generic, using the collector built from commit `20d1a05` plus temporary raw-record logging (removed after capture).
- **Selection**: The collector was restarted with logging restricted to `EventKind` 100 (`packet_ingress`), a 16-byte UDP datagram was transmitted over loopback, and the 44-byte IPv4 packet record was selected. Both the fixture and snapshot remain byte-identical to base commit `66f3022`; they were last changed in PR #46 (`46ff1db`).

## Capture and Correlation Method

### Temporary Userspace Logging

To capture raw ring-buffer bytes without altering kernel probe behavior or synthesizing records:
- Temporary instrumentation was added to `Sequencer::accept_raw(&mut self, raw: &[u8]) -> Result<()>` in `bloodhound/src/sequencer.rs`:
  ```rust
  if std::env::var("BH_CAPTURE_KIND").ok().and_then(|v| v.parse::<u8>().ok()) == raw.first().copied() {
      let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
      eprintln!("BH_RAW {hex}");
  }
  ```
- This logged the exact, unmodified byte sequence received from the ring buffer directly to stderr as `BH_RAW <hex>` when matching the expected `EventKind` byte (`raw[0]`).
- No eBPF program, ring-buffer layout, or raw bytes were modified.
- All instrumentation was removed prior to building final test artifacts and is not committed.

### Isolation, Readiness, and Collector Termination

1. **Isolation**: Each trigger was executed against a fresh collector instance started with `BH_CAPTURE_KIND=<kind> /tmp/bloodhound-capture --uid 1000 --heartbeat-interval 0 > /tmp/<name>.ndjson 2> /tmp/<name>.stderr < /dev/null &`.
2. **Readiness gating**: The test harness polled NDJSON stdout for the initial `bloodhound_ready` line before executing any trigger command. In early attempts, fixed sleeps (such as 2 seconds) were insufficient for LSM/tracepoint hook attachment, resulting in missed events; those pre-ready attempts were discarded.
3. **Termination and forced cleanup**: The collector was stopped after trigger execution by sending `kill -INT <pid>`. However, due to an existing shutdown hang in the collector, `kill -KILL <pid>` was sent after a 1-second timeout. Forced cleanup (`pkill -KILL`) was executed only before every run to prevent orphaned collector processes or active eBPF hooks from contaminating subsequent runs; after each run, `kill -INT` then `kill -KILL` targeted the recorded PID. Attempts contaminated by hung collector instances were discarded.
4. **Correlation**: The NDJSON event was matched by distinctive arguments or execution metadata. Exactly one NDJSON event was selected, and its kernel timestamp (offset 8 in raw record, nanoseconds) and `EventKind` byte (offset 0) were matched against the `BH_RAW` records on stderr. Exactly one raw record matched in each case. The raw bytes were base64-encoded directly into `bloodhound/testdata/qemu/<name>.b64`.

## Evolution of Snapshot Headers and Completeness Fields

Relative to historical snapshots from 2026-08-20, the recaptured fixtures reflect schema additions and probe evolution:

- **Namespace snapshots (`ns`)**: Every event header now includes a full 7-namespace snapshot (`cgroup`, `ipc`, `mnt`, `net`, `pid`, `user`, `uts`) with inode numbers and `"status": "complete"`, introduced in PR #61.
- **Thread ID (`tid`)**: Thread ID is now populated across all event headers.
- **Explicit completeness fields**: Completeness status fields were originally introduced in PR #53 (commit `7a6c54f`). In the historical 2026-08-20 fixtures (which predated #53), deserialization produced legacy defaults:
  - `execve`: Previously deserialized as `exec_capture_version: 0`, `argv_status: "unknown"`, `filename_status: "unknown"`. In the recaptured fixture, these are now `exec_capture_version: 1`, `argv_status: "complete"`, `filename_status: "complete"`.
  - `openat`: Previously deserialized as `file_identity_status: "unknown"`, `filename_status: "unknown"`. In the recaptured fixture, these are now `capture_version: 1`, `file_identity_status: "complete"`, `filename_status: "complete"`, along with `dirfd: -100`, `dev: 265289728` (`dev_major: 253`, `dev_minor: 0`), and `ino: 22773`.
- **System call registers (`raw_syscall`)**: Captures real register arguments and return value (calling PID 4743) for syscall 39 (`getpid`).
- **Dynamic identities**: Fresh timestamps, PIDs, TIDs, session IDs, and `process_ref.start_boottime_ns`.

## Special Trigger Prerequisites and Retained Probe Limitations

The recaptured fixtures record genuine eBPF probe output without synthetic adjustments; several fixtures document specific trigger prerequisites and retained kernel probe limitations:

- **`lsm_ptrace` guest capability requirement**: The collector runs as root (UID 0), while test triggers run as UID 1000 (`testuser`). Because the `lsm_ptrace` probe specifically monitors attachment attempts targeting the daemon, the trigger had to target the collector's PID. However, standard Linux DAC checks reject unprivileged ptrace attempts against a root-owned process before LSM hooks are invoked. To allow the attach request to reach the LSM `ptrace_access_check` hook, the guest Python binary was provisioned with `CAP_SYS_PTRACE` (`setcap cap_sys_ptrace+ep $(readlink -f /usr/bin/python3)`). The trigger executed as UID 1000 with this capability, successfully reaching the LSM probe where it was denied with `-EPERM` (-1). This is a guest capability prerequisite, not an unprivileged attempt.
- **`lsm_setuid` hardcoded zeroes**: In `lsm_setuid.snap`, the arguments report `"new_gid": 0, "new_uid": 0, "old_gid": 0, "old_uid": 0`. This does not reflect the calling process credentials (UID 1000); rather, the eBPF kernel hook (`try_setuid` in `bloodhound-ebpf/src/lsm_hooks.rs`) hardcodes zero into all four fields of `LsmSetuidPayload`. The snapshot faithfully preserves this retained probe limitation.
- **`rename` pathname truncation**: The decoded event reports `oldpath: "!"` and `newpath: ""` due to pathname resolution limitations in the probe. The trigger was isolated by PID and verified by the preceding `openat` for `/tmp/bh-golden-old`.
- **`read` return code**: The decoded event reports `return_code: 0` alongside `requested_size: 7`.
- **No byte synthesis**: These payloads reflect the actual behavior of the current probes on Linux 6.8 and were not manually edited or patched.

## Fixture Inventory

| Fixture | EventKind | Trigger / selection | Notes |
| --- | --- | --- | --- |
| `tty_write` | 1 | `script -q -c "bash --noprofile --norc -c 'printf BH_TTY_WRITE_GOLDEN'"` | PTY session; selected payload matching `BH_TTY_WRITE_GOLDEN` |
| `tty_read` | 0 | `printf 'BH_TTY_READ_GOLDEN\n' \| script -q -c "bash --noprofile --norc -c 'read x'"` | PTY session; selected payload matching `BH_TTY_READ_GOLDEN\n` |
| `execve` | 2 | `/usr/bin/true` | Executed binary; reports `exec_capture_version: 1`, `argv_status: "complete"`, `filename_status: "complete"` |
| `raw_syscall` | 10 | `python3 -c 'import ctypes; ctypes.CDLL(None).syscall(39)'` | x86_64 syscall 39 (`getpid`), captures raw registers and return PID 4743 |
| `openat` | 20 | `python3 -c 'open("/tmp/bh-golden-openat","w").close()'` | Opened `/tmp/bh-golden-openat` (`O_WRONLY\|O_CREAT\|O_TRUNC\|O_CLOEXEC`), reports `capture_version: 1`, complete identity/filename |
| `read` | 21 | `python3 -c 'import os; f=os.open("/etc/hostname",os.O_RDONLY); os.read(f,7)'` | Read 7 bytes from `/etc/hostname`; retained probe limitation `return_code: 0` |
| `connect_ipv4` | 23 | `python3 -c 'import socket; s=socket.socket(); s.setblocking(False); s.connect_ex(("127.0.0.1",18443))'` | Nonblocking IPv4 connect returning `-EINPROGRESS` (-115) |
| `connect_ipv6` | 23 | `python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.setblocking(False); s.connect_ex(("::1",18444))'` | Nonblocking IPv6 connect returning `-EINPROGRESS` (-115) |
| `clone` | 27 | `python3 -c 'import os; p=os.fork(); os._exit(0) if p==0 else os.waitpid(p,0)'` | Fork returning child PID 5562 |
| `mkdir` | 35 | `python3 -c 'import os; os.mkdir("/tmp/bh-golden-mkdir")'` | Created `/tmp/bh-golden-mkdir` |
| `rename` | 33 | `python3 -c 'import os; open("/tmp/bh-golden-old","w").close(); os.rename("/tmp/bh-golden-old","/tmp/bh-golden-new")'` | Retained probe limitation: decoded `oldpath: "!"` / `newpath: ""` |
| `sendto` | 52 | `python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"GOLDEN",("127.0.0.1",19090))'` | Sent 6 UDP bytes to `127.0.0.1:19090` |
| `lsm_task_kill` | 201 | `python3 -c 'import os,time; p=os.fork(); time.sleep(1) if p==0 else (os.kill(p,0),os.waitpid(p,0))'` | Sent signal 0 to child process |
| `lsm_bpf` | 202 | `bpftool prog show` | Pre-Phase-2 deny-all capture, denied by probe (-1). Fixture bytes and expectations unchanged; current opt-in Phase 2 behavior (observe-only return_code: 0) requires real guest recapture. No VM capture was performed in this worktree. |
| `lsm_setuid` | 206 | `python3 -c 'import os; os.setuid(os.getuid())'` | Retained probe limitation: kernel hook hardcodes all 4 UID/GID fields to 0 |
| `lsm_ptrace` | 203 | `python3 -c 'import ctypes; print(ctypes.CDLL(None).ptrace(16,<collector_pid>,0,0))'` | Python with `CAP_SYS_PTRACE` targeting root daemon PID; denied by LSM hook (-1) |
| `packet_ingress` | 100 | Sent 16-byte UDP datagram over loopback; selected 44-byte IPv4 packet | Historical 2026-08-20 decode-only (commit `20d1a05`), not evidence of active capture (retired in Phase 2) |
