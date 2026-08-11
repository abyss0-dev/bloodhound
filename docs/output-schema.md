# Output Schema: BehaviorEvent

The output schema is defined in `schema.json`. All events emitted by
Bloodhound conform to this structure.


## Structure Overview

```
BehaviorEvent
|
+-- header (REQUIRED)
|   +-- timestamp    : f64    (seconds since epoch)
|   +-- auid         : u32    (audit login UID)
|   +-- sessionid    : u32    (audit session ID)
|   +-- pid          : u32
|   +-- ppid         : u32    (optional in schema, but always populated)
|   +-- comm         : string (max 16 bytes)
|   +-- process_ref  : { tgid, start_boottime_ns } (process events only)
|
+-- event (REQUIRED)
|   +-- type         : enum [SYSCALL, TTY, PACKET, KPROBE, TRACEPOINT, LSM, LIFECYCLE, HEARTBEAT, USDT, DIAGNOSTIC]
|   +-- name         : string (hook point name, e.g. "openat", "tty_read")
|   +-- layer        : enum [intent, tooling, behavior]
|
+-- proc (OPTIONAL)
|   +-- main_executable : string (absolute path)
|   +-- cwd             : string
|   +-- tty             : string (device path)
|
+-- args (OPTIONAL, additionalProperties: true)
|   +-- filename : string
|   +-- argv     : [string]
|   +-- flags    : [string]   (human-readable, e.g. ["O_RDONLY", "O_SYNC"])
|   +-- data     : string     (raw TTY data, Base64 encoded)
|   +-- fd_type  : string     (regular, pipe, socket, tty, other)
|   +-- dev      : u64        (openat/mmap: encoded MKDEV(major, minor); omitted when 0)
|   +-- ino      : u64        (openat/mmap: inode number; omitted when 0)
|   +-- oldfd    : u32        (dup/dup2/dup3/fcntl-DUPFD: source fd)
|   +-- newfd    : i32        (dup family: destination fd, == return value)
|   +-- cloexec  : bool       (dup3 with O_CLOEXEC, fcntl(F_DUPFD_CLOEXEC))
|   +-- offset   : i64        (pread64/pwrite64: file offset; mmap: file offset)
|   +-- iov_count   : u32     (readv/writev: caller-supplied iov array length)
|   +-- iov_truncated : bool  (readv/writev: true ⇒ args.size is a lower bound)
|   +-- prot     : [string]   (mmap: ["PROT_READ", "PROT_WRITE", "PROT_EXEC"])
|   +-- length   : u64        (mmap: requested mapping length in bytes)
|   +-- in_fd, out_fd, in_fd_type, out_fd_type, size : sendfile/splice
|   +-- ...      : (extensible per event type)
|
+-- return_code (OPTIONAL) : i32
```


## Layer-to-Event-Type Mapping

| Layer    | event.type   | event.name examples                          |
|----------|--------------|----------------------------------------------|
| intent   | TTY          | tty_read, tty_write                          |
| tooling  | TRACEPOINT   | execve, execveat                             |
| behavior | TRACEPOINT   | openat, read, write, connect, mkdir...       |
| behavior | SYSCALL      | (Tier 1 raw: syscall NR as name)             |
| behavior | PACKET       | ingress, egress                              |
| behavior | LSM          | file_open, task_kill, bpf, ...               |
| behavior | LIFECYCLE    | process_start, process_fork, process_exit    |
| behavior | HEARTBEAT    | heartbeat                                    |


## Implementation Notes

### proc.main_executable and proc.cwd

These fields cannot be reliably obtained from within tracepoint BPF programs.
`bpf_d_path()` is only available in LSM and sleepable program types.

DECIDED approach: populate `proc` fields in userspace by reading
`/proc/<pid>/exe` and `/proc/<pid>/cwd` upon event receipt. For short-lived
processes, this is best-effort (the process may have exited). The `proc`
section is optional in the schema specifically to accommodate this.

### event.type PACKET

DECIDED: In scope. Raw packet capture via TC hooks. See
[tracing.md](tracing.md) for design details. PACKET events use
`event.layer = "behavior"`. `event.name` is `"ingress"` or `"egress"`.

### event.type LSM

DECIDED: LSM events use `event.layer = "behavior"`. LSM hooks both block
operations and emit BehaviorEvents, recording tamper attempts as
observable events.

`task_kill.args.target_ref` identifies the target process instance. A
successful `task_kill` event records signal delivery only; it is not evidence
that the target exited.

### event.type SYSCALL

DECIDED: Used for Tier 1 raw_syscalls events. These carry `syscall_nr`
(integer) and `raw_args` (array of 6 integers) in `args`. The
`event.name` is the syscall number as a string (e.g., "83" for mkdir).
`event.layer` is always `"behavior"`.

### event.type KPROBE

DECIDED: Reserved for future use. Not used in the current design. Kept
in the schema for forward compatibility.

### event.type LIFECYCLE

DECIDED: `sched_process_fork` and `sched_process_exit` are the lifecycle
authority. `event.layer` is always `"behavior"`.

`header.process_ref` is `{ "tgid", "start_boottime_ns" }`. It identifies
one Linux thread group within one kernel boot and the PID namespace observed
by Bloodhound. Every thread in a group has the same reference, and PID reuse
has a different `start_boottime_ns`. It is not comparable across boots or PID
namespaces without capture metadata establishing that those boundaries match.
Bloodhound does not manufacture a PID-only stable reference.

- `process_start` is emitted for a newly created thread group, including one
  that exits before userspace can read `/proc`. `args.process_ref` repeats the
  header reference. For a process that predates attachment, userspace emits the
  same event before its first observed behavior event using the reference
  already captured from kernel task state.
- `process_fork` follows the child `process_start` and carries
  `args.parent_ref`, `args.child_ref`, and decoded `args.clone_flags`.
  `CLONE_THREAD` creation emits neither event. `clone3` flags come from
  `struct clone_args.flags`, not the syscall argument pointer value.
- `process_exit` is emitted exactly once when the final live thread leaves the
  thread group. `args.exit_kind` is `"code"` or `"signal"`; the event also
  carries `exit_code` or `signal`, `raw_status`, and `core_dumped` for signaled
  exits.

Ordering for a new process is `process_start`, then `process_fork`, before any
behavior event from the child. `process_exit` is the kernel-observed terminal
lifecycle event. `task_kill` remains only a signal-delivery observation and
never implies or synthesizes `process_exit`.

### event.type HEARTBEAT

DECIDED: Periodic userspace-synthesised pulse. `event.layer =
"behavior"`, `event.name = "heartbeat"`. Emitted every
`--heartbeat-interval` seconds (default: 1.0; set to 0 to disable).

The header fields `auid`, `sessionid`, `pid` are sentinel zeroes and
`comm` is empty — `HEARTBEAT` is not attributable to a process.
`args` carries:

- `drop_count_delta` — drops observed since the previous heartbeat
- `drop_count_total` — cumulative drops since daemon startup
- `events_emitted_delta` — events serialised to stdout in the interval
- `gap_detected` — present and `true` only when
  `drop_count_delta > 0`; omitted otherwise so consumers can
  fast-path on the flag's presence

Downstream consumers should treat any interval between two
`HEARTBEAT` events with `gap_detected = true` as *undecidable* for
correlation — state accumulated across the gap may be incomplete.
