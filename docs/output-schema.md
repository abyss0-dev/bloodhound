# Output Schema: BehaviorEvent

The output schema is defined in `schema.json`. All events emitted by
Bloodhound conform to this structure.


## Structure Overview

```
BehaviorEvent
|
+-- header (REQUIRED)
|   +-- timestamp    : u64    (VM CLOCK_MONOTONIC nanoseconds)
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
|   +-- dev      : u64        (kernel encoding; openat validity is explicit, mmap is legacy)
|   +-- ino      : u64        (inode number; openat validity is explicit, mmap is legacy)
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
| behavior | TRACEPOINT   | signal_generate                              |
| behavior | HEARTBEAT    | heartbeat                                    |


## Implementation Notes

### proc.main_executable and proc.cwd

These fields cannot be reliably obtained from within tracepoint BPF programs.
`bpf_d_path()` is only available in LSM and sleepable program types.

DECIDED approach: populate `proc` fields in userspace by reading
`/proc/<pid>/exe` and `/proc/<pid>/cwd` upon event receipt. For short-lived
processes, this is best-effort (the process may have exited). The `proc`
section is optional in the schema specifically to accommodate this.

### header.timestamp

`header.timestamp` is an integer number of nanoseconds from the observed VM's
`CLOCK_MONOTONIC` clock. BPF and userspace-synthesized events use the same
domain. It is comparable within one VM run, but is not wall-clock time, is not
comparable across boots, and does not define total kernel causal order.

NDJSON line position is the canonical Bloodhound emission order. Each producer
retains FIFO order; cross-producer order is successful admission to the bounded
sequencer rather than timestamp sorting.

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
that the target exited. If the stable target identity cannot be read,
`target_ref` is omitted rather than populated with a zero start time.

### event.name signal_generate

DECIDED: `raw_tracepoint:signal_generate` is the non-enforcing signal
observation authority. It does not require BPF LSM and cannot allow, deny, or
modify a signal.

The event header identifies the process that generated the signal.
`args.target_ref` identifies the target process instance. `args.signal` is the
signal number, `args.group` records whether the signal is process-directed,
and `args.result` is one of `delivered`, `ignored`, `already_pending`,
`overflow_fail`, `lose_info`, or `unknown`. `args.result_code` preserves the
kernel enum value. There is no `return_code`: the tracepoint result describes
signal queueing, not the userspace syscall return value.

If either source or target stable identity is unavailable, the corresponding
reference is omitted and the bounded `DIAGNOSTIC/process.identity` event is
emitted. Consumers must fail closed rather than substitute a PID-only identity.

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

If kernel task state cannot supply a complete stable reference, the affected
`process_ref`, `parent_ref`, or `target_ref` is omitted. Bloodhound emits at
most one `DIAGNOSTIC/process.identity` event for each of the three bounded
sources (`event_header`, `process_fork.parent_ref`, `task_kill.target_ref`, and
`signal_generate.target_ref`) during a run. Its reason code is
`stable_process_ref_unavailable`; `observed_tgid` is diagnostic context only
and is not a stable identity.

- `process_start` is emitted for a newly created thread group, including one
  that exits before userspace can read `/proc`. `args.process_ref` repeats the
  header reference. For a process that predates attachment, userspace emits the
  same event before its first observed behavior event using the reference
  already captured from kernel task state. Kernel-created start metadata is
  read from the child task supplied by `sched_process_fork`.
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
lifecycle event. `task_kill` and `signal_generate` remain signal observations
and never imply or synthesize `process_exit`.

### event.type HEARTBEAT

DECIDED: Periodic userspace-synthesised pulse. `event.layer =
"behavior"`, `event.name = "heartbeat"`. Emitted every
`--heartbeat-interval` seconds (default: 1.0; set to 0 to disable).

The header fields `auid`, `sessionid`, `pid` are sentinel zeroes and
`comm` is empty — `HEARTBEAT` is not attributable to a process.
`args` carries:

- `drop_count_delta` — drops observed since the previous heartbeat
- `drop_count_total` — cumulative drops since daemon startup
- `reason_code` — `ring_buffer_overflow` once the cumulative drop count is
  nonzero; distinct from `deserialize_rejected` diagnostics
- `events_emitted_delta` — events serialised to stdout in the interval
- `run_prefix_incomplete` — present and `true` once cumulative ring-buffer
  drops are nonzero for this daemon run
- `gap_detected` — present and `true` only when
  `drop_count_delta > 0`; omitted otherwise so consumers can
  fast-path on the flag's presence

Downstream consumers should treat any interval between two
`HEARTBEAT` events with `gap_detected = true` as *undecidable* for
correlation — state accumulated across the gap may be incomplete.

### event.type DIAGNOSTIC

`event.name = "stream.health"` with
`args.reason_code = "deserialize_rejected"` reports a binary ring-buffer
record that Bloodhound could not deserialize. It includes bounded delta and
cumulative rejection counts, never the rejected payload. The diagnostic is
emitted before the next raw-derived event.

Ring-buffer drops and deserialization rejection are separate causes. Either
makes the cumulative run prefix incomplete. Later intervals with no new loss
do not claim recovery; consumers apply their own explicit recovery semantics.
# Openat acquisition status (capture version 1)

Execve/execveat completeness is specified separately by
[the #33 exec capture contract](exec-capture.md). Filesystem method recognition
must consume that contract; short argv or absent completeness fields do not
establish complete acquisition.

New openat producers retain the fixed payload size and identify their use of
formerly reserved bytes with `capture_version: 1`. NDJSON adds `dirfd`,
`filename_status` (`complete`, `truncated`, `read_error`, `invalid_encoding`, or `unknown`) and
`file_identity_status` (`complete`, `partial`, `unavailable`, `not_attempted`,
or `unknown`). Consumers must require an explicitly complete status, not infer
it from nonzero numbers or the absence of a truncation field. Older or unknown
producer versions have unknown status; legacy numeric fields remain available.

Successful opens can have complete, partial, or unavailable identity. Failed
opens have negative `return_code` and identity `not_attempted`. For version 1,
only successfully read components are emitted, including valid zero values.
`dev` is kernel-encoded major << 20 | minor. Compare `dev_major`/`dev_minor`
against userspace major(st_dev)/minor(st_dev), rather than comparing encoded
device values. A complete pair requires both components and a validated target
kernel layout. Current fixed layouts were measured on x86_64 6.8.0-49-generic.

Actor header and pathname are captured at entry; returned FD and identity at
exit. Later proc enrichment is not an operation-time snapshot. FD close/reuse
races and readable but incorrect kernel offsets cannot always be detected.
See [measurement and limits](development/filesystem-observation.md).

`DIAGNOSTIC/openat.collection` reports detected pre-ring-buffer loss with
`reason_code`, `failure_count_delta`, `failure_count_total`, `scope: openat`,
`sampling: userspace_poll`, and `run_prefix_incomplete: true`. Reasons are
`entry_capture_failed`, `entry_save_failed`, `exit_capture_failed`, and
`invocation_interrupted`. Counter-read failure has reason `counter_read_failed`
and null counts, never a fabricated zero. Counts are polled once per second and
once after kernel production stops during graceful shutdown. Their timestamps
describe the poll, not a missing operation, and do not identify affected actors.

This notification is distinct from ring-buffer drops and deserialize rejection.
It covers openat entry metadata/scratch acquisition, entry-map insertion, exit
metadata/assembly acquisition, and pending invocations removed at task exit.
Path-read failure is represented on the event; unsuccessful FD-identity reads
are represented by identity status. The counter does not certify unsupported
paths or detect every FD-table race. A missing entry with no recorded entry
(for example, tracing attached during an in-flight syscall) is not counted.

### Exec-entry filesystem view

`TRACEPOINT/exec_view` carries `view_capture_version` and `view_status`.
Version 1 complete capture exposes `root_inode`, kernel-encoded `root_dev`,
normalized `root_dev_major` / `root_dev_minor`, `mount_namespace` and
`root_mount_id`. Unsupported, unavailable, changed and unknown captures expose
no identity. Pair only with exec's exact immutable `process_ref` and entry
`timestamp`; a view record alone proves neither a successful exec nor exit.
See the [capture contract](development/exec-view.md) for acquisition and limits.

Wire event kinds 225, 226 and 227 are reserved for removed experiments and must
not be reused. The current producer emits no exec-stdio, fork-file or Bash
internal-function records. Application semantic probes remain `USDT` events
under the existing trusted collector contract.
