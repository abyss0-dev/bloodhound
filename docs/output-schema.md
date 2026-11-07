# Output Schema: BehaviorEvent

The output schema is defined in `schema.json`. All events emitted by
Bloodhound conform to this structure.

`schema.json` is a byte-for-byte copy of the workspace-canonical
`docs/spec/behavior_event/behavior_event.schema.json`, pinned at workspace
commit `6337baa4be3b5eabc0c9ee64a1c1d75939c31625`.


## Structure Overview

```
BehaviorEvent
|
+-- header (REQUIRED)
|   +-- timestamp    : u64    (VM CLOCK_MONOTONIC nanoseconds)
|   +-- auid         : u32    (audit login UID)
|   +-- sessionid    : u32    (audit session ID)
|   +-- pid          : u32
|   +-- tid          : u32    (kernel-captured task events only)
|   +-- ppid         : u32    (optional in schema, but always populated)
|   +-- comm         : string (max 16 bytes)
|   +-- process_ref  : { tgid, start_boottime_ns } (process events only)
|   +-- ns           : { mnt, net, uts, ipc, cgroup, user, pid } (present exactly with tid)
|       +-- <slot>   : { status: complete|unsupported|unavailable, inode: u32 | null }
|
+-- event (REQUIRED)
|   +-- type         : enum [SYSCALL, TTY, PACKET, KPROBE, TRACEPOINT, LSM, META, LIFECYCLE, HEARTBEAT, USDT, DIAGNOSTIC]
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
|   +-- oldpath, newpath : string (two-path syscalls: input paths)
|   +-- path_capture_version : u8 (path events: 1 when capture status is recorded, 0 when absent/legacy)
|   +-- path_status : string  (single-path events: complete, truncated, read_error, invalid_encoding, unknown)
|   +-- path1_status, path2_status : string (two-path events: complete, truncated, read_error, invalid_encoding, unknown)
|   +-- tty_capture_version : u8 (TTY events: 1 when capture status is recorded, 0 when absent/legacy)
|   +-- data_status : string  (TTY events: complete, truncated, read_error, unknown)
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
| behavior | PACKET       | ingress, egress (not produced since Phase 2; historical decode only) |
| behavior | LSM          | file_open, task_kill, bpf, ...               |
| behavior | LIFECYCLE    | process_start, process_fork, process_exit    |
| behavior | TRACEPOINT   | signal_generate                              |
| behavior | HEARTBEAT    | heartbeat                                    |

Note: `event.layer` remains emitted legacy producer metadata (`intent`, `tooling`, `behavior`) in the schema, but downstream consumers do not depend on it for event classification.


## Implementation Notes

### proc.main_executable, proc.cwd, and proc.tty

These fields were formerly populated via best-effort userspace `/proc` reads.
In Phase 2, live `/proc` enrichment has been completely removed from the producer.
For live processes, no `proc.*` values (`main_executable`, `cwd`, `tty`) are filled,
and missing `ppid` is never looked up from `/proc`. Synthesized `process_start` events
never copy `triggering.proc` (it is always `None`).

The `proc` object is retained in the schema for backward compatibility and
historical trace decoding only. Live processes continue to rely on authoritative
kernel-level lifecycle facts:
- Kernel child-start `ppid` and `process_fork` lineage authority remain intact.
- Executable context at execution entry is authoritatively provided by `exec_view`
  (root device/inode, mount namespace, root mount ID, and explicit status; see
  [exec-view.md](development/exec-view.md)), which is captured directly in the kernel
  without relying on `/proc`.

### header.timestamp

`header.timestamp` is an integer number of nanoseconds from the observed VM's
`CLOCK_MONOTONIC` clock. BPF and userspace-synthesized events use the same
domain. It is comparable within one VM run, but is not wall-clock time, is not
comparable across boots, and does not define total kernel causal order.

NDJSON line position is the canonical Bloodhound emission order. Each producer
retains FIFO order; cross-producer order is successful admission to the bounded
sequencer rather than timestamp sorting.

### header.tid and header.ns

Every kernel-captured record with a task context carries `tid` and the
namespace snapshot `ns` of that task (workspace tracer contract §2.8.1). The
snapshot is read inside the hook, at the same moment as `header.timestamp`.
Syscall records whose header is taken at entry and emitted at exit, such as
`execve`, therefore report the entry moment. A kernel-observed
`process_start` describes the child, so its `tid` and `ns` are the child's.

| Slot | Kernel source |
|------|---------------|
| `mnt`, `net`, `uts`, `ipc`, `cgroup` | `task->nsproxy-><type>_ns->ns.inum` |
| `user` | `task->real_cred->user_ns->ns.inum` (as `/proc/<tid>/ns/user`) |
| `pid` | `task->thread_pid->numbers[level].ns->ns.inum`, the task's own active PID namespace |

Each `inode` is the nsfs inode number. Together with `nsfs_dev` from
`META bloodhound_ready` it equals what `stat` on `/proc/<tid>/ns/<slot>`
reports. A slot is `unsupported` when the running kernel's BTF lacks a member
on its read path, and `unavailable` when a read fails or the task no longer
holds its namespaces (for example during exit). Slots are independent.

Records without a task context omit both fields: userspace-synthesised
records (including bootstrap `process_start`), `HEARTBEAT`, `DIAGNOSTIC`,
`META` and `PACKET`. Bloodhound never fills them in from `/proc`. The snapshot
states which namespaces the task belonged to, not which namespace an
operation acted on.

### event.type META

`event.name = "bloodhound_ready"` is emitted once per run after every probe is
attached. It is admitted before starting or admitting any emitting producer task
(collection monitors, heartbeat, ring-buffer consumer, or USDT diagnostics), so it
is strictly the first record emitted on stdout for a successful run. (An invalid
USDT selection on startup may emit a diagnostic before process termination, but
never emits ready).

The header is not attributable to a process (sentinel zeroes, empty `comm`, no `tid`,
no `ns`). `args` carries:

- `probes_attached` (u32) — count of successfully attached eBPF programs (tracepoints,
  kprobes, LSM hooks, and USDT locations). Excludes TC programs (removed in Phase 2).
  Counts actual program attachments, not available collectors.
- `ring_buffer_size` (u32) — actual kernel readback of the `EVENTS` ring buffer
  capacity in bytes, verified against the requested `--ring-buffer-size`
  (default: 4 MiB / 4,194,304 bytes; must be a power of two and at least the
  system page size). Sizing is applied to the map pre-load and confirmed
  against kernel map metadata before probe attachment. (32 MiB recommended
  under sustained load).
- `nsfs_dev` (u64 | null) — device number of nsfs. At startup Bloodhound opens
  `/proc/self/ns/net`, verifies with `fstatfs` that it lives on nsfs, and
  reports its `st_dev`. `null` when the check fails; header inodes are then
  comparable only within this run.
- `boot_id` (string UUID) — kernel boot ID read from `/proc/sys/kernel/random/boot_id`.
  Startup fails immediately if the file cannot be read or fails UUID validation.
- `auid` (u32) — principal AUID from `--uid` argument.
- `excluded` (array of u32) — exactly `[daemon PID]`; Tier 1 self-exclusion declaration,
  not consumed by the observer.
- `attached` (object) — per-collector attach status map with fixed keys and aggregation
  rules mirroring `loader.rs`:
  - Required keys: `lifecycle`, `signal`, `exec.execve`, `raw_syscalls`. Always `true`
    in an emitted ready record (failure aborts startup).
  - Optional keys:
    - `exec.execveat`: `true` iff both enter and exit halves attached.
    - `tier2.<name>`: 42 compiled Tier 2 names (`openat`, `read`, `write`, `connect`,
      `bind`, `listen`, `socket`, `clone`, `clone3`, `chdir`, `fchdir`, `unlink`,
      `unlinkat`, `rename`, `renameat2`, `mkdir`, `mkdirat`, `rmdir`, `symlink`,
      `symlinkat`, `link`, `linkat`, `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`,
      `fchownat`, `truncate`, `ftruncate`, `mount`, `umount2`, `sendto`, `recvfrom`,
      `dup`, `dup2`, `dup3`, `pread64`, `pwrite64`, `readv`, `writev`, `mmap`) plus
      `tier2.fcntl`. `true` iff both enter and exit halves attached; for the 42 names
      this equals `TIER2_BITMAP` registration. `fcntl` remains deliberately unregistered
      in `TIER2_BITMAP` regardless, so non-DUPFD commands retain raw coverage.
    - `tier2.sendfile`, `tier2.splice`: rich extraction for sendfile and splice; present
      only when `--enable-rich-sendfile` is passed; `true` iff both enter and exit
      halves attached.
    - `tty.write`, `tty.read`, `tty.read_ret`: kprobes (`pty_write`, `n_tty_read`, and
      `n_tty_read` kretprobe); `true` iff attached and TTY BTF classification offsets
      are resolved; `false` if probe attach failed or BTF classification is unsupported.
    - `lsm.<hook>`: 7 LSM hooks (`task_kill`, `bpf`, `ptrace_access_check`, `file_open`,
      `inode_unlink`, `inode_rename`, `task_fix_setuid`). Present only when `--enable-lsm`
      is opted in; `true` if attached, `false` if attempted and failed. Note that the
      BPF hook key is `lsm.bpf`.
    - `usdt.<collector_id>`: selected USDT collectors; present only for enabled selections
      (`true` if attached, `false` if failed).
  - Aggregation rules:
    - A pair is `true` only when both halves attached. A half-attached pair is `false`,
      and for `tier2.*` keys other than `fcntl`, its syscall is not registered in
      `TIER2_BITMAP` (Tier 1 keeps capturing it).
    - Both halves of an optional pair are attempted even if one fails.
    - A key is **absent** when its collector was not selected by configuration (e.g.,
      `--enable-rich-sendfile` not passed, `--enable-lsm` not passed, or USDT ID not
      selected). It is **`false`** when the collector was attempted and failed, or
      when required BTF classification offsets are unavailable.
      Downstream consumers never treat absent or `false` as available.
- `heartbeat_interval_ms` (u32) — configured periodic heartbeat cadence in milliseconds.
  Configured on the CLI as f64 seconds via `--heartbeat-interval`; Bloodhound quantizes
  it once via `round(seconds * 1000.0)` as u32, and the internal timer uses
  `Duration::from_millis(heartbeat_interval_ms)` of exactly that value. Passing `0`
  (including `-0.0`) disables both periodic and final heartbeats (valid for standalone use;
  connected observers fail startup on `0`). Producer startup rejects non-finite input,
  negative values, positive values rounding to zero (<0.5 ms), and values exceeding `u32::MAX`.

`bloodhound_shutdown`, `session_start` and `session_end` are not emitted.

### event.type PACKET

Not produced since Phase 2; historical decode only.

Raw packet capture via TC hooks has been retired. Event kinds 100 (`packet_ingress`)
and 101 (`packet_egress`) remain permanently reserved for historical playback and
offline decoding. No live TC programs are attached, no qdisc changes are made, no
packet correlation or socket table is maintained, and no `--exclude-ports` flag exists.
Network observations are captured exclusively via Layer 3 syscall tracepoints
(`connect`, `bind`, `listen`, `socket`, `sendto`, `recvfrom`).

### event.type LSM

LSM hooks are opt-in and disabled by default (`--enable-lsm`). When enabled, all
7 hooks are attempted independently, and their readiness is reported in `args.attached`
(failure to attach an LSM hook reports `false` and does not abort startup).

When opted in:
- `task_kill` and `ptrace_access_check` retain daemon-protection enforcement: they block
  unauthorized signals or ptrace operations targeting the daemon PID (returning `-1` / `-EPERM`)
  and emit an LSM event with `return_code = -1`. Non-daemon signals emit `return_code = 0`.
- The `bpf` hook (`lsm.bpf`) is observe-only: it always returns 0 and emits `return_code = 0`
  (no blanket denial).
- `file_open`, `inode_unlink`, `inode_rename`, and `task_fix_setuid` emit behavior events
  with `return_code = 0`.
- An observed hook decision is not a promise that DAC or another LSM permits the syscall.
  For example, standard Linux DAC checks reject unprivileged kill or ptrace attempts
  against root before LSM hooks are reached.

`task_kill.args.target_ref` identifies the target process instance. A
successful `task_kill` event records signal delivery only; it is not evidence
that the target exited. If the stable target identity cannot be read,
`target_ref` is omitted rather than populated with a zero start time.

### event.name signal_generate

DECIDED: `raw_tracepoint:signal_generate` is the non-enforcing signal
observation authority. It does not require BPF LSM and cannot allow, deny, or
modify a signal.

Observation applies across the single configured AUID: an event is emitted if
either the sender or the target matches that AUID. Daemon senders are excluded
before evaluating either branch, but target daemons are not blanket excluded.
The event header always records the current task's own `auid` (`loginuid`) and process
identity, which may be non-principal when an unmonitored sender targets a
monitored process; the header is never relabeled.

The sender recorded in the header reflects the task context executing the hook,
which is not necessarily the true originator (signals raised from hard IRQs,
softirqs, or kernel timers run in whatever task context is current — the
interrupted task or a kernel thread such as ksoftirqd — so no provenance or
causal claim is made). If the daemon was the currently running task when an
IRQ/timer signal occurred, daemon self-exclusion may omit the event.
Signals are non-authoritative seeds and never synthesize a lifecycle `process_start`.

The event header identifies the process context that generated the signal.
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
`event.layer` is always `"behavior"`. Raw `exit` (60) and `exit_group` (231)
are emitted at syscall entry because they never return through syscall exit;
`raw_args[0]` carries the exit status and `return_code` is 0 as a placeholder
that does not mean a returned value.

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

Userspace-synthesised pulse. `event.layer = "behavior"`, `event.name = "heartbeat"`.
Emitted periodically every `--heartbeat-interval` seconds (default: 1.0; set to
0 to disable both periodic and final heartbeats) and as an ordinary last event
on orderly daemon shutdown.

The header fields `auid`, `sessionid`, `pid` are sentinel zeroes and
`comm` is empty — `HEARTBEAT` is not attributable to a process.
`args` carries:

- `drop_count_delta` — ring-buffer drops observed since the previous admitted
  heartbeat (or since daemon start for the first heartbeat)
- `drop_count_total` — cumulative ring-buffer drops since daemon startup
- `reason_code` — `ring_buffer_overflow` once the cumulative drop count is
  nonzero; distinct from `deserialize_rejected` diagnostics
- `events_emitted_delta` — events serialised to stdout since the previous admitted
  heartbeat (or since daemon start for the first heartbeat)
- `run_prefix_incomplete` — present and `true` once cumulative ring-buffer
  drops are nonzero for this daemon run
- `gap_detected` — present and `true` only when
  `drop_count_delta > 0`; omitted otherwise so consumers can
  fast-path on the flag's presence

Accounting deltas start from a zero baseline at daemon start (covering any events
or drops occurring before heartbeat emitter initialization). An admitted sample
advances the baseline only after successful acceptance into the bounded sequencer
channel; backpressured or cancelled sends do not advance accounting. Across a run,
periodic and final `drop_count_delta` values sum to the final `drop_count_total`,
and `events_emitted_delta` values sum to all serialized events preceding the last
heartbeat.

Downstream consumers should treat any interval between two
`HEARTBEAT` events with `gap_detected = true` as *undecidable* for
correlation — state accumulated across the gap may be incomplete.

#### Graceful shutdown and final heartbeat

On orderly shutdown (SIGINT or SIGTERM), Bloodhound synchronously detaches BPF
and USDT probes, drains the sequencer admission channel while joining producers
under a 5-second asynchronous deadline starting after synchronous detach, stops
the drop counter bridge, and performs a fresh read of the kernel BPF drop counter.
When enabled, an ordinary final `HEARTBEAT` is submitted as the last event before
stdout flush.

- **No new fields**: The final heartbeat uses the exact same schema; there is no
  `final: true` field, no separate event type, args field, or reason code.
- **Interval 0**: Passing `--heartbeat-interval 0` disables both periodic and
  shutdown heartbeats. The final BPF map drop read is still performed on shutdown
  to detect and report read errors.
- **Aborted shutdown**: If a producer task panics or errors, the drain deadline
  expires, or the final BPF drop count read fails, shutdown terminates with an
  error and no final heartbeat is emitted.
- **Exit status non-equivalence**: The appearance of a final `HEARTBEAT` line
  is not an if-and-only-if marker of process exit success (`0`); writing or
  flushing the output stream may fail after the heartbeat line has been written.
- **Observation limits**: The 5-second asynchronous deadline begins after
  synchronous detach (which is not preemptible by an async timeout) and does not
  form a wall-clock guarantee for total shutdown time. Kernel effects in flight
  during or after probe detachment are not guaranteed to be captured. Periodic
  per-CPU drop map reads into userspace and periodic stderr warnings remain
  best-effort operational diagnostics with known polling intervals and do not
  guarantee immediate or synchronous notification of in-kernel drops.

### event.type DIAGNOSTIC

`event.name = "stream.health"` with
`args.reason_code = "deserialize_rejected"` reports a binary ring-buffer
record that Bloodhound could not deserialize. It includes bounded delta and
cumulative rejection counts, never the rejected payload. The diagnostic is
emitted before the next raw-derived event.

Ring-buffer drops and deserialization rejection are separate causes. Either
makes the cumulative run prefix incomplete. Later intervals with no new loss
do not claim recovery; consumers apply their own explicit recovery semantics.
### Openat acquisition status (capture version 1)

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
device values. A complete pair requires both components. Member offsets are
resolved at runtime from the running kernel's BTF (`/sys/kernel/btf/vmlinux`).
When fd identity BTF fields are unresolved, `file_identity_status` is `unavailable`.
Because transient runtime read failures also report `unavailable`, consumers
cannot distinguish kernel-unsupported from read failure.

Actor header and pathname are captured at entry; returned FD and identity at
exit. FD close/reuse races and readable but incorrect kernel offsets cannot
always be detected. See [measurement and limits](development/filesystem-observation.md).

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
metadata/assembly acquisition (including oversize payload assembly and `bpf_memcpy`
failure at exit, which are counted under `exit_capture_failed`), and pending
invocations removed at task exit. Path-read failure is represented on the event;
unsuccessful FD-identity reads are represented by identity status. The counter
does not certify unsupported paths or detect every FD-table race. A missing entry
with no recorded entry (for example, tracing attached during an in-flight syscall)
is not counted.

`DIAGNOSTIC/exec.collection` reports the same kind of loss for `execve` /
`execveat`, with the same fields, polling and shutdown behavior, and
`scope: exec`. Reasons are `entry_capture_failed`, `entry_save_failed`,
`exit_capture_failed`, `invocation_interrupted` (a pending exec removed at task
exit), and `entry_cleanup_failed` (the pending entry could not be removed).
Entry and exit are paired by the calling task, not by PID/TID, so an exec from a
non-leader thread keeps its pairing after the kernel hands it the leader PID.
A failed return-value read still releases the pending entry and is reported as
`exit_capture_failed`.

`DIAGNOSTIC/syscall.collection` reports pre-ring-buffer collection loss for
Tier-2 rich and path syscalls (excluding `openat` and `execve`/`execveat`, which
retain their dedicated scopes), with `reason_code`, `failure_count_delta`,
`failure_count_total`, `scope: syscall`, `sampling: userspace_poll`, and sticky
`run_prefix_incomplete: true`. Counts are polled periodically (once per second)
and once after kernel production stops during graceful shutdown. Their timestamps
describe the userspace poll, not the missing operation, and do not identify
affected actors or processes.

The reason names for the `syscall` scope in `bloodhound_common::SYSCALL_FAILURE_REASONS`
are:
- `entry_capture_failed`: Syscall entry context/argument read failure or per-CPU scratch buffer acquisition failure.
- `entry_save_failed`: Map insertion failure when storing in-flight entry state in `RICH_ENTRY_MAP` or `PATH_ENTRY_MAP` (e.g., map capacity reached or `NO_PREALLOC` memory allocation failure).
- `exit_capture_failed`: Exit tracepoint argument read failure, assembly scratch acquisition failure, oversized payload assembly, or variable-length `bpf_memcpy` failure after a recorded entry was found.
- `invocation_interrupted`: Pending invocation entry removed during lifecycle exit cleanup (`sched_process_exit`) when a thread terminates before reaching syscall exit.
- `entry_cleanup_failed`: Map deletion error when removing a recorded entry from `RICH_ENTRY_MAP` or `PATH_ENTRY_MAP`, indicating correlation-state integrity loss.

In addition, the userspace monitor reports `counter_read_failed` with null counts
(`failure_count_delta: null`, `failure_count_total: null`, never fabricated zeroes)
when the kernel BPF counter map cannot be read. See
[observer-connection rows 115/116](https://github.com/abyss0-dev/workspace/blob/99d751b90f8520a62c428d2012d018c6100a30ad/docs/spec/tracer/observer-connection.md#5-loss-accounting-and-health-mapping)
for consumer mapping.

Invocations already in flight when tracing attaches have no recorded entry in the
in-flight maps and are not counted as failures. Map removal of an unrecorded or
already-removed entry returns `-ENOENT` (`-2`), which is tolerated and not counted.
Interrupted-invocation accounting requires a recorded entry; lifecycle cleanup
increments `invocation_interrupted` only when a saved entry is found for the exiting
thread. Ring-buffer overflow is represented strictly in `DROP_COUNT` / `HEARTBEAT` drop
counters and is never counted on collection scope counters (`emit_varlen` reports
pre-emission assembly success independently of ring-buffer acceptance).

`DIAGNOSTIC/raw_syscall.collection` reports pre-ring-buffer collection loss for
Tier-1 raw syscalls, with the same fields (`reason_code`, `failure_count_delta`,
`failure_count_total`, `scope: raw_syscall`, `sampling: userspace_poll`, and sticky
`run_prefix_incomplete: true`) and periodic/shutdown polling behavior as
`syscall.collection`. It uses the same reason set (`bloodhound_common::RAW_SYSCALL_FAILURE_REASONS`,
which aliases `SYSCALL_FAILURE_REASONS`). Operational meanings differ only where raw
capture specifics apply:
- `entry_capture_failed`: Tracepoint ID or argument read failure at syscall entry.
- `entry_save_failed` and `entry_cleanup_failed`: Map insertion or deletion failures on `SYSCALL_ENTRY_MAP`.
- `exit_capture_failed`: Return-code read failure at syscall exit after a recorded entry was found in `SYSCALL_ENTRY_MAP` (the saved entry is removed before reporting loss).
- `invocation_interrupted`: Pending invocation entry removed from `SYSCALL_ENTRY_MAP` during lifecycle exit cleanup (`sched_process_exit`).

As with other collection scopes, the userspace monitor reports `counter_read_failed`
with null counts when `RAW_SYSCALL_FAILURES` cannot be read; see
[observer-connection rows 115/116](https://github.com/abyss0-dev/workspace/blob/99d751b90f8520a62c428d2012d018c6100a30ad/docs/spec/tracer/observer-connection.md#5-loss-accounting-and-health-mapping)
for consumer mapping. Not counted as failures: `should_trace` exclusion,
Tier-2-covered syscall numbers (delegated to rich/path capture), out-of-range or
excluded syscall numbers, invocations in flight at attach, and `-ENOENT` return
values on map removal. Interrupted accounting requires a recorded entry, and
ring-buffer drops remain strictly in `DROP_COUNT` / `HEARTBEAT`.

`DIAGNOSTIC/tty.collection` reports pre-ring-buffer collection loss for
TTY capture (`pty_write` and `n_tty_read` kprobes / `n_tty_read` kretprobe),
with the same fields (`reason_code`, `failure_count_delta`, `failure_count_total`,
`scope: tty`, `sampling: userspace_poll`, and sticky `run_prefix_incomplete: true`)
and periodic/shutdown polling behavior as `syscall.collection`. It uses the same
reason set (`bloodhound_common::TTY_FAILURE_REASONS`, which aliases
`SYSCALL_FAILURE_REASONS`). Operational meanings reflect TTY capture specifics
verified from `bloodhound-ebpf/src/layer1_tty.rs` and `maps.rs`:
- `entry_capture_failed`: Context or probe argument read failure on `pty_write`
  or `n_tty_read` entry, or internal assembly failure on write (scratch or assembly
  buffer acquisition failure, or `bpf_memcpy` failure during `emit_tty_event`).
- `entry_save_failed`: Map insertion failure when storing in-flight read entry state
  in `TTY_READ_ENTRY_MAP` (e.g. map capacity reached or memory allocation failure).
- `exit_capture_failed`: Return-code read failure at `n_tty_read` kretprobe after a
  recorded entry was found in `TTY_READ_ENTRY_MAP`, or internal assembly failure on read
  (scratch or assembly buffer acquisition failure, or `bpf_memcpy` failure during `emit_tty_event`).
- `invocation_interrupted`: Pending `n_tty_read` invocation entry never paired with a return.
  This is accounted when a thread terminates before returning (removed from
  `TTY_READ_ENTRY_MAP` during lifecycle exit cleanup via `sched_process_exit`) or when
  a subsequent `n_tty_read` on the same thread arrives before the prior return and
  reclaims the stale entry (`tty_interrupt` at entry). This includes concurrent blocked
  reads beyond the kretprobe maxactive limit (Aya 0.13.1 leaves maxactive at zero,
  defaulting in Linux 6.8 `register_kretprobe` to `max(10, 2 * num_possible_cpus())`
  instances; concurrent blocked reads consume instances, causing excess invocations to
  miss returns and later be counted as `invocation_interrupted`).
- `entry_cleanup_failed`: Map deletion error when removing a recorded entry from
  `TTY_READ_ENTRY_MAP`.

As with other collection scopes, the userspace monitor reports `counter_read_failed`
with null counts when `TTY_FAILURES` cannot be read; see
[observer-connection rows 115/116](https://github.com/abyss0-dev/workspace/blob/99d751b90f8520a62c428d2012d018c6100a30ad/docs/spec/tracer/observer-connection.md#5-loss-accounting-and-health-mapping)
for consumer mapping. Not counted as failures: AUID filtering (`should_trace`),
non-pts device filtering (`is_pts_slave`), invocations already in flight when tracing
attaches (an absent entry in `TTY_READ_ENTRY_MAP` at kretprobe is not counted),
return values <= 0 (EOF or error), and `-ENOENT` return values on map removal.
Interrupted accounting requires a recorded entry, and ring-buffer drops remain
strictly in `DROP_COUNT` / `HEARTBEAT`.

### Path event acquisition status (capture version 1)

Path capture status reports the acquisition completeness for all TRACEPOINT
path-bearing syscall events other than `openat` and `exec` (`execve`/`execveat`),
which retain their own dedicated capture metadata and public fields. The wire
layout contract is defined in
[workspace docs/spec/tracer/README.md §2.4.4](https://github.com/abyss0-dev/workspace/blob/main/docs/spec/tracer/README.md#244-on-event-completeness-status-present-events).

#### Covered Events

The events covered by this rule, verified from `bloodhound/src/deserializer.rs`,
are every path-bearing syscall event other than `openat` and `exec`:

- **Single-path syscalls** (12 events, reporting `args.filename`):
  `chdir`, `unlink`, `unlinkat`, `mkdir`, `mkdirat`, `rmdir`, `chmod`,
  `fchmodat`, `chown`, `fchownat`, `truncate`, `umount2`.
- **Two-path syscalls** (7 events, reporting `args.oldpath` and `args.newpath`):
  `rename`, `renameat2`, `symlink`, `symlinkat`, `link`, `linkat`, `mount`.

(FD-only variants such as `fchdir`, `fchmod`, `fchown`, and `ftruncate` operate
on file descriptors rather than paths and do not carry path capture fields.)

`openat` and `exec` (`execve`/`execveat`) are governed by their respective
capture contracts and retain their existing published fields (`capture_version`,
`dirfd`, `filename_status`, and `file_identity_status` for `openat`;
`exec_capture_version`, `argv_status`, and `filename_status` for `exec`);
their schemas are unchanged.

#### Added `args` Fields

For covered events, `args` carries:

- `path_capture_version` (integer): Wire capture version. Emitted as `1` for
  records with capture status metadata, or `0` for legacy or unversioned records.
- For single-path events:
  - `path_status` (string): Capture status for `args.filename`.
- For two-path events:
  - `path1_status` (string): Capture status for the primary input path (`args.oldpath`).
  - `path2_status` (string): Capture status for the secondary input path (`args.newpath`).

#### Status Values and Semantics

The status fields take one of the following string values:

- `complete`: The pathname was completely and successfully read from user memory
  into the kernel buffer and verified by userspace as valid UTF-8.
- `truncated`: The pathname reached the kernel read buffer limit. Specifically,
  a path of exactly 4095 bytes is reported `truncated` because the kernel string
  read cannot distinguish a 4095-byte pathname from a longer one (the same
  conservative saturation rule used by `openat` and `exec`).
- `read_error`: The pathname pointer was NULL (`0`) or pointed to an unreadable
  user-memory address (e.g. invalid address or unmapped memory). NULL is treated
  as an actual user-memory read failure and produces `read_error`; userspace
  never infers successful acquisition from an empty string.
- `invalid_encoding`: The kernel read succeeded without truncation
  (`CaptureStatus::Complete`), but userspace string validation detected non-UTF-8
  byte sequences. UTF-8 validation is owned by userspace; lossy conversion is
  never labeled `complete`.
- `unknown`: Reported when `path_capture_version` is 0 or absent (legacy records).
  Downstream consumers must require an explicitly `complete` status rather than
  inferring completeness from an empty string or the absence of a truncation flag.

#### Wire and Validation Rules

In `HeaderCapture`, capture status codes are mapped in input path order:
- For single-path events, `primary` carries the status of `filename`. `secondary`
  must be zero (`0x00`); a single-path version 1 record with a non-zero secondary
  status byte is rejected by the deserializer as invalid wire metadata.
- For two-path events, `primary` carries the status of `oldpath` and `secondary`
  carries the status of `newpath`.

For version 1 records, the deserializer strictly validates that `path_len`
(single-path) or `path1_len + path2_len` (two-path) equals the variable-length
payload length. Any record with inconsistent lengths, unknown status codes, or a
non-zero secondary byte on a single-path event is rejected via the
`DIAGNOSTIC/stream.health` deserialization rejection path.

### TTY event acquisition status (capture version 1)

TTY capture status reports the acquisition completeness for TTY intent events
(`tty_read` and `tty_write`). The wire layout contract is defined in
[workspace docs/spec/tracer/README.md §2.4.4](https://github.com/abyss0-dev/workspace/blob/main/docs/spec/tracer/README.md#244-on-event-completeness-status-present-events).

#### Covered Events

The events covered by this rule, verified from `bloodhound/src/deserializer.rs`
and `bloodhound-ebpf/src/layer1_tty.rs`, are:

- `tty_read` (`event.type == "TTY"`, `event.layer == "intent"`)
- `tty_write` (`event.type == "TTY"`, `event.layer == "intent"`)

#### Added `args` Fields

For covered events, `args` carries:

- `tty_capture_version` (integer): Wire capture version. Emitted as `1` for
  records with capture status metadata, or `0` for legacy or unversioned records.
- `data_status` (string): Capture status for raw binary `args.data`.

#### Status Values and Semantics

The `data_status` field takes one of the following string values:

- `complete`: The TTY data was completely and successfully read from kernel memory
  into the capture buffer. Data of up to 4095 bytes (including exactly 4095 bytes,
  matching `MAX_TTY_DATA - 1`) is reported `complete`. A complete capture must be
  non-empty.
- `truncated`: More than 4095 bytes were written or read (`count > 4095`, verified
  in `bloodhound-ebpf/src/layer1_tty.rs`). The payload contains the bounded prefix of
  exactly 4095 bytes.
- `read_error`: The kernel buffer pointer was NULL (`0`) or `bpf_probe_read_kernel_buf`
  failed. The event carries empty data (`args.data: ""` / 0 decoded bytes) rather
  than omitting the event or reporting collection loss. Events with `read_error` are
  still subject to pts-only device filtering and AUID filtering.
- `unknown`: Reported when `tty_capture_version` is 0 or absent (legacy records).
  Downstream consumers must require an explicitly `complete` status rather than
  inferring completeness from the presence of data or the absence of a truncation flag.

Unlike pathname capture, TTY capture processes arbitrary binary streams (Base64-encoded
in `args.data`), so text encoding validation is not performed and `invalid_encoding`
does not apply.

#### Wire and Validation Rules

In `HeaderCapture`, capture status is encoded in three bytes `[version, primary, secondary]`:
- For version 1, `version` is `1`, `primary` carries the `CaptureStatus` code
  for `data_status`, and `secondary` (the third byte) must be zero (`0x00`).
- The deserializer strictly validates records and rejects invalid wire metadata:
  - Version other than `0` or `1`.
  - Non-zero third byte (`secondary != 0`).
  - Unknown status code (a primary byte that does not map to `Complete`, `Truncated`, or `ReadError`).
  - Length mismatch (`declared_len != var_data.len()` or `declared_len > 4095`).
  - Truncated status without exactly 4095 bytes (`data_status == "truncated"` with `declared_len != 4095`).
  - Read error status with data (`data_status == "read_error"` with `declared_len != 0`).
  - Complete status with empty data (`data_status == "complete"` with `declared_len == 0`).

Any record violating these constraints is rejected via the
`DIAGNOSTIC/stream.health` deserialization rejection path.

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
