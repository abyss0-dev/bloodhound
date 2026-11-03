# Daemon Lifecycle


## Startup

1. Parse CLI arguments (`--uid <N>`, `--ring-buffer-size <bytes>`,
   `--heartbeat-interval <seconds>`, `--enable-lsm`, `--enable-rich-sendfile`,
   `--usdt-config <path>`, etc.).
2. Validate system page size, ring buffer size, and heartbeat cadence early:
   quantize cadence once to u32 milliseconds; reject non-finite, negative,
   sub-0.5ms, or overflowing cadence.
3. Read and validate kernel boot ID from `/proc/sys/kernel/random/boot_id`
   (startup fails immediately if read fails or format is invalid).
4. Initialize the single bounded admission sequencer before any producer can emit.
5. Ingest trusted USDT configuration selections (invalid configuration files emit a
   startup diagnostic on stdout before non-zero termination; validation failures in
   loader startup such as duplicate collector selections abort immediately without
   emitting a stdout diagnostic; in neither failure case is ready emitted).
6. Resolve running kernel BTF offsets and set global BPF variables (`TARGET_AUID`,
   `DAEMON_PID`, task_struct offsets, namespace offsets, exec_view offsets).
7. Load eBPF programs, attach required tracepoints (`lifecycle`, `signal`,
   `exec.execve`, `raw_syscalls`), optional tracepoints (`exec.execveat`, Tier 2
   syscalls, sendfile/splice), TTY kprobes, opt-in LSM hooks (`--enable-lsm`),
   and selected USDT probes, generating an explicit `AttachReport`. Rejects duplicate
   USDT selections across config files before attachment.
8. Read back actual kernel ring buffer size and verify nsfs device number.
9. Admit `META bloodhound_ready` to the sequencer as the strictly first record
   of a successful run, ahead of starting or admitting any emitting tasks (collection
   health monitors, heartbeat emitter, ring-buffer consumer, or USDT diagnostics).
10. Start background drop counter bridge, collection health monitors, heartbeat task,
    and ring buffer consumer.


## Shutdown

DECIDED: Graceful shutdown on SIGTERM.

1. Receive SIGTERM
2. Detach all BPF programs (stops new events from being produced)
3. Drain remaining events from ring buffer
4. Flush all pending NDJSON to stdout
5. Exit with code 0

A timeout (e.g., 5 seconds) guards against infinite drain loops.
If the timeout expires, or if the sequencer/stdout writer fails, Bloodhound
reports incomplete shutdown and exits non-zero. It never reports a clean
shutdown after silently abandoning admitted records.


## Crash Recovery

DECIDED: systemd `Restart=always`. If Bloodhound crashes, systemd
restarts it automatically. [ACCEPTANCE] Events during the restart gap
are lost. The systemd unit should include `RestartSec=1` for fast
recovery.


## Nohup / Orphan Processes

DECIDED: Processes that outlive the SSH session (e.g., via `nohup`)
retain the target user's `auid` and continue to be traced. This is
intentional -- the target user's background processes are part of their
observable behavior.


## Scope Boundary

Bloodhound is responsible for:
- Loading and managing BPF programs
- Filtering events by auid with daemon self-exclusion
- Emitting authoritative kernel-observed lifecycle and execution facts
- Serializing BehaviorEvents as NDJSON to stdout

Bloodhound is NOT responsible for:
- Event evaluation / matching logic
- Scenario task definitions
- Signaling task completion (virtio-serial)
- Hint generation
- Live packet capture or TCP/IP packet reconstruction (packet capture is retired;
  network activity is traced via Layer 3 socket syscalls)

Downstream consumers read Bloodhound's stdout stream. This separation
keeps Bloodhound focused and testable.
