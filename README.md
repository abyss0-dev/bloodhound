# Bloodhound

eBPF-based behavioral tracing daemon for isolated VMs.

Bloodhound is a resident daemon that traces user behavior inside QEMU/KVM
guest VMs. It captures every kernel-level event attributable to a target
user — syscalls, TTY I/O, network packets, and process lifecycle — correlates
them via `auid` (audit login UID), and emits structured events as NDJSON.

```mermaid
graph TD
    subgraph VM["Guest VM (Ubuntu)"]
        User["Target User<br/>(fixed UID)"]

        subgraph Kernel["Kernel (eBPF)"]
            L1["Layer 1<br/>TTY<br/>(kprobe)"]
            L2["Layer 2<br/>Exec<br/>(tracepoint)"]
            L3["Layer 3<br/>Syscalls<br/>(tracepoint)"]
            TC["TC<br/>Packets<br/>(sched_cls)"]
            LSM["LSM Hooks<br/>(7 hooks)"]
            Filter["auid filter<br/>+ port exclusion"]
            RB["Ring Buffer"]
        end

        subgraph Userspace["Bloodhound (userspace)"]
            PktJoin["5-tuple<br/>packet join"]
            Enrich["/proc enrichment<br/>+ JSON serialize"]
        end

        Output["stdout (NDJSON)"]

        User --> L1 & L2 & L3 & TC
        L1 & L2 & L3 & TC --> Filter
        Filter --> RB
        LSM --> RB
        RB --> PktJoin & Enrich
        PktJoin & Enrich --> Output
    end
```

## Features

- **Layer 1 — TTY capture**: kprobe hooks on `pty_write` / `n_tty_read` for raw terminal I/O
- **Layer 2 — Process tracking**: `execve` / `execveat` tracepoints with full argv capture
- **Exec filesystem view**: root device/inode, mount namespace and root mount ID
  captured at exec entry, with explicit acquisition status and exact actor/time
  pairing ([contract](docs/development/exec-view.md))
- **Layer 3 — Syscall tracing**: raw syscall stream + rich extraction for 30+ syscalls (file, network, process, directory operations)
- **Signal observation**: non-enforcing `signal_generate` raw tracepoint with immutable sender and target identities
- **Packet capture**: TC (Traffic Control) hooks on all network interfaces, ingress and egress
- **Tamper resistance**: 7 LSM hooks protect the daemon from the target user (task_kill, bpf, ptrace, file_open, inode_unlink, inode_rename, task_fix_setuid)
- **Structured output**: All events emitted as NDJSON with unified `BehaviorEvent` schema

## Requirements

| Component       | Version                        |
|-----------------|--------------------------------|
| Rust            | nightly (see `rust-toolchain.toml`) |
| Target kernel   | 6.8+ with BTF                  |
| Target OS       | Ubuntu (LTS)                   |
| Docker          | Required for production builds |
| QEMU/KVM        | Required for E2E tests         |

> [!IMPORTANT]
> **Development environment**: Linux or WSL2 is required for building and
> running E2E tests. The eBPF daemon depends on `CONFIG_AUDIT` (for
> `loginuid`/`auid` tracking) and KVM acceleration, neither of which is
> available on macOS. Docker-based builds (`make build-docker`) work on
> macOS but the E2E test pipeline does not.

BPF LSM is optional and belongs to the separate tamper-resistance boundary.
The `signal_generate` collector neither enables nor depends on LSM.

Application semantic probes use the [trusted USDT contract](docs/usdt-collectors.md).
Probing arbitrary application-internal functions or fixed binary offsets is not
supported. Exec filesystem view capture is a kernel observation and needs no
USDT collector. Filesystem command correlation belongs to the consumer; it does
not require proof that shell pipeline syntax was absent or classify commands
by their standard descriptor kinds.

## Quick Start

### Build (via Docker — recommended)

```bash
# Build the static musl binary
make build-docker

# Output: target/docker/bloodhound
```

### Build & Deploy to E2E VM

```bash
cd e2e

# Build rootfs, boot VM, deploy binary, run tests
bash scripts/deploy.sh --no-cache   # full rebuild
bash scripts/deploy.sh              # incremental (uses Docker cache)

# Run E2E tests
cd tests && ../venv/bin/python3 -m pytest --ssh-port=2222 --ssh-host=localhost
```

### Run the Daemon

```bash
# Inside the VM (as root):
bloodhound --uid 1000           # trace user with UID 1000
bloodhound --uid 1000 --exclude-ports 22  # exclude SSH traffic
bloodhound --uid 1000 --ring-buffer-size 8388608  # 8 MiB BPF ring buffer
```

#### Ring Buffer Configuration

`--ring-buffer-size` sets the capacity of the kernel `EVENTS` ring buffer in bytes (default: `4194304`, 4 MiB):

- **Validation**: Must be a power of two and at least the system page size (`sysconf(_SC_PAGESIZE)`). Invalid values are rejected early at startup before output initialization, BTF resolution, or BPF loading.
- **Pre-load application & verification**: The requested size is applied to the `EVENTS` map before BPF loading (`set_max_entries`) and verified against the actual kernel map size before probe attachment.
- **Readiness report**: The actual kernel readback is emitted in the initial `META bloodhound_ready` event (`args.ring_buffer_size`), not echoed from the CLI argument.
- **Recommendation**: For high-volume workloads (such as `--enable-rich-sendfile` or sustained I/O), sizing to 32 MiB (`33554432`) or higher is recommended to avoid drops.

### View Logs with TUI

```bash
cargo run --package bloodhound-tui -- /path/to/bloodhound.ndjson
```

## Technology Stack

| Component        | Choice                                  |
|------------------|-----------------------------------------|
| BPF programs     | Rust (`no_std`) via [Aya](https://aya-rs.dev/) |
| Userspace daemon | Rust via Aya + tokio                    |
| TUI viewer       | Rust via [Ratatui](https://ratatui.rs/) |
| BPF-to-user pipe | `BPF_MAP_TYPE_RINGBUF`                  |
| Output format    | NDJSON (`BehaviorEvent` schema)         |
| Build            | Docker multi-stage (musl static binary) |
| E2E tests        | QEMU/KVM + pytest                       |

## Development Notes

### Kernel Struct Offsets

The eBPF code reads `task_struct` fields (`loginuid`, `sessionid`, `tgid`)
using hardcoded byte offsets. These are **kernel-version-specific** and must
be verified on the **target VM kernel**, not the build host.

See [docs/ebpf-offsets.md](docs/ebpf-offsets.md) for the verification procedure.

### BPF Verifier

eBPF programs must pass the kernel's BPF verifier at load time. Common
pitfalls are documented in [docs/build.md](docs/build.md#bpf-verifier-gotchas).

### Feature Development

Developer-facing architecture and contribution guides live under
[`docs/development/`](docs/development/README.md). Start with
[Developing trusted USDT collectors](docs/development/usdt-collectors.md) when
changing the USDT collector registry, eBPF programs, payload ABI, or E2E tests.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 OldBigBuddha
