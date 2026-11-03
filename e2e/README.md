# Bloodhound E2E

Tools for running the bloodhound eBPF tracing daemon inside a QEMU VM and verifying its behavior.

## Prerequisites

- Docker
- QEMU with KVM support
- `sshpass`
- Python 3 + venv (`pexpect`, `pytest`, `jsonschema`)

## Directory Layout

```
e2e/
├── Dockerfile              # Base image definition for VM rootfs
├── Makefile                # Shortcuts for build / test / VM lifecycle
├── scripts/
│   ├── build-rootfs.sh     # Docker export → ext4 rootfs image
│   ├── boot-vm.sh          # Boot QEMU VM
│   ├── deploy.sh           # Build, copy, and restart the bloodhound binary
│   ├── run-and-record.sh   # Feed a shell script line-by-line and collect traces
│   ├── smoke-test.sh       # Quick daemon health check
│   └── scenario/           # Pre-built scripts for trace verification
├── tests/
│   ├── conftest.py         # pytest fixtures (SSH, SCP, event retrieval)
│   ├── helpers.py          # Event filtering & schema validation utilities
│   └── test_*.py           # E2E test suites
├── vmlinuz                 # Kernel image for the VM
└── rootfs.ext4             # Root filesystem (generated)
```

## Setup

```bash
# 1. Create a venv (first time only)
python3 -m venv venv
venv/bin/pip install pexpect pytest jsonschema

# 2. Build the bloodhound binary
make build

# 3. Generate the rootfs image (first time or after Dockerfile changes)
make rootfs
```

## Running E2E Tests

```bash
# Full cycle: boot VM → run tests → shut down VM
make e2e

# Or step by step
make vm-up        # Boot VM
make test          # Run pytest suite
make vm-down       # Shut down VM
```

## run-and-record: Trace a Shell Script

Boots a VM, feeds each line of a shell script **one at a time** through an
interactive SSH session (PTY allocated via `pexpect`), and collects the
bloodhound NDJSON trace. Because commands are typed into a real terminal
rather than executed as `bash script.sh`, each command is recorded
individually as `tty_write` / `exec` / `syscall` events.

### Usage

```bash
./scripts/run-and-record.sh <script.sh> [output-dir]
```

### Example

```bash
./scripts/run-and-record.sh ./scripts/scenario/01_file_exploration.sh ./output
```

Logs are saved as `output/bloodhound_YYYYMMDD_HHMMSS.ndjson`.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_PORT` | `2222` | VM SSH port |
| `SSH_USER` | `testuser` | Target user (uid=1000) |
| `SSH_PASS` | `testpass` | SSH password |
| `ROOTFS_IMG` | `rootfs.ext4` | Rootfs image filename |
| `VM_MEMORY` | `2048` | VM memory in MB |
| `VM_CPUS` | `2` | VM CPU count |
| `SNAPSHOT` | `1` | Set to `1` to use QEMU `-snapshot` (keeps rootfs clean) |

### How It Works

1. **Boot VM** — Starts QEMU in the background with `-snapshot`
2. **Verify daemon** — Checks that bloodhound is active
3. **Clear log** — Truncates NDJSON for a clean recording
4. **Execute commands** — Opens an interactive SSH session via pexpect, sends each line with `sendline()`
5. **Retrieve log** — SCPs the NDJSON file to the host
6. **Destroy VM** — Kills the QEMU process via trap

> [!NOTE]
> Lines starting with `#`, empty lines, and shebangs (`#!/...`) are automatically skipped.

> [!TIP]
> Set `SNAPSHOT=0` to persist rootfs changes across runs — useful when chaining multiple scripts.

## Scenarios

Pre-built scripts under `scripts/scenario/` exercise different eBPF trace
layers. Each script focuses on specific event types to make verification easier.

| Script | Focus | Key Events |
|--------|-------|------------|
| `01_file_exploration.sh` | Reading files and text processing | `execve`, `openat`, `read`, `write` |
| `02_file_mutation.sh` | Creating, modifying, deleting files | `openat` (write flags), `mkdir`, `rmdir`, `unlink`, `rename` |
| `03_process_lifecycle.sh` | Forking, pipes, background jobs | `execve`, `clone`/`clone3`, subshells |
| `04_network_activity.sh` | HTTP requests, DNS lookups | socket syscalls (`connect`, `socket`, `sendto`, `recvfrom`) |
| `05_permission_boundary.sh` | Privilege escalation, access denial | `sudo` execve, DAC permission errors (ordinary testuser kill of root daemon demonstrates DAC, not LSM) |
| `06_realistic_workflow.sh` | End-to-end learner workflow | All layers combined; tests event correlation |

## Test Suites (Phase 2 Status)

- **`test_packet.py`**: Positive live packet capture tests were removed (not skipped) following TC retirement. Historical packet decoding remains verified via unit tests.
- **`test_lsm.py`**: Verifies opt-in LSM hook behavior using capable root execution under the principal AUID (`TARGET_AUID`), testing a harmless `SIGCONT` denial to the daemon PID with an actual `task_kill` event (`return_code = -1`), and a valid `BPF_MAP_CREATE` syscall with an actual observe-only `bpf` hook event (`return_code = 0`). Skips explicitly when optional LSM hooks fail to attach.
- **`test_readiness.py`**: Validates `bloodhound_ready` facts (`boot_id`, `auid`, `excluded`, `probes_attached`, `ring_buffer_size`, `nsfs_dev`, `attached`, `heartbeat_interval_ms`), default startup with no LSM and no qdisc or TC filter changes, cadence quantization and zero handling, and the complete absence of live `/proc` enrichment.

> [!NOTE]
> In this producer worktree, these VM test suites are collected and syntax-checked (`pytest --collect-only`),
> but are **not executed** against a running guest VM. Live VM execution and end-to-end validation are
> owned by parent integration.

## Debugging

```bash
# View VM console output
cat e2e/qemu.log

# Check bloodhound daemon logs
sshpass -p root ssh -p 2222 root@localhost journalctl -u bloodhound --no-pager -n 30

# SSH into the VM manually
sshpass -p testpass ssh -p 2222 testuser@localhost
```
