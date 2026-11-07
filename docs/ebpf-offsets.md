# eBPF Kernel Struct Offset Resolution

Bloodhound resolves all kernel struct member offsets needed for event
filtering, process instance identity, namespace membership, mount/exec views
(`exec_view`), file-descriptor identity (`fd_ident`), and TTY classification
at daemon startup from the running kernel's BTF (`/sys/kernel/btf/vmlinux`).

## How It Works: Runtime BTF Offset Resolution

The byte offset of each member is resolved at daemon start from the running
kernel's own BTF, then injected into eBPF programs as global variables before
load. This makes the daemon portable to any BTF-bearing kernel without
recompilation or hard-coded kernel layout headers.

The pieces:

- **Userspace resolver** (`bloodhound::btf_offsets`): A single BTF reader
  parses `/sys/kernel/btf/vmlinux` and resolves all required member offsets:
  - *Process lifecycle and filtering*: `task_struct::{loginuid, sessionid, pid,
    tgid, group_leader, start_boottime, signal, exit_code, comm}` and
    `signal_struct::{live, group_exit_code}`.
  - *Namespace membership*: `task_struct::nsproxy` and namespace hierarchy
    offsets (`uts_ns`, `ipc_ns`, `mnt_ns`, `pid_ns_for_children`, `net_ns`,
    `cgroup_ns`, `pid.numbers`, `upid.ns`).
  - *Exec mount views* (`exec_view`): 14 member offsets across `fs_struct`,
    `path`, `dentry`, and `mount`.
  - *File-descriptor identity* (`fd_ident`): 5 traversal offsets
    (`task_struct.files`, `files_struct.fdt`, `fdtable.max_fds`, `fdtable.fd`,
    `file.f_inode`) plus 3 shared inode/superblock endpoints (`inode.i_ino`,
    `inode.i_sb`, `super_block.s_dev`). Shared endpoints are resolved once and
    reused independently of `exec_view` support.
  - *TTY device classification* (`tty`): 3 direct offsets
    (`tty_struct.driver`, `tty_driver.type`, `tty_driver.subtype`).
- **Loader injection** (`bloodhound::loader`): The resolved offsets and feature
  support flags are passed via `EbpfLoader::set_global` into corresponding
  global variables (`OFF_FD_IDENT`, `FD_IDENT_SUPPORTED`, `OFF_TTY`,
  `TTY_SUPPORTED`, `OFF_EXEC_VIEW`, `EXEC_VIEW_SUPPORTED`, `OFF_NS`).
- **eBPF in-kernel reads** (`filter.rs`, `fd_ident.rs`, `layer1_tty.rs`,
  `lsm_hooks.rs`): Fields are read dynamically with `bpf_probe_read_kernel`
  using base pointer plus injected offset. No compile-time layout bindings or
  hard-coded struct offsets exist in the eBPF programs.

## Fail-Closed Behavior and Degraded Observations

Different subsystems enforce distinct degradation semantics when BTF members
are absent:

- **Process lifecycle and identity (Required)**: If `/sys/kernel/btf/vmlinux`
  is unavailable or any required `task_struct` / `signal_struct` member is
  missing, `btf_offsets::resolve()` returns an error and the daemon refuses to
  start. Guessing identity offsets risks misidentifying processes or conflating
  distinct process instances across PID reuse.
- **File-descriptor identity (`fd_ident`)**: If any member in the fd chain is
  unresolved, `offsets.fd_ident` is `None`. The daemon logs a warning at
  startup:
  ```text
  BTF fd identity fields unavailable: openat/mmap dev/ino validity bits remain clear
  ```
  The loader sets `FD_IDENT_SUPPORTED = 0`. In eBPF, `fd_to_dev_ino` checks
  this flag and returns a default identity with validity bits clear:
  - `openat`: reports `file_identity_status: unavailable`. Because transient
    runtime read failures also report `unavailable`, consumers cannot
    distinguish kernel-unsupported from read failure.
  - `mmap`: emits zero values (`dev: 0, ino: 0`), preserving the existing wire
    format without extra validity fields.
  - *Runtime traversal failures* (negative fd, fd out of bounds, null pointer,
    or probe read error) also fail closed. If the inode is successfully read
    but the superblock read fails, partial identity (inode valid, dev invalid)
    is reported.
- **TTY classification (`tty`)**: If any member of `tty_struct` or `tty_driver`
  is unresolved, `offsets.tty` is `None`. The daemon logs a warning at startup:
  ```text
  BTF TTY classification fields unavailable: TTY events suppressed (fail closed)
  ```
  The loader sets `TTY_SUPPORTED = 0` and the startup `ready` event reports TTY
  collectors as unavailable (`tty.write`, `tty.read`, and `tty.read_ret` set to
  `false` in `attached`). In eBPF, `is_pts_slave` returns `false` whenever
  `TTY_SUPPORTED == 0` (as well as on null pointer, probe read error, or
  non-PTY slave device). The `pty_write` and `n_tty_read` entry probes check
  `is_pts_slave` and drop the event when false. All TTY events are suppressed,
  preventing misclassification or noise.

## Why Not Typed Struct Definitions in eBPF?

Rustc does not emit CO-RE (`preserve_access_index`) relocations for eBPF
targets. Defining C struct layouts in Rust compiles to fixed byte offsets baked
for a specific kernel build. Across different kernel builds or configurations,
struct layouts drift; fixed offsets cause eBPF probes to silently read the
wrong fields.

Runtime BTF resolution inspects the running kernel's `/sys/kernel/btf/vmlinux`
directly, eliminating compile-time kernel layout definitions (`vmlinux.rs` and
hard-coded `FILES_OFFSET_IN_TASK` are completely absent).

> **Scope:** Runtime BTF resolution covers direct member offsets only, not full
> CO-RE (no type, enum, field-existence, or bitfield relocation). Read widths
> (e.g. `fdtable.max_fds` `u32`, `inode.i_ino` `u64`, `super_block.s_dev` `u32`,
> `tty_driver.type`/`subtype` `i16`) are compile-time assumptions in eBPF, not
> verified against BTF.

## How to Verify Offsets Manually

Compare the daemon's logged offsets against `pahole` on the target kernel:

```bash
# Lifecycle & filtering
pahole -C task_struct /sys/kernel/btf/vmlinux | grep -E '\b(pid|tgid|group_leader|start_boottime|signal|exit_code|comm|loginuid|sessionid|files)\b'
pahole -C signal_struct /sys/kernel/btf/vmlinux | grep -E '\b(live|group_exit_code)\b'

# File descriptor traversal & identity endpoints
pahole -C files_struct /sys/kernel/btf/vmlinux | grep fdt
pahole -C fdtable /sys/kernel/btf/vmlinux | grep -E '\b(max_fds|fd)\b'
pahole -C file /sys/kernel/btf/vmlinux | grep f_inode
pahole -C inode /sys/kernel/btf/vmlinux | grep -E '\b(i_ino|i_sb)\b'
pahole -C super_block /sys/kernel/btf/vmlinux | grep s_dev

# TTY classification
pahole -C tty_struct /sys/kernel/btf/vmlinux | grep driver
pahole -C tty_driver /sys/kernel/btf/vmlinux | grep -E '\b(type|subtype)\b'
```

> **Note:** `pahole` is provided by the `dwarves` package (`apt install dwarves`).

The byte offsets printed by `pahole` match the daemon's startup log.

## Host ≠ Target Kernel Portability

Build hosts (such as WSL2 or build containers) and target machines run
different kernels with different struct layouts:

| Field | WSL2 6.6 | 6.8.0-49 HWE | 6.8.0-117 |
|---|---|---|---|
| `tgid` | 0x974 (2420) | 0x9a4 (2468) | (shifted) |
| `loginuid` | 0xc30 (3120) | 0xc88 (3208) | 0xca0 (3232) |

Because runtime resolution queries the running kernel's BTF at startup, a single
binary artifact runs across differing kernel builds without recompilation. If
`/sys/kernel/btf/vmlinux` is absent, unparseable, or missing required lifecycle
fields, the daemon refuses to attach.

## DAC vs LSM Permission Ordering

Linux `check_kill_permission()` checks standard Unix permissions (DAC)
**before** calling the LSM `security_task_kill()` hook:

```c
// kernel/signal.c — simplified
int check_kill_permission(int sig, struct task_struct *t) {
    if (!kill_ok_by_cred(t))
        return -EPERM;          // ← DAC blocks here
    return security_task_kill(t, ...);  // ← LSM only runs if DAC allows
}
```

This means:
- testuser (uid 1000) → root daemon: DAC returns `-EPERM`, **LSM never fires**
- If testuser had `CAP_KILL`: DAC allows, **LSM would fire and block**

The LSM hook is a **secondary defense layer** — it blocks kills that bypass
DAC (e.g., via capabilities or setuid binaries). Both layers work together
to protect the daemon.
