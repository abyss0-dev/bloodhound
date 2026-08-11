# eBPF `task_struct` Field Access

Bloodhound resolves the kernel fields needed both to filter events and to
identify a process instance: `task_struct::{loginuid,sessionid,pid,tgid,
group_leader,start_boottime,signal,exit_code}` and
`signal_struct::{live,group_exit_code}`.

## How It Works: runtime BTF offset resolution ("manual CO-RE")

The byte offset of each field is resolved **at daemon start** from the
running kernel's own BTF, then injected into the eBPF programs as global
constants before load. This makes the daemon portable to any BTF-bearing
kernel without recompilation. See issue #37 for the failure this replaces.

The pieces:

- **Userspace** (`bloodhound::btf_offsets`): a minimal BTF reader parses
  `/sys/kernel/btf/vmlinux`, finds `task_struct` and `signal_struct`, and
  returns all required member offsets.
- **Injection** (`bloodhound::loader`): the resolved offsets are passed
  via `EbpfLoader::set_global` into the corresponding `OFF_*` globals.
- **eBPF** (`filter.rs`, `lsm_hooks.rs`): each field is read as
  `bpf_probe_read_kernel((task_base + offset))`. A variable offset is
  accepted by the verifier, unlike a typed deref that bakes a fixed
  compile-time offset.

The daemon logs the resolved offsets at startup. If BTF is unavailable or
any required field is missing, startup fails closed. Guessing an identity
offset could merge unrelated processes after PID reuse.

## Why not typed `vmlinux.rs` struct access?

The previous approach (issue #1) defined a typed `task_struct` in
`vmlinux.rs` and used `core::ptr::addr_of!` to compute the offset. Because
rustc does **not** emit `preserve_access_index` BTF relocations, that
still compiled to a fixed offset baked to the kernel `vmlinux.rs` was
generated against (`6.8.0-49-generic`). On any other kernel build the
fields had drifted, the daemon silently read the wrong bytes, and every
task-scoped event was dropped in-kernel — only `HEARTBEAT` and `PACKET`
survived. Runtime resolution sidesteps this without depending on rustc
gaining CO-RE.

> **Scope:** This covers direct member offsets only. It is not full CO-RE
> (no type / enum /
> field-existence / bitfield relocation). The nested-pointer traversal
> structs that remain in `vmlinux.rs` (TTY device class, fd → inode →
> super_block) are still compile-time fixed.

## How to Verify Offsets Manually

For debugging, compare the daemon's logged offsets against `pahole` on the
**same kernel the daemon runs on**:

```bash
pahole -C task_struct /sys/kernel/btf/vmlinux | grep -E '\b(pid|tgid|group_leader|start_boottime|signal|exit_code|loginuid|sessionid)\b'
pahole -C signal_struct /sys/kernel/btf/vmlinux | grep -E '\b(live|group_exit_code)\b'
```

> **Note:** `pahole` is provided by the `dwarves` package (`apt install dwarves`).

The byte offsets printed by `pahole` should match the daemon startup log.

## Host ≠ VM Kernel (now handled automatically)

The **build host** and the **target VM** run different kernels with
different `task_struct` layouts. Previously this required regenerating
`vmlinux.rs` per kernel; the offset drift was silent and easy to miss:

| Field  | WSL2 6.6      | 6.8.0-49 HWE  | 6.8.0-117     |
|--------|---------------|---------------|---------------|
| `tgid` | 0x974 (2420)  | 0x9a4 (2468)  | (shifted)     |
| `loginuid` | 0xc30 (3120) | 0xc88 (3208) | 0xca0 (3232) |

Runtime resolution reads whatever the running kernel reports, so no
per-kernel code change is needed. If `/sys/kernel/btf/vmlinux` is absent,
unparseable, or incomplete, the daemon refuses to attach.

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
