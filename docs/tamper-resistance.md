# Tamper Resistance

Defense is implemented in two complementary layers: capability restriction
(primary) and BPF LSM hooks (secondary, defense in depth).


## Capability Restriction (Primary Defense)

The target user has root UID but restricted Linux capabilities. This is
the primary defense mechanism.

| Capability to DROP   | Effect                                         |
|----------------------|------------------------------------------------|
| CAP_BPF              | Cannot load BPF programs                       |
| CAP_PERFMON          | Cannot attach BPF to perf events               |
| CAP_SYS_PTRACE       | Cannot ptrace the daemon                       |
| CAP_SYS_BOOT         | Cannot reboot to bypass monitoring             |
| CAP_SYS_ADMIN        | Broad restriction on privileged operations     |
| CAP_SYS_TIME         | Cannot change system clock (protects timestamps)|
| CAP_SYS_MODULE       | Cannot load kernel modules (protects BPF hooks)|

DECIDED: The above list is the recommended set. [ACCEPTANCE] Actual
enforcement is the operator's responsibility during VM provisioning.
Some deployment contexts may need capabilities that conflict with
tamper resistance (e.g., CAP_NET_RAW for network exercises).


## BPF LSM Hooks (Optional Defense in Depth)

BPF LSM hooks are optional and disabled by default (`--enable-lsm`). When disabled,
default Bloodhound collection is strictly non-enforcing.

When opted in via `--enable-lsm`, BPF LSM hooks provide defense in depth and tamper
observability. Each hook is attempted independently and reported in `args.attached`:
- **Defense:** Enforcing hooks block the operation (returning -1 / `-EPERM`).
- **Observation:** Hooks emit BehaviorEvents with `event.type = "LSM"` and `event.layer = "behavior"`.
  The attempt and outcome are recorded in `args` and `return_code`.

> [!NOTE]
> **DAC vs. LSM Distinction**: In Linux, standard Discretionary Access Control (DAC)
> checks precede LSM hooks. For example, an unprivileged user attempting to kill or
> ptrace the root daemon process will be denied by DAC before the request reaches the
> LSM hook. LSM hooks only execute if DAC allows the operation to proceed (or if the
> caller has sufficient capabilities, such as `CAP_SYS_PTRACE`). An observed hook
> decision is not a guarantee that DAC or another security module permits the syscall.

**Hooks and Semantics:**
- `lsm/task_kill` (`lsm.task_kill`) — blocks signals (`SIGKILL`, `SIGSTOP`, `SIGTERM`, etc.)
  targeting the daemon PID (returns -1 / `-EPERM`, emits `return_code = -1`). Non-daemon
  signals are allowed and emitted with `return_code = 0`.
- `lsm/ptrace_access_check` (`lsm.ptrace_access_check`) — blocks ptrace attachment
  targeting the daemon PID (returns -1 / `-EPERM`, emits `return_code = -1`).
- `lsm/bpf` (`lsm.bpf`) — observe-only: records target user BPF operations with `return_code = 0`
  and always returns 0 (never enforces a blanket denial).
- `lsm/file_open` (`lsm.file_open`) — records target user file opens with `return_code = 0` (returns 0).
- `lsm/inode_unlink` (`lsm.inode_unlink`) — records target user file unlinks with `return_code = 0` (returns 0).
- `lsm/inode_rename` (`lsm.inode_rename`) — records target user file renames with `return_code = 0` (returns 0).
- `lsm/task_fix_setuid` (`lsm.task_fix_setuid`) — records target user setuid/setgid transitions with `return_code = 0` (returns 0).


## Daemon Identification Strategy

DECIDED: Two-layer identification for LSM hook whitelisting.

1. **Primary (fast):** Daemon PID stored in a BPF global variable at
   startup. All LSM hooks first check `bpf_get_current_pid_tgid()`
   against the stored PID for fast-path filtering.

2. **Secondary (robust):** LSM hooks that support `bpf_d_path()` (e.g.,
   `file_open`, `inode_unlink`) additionally verify the target binary
   path. This guards against PID recycling: if the daemon crashes and
   the PID is reused by another process, path verification prevents
   the impersonator from being whitelisted.

The daemon PID global variable is updated on restart (systemd
`Restart=always`). During the brief window between crash and restart,
no daemon PID is active and LSM hooks block all matching operations.
