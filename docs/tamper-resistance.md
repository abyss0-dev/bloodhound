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

The daemon is identified solely by its PID (`DAEMON_PID`), stored in a BPF global
variable at startup. LSM hooks check `bpf_get_current_pid_tgid()` against this
stored PID for filtering and self-protection.

Secondary verification via binary path (such as `bpf_d_path`) is intentionally
not implemented (deliberate absence); the daemon is identified exclusively by PID.
Consequently, PID reuse following a crash before restart is a known limitation.

When the daemon is down or uninitialized (`DAEMON_PID == 0`), no process matches
the daemon PID. LSM hooks do not deny operations in this state: enforcing hooks
(`task_kill` and `ptrace_access_check`) allow matching operations with return
code 0 rather than blocking them.
