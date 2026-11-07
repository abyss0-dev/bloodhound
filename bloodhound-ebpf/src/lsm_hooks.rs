use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};
use bloodhound_common::*;

use crate::filter::{get_current_auid, get_task_info, process_ref_from_task, should_trace};
use crate::helpers::emit_fixed;
use crate::{DAEMON_PID, OFF_TGID, TARGET_AUID};

// ── lsm/task_kill ────────────────────────────────────────────────────────────
//
// Protects the daemon from being killed by the target user.
//
// # Linux Permission Model & LSM Interaction
//
// The kernel's `check_kill_permission()` checks DAC (standard Unix
// permissions) BEFORE calling the LSM `security_task_kill()` hook.
// This means:
//
//   - If testuser (uid 1000) tries to kill a root daemon:
//     DAC returns -EPERM immediately → LSM hook is NEVER invoked.
//   - If testuser has CAP_KILL (or uses a setuid binary):
//     DAC allows → LSM hook fires → we return -EPERM to block.
//
// The LSM hook is a **secondary defense** for cases that bypass DAC.
// Both layers together protect the daemon.
//
// See docs/ebpf-offsets.md for full explanation and offset verification.

#[lsm]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_task_kill(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // Read the target task_struct pointer from context.
    // LSM hook signature: security_task_kill(task_struct *p, siginfo *info, int sig, cred *cred)
    //   ctx.arg(0) = target task_struct *p
    //   ctx.arg(2) = signal number
    let target_task: *const u8 = ctx.arg(0);
    let sig: i32 = ctx.arg(2);

    // Read the target task's tgid (= userspace PID) via the runtime-resolved
    // byte offset (`OFF_TGID`, supplied by userspace from kernel BTF — see
    // issue #37). `tgid` is an `i32`; its bit pattern read as `u32` is the
    // userspace PID for the thread-group leader.
    let off = core::ptr::read_volatile(&raw const OFF_TGID) as usize;
    let tgid_ptr = (target_task as usize + off) as *const u32;
    let target_tgid: u32 = bpf_probe_read_kernel(tgid_ptr).unwrap_or(0);
    let target_start_boottime_ns = process_ref_from_task(target_task)
        .map(|process_ref| process_ref.start_boottime_ns)
        .unwrap_or(0);

    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);

    // Only block kills targeting the daemon process
    if daemon_pid != 0 && target_tgid == daemon_pid {
        let payload = LsmTaskKillPayload {
            target_pid: target_tgid,
            signal: sig as u32,
            target_start_boottime_ns,
            return_code: -1,
            _pad: 0,
        };
        emit_fixed(&get_task_info(EventKind::LsmTaskKill as u8), Some(&payload));
        Ok(-1) // -EPERM: block target user from killing daemon
    } else {
        // Allow kills to non-daemon processes, but still emit an event for observability
        let payload = LsmTaskKillPayload {
            target_pid: target_tgid,
            signal: sig as u32,
            target_start_boottime_ns,
            return_code: 0,
            _pad: 0,
        };
        emit_fixed(&get_task_info(EventKind::LsmTaskKill as u8), Some(&payload));
        Ok(0)
    }
}

// ── lsm/bpf ─────────────────────────────────────────────────────────────────

#[lsm]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf_hook(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_bpf_hook(_ctx: &LsmContext) -> Result<i32, i64> {
    if !should_trace() {
        return Ok(0); // Allow non-target user BPF operations
    }

    // Observe only. A successful hook decision does not imply that DAC or
    // another security module will permit the syscall.
    let payload = LsmBpfPayload {
        cmd: 0,
        return_code: 0,
    };
    emit_fixed(&get_task_info(EventKind::LsmBpf as u8), Some(&payload));
    Ok(0) // Never enforce a blanket BPF denial.
}

// ── lsm/ptrace_access_check ─────────────────────────────────────────────────

#[lsm]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_ptrace(ctx: &LsmContext) -> Result<i32, i64> {
    // Preserve an earlier LSM decision and inspect the actual child task.
    // /proc/P/root and namespace links also use this hook: rejecting every
    // target-AUID invocation would block ordinary filesystem investigation.
    let previous: i32 = ctx.arg(2);
    if previous != 0 {
        return Ok(previous);
    }
    if !should_trace() {
        return Ok(0); // Allow non-target user ptrace
    }

    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);
    let child: *const u8 = ctx.arg(0);
    let tgid_offset = core::ptr::read_volatile(&raw const crate::OFF_TGID) as usize;
    let target_pid = aya_ebpf::helpers::bpf_probe_read_kernel(
        child.add(tgid_offset) as *const u32,
    ).map_err(|_| -1i64)?;
    if target_pid != daemon_pid {
        return Ok(0);
    }
    let payload = LsmPtracePayload {
        target_pid: daemon_pid,
        return_code: -1,
    };
    emit_fixed(&get_task_info(EventKind::LsmPtraceAccessCheck as u8), Some(&payload));
    Ok(-1) // Block target user ptrace on daemon
}

// ── lsm/file_open ───────────────────────────────────────────────────────────

#[lsm]
pub fn file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_file_open(_ctx: &LsmContext) -> Result<i32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    let payload = LsmFileOpenPayload {
        path_len: 0,
        _pad: [0; 2],
        return_code: 0,
    };
    emit_fixed(&get_task_info(EventKind::LsmFileOpen as u8), Some(&payload));
    Ok(0)
}

// ── lsm/inode_unlink ─────────────────────────────────────────────────────────

#[lsm]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    match unsafe { try_inode_op(&ctx, EventKind::LsmInodeUnlink as u8) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_inode_op(_ctx: &LsmContext, kind: u8) -> Result<i32, i64> {
    if !should_trace() {
        return Ok(0);
    }
    let payload = LsmInodePayload {
        path_len: 0,
        _pad: [0; 2],
        return_code: 0,
    };
    emit_fixed(&get_task_info(kind), Some(&payload));
    Ok(0)
}

// ── lsm/inode_rename ─────────────────────────────────────────────────────────

#[lsm]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    match unsafe { try_inode_rename(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_inode_rename(_ctx: &LsmContext) -> Result<i32, i64> {
    if !should_trace() {
        return Ok(0);
    }
    let payload = LsmInodeRenamePayload {
        old_path_len: 0,
        new_path_len: 0,
        return_code: 0,
    };
    emit_fixed(&get_task_info(EventKind::LsmInodeRename as u8), Some(&payload));
    Ok(0)
}

// ── lsm/task_fix_setuid ─────────────────────────────────────────────────────

#[lsm]
pub fn task_fix_setuid(ctx: LsmContext) -> i32 {
    match unsafe { try_setuid(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_setuid(_ctx: &LsmContext) -> Result<i32, i64> {
    // Keep daemon credential transitions observable when its AUID matches the target.
    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0);
    }
    let payload = LsmSetuidPayload {
        old_uid: 0,
        new_uid: 0,
        old_gid: 0,
        new_gid: 0,
        return_code: 0,
    };
    emit_fixed(&get_task_info(EventKind::LsmTaskFixSetuid as u8), Some(&payload));
    Ok(0)
}
