//! Kernel-observed process lifecycle events.
//!
//! Raw scheduler tracepoints expose `task_struct *` arguments before the task
//! can disappear. This lets Bloodhound identify thread groups without a later
//! `/proc` lookup and emit one exit only when `signal_struct::live` reaches 0.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};
use bloodhound_common::{
    select_process_exit_status, EventKind, ProcessExitPayload, ProcessForkPayload,
};

use crate::filter::{
    get_task_info, get_task_info_from_task, process_ref_from_task, should_trace,
    KernelProcessRef,
};
use crate::helpers::{emit_fixed, raw_tracepoint_arg};
use crate::layer3_rich::pending_clone_flags;
use crate::{
    OFF_EXIT_CODE, OFF_PID, OFF_SIGNAL, OFF_SIGNAL_GROUP_EXIT_CODE, OFF_SIGNAL_LIVE,
};

#[raw_tracepoint(tracepoint = "sched_process_fork")]
pub fn sched_process_fork(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_process_fork(&ctx) } {
        Ok(()) | Err(_) => 0,
    }
}

unsafe fn try_process_fork(ctx: &RawTracePointContext) -> Result<(), i64> {
    if !should_trace() {
        return Ok(());
    }
    let parent = raw_tracepoint_arg(ctx, 0) as *const u8;
    let child = raw_tracepoint_arg(ctx, 1) as *const u8;
    if parent.is_null() || child.is_null() {
        return Ok(());
    }

    let pid_off = core::ptr::read_volatile(&raw const OFF_PID) as usize;
    let child_pid = bpf_probe_read_kernel((child as usize + pid_off) as *const u32)
        .map_err(|_| -1i64)?;
    let mut fork_header = get_task_info(EventKind::ProcessFork as u8);
    let parent_ref = process_ref_from_task(parent).unwrap_or(KernelProcessRef {
        tgid: fork_header.pid,
        start_boottime_ns: 0,
        group_leader: core::ptr::null(),
    });
    let Some(child_ref) = process_ref_from_task(child) else {
        return Ok(());
    };

    // A CLONE_THREAD child has a distinct task PID but inherits its TGID. It
    // does not create a new process instance and therefore emits no semantic
    // process_start/process_fork pair.
    if child_pid != child_ref.tgid || child_ref.start_boottime_ns == 0 {
        return Ok(());
    }

    let mut child_header = get_task_info_from_task(EventKind::ProcessStart as u8, child);
    child_header.pid = child_ref.tgid;
    child_header.ppid = parent_ref.tgid;
    child_header.process_start_boottime_ns = child_ref.start_boottime_ns;
    emit_fixed::<u8>(&child_header, None);

    fork_header.pid = parent_ref.tgid;
    fork_header.process_start_boottime_ns = parent_ref.start_boottime_ns;
    let payload = ProcessForkPayload {
        parent_tgid: parent_ref.tgid,
        child_tgid: child_ref.tgid,
        parent_start_boottime_ns: parent_ref.start_boottime_ns,
        child_start_boottime_ns: child_ref.start_boottime_ns,
        clone_flags: pending_clone_flags(),
    };
    emit_fixed(&fork_header, Some(&payload));
    Ok(())
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn sched_process_exit(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_process_exit(&ctx) } {
        Ok(()) | Err(_) => 0,
    }
}

unsafe fn try_process_exit(ctx: &RawTracePointContext) -> Result<(), i64> {
    // A task killed during openat may never reach sys_exit_openat. Release
    // its pathname before filtering or thread-group exit checks, so PID
    // reuse cannot inherit the pending invocation and the map stays bounded.
    let tid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    if crate::maps::OPENAT_ENTRY_MAP.get(&tid).is_some() {
        crate::maps::openat_failure(3);
        let _ = crate::maps::OPENAT_ENTRY_MAP.remove(&tid);
    }
    if !should_trace() {
        return Ok(());
    }
    let task = raw_tracepoint_arg(ctx, 0) as *const u8;
    if task.is_null() {
        return Ok(());
    }

    let signal_off = core::ptr::read_volatile(&raw const OFF_SIGNAL) as usize;
    let live_off = core::ptr::read_volatile(&raw const OFF_SIGNAL_LIVE) as usize;
    let signal = bpf_probe_read_kernel((task as usize + signal_off) as *const *const u8)
        .map_err(|_| -1i64)?;
    if signal.is_null() {
        return Ok(());
    }
    let live = bpf_probe_read_kernel((signal as usize + live_off) as *const i32)
        .map_err(|_| -1i64)?;
    if live != 0 {
        return Ok(());
    }

    let Some(process_ref) = process_ref_from_task(task) else {
        return Ok(());
    };
    let exit_off = core::ptr::read_volatile(&raw const OFF_EXIT_CODE) as usize;
    let leader_status = bpf_probe_read_kernel(
        (process_ref.group_leader as usize + exit_off) as *const i32,
    )
        .map_err(|_| -1i64)?;
    let group_exit_off =
        core::ptr::read_volatile(&raw const OFF_SIGNAL_GROUP_EXIT_CODE) as usize;
    let group_status = bpf_probe_read_kernel((signal as usize + group_exit_off) as *const i32)
        .map_err(|_| -1i64)?;
    let raw_status = select_process_exit_status(group_status, leader_status);

    let mut header = get_task_info(EventKind::ProcessExit as u8);
    header.pid = process_ref.tgid;
    header.process_start_boottime_ns = process_ref.start_boottime_ns;
    let payload = ProcessExitPayload { raw_status, _pad: 0 };
    emit_fixed(&header, Some(&payload));
    Ok(())
}
