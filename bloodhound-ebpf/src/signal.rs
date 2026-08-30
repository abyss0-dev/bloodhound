//! Non-enforcing kernel signal observation.
//!
//! `signal_generate` runs after the kernel permission path and supplies both
//! the current sender and the target `task_struct`. Unlike `lsm/task_kill`,
//! this collector does not require BPF LSM and cannot allow or deny a signal.

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};
use bloodhound_common::{EventKind, SignalGeneratePayload};

use crate::filter::{get_task_info, process_ref_from_task, should_trace};
use crate::helpers::{emit_fixed, raw_tracepoint_arg};
use crate::OFF_TGID;

#[raw_tracepoint(tracepoint = "signal_generate")]
pub fn signal_generate(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_signal_generate(&ctx) } {
        Ok(()) | Err(_) => 0,
    }
}

unsafe fn try_signal_generate(ctx: &RawTracePointContext) -> Result<(), i64> {
    if !should_trace() {
        return Ok(());
    }

    // Kernel callback prototype:
    // (int sig, kernel_siginfo *info, task_struct *task, int group, int result)
    let signal = raw_tracepoint_arg(ctx, 0) as u32;
    let target_task = raw_tracepoint_arg(ctx, 2) as *const u8;
    if target_task.is_null() {
        return Ok(());
    }
    let group = raw_tracepoint_arg(ctx, 3) as u32;
    let result = raw_tracepoint_arg(ctx, 4) as i32;

    let target_ref = process_ref_from_task(target_task);
    let target_tgid = match target_ref {
        Some(process_ref) => process_ref.tgid,
        None => {
            let off = core::ptr::read_volatile(&raw const OFF_TGID) as usize;
            bpf_probe_read_kernel((target_task as usize + off) as *const u32).unwrap_or(0)
        }
    };
    let payload = SignalGeneratePayload {
        target_tgid,
        signal,
        target_start_boottime_ns: target_ref
            .map(|process_ref| process_ref.start_boottime_ns)
            .unwrap_or(0),
        group,
        result,
    };
    let header = get_task_info(EventKind::SignalGenerate as u8);
    emit_fixed(&header, Some(&payload));
    Ok(())
}
