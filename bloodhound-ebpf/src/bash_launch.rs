use crate::{
    filter::{get_task_info, should_trace},
    helpers::emit_fixed,
};
use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use bloodhound_common::{BashLaunchPayload, EventKind};

unsafe fn capture(ctx: &ProbeContext) -> Result<BashLaunchPayload, i64> {
    let command = ctx.arg::<u64>(0).ok_or(-1i64)?;
    if command == 0 {
        return Err(-1);
    }
    let command_type: i32 = bpf_probe_read_user(command as *const i32)?;
    let command_flags: u32 = bpf_probe_read_user((command + 4) as *const u32)?;
    Ok(BashLaunchPayload {
        version: 1,
        status: 1,
        phase: 1,
        _pad: 0,
        command_type,
        command_flags,
        asynchronous: ctx.arg::<u64>(1).ok_or(-1i64)? as i32,
        pipe_in: ctx.arg::<u64>(2).ok_or(-1i64)? as i32,
        pipe_out: ctx.arg::<u64>(3).ok_or(-1i64)? as i32,
    })
}

#[uprobe]
pub fn bash_command_entry(ctx: ProbeContext) -> u32 {
    unsafe {
        if !should_trace() {
            return 0;
        }
        let header = get_task_info(EventKind::BashLaunch as u8);
        let payload = capture(&ctx).unwrap_or(BashLaunchPayload {
            version: 1,
            status: 2,
            phase: 1,
            ..Default::default()
        });
        emit_fixed(&header, Some(&payload));
    }
    0
}

#[uretprobe]
pub fn bash_command_return(_ctx: RetProbeContext) -> u32 {
    unsafe {
        if !should_trace() {
            return 0;
        }
        let header = get_task_info(EventKind::BashLaunch as u8);
        let payload = BashLaunchPayload {
            version: 1,
            status: 1,
            phase: 2,
            ..Default::default()
        };
        emit_fixed(&header, Some(&payload));
    }
    0
}
