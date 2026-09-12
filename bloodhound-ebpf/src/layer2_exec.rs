use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use bloodhound_common::*;

use crate::filter::{get_task_info, should_trace};
use crate::helpers::emit_event;
use crate::maps::{ASSEMBLY_BUF, EXECVE_ENTRY_MAP, EXECVE_TMP_BUF, SCRATCH_BUF};

// ── sys_enter_execve ─────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // Tracepoint args layout for sys_enter_execve:
    // offset 16: filename pointer (u64)
    // offset 24: argv pointer (u64)
    let filename_ptr: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let argv_ptr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;

    capture_exec(EventKind::Execve, filename_ptr, argv_ptr)
}

// ── sys_exit_execve ──────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_exit_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry = match EXECVE_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => e,
        None => return Ok(0),
    };

    // sys_exit tracepoint: offset 16 = return value (i64)
    let return_code: i64 = ctx.read_at(16).map_err(|_| -1i64)?;

    let mut header = entry.header;
    let mut filename_len = (entry.filename_len as usize).min(MAX_PATH_SIZE - 1);
    let mut argv_len = (entry.argv_len as usize).min(MAX_ARGV_SIZE - 1);
    if let Some(asm) = ASSEMBLY_BUF.get_ptr_mut(0) {
        let buf = &mut (*asm).buf;
        let fixed = EventHeader::SIZE + ExecvePayload::SIZE;
        let ptr = buf.as_mut_ptr();
        if filename_len > 0 && !copy_checked(ptr.add(fixed), entry.filename_buf.as_ptr(), filename_len as u32) {
            filename_len = 0;
            header._pad[2] = 3;
        }
        let argv_offset = fixed + filename_len;
        if argv_len > 0 && !copy_checked(ptr.add(argv_offset), entry.argv_buf.as_ptr(), argv_len as u32) {
            argv_len = 0;
            header._pad[1] = 3;
        }
        let payload = ExecvePayload {
            filename_len: filename_len as u16, argv_len: argv_len as u16,
            return_code: return_code as i32,
        };
        core::ptr::copy_nonoverlapping(
            &header as *const EventHeader as *const u8, ptr, EventHeader::SIZE,
        );
        core::ptr::copy_nonoverlapping(
            &payload as *const ExecvePayload as *const u8,
            ptr.add(EventHeader::SIZE), ExecvePayload::SIZE,
        );
        let total = fixed + filename_len + argv_len;
        if total <= buf.len() { emit_event(&buf[..total]); }
    }

    let _ = EXECVE_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── sys_enter_execveat ───────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execveat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execveat(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // execveat: offset 16=dirfd, offset 24=filename, offset 32=argv
    let filename_ptr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;
    let argv_ptr: u64 = ctx.read_at(32).map_err(|_| -1i64)?;

    capture_exec(EventKind::Execveat, filename_ptr, argv_ptr)
}

#[tracepoint]
pub fn sys_exit_execveat(ctx: TracePointContext) -> u32 {
    // Reuse the same exit handler
    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── Shared execve/execveat capture (#33) ──────────────────────────────────

#[inline(always)]
unsafe fn copy_checked(dst: *mut u8, src: *const u8, len: u32) -> bool {
    aya_ebpf::helpers::gen::bpf_probe_read_kernel(
        dst as *mut core::ffi::c_void, len, src as *const core::ffi::c_void,
    ) == 0
}

unsafe fn capture_exec(kind: EventKind, filename_ptr: u64, argv_ptr: u64) -> Result<u32, i64> {
    let header = get_task_info(kind as u8);
    let (filename_len, filename_status) = read_filename(filename_ptr as *const u8);
    let (argv_len, argv_status) = read_argv(argv_ptr as *const *const u8);
    let entry = match EXECVE_TMP_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p, None => return Ok(0),
    };
    entry.header = header;
    entry.header._pad = [1, argv_status, filename_status];
    entry.filename_len = filename_len;
    entry.argv_len = argv_len;
    if filename_len > 0 {
        let copied = match SCRATCH_BUF.get_ptr(0) {
            Some(p) => copy_checked(entry.filename_buf.as_mut_ptr(), (*p).buf.as_ptr(),
                                    filename_len.min((MAX_PATH_SIZE - 1) as u16) as u32),
            None => false,
        };
        if !copied { entry.filename_len = 0; entry.header._pad[2] = 3; }
    }
    if argv_len > 0 {
        let copied = match SCRATCH_BUF.get_ptr(1) {
            Some(p) => copy_checked(entry.argv_buf.as_mut_ptr(), (*p).buf.as_ptr(),
                                    argv_len.min((MAX_ARGV_SIZE - 1) as u16) as u32),
            None => false,
        };
        if !copied { entry.argv_len = 0; entry.header._pad[1] = 3; }
    }
    let _ = EXECVE_ENTRY_MAP.insert(&bpf_get_current_pid_tgid(), entry, 0);
    Ok(0)
}

// Status: 1 complete, 2 truncated, 3 read error. Only a witnessed argv NULL
// terminator certifies completion; hitting a bound never does.
#[inline(always)]
unsafe fn read_filename(filename_ptr: *const u8) -> (u16, u8) {
    let buf = match SCRATCH_BUF.get_ptr_mut(0) {
        Some(b) => &mut (*b).buf, None => return (0, 3),
    };
    match bpf_probe_read_user_str_bytes(filename_ptr, buf) {
        Ok(s) => (s.len() as u16, if s.len() < MAX_PATH_SIZE - 1 { 1 } else { 2 }),
        Err(_) => (0, 3),
    }
}

#[inline(always)]
unsafe fn read_argv(argv_ptr: *const *const u8) -> (u16, u8) {
    if argv_ptr.is_null() { return (0, 1); }
    let buf = match SCRATCH_BUF.get_ptr_mut(1) {
        Some(b) => &mut (*b).buf, None => return (0, 3),
    };
    let tmp = match SCRATCH_BUF.get_ptr_mut(3) {
        Some(b) => &mut (*b).buf, None => return (0, 3),
    };
    const MASK: usize = MAX_ARGV_SIZE - 1;
    const MAX_SINGLE_ARG: usize = 256;
    const OFFSET_LIMIT: usize = MAX_ARGV_SIZE - MAX_SINGLE_ARG - 1;
    const MAX_ARGS: usize = 20;
    let mut offset = 0usize;
    for i in 0..MAX_ARGS {
        let arg = match bpf_probe_read_user(argv_ptr.add(i)) {
            Ok(p) => p, Err(_) => return (offset as u16, 3),
        };
        if arg.is_null() { return (offset as u16, 1); }
        let safe_offset = offset & MASK;
        if safe_offset > OFFSET_LIMIT { return (offset as u16, 2); }
        let arg_len = match bpf_probe_read_user_str_bytes(arg, tmp) {
            Ok(s) => s.len(), Err(_) => return (offset as u16, 3),
        };
        if !copy_checked(buf.as_mut_ptr().add(safe_offset), tmp.as_ptr(), MAX_SINGLE_ARG as u32) {
            return (offset as u16, 3);
        }
        if arg_len > MAX_SINGLE_ARG - 1 {
            buf[(safe_offset + MAX_SINGLE_ARG - 1) & MASK] = 0;
            return ((safe_offset + MAX_SINGLE_ARG) as u16, 2);
        }
        let len = arg_len & (MAX_SINGLE_ARG - 1);
        let separator = (safe_offset + len) & MASK;
        buf[separator] = 0;
        offset = separator + 1;
    }
    match bpf_probe_read_user(argv_ptr.add(MAX_ARGS)) {
        Ok(p) if p.is_null() => (offset as u16, 1),
        Ok(_) => (offset as u16, 2),
        Err(_) => (offset as u16, 3),
    }
}
