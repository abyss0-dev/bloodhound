use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use bloodhound_common::{EventHeader, EventKind, ExecStdioPayload};

unsafe fn offset(index: usize) -> usize {
    core::ptr::read_volatile(
        core::ptr::addr_of!(crate::OFF_EXEC_STDIO)
            .cast::<u32>()
            .add(index),
    ) as usize
}
pub(crate) unsafe fn read<T: Copy>(base: usize, index: usize) -> Result<T, i64> {
    bpf_probe_read_kernel((base + offset(index)) as *const T)
}
pub(crate) unsafe fn pointer(base: usize, index: usize) -> Result<usize, i64> {
    let value: usize = read(base, index)?;
    if value == 0 {
        return Err(-1);
    }
    Ok(value)
}
pub(crate) unsafe fn descriptor(table: usize, fd: usize) -> Result<usize, i64> {
    bpf_probe_read_kernel((table + fd * core::mem::size_of::<usize>()) as *const usize)
}
pub(crate) unsafe fn kind(file: usize) -> Result<u8, i64> {
    if file == 0 {
        return Ok(1);
    } // closed is an explicit observation
    let inode = pointer(file, 4)?;
    let mode: u16 = read(inode, 5)?;
    Ok(match mode & 0xf000 {
        0x8000 => 2,
        0x4000 => 3,
        0x2000 => 4,
        0x6000 => 5,
        0x1000 => 6,
        0xc000 => 7,
        _ => 8,
    })
}

unsafe fn capture() -> Result<ExecStdioPayload, i64> {
    let task = bpf_get_current_task() as usize;
    let files = pointer(task, 0)?;
    let fdt = pointer(files, 1)?;
    let max: u32 = read(fdt, 2)?;
    if max < 2 {
        return Err(-1);
    }
    let table = pointer(fdt, 3)?;
    let stdin = descriptor(table, 0)?;
    let stdout = descriptor(table, 1)?;
    let mut payload = ExecStdioPayload {
        version: 1,
        status: 1,
        stdin_kind: kind(stdin)?,
        stdout_kind: kind(stdout)?,
        _pad: [0; 4],
    };
    if pointer(task, 0)? != files
        || pointer(files, 1)? != fdt
        || pointer(fdt, 3)? != table
        || descriptor(table, 0)? != stdin
        || descriptor(table, 1)? != stdout
    {
        payload.status = 3;
        payload.stdin_kind = 0;
        payload.stdout_kind = 0;
    }
    Ok(payload)
}

pub unsafe fn emit(exec_header: &EventHeader) {
    let mut header = *exec_header;
    header.kind = EventKind::ExecStdio as u8;
    header._pad = [0; 3];
    let payload = if core::ptr::read_volatile(&raw const crate::EXEC_STDIO_SUPPORTED) == 0 {
        ExecStdioPayload {
            version: 1,
            status: 0,
            ..Default::default()
        }
    } else {
        capture().unwrap_or(ExecStdioPayload {
            version: 1,
            status: 2,
            ..Default::default()
        })
    };
    crate::helpers::emit_fixed(&header, Some(&payload));
}
