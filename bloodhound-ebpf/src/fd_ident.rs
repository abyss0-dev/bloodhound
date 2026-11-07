//! File-descriptor identity for openat and file-backed mmap.
//! Offsets are resolved from the running kernel's BTF before program load.

use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use bloodhound_common::{DEV_VALID, INO_VALID};

/// Partial `(device, inode)` observation using the shared validity flags.
#[derive(Clone, Copy, Default)]
pub struct DevIno {
    pub dev: u64,
    pub ino: u64,
    pub valid: u8,
}

#[inline(always)]
unsafe fn read<T: Copy>(base: usize, index: usize) -> Result<T, i64> {
    let offset = core::ptr::read_volatile(
        core::ptr::addr_of!(crate::OFF_FD_IDENT).cast::<u32>().add(index),
    );
    bpf_probe_read_kernel((base + offset as usize) as *const T)
}

#[inline(always)]
unsafe fn pointer(base: usize, index: usize) -> Result<usize, i64> {
    let value: usize = read(base, index)?;
    if value == 0 { return Err(-1); }
    Ok(value)
}

#[inline(always)]
unsafe fn inode_for_fd(fd: u32) -> Result<usize, i64> {
    let task = bpf_get_current_task() as usize;
    if task == 0 { return Err(-1); }
    let files = pointer(task, 0)?;
    let fdt = pointer(files, 1)?;
    let max_fds: u32 = read(fdt, 2)?;
    if fd >= max_fds { return Err(-1); }
    let array = pointer(fdt, 3)?;
    let file: usize = bpf_probe_read_kernel((array + fd as usize * core::mem::size_of::<usize>()) as *const usize)?;
    if file == 0 { return Err(-1); }
    pointer(file, 4)
}

/// Resolve an fd without pinning a file reference. Unresolved BTF fields or
/// failed traversal leave validity bits clear; endpoint failures may be partial.
///
/// # Safety
/// Must be called in a BPF context with a valid current task.
#[inline(always)]
pub unsafe fn fd_to_dev_ino(fd: i32) -> DevIno {
    if fd < 0 || core::ptr::read_volatile(&raw const crate::FD_IDENT_SUPPORTED) == 0 {
        return DevIno::default();
    }
    let inode = match inode_for_fd(fd as u32) {
        Ok(inode) => inode,
        Err(_) => return DevIno::default(),
    };
    let (ino, ino_valid) = match read::<u64>(inode, 5) {
        Ok(value) => (value, INO_VALID),
        Err(_) => (0, 0),
    };
    let sb = match pointer(inode, 6) {
        Ok(sb) => sb,
        Err(_) => return DevIno { dev: 0, ino, valid: ino_valid },
    };
    let (dev, dev_valid) = match read::<u32>(sb, 7) {
        Ok(value) => (value as u64, DEV_VALID),
        Err(_) => (0, 0),
    };
    DevIno { dev, ino, valid: ino_valid | dev_valid }
}
