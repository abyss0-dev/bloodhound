use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use bloodhound_common::ExecEntryNetworkContextPayload;

unsafe fn offset(index: usize) -> usize {
    core::ptr::read_volatile(
        core::ptr::addr_of!(crate::OFF_EXEC_NETNS)
            .cast::<u32>()
            .add(index),
    ) as usize
}
unsafe fn read<T: Copy>(base: usize, index: usize) -> Result<T, i64> {
    bpf_probe_read_kernel((base + offset(index)) as *const T)
}
unsafe fn pointer(base: usize, index: usize) -> Result<usize, i64> {
    let ptr: usize = read(base, index)?;
    if ptr == 0 {
        Err(-1)
    } else {
        Ok(ptr)
    }
}

/// Capture current task's net namespace identity at exec entry. The device is
/// startup-calibrated from a verified nsfs descriptor; the inode is task-local.
pub unsafe fn capture() -> ExecEntryNetworkContextPayload {
    let unavailable = ExecEntryNetworkContextPayload {
        status: 2,
        ..Default::default()
    };
    let changed = ExecEntryNetworkContextPayload {
        status: 3,
        ..Default::default()
    };
    if core::ptr::read_volatile(&raw const crate::EXEC_NETNS_SUPPORTED) == 0
        || core::ptr::read_volatile(&raw const crate::NSFS_DEVICE_VALID) == 0
    {
        return unavailable;
    }
    let task = bpf_get_current_task() as usize;
    let nsproxy = match pointer(task, 0) {
        Ok(v) => v,
        Err(_) => return unavailable,
    };
    let net = match pointer(nsproxy, 1) {
        Ok(v) => v,
        Err(_) => return unavailable,
    };
    // `net::ns` is an embedded ns_common, not a pointer.
    let ns = net + offset(2);
    let inode = match read::<u32>(ns, 3) {
        Ok(v) if v != 0 => v as u64,
        _ => return unavailable,
    };
    let inode_recheck = match read::<u32>(ns, 3) {
        Ok(value) if value != 0 => value as u64,
        _ => return unavailable,
    };
    if pointer(task, 0) != Ok(nsproxy)
        || pointer(nsproxy, 1) != Ok(net)
        || inode_recheck != inode
    {
        return changed;
    }
    ExecEntryNetworkContextPayload {
        device: core::ptr::read_volatile(&raw const crate::NSFS_DEVICE),
        inode,
        status: 1,
        _pad: [0; 7],
    }
}
