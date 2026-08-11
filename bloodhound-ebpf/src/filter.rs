use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use bloodhound_common::{EventHeader, COMM_SIZE};

use crate::{
    DAEMON_PID, OFF_GROUP_LEADER, OFF_LOGINUID, OFF_SESSIONID, OFF_START_BOOTTIME,
    OFF_TGID, TARGET_AUID,
};

#[derive(Clone, Copy)]
pub struct KernelProcessRef {
    pub tgid: u32,
    pub start_boottime_ns: u64,
}

#[inline(always)]
pub unsafe fn process_ref_from_task(task: *const u8) -> KernelProcessRef {
    if task.is_null() {
        return KernelProcessRef { tgid: 0, start_boottime_ns: 0 };
    }
    let leader_off = core::ptr::read_volatile(&raw const OFF_GROUP_LEADER) as usize;
    let leader_ptr = (task as usize + leader_off) as *const *const u8;
    let leader = bpf_probe_read_kernel(leader_ptr).unwrap_or(core::ptr::null());
    let leader = if leader.is_null() { task } else { leader };
    let tgid_off = core::ptr::read_volatile(&raw const OFF_TGID) as usize;
    let start_off = core::ptr::read_volatile(&raw const OFF_START_BOOTTIME) as usize;
    KernelProcessRef {
        tgid: bpf_probe_read_kernel((leader as usize + tgid_off) as *const u32).unwrap_or(0),
        start_boottime_ns: bpf_probe_read_kernel(
            (leader as usize + start_off) as *const u64,
        )
        .unwrap_or(0),
    }
}

/// Read auid (loginuid.val) from the current task's task_struct.
///
/// # Manual CO-RE
///
/// The byte offset of `loginuid` within `task_struct` is supplied at
/// load time via the `OFF_LOGINUID` global, which userspace resolves
/// from the running kernel's BTF (see `bloodhound::btf_offsets` and
/// issue #37). The field address is computed as `task_base + offset`
/// and read with `bpf_probe_read_kernel` — a variable offset the
/// verifier accepts, unlike a typed deref that bakes a compile-time
/// offset. `loginuid` is a `kuid_t { val: u32 }`, so reading a `u32`
/// at the field offset yields `loginuid.val` directly.
#[inline(always)]
pub unsafe fn get_current_auid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let off = core::ptr::read_volatile(&raw const OFF_LOGINUID) as usize;
    let loginuid_ptr = (task as usize + off) as *const u32;
    bpf_probe_read_kernel(loginuid_ptr).unwrap_or(u32::MAX)
}

/// Read sessionid from the current task's task_struct.
///
/// Same manual-CO-RE approach as `get_current_auid`: the byte offset
/// comes from the `OFF_SESSIONID` global, resolved from kernel BTF.
#[inline(always)]
pub unsafe fn get_current_sessionid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let off = core::ptr::read_volatile(&raw const OFF_SESSIONID) as usize;
    let sessionid_ptr = (task as usize + off) as *const u32;
    bpf_probe_read_kernel(sessionid_ptr).unwrap_or(u32::MAX)
}

/// Check if the current task should be traced (matches TARGET_AUID).
#[inline(always)]
pub unsafe fn should_trace() -> bool {
    let auid = get_current_auid();
    let target = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target {
        return false;
    }
    // Don't trace ourselves
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);
    if tgid == daemon_pid {
        return false;
    }
    true
}

/// Populate an EventHeader with current task info.
#[inline(always)]
pub unsafe fn get_task_info(kind: u8) -> EventHeader {
    let timestamp_ns = bpf_ktime_get_ns();
    let auid = get_current_auid();
    let sessionid = get_current_sessionid();
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let process_ref = process_ref_from_task(bpf_get_current_task() as *const u8);

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; COMM_SIZE],
    };

    // ppid is populated in userspace from /proc
    EventHeader {
        kind,
        _pad: [0; 3],
        timestamp_ns,
        auid,
        sessionid,
        pid: tgid,
        ppid: 0,
        process_start_boottime_ns: process_ref.start_boottime_ns,
        comm,
    }
}
