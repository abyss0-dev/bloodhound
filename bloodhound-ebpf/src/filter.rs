use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use bloodhound_common::{EventHeader, NsSnapshot, COMM_SIZE};

use crate::{
    DAEMON_PID, OFF_COMM, OFF_GROUP_LEADER, OFF_LOGINUID, OFF_PID, OFF_SESSIONID,
    OFF_START_BOOTTIME, OFF_TGID, TARGET_AUID,
};

#[derive(Clone, Copy, Default)]
pub struct KernelProcessRef {
    pub tgid: u32,
    pub start_boottime_ns: u64,
    pub group_leader: *const u8,
}

#[inline(always)]
pub unsafe fn process_ref_from_task(task: *const u8) -> Option<KernelProcessRef> {
    if task.is_null() {
        return None;
    }
    let leader_off = core::ptr::read_volatile(&raw const OFF_GROUP_LEADER) as usize;
    let leader_ptr = (task as usize + leader_off) as *const *const u8;
    let leader = match bpf_probe_read_kernel(leader_ptr) {
        Ok(leader) if !leader.is_null() => leader,
        _ => return None,
    };
    let tgid_off = core::ptr::read_volatile(&raw const OFF_TGID) as usize;
    let start_off = core::ptr::read_volatile(&raw const OFF_START_BOOTTIME) as usize;
    let tgid = bpf_probe_read_kernel((leader as usize + tgid_off) as *const u32).ok()?;
    let start_boottime_ns =
        bpf_probe_read_kernel((leader as usize + start_off) as *const u64).ok()?;
    if tgid == 0 || start_boottime_ns == 0 {
        return None;
    }
    Some(KernelProcessRef {
        tgid,
        start_boottime_ns,
        group_leader: leader,
    })
}

#[inline(always)]
unsafe fn task_auid(task: *const u8) -> u32 {
    if task.is_null() {
        return u32::MAX;
    }
    let off = core::ptr::read_volatile(&raw const OFF_LOGINUID) as usize;
    bpf_probe_read_kernel((task as usize + off) as *const u32).unwrap_or(u32::MAX)
}

#[inline(always)]
unsafe fn task_sessionid(task: *const u8) -> u32 {
    if task.is_null() {
        return u32::MAX;
    }
    let off = core::ptr::read_volatile(&raw const OFF_SESSIONID) as usize;
    bpf_probe_read_kernel((task as usize + off) as *const u32).unwrap_or(u32::MAX)
}

#[inline(always)]
unsafe fn task_tid(task: *const u8) -> u32 {
    if task.is_null() {
        return 0;
    }
    let off = core::ptr::read_volatile(&raw const OFF_PID) as usize;
    bpf_probe_read_kernel((task as usize + off) as *const u32).unwrap_or(0)
}

#[inline(always)]
unsafe fn task_comm(task: *const u8) -> [u8; COMM_SIZE] {
    if task.is_null() {
        return [0; COMM_SIZE];
    }
    let off = core::ptr::read_volatile(&raw const OFF_COMM) as usize;
    bpf_probe_read_kernel((task as usize + off) as *const [u8; COMM_SIZE])
        .unwrap_or([0; COMM_SIZE])
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
    task_auid(bpf_get_current_task() as *const u8)
}

/// Read sessionid from the current task's task_struct.
///
/// Same manual-CO-RE approach as `get_current_auid`: the byte offset
/// comes from the `OFF_SESSIONID` global, resolved from kernel BTF.
#[inline(always)]
pub unsafe fn get_current_sessionid() -> u32 {
    task_sessionid(bpf_get_current_task() as *const u8)
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
    let mut header: EventHeader = core::mem::zeroed();
    fill_task_info(kind, &mut header);
    header
}

/// Write current task info into `header` in place. Callers near the 512-byte
/// combined stack limit pass map memory, so the header never sits on their
/// stack frame.
#[inline(always)]
pub unsafe fn fill_task_info(kind: u8, header: &mut EventHeader) {
    header.kind = kind;
    header._pad = [0; 3];
    header.timestamp_ns = bpf_ktime_get_ns();
    header.auid = get_current_auid();
    header.sessionid = get_current_sessionid();
    let pid_tgid = bpf_get_current_pid_tgid();
    header.pid = (pid_tgid >> 32) as u32;
    // ppid is populated in userspace from /proc
    header.ppid = 0;
    header.process_start_boottime_ns = process_ref_from_task(bpf_get_current_task() as *const u8)
        .map(|process_ref| process_ref.start_boottime_ns)
        .unwrap_or(0);
    header.comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; COMM_SIZE],
    };
    header.tid = pid_tgid as u32;
    crate::ns::snapshot(bpf_get_current_task() as usize, &mut header.ns);
}

/// Populate an event header from a task supplied by a kernel hook.
#[inline(always)]
pub unsafe fn get_task_info_from_task(kind: u8, task: *const u8) -> EventHeader {
    let process_ref = process_ref_from_task(task);
    let mut header = EventHeader {
        kind,
        _pad: [0; 3],
        timestamp_ns: bpf_ktime_get_ns(),
        auid: task_auid(task),
        sessionid: task_sessionid(task),
        pid: process_ref.map(|value| value.tgid).unwrap_or(0),
        ppid: 0,
        process_start_boottime_ns: process_ref
            .map(|value| value.start_boottime_ns)
            .unwrap_or(0),
        comm: task_comm(task),
        tid: task_tid(task),
        ns: NsSnapshot::default(),
    };
    if !task.is_null() {
        crate::ns::snapshot(task as usize, &mut header.ns);
    }
    header
}
