use aya_ebpf::helpers::bpf_probe_read_kernel;
use bloodhound_common::{
    NsSnapshot, NS_STATUS_COMPLETE, NS_STATUS_UNAVAILABLE, NS_STATUS_UNSUPPORTED,
    NS_UPID_SIZE_INDEX,
};

// Offsets follow NS_FIELDS in bloodhound-common.
const INUM: usize = 13;
const PID_NAMESPACE_NS: usize = 20;

#[inline(always)]
unsafe fn offset(index: usize) -> usize {
    core::ptr::read_volatile(core::ptr::addr_of!(crate::OFF_NS).cast::<u32>().add(index)) as usize
}

#[inline(always)]
unsafe fn pointer(address: usize) -> Option<usize> {
    match bpf_probe_read_kernel(address as *const usize) {
        Ok(value) if value != 0 => Some(value),
        _ => None,
    }
}

/// `ns_common.inum` of the namespace object at `ns`, whose `ns` member is
/// at NS_FIELDS index `ns_member`.
#[inline(always)]
unsafe fn inum(ns: Option<usize>, ns_member: usize) -> Option<u32> {
    let address = ns? + offset(ns_member) + offset(INUM);
    match bpf_probe_read_kernel(address as *const u32) {
        Ok(value) if value != 0 => Some(value),
        _ => None,
    }
}

#[inline(always)]
unsafe fn nsproxy_member(nsproxy: Option<usize>, member: usize) -> Option<usize> {
    pointer(nsproxy? + offset(member))
}

/// The task's own active PID namespace: `thread_pid->numbers[level].ns`.
#[inline(always)]
unsafe fn active_pid_ns(task: usize) -> Option<usize> {
    let pid = pointer(task + offset(8))?;
    let level = bpf_probe_read_kernel((pid + offset(9)) as *const u32).ok()? as usize;
    let upid = pid + offset(10) + level * offset(NS_UPID_SIZE_INDEX);
    pointer(upid + offset(11))
}

/// Read the namespace membership of `task` at the current hook moment
/// (tracer contract §2.8.1). A slot whose fields the running kernel lacks is
/// unsupported; a failed read, such as after the task released its
/// namespaces during exit, makes only that slot unavailable.
#[inline(always)]
unsafe fn put(out: &mut NsSnapshot, slot: usize, supported: u32, value: Option<u32>) {
    let (status, inum) = if supported & (1 << slot) == 0 {
        (NS_STATUS_UNSUPPORTED, 0)
    } else {
        match value {
            Some(inum) => (NS_STATUS_COMPLETE, inum),
            None => (NS_STATUS_UNAVAILABLE, 0),
        }
    };
    out.status[slot] = status;
    out.inum[slot] = inum;
}

/// Read the namespace membership of `task` at the current hook moment
/// (tracer contract §2.8.1). A slot whose fields the running kernel lacks is
/// unsupported; a failed read, such as after the task released its
/// namespaces during exit, makes only that slot unavailable.
#[inline(never)]
pub unsafe fn snapshot(task: usize, out: &mut NsSnapshot) {
    let supported = core::ptr::read_volatile(&raw const crate::NS_SUPPORTED);
    let nsproxy = if supported & 0x1f != 0 { pointer(task + offset(0)) } else { None };
    for slot in 0..5 {
        let value = if supported & (1 << slot) != 0 {
            inum(nsproxy_member(nsproxy, slot + 1), slot + 14)
        } else {
            None
        };
        put(out, slot, supported, value);
    }
    let user = if supported & (1 << 5) != 0 {
        inum(pointer(task + offset(6)).and_then(|cred| pointer(cred + offset(7))), 19)
    } else {
        None
    };
    put(out, 5, supported, user);
    let pid = if supported & (1 << 6) != 0 { inum(active_pid_ns(task), PID_NAMESPACE_NS) } else { None };
    put(out, 6, supported, pid);
    out._pad = 0;
}
