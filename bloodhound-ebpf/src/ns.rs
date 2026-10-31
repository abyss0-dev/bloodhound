use aya_ebpf::{cty::c_void, helpers::gen};
use bloodhound_common::{
    NsSnapshot, NS_STATUS_COMPLETE, NS_STATUS_UNAVAILABLE, NS_STATUS_UNSUPPORTED,
    NS_UPID_SIZE_INDEX,
};

// Offsets follow NS_FIELDS in bloodhound-common.
const INUM: usize = 13;
const PID_NAMESPACE_NS: usize = 20;

// The snapshot runs in every task-context program, so it is branch-free: a
// conditional here would fork verifier states that the caller then walks
// separately, which pushed raw_sys_enter past the 1M instruction limit.

#[inline(always)]
unsafe fn offset(index: usize) -> usize {
    core::ptr::read_volatile(core::ptr::addr_of!(crate::OFF_NS).cast::<u32>().add(index)) as usize
}

/// Read a `T` at `address`, folding a failed read into `failed`. The helper
/// zeroes the value on failure, and a zero pointer makes the next read in a
/// chain fail, so a broken chain needs no early return.
#[inline(always)]
unsafe fn read<T: Default>(address: usize, failed: &mut u64) -> T {
    let mut value = T::default();
    let result = gen::bpf_probe_read_kernel(
        (&mut value as *mut T).cast::<c_void>(),
        core::mem::size_of::<T>() as u32,
        address as *const c_void,
    );
    *failed |= result as u64;
    value
}

/// 1 when `value` is nonzero, else 0, without a branch.
#[inline(always)]
fn nonzero(value: u64) -> u64 {
    (value | value.wrapping_neg()) >> 63
}

/// `ns_common.inum` of the namespace object at `ns`, whose `ns` member is
/// at NS_FIELDS index `ns_member`.
#[inline(always)]
unsafe fn inum(ns: usize, ns_member: usize, failed: &mut u64) -> u32 {
    read(ns + offset(ns_member) + offset(INUM), failed)
}

/// The task's own active PID namespace: `thread_pid->numbers[level].ns`.
#[inline(always)]
unsafe fn active_pid_ns(task: usize, failed: &mut u64) -> usize {
    let pid: usize = read(task + offset(8), failed);
    let level: u32 = read(pid + offset(9), failed);
    let upid = pid + offset(10) + level as usize * offset(NS_UPID_SIZE_INDEX);
    read(upid + offset(11), failed)
}

/// A slot whose fields the running kernel lacks is unsupported; a failed
/// read or a zero inode makes only that slot unavailable.
#[inline(always)]
unsafe fn put(out: &mut NsSnapshot, slot: usize, supported: u32, inum: u32, failed: u64) {
    let supported = ((supported >> slot) & 1) as u64;
    let complete = supported & nonzero(inum as u64) & (nonzero(failed) ^ 1);
    let unavailable = supported & (complete ^ 1);
    // Exactly one of the three flags is 1.
    let status = complete * NS_STATUS_COMPLETE as u64
        + unavailable * NS_STATUS_UNAVAILABLE as u64
        + (supported ^ 1) * NS_STATUS_UNSUPPORTED as u64;
    out.status[slot] = status as u8;
    out.inum[slot] = inum & complete.wrapping_neg() as u32;
}

/// Read the namespace membership of `task` at the current hook moment
/// (tracer contract §2.8.1). A failed read, such as after the task released
/// its namespaces during exit, makes only the affected slots unavailable.
#[inline(never)]
pub unsafe fn snapshot(task: usize, out: &mut NsSnapshot) {
    let supported = core::ptr::read_volatile(&raw const crate::NS_SUPPORTED);
    let mut nsproxy_failed = 0;
    let nsproxy: usize = read(task + offset(0), &mut nsproxy_failed);
    for slot in 0..5 {
        let mut failed = nsproxy_failed;
        let ns: usize = read(nsproxy + offset(slot + 1), &mut failed);
        let value = inum(ns, slot + 14, &mut failed);
        put(out, slot, supported, value, failed);
    }
    let mut failed = 0;
    let cred: usize = read(task + offset(6), &mut failed);
    let user: usize = read(cred + offset(7), &mut failed);
    let value = inum(user, 19, &mut failed);
    put(out, 5, supported, value, failed);
    let mut failed = 0;
    let pid = active_pid_ns(task, &mut failed);
    let value = inum(pid, PID_NAMESPACE_NS, &mut failed);
    put(out, 6, supported, value, failed);
    out._pad = 0;
}
