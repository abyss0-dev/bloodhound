use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    programs::RawTracePointContext,
    EbpfContext,
};
use bloodhound_common::{CaptureStatus, EventHeader, MAX_PATH_SIZE};

use crate::maps::{DROP_COUNT, EVENTS};

/// Read a user-space path, returning its byte length (excluding NUL) and capture status.
#[inline(always)]
pub unsafe fn read_user_str(src: *const u8, buffer: &mut [u8; MAX_PATH_SIZE]) -> (u16, CaptureStatus) {
    match bpf_probe_read_user_str_bytes(src, buffer) {
        // Aya excludes NUL; a full buffer cannot certify that the source ended.
        Ok(s) => (s.len() as u16, if s.len() < MAX_PATH_SIZE - 1 {
            CaptureStatus::Complete
        } else {
            CaptureStatus::Truncated
        }),
        Err(_) => (0, CaptureStatus::ReadError),
    }
}

/// Write raw bytes to the ring buffer using output().
/// This is the correct approach for variable-length data.
#[inline(always)]
pub unsafe fn emit_event(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    match EVENTS.output(data, 0) {
        Ok(()) => true,
        Err(_) => {
            increment_drop_count();
            false
        }
    }
}

#[inline(always)]
pub unsafe fn raw_tracepoint_arg(ctx: &RawTracePointContext, index: usize) -> u64 {
    let args = ctx.as_ptr() as *const u64;
    core::ptr::read(args.add(index))
}

#[inline(always)]
pub unsafe fn emit_fixed<T>(header: &EventHeader, payload: Option<&T>) {
    let payload_size = payload.map_or(0, |_| core::mem::size_of::<T>());
    let total = EventHeader::SIZE + payload_size;
    let mut buf = [0u8; 128];
    const { assert!(EventHeader::SIZE + core::mem::size_of::<T>() <= 128); }
    core::ptr::copy_nonoverlapping(
        header as *const EventHeader as *const u8,
        buf.as_mut_ptr(),
        EventHeader::SIZE,
    );
    if let Some(payload) = payload {
        core::ptr::copy_nonoverlapping(
            payload as *const T as *const u8,
            buf.as_mut_ptr().add(EventHeader::SIZE),
            payload_size,
        );
    }
    emit_event(&buf[..total]);
}

/// Increment the per-CPU drop counter.
///
/// Uses `PerCpuArray<u64>` so each CPU writes to its own slot (no
/// cross-CPU race). Userspace reads all slots and sums them via the
/// drop-counter bridge (see `bloodhound::drop_counter`).
#[inline(always)]
pub unsafe fn increment_drop_count() {
    if let Some(ptr) = DROP_COUNT.get_ptr_mut(0) {
        *ptr = (*ptr).wrapping_add(1);
    }
}

/// Copy bytes between kernel memory regions using `bpf_probe_read_kernel` helper.
///
/// Unlike `core::ptr::copy_nonoverlapping`, this compiles to a single BPF helper
/// call instruction. `copy_nonoverlapping` with variable or large sizes gets
/// unrolled by LLVM into N individual load/store pairs, which can exceed the
/// BPF verifier's 1M instruction limit.
///
/// # BPF Verifier Constraint
///
/// Prefer this helper for large or variable-length copies between map values
/// to avoid verifier instruction growth. Reassess fixed-size copies against
/// `EventHeader::SIZE` when the header layout changes rather than assuming
/// LLVM's unrolled copy remains small.
#[inline(always)]
pub unsafe fn bpf_memcpy(dst: *mut u8, src: *const u8, len: u32) -> bool {
    if len == 0 { return true; }
    aya_ebpf::helpers::gen::bpf_probe_read_kernel(
        dst as *mut core::ffi::c_void,
        len,
        src as *const core::ffi::c_void,
    ) == 0
}
