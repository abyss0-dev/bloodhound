#![allow(unused)]
use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use bloodhound_common::*;

// ── Ring Buffer ──────────────────────────────────────────────────────────────

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_DEFAULT, 0);

/// Cumulative ring buffer overflow count. One slot per CPU so BPF
/// programs can increment without atomic ops or cross-CPU contention;
/// userspace reads all slots and sums them. Replaces the previous
/// `static mut DROP_COUNT: u64` global, which userspace never read
/// back — see issue #28.
#[map]
pub static DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// ── Syscall Entry Maps (enter/exit correlation) ──────────────────────────────

/// Keyed by task_struct address, which survives the de_thread() PID exchange
/// of a non-leader exec. Stores execve entry data for sys_exit correlation.
#[map]
pub static EXECVE_ENTRY_MAP: HashMap<u64, ExecveEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// Keyed by pid_tgid (u64). Stores raw syscall entry data.
#[map]
pub static SYSCALL_ENTRY_MAP: HashMap<u64, SyscallEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// Keyed by pid_tgid (u64). Stores rich syscall entry data.
#[map]
pub static RICH_ENTRY_MAP: HashMap<u64, RichSyscallEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// Own the pathname for the entire openat invocation, including CPU migration.
/// Do not retain a pointer into per-CPU scratch storage across tracepoints.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenatEntry {
    pub header: EventHeader,
    pub flags: u32,
    pub mode: u32,
    pub filename_len: u16,
    pub capture_flags: u8,
    pub dirfd: i32,
    pub filename: [u8; MAX_PATH_SIZE],
}

// Entry-owned bytes survive both CPU migration and reuse of per-CPU scratch.
#[repr(C)]
pub struct PathEntry {
    pub header: EventHeader,
    pub path1_len: u16,
    pub path2_len: u16,
    pub path1: [u8; MAX_PATH_SIZE],
    pub path2: [u8; MAX_PATH_SIZE],
}

// Preallocating ~8.3 KB per entry at 10,240 slots would reserve ~85 MB even
// when idle. These syscall tracepoints and sched_process_exit (not NMI hooks)
// can use NO_PREALLOC so value storage scales with in-flight invocations.
// Allocation under memory pressure can fail at insertion; SYSCALL_FAILURES
// accounts for that loss.
#[map]
pub static PATH_ENTRY_MAP: HashMap<u64, PathEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, BPF_F_NO_PREALLOC);

// Construct in map memory to stay below the 512-byte BPF stack limit.
#[map]
pub static PATH_TMP_BUF: PerCpuArray<PathEntry> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static OPENAT_ENTRY_MAP: HashMap<u64, OpenatEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

#[map]
pub static OPENAT_TMP_BUF: PerCpuArray<OpenatEntry> = PerCpuArray::with_max_entries(1, 0);

/// Detected loss before ring-buffer emission, distinct from DROP_COUNT.
/// Slots: entry capture, entry map update, exit capture, interrupted invocation.
#[map]
pub static OPENAT_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(OPENAT_FAILURE_REASONS.len() as u32, 0);

#[inline(always)]
pub unsafe fn openat_failure(reason: u32) {
    if let Some(counter) = OPENAT_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}

/// Detected exec loss before ring-buffer emission, indexed by the
/// `EXEC_*` reason constants in bloodhound-common.
#[map]
pub static EXEC_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(EXEC_FAILURE_REASONS.len() as u32, 0);

#[inline(always)]
pub unsafe fn exec_failure(reason: u32) {
    if let Some(counter) = EXEC_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}

/// Detected Tier-2 rich/path loss, excluding exec and openat.
#[map]
pub static SYSCALL_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(SYSCALL_FAILURE_COUNT, 0);

#[inline(always)]
pub unsafe fn syscall_failure(reason: u32) {
    if let Some(counter) = SYSCALL_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}

#[inline(always)]
pub unsafe fn syscall_save(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::save_outcome(result) {
        syscall_failure(reason);
    }
}

#[inline(always)]
pub unsafe fn syscall_cleanup(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::cleanup_outcome(result) {
        syscall_failure(reason);
    }
}

/// Detected Tier-1 raw syscall loss, using the shared syscall reason indices.
#[map]
pub static RAW_SYSCALL_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(RAW_SYSCALL_FAILURE_COUNT, 0);

#[inline(always)]
pub unsafe fn raw_syscall_failure(reason: u32) {
    if let Some(counter) = RAW_SYSCALL_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}

#[inline(always)]
pub unsafe fn raw_syscall_save(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::save_outcome(result) {
        raw_syscall_failure(reason);
    }
}

#[inline(always)]
pub unsafe fn raw_syscall_cleanup(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::cleanup_outcome(result) {
        raw_syscall_failure(reason);
    }
}

/// Correlates n_tty_read entry/return without retaining per-CPU pointers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TtyReadEntry {
    pub buf_ptr: u64,
    pub count: u64,
}

#[map]
pub static TTY_READ_ENTRY_MAP: HashMap<u64, TtyReadEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// TTY loss before ring emission. Payload read errors are event statuses;
/// ring failures belong exclusively to DROP_COUNT.
#[map]
pub static TTY_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(TTY_FAILURE_COUNT, 0);

#[inline(always)]
pub unsafe fn tty_failure(reason: u32) {
    if let Some(counter) = TTY_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}

#[inline(always)]
pub unsafe fn tty_save(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::save_outcome(result) {
        tty_failure(reason);
    }
}

#[inline(always)]
pub unsafe fn tty_cleanup(result: Result<(), i64>) {
    if let Some(reason) = syscall_collection::cleanup_outcome(result) {
        tty_failure(reason);
    }
}

/// Reclaim only recorded reads, including a missed return before task reuse.
#[inline(always)]
pub unsafe fn tty_interrupt(pid_tgid: u64) {
    if TTY_READ_ENTRY_MAP.get(&pid_tgid).is_some() {
        tty_failure(SYSCALL_INVOCATION_INTERRUPTED);
        tty_cleanup(TTY_READ_ENTRY_MAP.remove(&pid_tgid));
    }
}

// ── Per-CPU Scratch Buffers ──────────────────────────────────────────────────

/// Scratch buffer for reading variable-length data in BPF programs.
/// Slot allocation:
///   Index 0 = filename buffer (used by layer2_exec read_filename)
///   Index 1 = argv buffer (used by layer2_exec read_argv, accumulated output)
///   Index 2 = TTY data buffer (used by layer1_tty)
///   Index 3 = temp buffer for read_argv (BPF verifier workaround:
///             each arg is read into slot 3 at offset 0, then copied to slot 1
///             at a variable offset, because the verifier rejects variable-offset
///             helper calls directly into slot 1)
#[repr(C)]
pub struct ScratchBuf {
    pub buf: [u8; MAX_PATH_SIZE],
}

#[map]
pub static SCRATCH_BUF: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(4, 0);

/// Larger assembly buffer for constructing events with variable-length data.
/// Used by execve (header + payload + filename + argv can exceed 4KB).
pub const ASSEMBLY_BUF_SIZE: usize = 2 * MAX_PATH_SIZE + 256; // ~8.5 KB

#[repr(C)]
pub struct AssemblyBuf {
    pub buf: [u8; ASSEMBLY_BUF_SIZE],
}

#[map]
pub static ASSEMBLY_BUF: PerCpuArray<AssemblyBuf> = PerCpuArray::with_max_entries(1, 0);

/// Scratch buffer for constructing SyscallEntry without hitting BPF stack limit
#[map]
pub static SYSCALL_TMP_BUF: PerCpuArray<RichSyscallEntry> = PerCpuArray::with_max_entries(1, 0);

/// Scratch buffer for constructing ExecveEntry without hitting BPF stack limit
#[map]
pub static EXECVE_TMP_BUF: PerCpuArray<ExecveEntry> = PerCpuArray::with_max_entries(1, 0);

// ── Bitmaps ──────────────────────────────────────────────────────────────────

/// Exclusion bitmap: syscall NR → 1 means excluded from Tier 1
#[map]
pub static EXCLUSION_BITMAP: Array<u32> = Array::with_max_entries(BITMAP_SIZE as u32, 0);

/// Tier 2 bitmap: syscall NR → 1 means handled by Tier 2 (skip in Tier 1)
#[map]
pub static TIER2_BITMAP: Array<u32> = Array::with_max_entries(BITMAP_SIZE as u32, 0);

// ── Daemon Path (for LSM hooks) ─────────────────────────────────────────────

#[repr(C)]
pub struct DaemonPath {
    pub len: u16,
    pub path: [u8; 256],
}

#[map]
pub static DAEMON_PATH: Array<DaemonPath> = Array::with_max_entries(1, 0);

// Shared, non-LRU: eviction would let a second exiting thread claim again.
#[map]
pub static EXIT_CLAIMS: HashMap<exit_claim::ExitClaimKey, u8> =
    HashMap::with_max_entries(exit_claim::EXIT_CLAIM_CAPACITY, 0);

#[map]
pub static EXIT_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(exit_claim::EXIT_FAILURE_REASONS.len() as u32, 0);

pub unsafe fn exit_failure(reason: u32) {
    if let Some(counter) = EXIT_FAILURES.get_ptr_mut(reason) {
        *counter = (*counter).wrapping_add(1);
    }
}
