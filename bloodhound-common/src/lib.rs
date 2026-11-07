#![no_std]

pub mod exit_claim;
pub mod syscall_collection;

// ── Constants ────────────────────────────────────────────────────────────────

pub const MAX_ARGV_SIZE: usize = 4096;
pub const MAX_PATH_SIZE: usize = 4096;
pub const MAX_TTY_DATA: usize = 4096;
pub const RING_BUFFER_DEFAULT: u32 = 4 * 1024 * 1024; // 4 MB
pub const COMM_SIZE: usize = 16;
pub const SYSCALL_ENTRY_MAP_SIZE: u32 = 10240;
pub const SOCKET_TABLE_SIZE: u32 = 4096;

/// Exec collection loss reasons. Indices into the BPF `EXEC_FAILURES`
/// counters; names are the `reason_code` of `DIAGNOSTIC/exec.collection`.
pub const EXEC_ENTRY_CAPTURE_FAILED: u32 = 0;
pub const EXEC_ENTRY_SAVE_FAILED: u32 = 1;
pub const EXEC_EXIT_CAPTURE_FAILED: u32 = 2;
pub const EXEC_INVOCATION_INTERRUPTED: u32 = 3;
pub const EXEC_ENTRY_CLEANUP_FAILED: u32 = 4;
pub const EXEC_FAILURE_REASONS: [&str; 5] = [
    "entry_capture_failed",
    "entry_save_failed",
    "exit_capture_failed",
    "invocation_interrupted",
    "entry_cleanup_failed",
];

/// Tier-2 rich/path collection loss counters in the BPF `SYSCALL_FAILURES`
/// map, excluding openat and execve/execveat (which own separate scopes).
pub const SYSCALL_ENTRY_CAPTURE_FAILED: u32 = 0;
pub const SYSCALL_ENTRY_SAVE_FAILED: u32 = 1;
pub const SYSCALL_EXIT_CAPTURE_FAILED: u32 = 2;
pub const SYSCALL_INVOCATION_INTERRUPTED: u32 = 3;
pub const SYSCALL_ENTRY_CLEANUP_FAILED: u32 = 4;
pub const SYSCALL_FAILURE_REASONS: [&str; 5] = [
    "entry_capture_failed",
    "entry_save_failed",
    "exit_capture_failed",
    "invocation_interrupted",
    "entry_cleanup_failed",
];
pub const SYSCALL_FAILURE_COUNT: u32 = SYSCALL_FAILURE_REASONS.len() as u32;

/// Tier-1 raw capture has the same reachable failures and uses the shared
/// `SYSCALL_*` reason indices and syscall_collection outcome policies.
/// Counters remain separate from Tier-2 capture.
pub const RAW_SYSCALL_FAILURE_REASONS: [&str; 5] = SYSCALL_FAILURE_REASONS;
pub const RAW_SYSCALL_FAILURE_COUNT: u32 = RAW_SYSCALL_FAILURE_REASONS.len() as u32;

pub const OPENAT_ENTRY_CAPTURE_FAILED: u32 = 0;
pub const OPENAT_ENTRY_SAVE_FAILED: u32 = 1;
pub const OPENAT_EXIT_CAPTURE_FAILED: u32 = 2;
pub const OPENAT_INVOCATION_INTERRUPTED: u32 = 3;
pub const OPENAT_FAILURE_REASONS: [&str; 4] = [
    "entry_capture_failed",
    "entry_save_failed",
    "exit_capture_failed",
    "invocation_interrupted",
];

pub const DEV_VALID: u8 = 1;
pub const INO_VALID: u8 = 2;
pub const PATH_COMPLETE: u8 = 4;
pub const PATH_READ_FAILED: u8 = 8;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStatus {
    Complete = 1,
    Truncated = 2,
    ReadError = 3,
}

impl TryFrom<u8> for CaptureStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            v if v == Self::Complete as u8 => Ok(Self::Complete),
            v if v == Self::Truncated as u8 => Ok(Self::Truncated),
            v if v == Self::ReadError as u8 => Ok(Self::ReadError),
            _ => Err(()),
        }
    }
}

/// Version 1 uses primary/secondary for exec argv/filename or path1/path2 status.
/// Single-path events use primary and leave secondary zero. Version 0 is unknown.
/// Raw bytes allow legacy versions and untrusted wire values to be validated
/// before conversion to `CaptureStatus`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HeaderCapture {
    pub version: u8,
    pub primary: u8,
    pub secondary: u8,
}

// ── EventKind ────────────────────────────────────────────────────────────────

macro_rules! event_kinds {
    ($( $(#[$attr:meta])* $variant:ident = $wire:literal, )*) => {
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum EventKind {
            $( $(#[$attr])* $variant = $wire, )*
        }

        impl EventKind {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            pub fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $($wire => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

event_kinds! {
    // Layer 1: Intent (TTY)
    TtyRead = 0,
    TtyWrite = 1,

    // Layer 2: Tooling (Execution)
    Execve = 2,
    Execveat = 3,

    // Layer 3 Tier 1: Raw syscall
    RawSyscall = 10,

    // Layer 3 Tier 2: Rich extraction
    Openat = 20,
    Read = 21,
    Write = 22,
    Connect = 23,
    Bind = 24,
    Listen = 25,
    Socket = 26,
    Clone = 27,
    Clone3 = 28,
    Chdir = 29,
    Fchdir = 30,
    Unlink = 31,
    Unlinkat = 32,
    Rename = 33,
    Renameat2 = 34,
    Mkdir = 35,
    Mkdirat = 36,
    Rmdir = 37,
    Symlink = 38,
    Symlinkat = 39,
    Link = 40,
    Linkat = 41,
    Chmod = 42,
    Fchmod = 43,
    Fchmodat = 44,
    Chown = 45,
    Fchown = 46,
    Fchownat = 47,
    Truncate = 48,
    Ftruncate = 49,
    Mount = 50,
    Umount2 = 51,
    Sendto = 52,
    Recvfrom = 53,
    Dup = 54,
    Dup2 = 55,
    Dup3 = 56,
    Fcntl = 57,
    Pread64 = 58,
    Pwrite64 = 59,
    Readv = 60,
    Writev = 61,
    Mmap = 62,
    Sendfile = 63,
    Splice = 64,

    // Reserved forever: historical offline packet decode only (Phase 2 retirement).
    // Keep these decodable variants, not RESERVED unknown IDs, for legacy records.
    PacketIngress = 100,
    PacketEgress = 101,

    // LSM hooks
    LsmFileOpen = 200,
    LsmTaskKill = 201,
    LsmBpf = 202,
    LsmPtraceAccessCheck = 203,
    LsmInodeUnlink = 204,
    LsmInodeRename = 205,
    LsmTaskFixSetuid = 206,

    // Kernel-observed process lifecycle
    ProcessStart = 220,
    ProcessFork = 221,
    ProcessExit = 222,
    SignalGenerate = 223,
    ExecView = 224,

    // Trusted in-tree USDT collectors. Their payload layouts are collector
    // owned; VM configuration can only select the already compiled program.
    UsdtTrainingShellV3 = 240,
    UsdtTrainingPeerV1 = 241,
    /// A collector-owned capture failure. Userspace renders it as the
    /// canonical `DIAGNOSTIC/usdt.collector` event rather than a partial USDT
    /// semantic event.
    UsdtTrainingShellV3CaptureError = 242,
}

impl EventKind {
    /// Retired wire IDs that must stay unknown and must never be reused.
    pub const RESERVED: &'static [u8] = &[
        // Reserved: 225 (removed exec stdio), 226 (removed fork-file scan),
        // 227 (removed Bash internal-function probes). Never reuse these wire IDs.
        225, 226, 227,
    ];
}

// ── Event Headers ────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    pub kind: u8,
    pub capture: HeaderCapture,
    pub timestamp_ns: u64,
    pub auid: u32,
    pub sessionid: u32,
    pub pid: u32,
    pub ppid: u32,
    /// Boot-clock start time of the thread-group leader. Together with
    /// `pid` (the TGID), this identifies one process instance across PID reuse.
    pub process_start_boottime_ns: u64,
    pub comm: [u8; COMM_SIZE],
    /// Thread ID of the task this header describes. Zero means the record
    /// has no task context, and `ns` is then not reported.
    pub tid: u32,
    /// Namespaces of that task at `timestamp_ns` (tracer contract §2.8.1).
    pub ns: NsSnapshot,
}

impl EventHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub data_len: u32,
}

impl PacketEventHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── Event Payloads ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecvePayload {
    pub filename_len: u16,
    pub argv_len: u16,
    pub return_code: i32,
    // Followed by: filename bytes (filename_len), then argv bytes (argv_len)
    // argv is null-separated
}

impl ExecvePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawSyscallPayload {
    pub syscall_nr: u64,
    pub args: [u64; 6],
    pub return_code: i64,
}

impl RawSyscallPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TtyPayload {
    pub data_len: u16,
    pub _pad: [u8; 2],
    // Followed by: data bytes (data_len)
}

/// Fixed prefix emitted by the `training-shell-v3` USDT collector.
///
/// The bounded UTF-8 command name follows this prefix. No pointer value is
/// copied into the ring buffer and no field may exceed `command_name_len`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UsdtTrainingShellPayload {
    pub attach_point_id: u32,
    pub shell_pid: u32,
    pub command_id: u64,
    pub command_kind: u32,
    pub semantic_flags: u32,
    pub exit_status: i32,
    pub command_name_len: u16,
    pub command_name_truncated: u8,
    pub _pad: u8,
}

impl UsdtTrainingShellPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Fixed error payload for a required `training-shell-v3` argument that could
/// not be read safely. The raw pointer and any surrounding process memory are
/// deliberately not included.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UsdtTrainingShellCaptureErrorPayload {
    pub attach_point_id: u32,
    pub field_id: u8,
    pub read_error_code: u8,
    pub _pad: [u8; 2],
}

impl UsdtTrainingShellCaptureErrorPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Fixed payload emitted by the independent `training-peer-v1` collector.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UsdtTrainingPeerPayload {
    pub attach_point_id: u32,
    pub _pad: u32,
    pub task_id: u64,
    pub result: u32,
    pub _pad2: u32,
}

impl UsdtTrainingPeerPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl TtyPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── Tier 2 Rich Payloads ─────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpenatPayload {
    pub flags: u32,
    pub mode: u32,
    pub filename_len: u16,
    pub capture_version: u8,
    /// Capture flags: [`DEV_VALID`], [`INO_VALID`], [`PATH_COMPLETE`], [`PATH_READ_FAILED`].
    pub capture_flags: u8,
    pub return_code: i32,
    pub dirfd: i32,
    /// Device of the underlying inode (kernel `s_dev`, major << 20 | minor).
    /// Valid only when capture_version == 1 and [`DEV_VALID`] is set in capture_flags.
    pub dev: u64,
    /// Inode number; valid only when capture_version == 1 and [`INO_VALID`] is set in capture_flags.
    pub ino: u64,
    // Followed by: filename bytes
}

impl OpenatPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadWritePayload {
    pub fd: u32,
    pub fd_type: u8,
    pub _pad: [u8; 3],
    pub requested_size: u64,
    pub return_code: i64,
}

impl ReadWritePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// fd_type constants
pub const FD_TYPE_REGULAR: u8 = 0;
pub const FD_TYPE_PIPE: u8 = 1;
pub const FD_TYPE_SOCKET: u8 = 2;
pub const FD_TYPE_TTY: u8 = 3;
pub const FD_TYPE_OTHER: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectBindPayload {
    pub family: u16,
    pub port: u16,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
    pub return_code: i32,
}

impl ConnectBindPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketPayload {
    pub domain: u32,
    pub sock_type: u32,
    pub protocol: u32,
    pub return_code: i32,
}

impl SocketPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ClonePayload {
    pub flags: u64,
    pub return_code: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessForkPayload {
    pub parent_tgid: u32,
    pub child_tgid: u32,
    pub parent_start_boottime_ns: u64,
    pub child_start_boottime_ns: u64,
    pub clone_flags: u64,
}

impl ProcessForkPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitPayload {
    /// Linux wait status captured from the exiting thread group.
    pub raw_status: i32,
    pub _pad: u32,
}

impl ProcessExitPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for the non-enforcing `signal_generate` kernel tracepoint.
/// The event header identifies the sender; these fields identify the target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SignalGeneratePayload {
    pub target_tgid: u32,
    pub signal: u32,
    pub target_start_boottime_ns: u64,
    pub group: u32,
    pub result: i32,
}

impl SignalGeneratePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

pub const SIGNAL_RESULT_DELIVERED: i32 = 0;
pub const SIGNAL_RESULT_IGNORED: i32 = 1;
pub const SIGNAL_RESULT_ALREADY_PENDING: i32 = 2;
pub const SIGNAL_RESULT_OVERFLOW_FAIL: i32 = 3;
pub const SIGNAL_RESULT_LOSE_INFO: i32 = 4;

/// Select the wait status for a whole-process exit. `group_exit_status` is
/// authoritative for exit_group/fatal-signal teardown; otherwise Linux
/// reports the thread-group leader's status even if another thread exits last.
#[inline(always)]
pub const fn select_process_exit_status(
    group_exit_status: i32,
    group_leader_status: i32,
) -> i32 {
    if group_exit_status != 0 {
        group_exit_status
    } else {
        group_leader_status
    }
}

impl ClonePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathPayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes (path_len)
}

impl PathPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TwoPathPayload {
    pub path1_len: u16,
    pub path2_len: u16,
    pub return_code: i32,
    // Followed by: path1 bytes, then path2 bytes
}

impl TwoPathPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChmodPayload {
    pub mode: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes (path_len)
}

impl ChmodPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FchmodPayload {
    pub fd: u32,
    pub mode: u32,
    pub return_code: i32,
}

impl FchmodPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChownPayload {
    pub uid: u32,
    pub gid: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl ChownPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FchownPayload {
    pub fd: u32,
    pub uid: u32,
    pub gid: u32,
    pub return_code: i32,
}

impl FchownPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TruncatePayload {
    pub length: u64,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl TruncatePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FtruncatePayload {
    pub fd: u32,
    pub _pad2: [u8; 4],
    pub length: u64,
    pub return_code: i64,
}

impl FtruncatePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MountPayload {
    pub source_len: u16,
    pub target_len: u16,
    pub fstype_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    pub _pad2: [u8; 4],
    // Followed by: source, target, fstype bytes
}

impl MountPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SendtoRecvfromPayload {
    pub fd: u32,
    pub family: u16,
    pub port: u16,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
    pub size: u64,
    pub return_code: i64,
}

impl SendtoRecvfromPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdPayload {
    pub fd: u32,
    pub return_code: i32,
}

impl FdPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListenPayload {
    pub fd: u32,
    pub backlog: u32,
    pub return_code: i32,
}

impl ListenPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Umount2Payload {
    pub flags: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl Umount2Payload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── New Tier 2 Payloads (dup/fcntl, pread/pwrite, readv/writev, mmap, sendfile/splice) ─

/// Payload for `dup`, `dup2`, `dup3`, and `fcntl(F_DUPFD*)` events.
///
/// `oldfd` is the source fd from `args[0]`. `newfd` is the destination fd
/// from the syscall return value (negative on error). `cloexec` reflects
/// whether the new fd has FD_CLOEXEC set: true for `dup3` with `O_CLOEXEC`
/// and for `fcntl(F_DUPFD_CLOEXEC)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DupPayload {
    pub oldfd: u32,
    pub newfd: i32,
    pub cloexec: u8,
    pub _pad: [u8; 3],
    pub return_code: i64,
}

impl DupPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `pread64` and `pwrite64` events.
///
/// Mirrors `ReadWritePayload` plus the explicit `offset` argument.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PreadPwritePayload {
    pub fd: u32,
    pub fd_type: u8,
    pub _pad: [u8; 3],
    pub requested_size: u64,
    pub offset: i64,
    pub return_code: i64,
}

impl PreadPwritePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `readv` and `writev` events.
///
/// `requested_size` is the sum of `iov_len` across the first
/// `MAX_IOV_TRAVERSE` iov entries. If `iov_count > MAX_IOV_TRAVERSE`,
/// `iov_truncated` is 1 and `requested_size` underestimates the true total.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadvWritevPayload {
    pub fd: u32,
    pub fd_type: u8,
    pub iov_truncated: u8,
    pub _pad: [u8; 2],
    pub iov_count: u32,
    pub _pad2: [u8; 4],
    pub requested_size: u64,
    pub return_code: i64,
}

impl ReadvWritevPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Maximum number of `iovec` entries traversed in BPF for `readv`/`writev`.
///
/// This bound exists for the BPF verifier: each iov entry costs one
/// `bpf_probe_read_user` call, and the verifier rejects unbounded loops.
/// Eight covers the overwhelming majority of real-world vectored I/O.
pub const MAX_IOV_TRAVERSE: u32 = 8;

/// Payload for `mmap` events (file-backed only).
///
/// Anonymous mappings are filtered in BPF and never reach userspace.
/// `dev` and `ino` identify the underlying file via the same fd-table
/// traversal used by `openat`. They are zero when identity resolution
/// failed or the file backing was not resolvable.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MmapPayload {
    pub fd: i32,
    pub prot: u32,
    pub flags: u32,
    pub _pad: [u8; 4],
    pub length: u64,
    pub offset: u64,
    pub dev: u64,
    pub ino: u64,
    pub return_code: i64,
}

impl MmapPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `sendfile` and `splice` events (opt-in).
///
/// Both syscalls move data between two fds; this payload surfaces both
/// fds and their classified types alongside the requested and actual
/// transferred byte counts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SendfileSplicePayload {
    pub in_fd: u32,
    pub out_fd: u32,
    pub in_fd_type: u8,
    pub out_fd_type: u8,
    pub _pad: [u8; 6],
    pub size: u64,
    pub return_code: i64,
}

impl SendfileSplicePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── LSM Payloads ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmFileOpenPayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl LsmFileOpenPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmTaskKillPayload {
    pub target_pid: u32,
    pub signal: u32,
    pub target_start_boottime_ns: u64,
    pub return_code: i32,
    pub _pad: u32,
}

impl LsmTaskKillPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmBpfPayload {
    pub cmd: u32,
    pub return_code: i32,
}

impl LsmBpfPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmPtracePayload {
    pub target_pid: u32,
    pub return_code: i32,
}

impl LsmPtracePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmInodePayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl LsmInodePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmInodeRenamePayload {
    pub old_path_len: u16,
    pub new_path_len: u16,
    pub return_code: i32,
    // Followed by: old_path, new_path bytes
}

impl LsmInodeRenamePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmSetuidPayload {
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_gid: u32,
    pub new_gid: u32,
    pub return_code: i32,
}

impl LsmSetuidPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── BPF Entry Map Structs (for enter/exit correlation) ───────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEntry {
    pub header: EventHeader,
    pub filename_len: u16,
    pub argv_len: u16,
    pub filename_buf: [u8; MAX_PATH_SIZE],
    pub argv_buf: [u8; MAX_ARGV_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub header: EventHeader,
    pub syscall_nr: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RichSyscallEntry {
    pub header: EventHeader,
    pub data: [u8; 256],
    pub data_len: u16,
}

// ── Excluded Syscall Numbers (x86_64) ────────────────────────────────────────

pub const NR_FUTEX: u64 = 202;
pub const NR_CLOCK_GETTIME: u64 = 228;
pub const NR_CLOCK_NANOSLEEP: u64 = 230;
pub const NR_GETTIMEOFDAY: u64 = 96;
pub const NR_NANOSLEEP: u64 = 35;
pub const NR_EPOLL_WAIT: u64 = 232;
pub const NR_EPOLL_PWAIT: u64 = 281;
pub const NR_POLL: u64 = 7;
pub const NR_PPOLL: u64 = 271;
pub const NR_SELECT: u64 = 23;
pub const NR_PSELECT6: u64 = 270;
pub const NR_SCHED_YIELD: u64 = 24;
pub const NR_RESTART_SYSCALL: u64 = 219;

pub const EXCLUDED_SYSCALLS: &[u64] = &[
    NR_FUTEX,
    NR_CLOCK_GETTIME,
    NR_CLOCK_NANOSLEEP,
    NR_GETTIMEOFDAY,
    NR_NANOSLEEP,
    NR_EPOLL_WAIT,
    NR_EPOLL_PWAIT,
    NR_POLL,
    NR_PPOLL,
    NR_SELECT,
    NR_PSELECT6,
    NR_SCHED_YIELD,
    NR_RESTART_SYSCALL,
];

// Tier 2 syscall numbers (x86_64) for dedup bitmap
pub const NR_EXECVE: u64 = 59;
pub const NR_EXECVEAT: u64 = 322;

/// Layer-2 collectors whose complete attachment can suppress raw syscalls.
// Why only execve: ExecvePayload omits execveat's dirfd and flags. Raw 322
// must remain visible to identify fd-based exec (empty filename + AT_EMPTY_PATH).
pub const EXEC_DEDUP: &[(u64, &str)] = &[(NR_EXECVE, "exec.execve")];
pub const NR_OPENAT: u64 = 257;
pub const NR_READ: u64 = 0;
pub const NR_WRITE: u64 = 1;
pub const NR_CONNECT: u64 = 42;
pub const NR_BIND: u64 = 49;
pub const NR_LISTEN: u64 = 50;
pub const NR_SOCKET: u64 = 41;
pub const NR_CLONE: u64 = 56;
pub const NR_CLONE3: u64 = 435;
pub const NR_CHDIR: u64 = 80;
pub const NR_FCHDIR: u64 = 81;
pub const NR_UNLINK: u64 = 87;
pub const NR_UNLINKAT: u64 = 263;
pub const NR_RENAME: u64 = 82;
pub const NR_RENAMEAT2: u64 = 316;
pub const NR_MKDIR: u64 = 83;
pub const NR_MKDIRAT: u64 = 258;
pub const NR_RMDIR: u64 = 84;
pub const NR_SYMLINK: u64 = 88;
pub const NR_SYMLINKAT: u64 = 266;
pub const NR_LINK: u64 = 86;
pub const NR_LINKAT: u64 = 265;
pub const NR_CHMOD: u64 = 90;
pub const NR_FCHMOD: u64 = 91;
pub const NR_FCHMODAT: u64 = 268;
pub const NR_CHOWN: u64 = 92;
pub const NR_FCHOWN: u64 = 93;
pub const NR_FCHOWNAT: u64 = 260;
pub const NR_TRUNCATE: u64 = 76;
pub const NR_FTRUNCATE: u64 = 77;
pub const NR_MOUNT: u64 = 165;
pub const NR_UMOUNT2: u64 = 166;
pub const NR_SENDTO: u64 = 44;
pub const NR_RECVFROM: u64 = 45;
pub const NR_DUP: u64 = 32;
pub const NR_DUP2: u64 = 33;
pub const NR_DUP3: u64 = 292;
pub const NR_FCNTL: u64 = 72;
pub const NR_PREAD64: u64 = 17;
pub const NR_PWRITE64: u64 = 18;
pub const NR_READV: u64 = 19;
pub const NR_WRITEV: u64 = 20;
pub const NR_MMAP: u64 = 9;
pub const NR_SENDFILE: u64 = 40;
pub const NR_SPLICE: u64 = 275;

/// `exit` — emitted at sys_enter by Tier 1 raw capture because the
/// matching sys_exit tracepoint never fires (the task is gone by then). See
/// `layer3_raw::try_raw_sys_enter` and the `process_exit` contract in
/// `docs/output-schema.md`.
pub const NR_EXIT: u64 = 60;

/// `exit_group` — emitted at sys_enter by Tier 1 raw capture because the
/// matching sys_exit tracepoint never fires (the task is gone by then). See
/// `layer3_raw::try_raw_sys_enter` and the `process_exit` contract in
/// `docs/output-schema.md`.
pub const NR_EXIT_GROUP: u64 = 231;

/// `fcntl` `cmd` values that perform fd duplication.
///
/// `F_DUPFD` and `F_DUPFD_CLOEXEC` are the only `fcntl` commands rich-extracted
/// by Bloodhound; all other commands fall through to Tier 1 raw capture.
pub const F_DUPFD: u32 = 0;
pub const F_DUPFD_CLOEXEC: u32 = 1030;

/// `mmap` `flags` bit indicating an anonymous mapping (no file backing).
pub const MAP_ANONYMOUS: u32 = 0x20;

/// `dup3` `flags` bit setting `FD_CLOEXEC` on the new fd.
pub const O_CLOEXEC: u32 = 0o2000000;

/// Whether a rich collector replaces raw capture for the whole syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dedup {
    Dedup,
    NoDedup,
    OptIn,
}

#[derive(Clone, Copy, Debug)]
pub struct Tier2 {
    pub name: &'static str,
    pub tracepoint: &'static str,
    pub nr: u64,
    pub dedup: Dedup,
}

/// Layer-3 rich syscall attachment and raw-dedup policy (x86_64).
pub const TIER2: &[Tier2] = &[
    Tier2 {
        name: "openat",
        tracepoint: "openat",
        nr: NR_OPENAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "read",
        tracepoint: "read",
        nr: NR_READ,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "write",
        tracepoint: "write",
        nr: NR_WRITE,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "connect",
        tracepoint: "connect",
        nr: NR_CONNECT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "bind",
        tracepoint: "bind",
        nr: NR_BIND,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "listen",
        tracepoint: "listen",
        nr: NR_LISTEN,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "socket",
        tracepoint: "socket",
        nr: NR_SOCKET,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "clone",
        tracepoint: "clone",
        nr: NR_CLONE,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "clone3",
        tracepoint: "clone3",
        nr: NR_CLONE3,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "chdir",
        tracepoint: "chdir",
        nr: NR_CHDIR,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "fchdir",
        tracepoint: "fchdir",
        nr: NR_FCHDIR,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "unlink",
        tracepoint: "unlink",
        nr: NR_UNLINK,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "unlinkat",
        tracepoint: "unlinkat",
        nr: NR_UNLINKAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "rename",
        tracepoint: "rename",
        nr: NR_RENAME,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "renameat2",
        tracepoint: "renameat2",
        nr: NR_RENAMEAT2,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "mkdir",
        tracepoint: "mkdir",
        nr: NR_MKDIR,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "mkdirat",
        tracepoint: "mkdirat",
        nr: NR_MKDIRAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "rmdir",
        tracepoint: "rmdir",
        nr: NR_RMDIR,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "symlink",
        tracepoint: "symlink",
        nr: NR_SYMLINK,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "symlinkat",
        tracepoint: "symlinkat",
        nr: NR_SYMLINKAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "link",
        tracepoint: "link",
        nr: NR_LINK,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "linkat",
        tracepoint: "linkat",
        nr: NR_LINKAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "chmod",
        tracepoint: "chmod",
        nr: NR_CHMOD,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "fchmod",
        tracepoint: "fchmod",
        nr: NR_FCHMOD,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "fchmodat",
        tracepoint: "fchmodat",
        nr: NR_FCHMODAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "chown",
        tracepoint: "chown",
        nr: NR_CHOWN,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "fchown",
        tracepoint: "fchown",
        nr: NR_FCHOWN,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "fchownat",
        tracepoint: "fchownat",
        nr: NR_FCHOWNAT,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "truncate",
        tracepoint: "truncate",
        nr: NR_TRUNCATE,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "ftruncate",
        tracepoint: "ftruncate",
        nr: NR_FTRUNCATE,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "mount",
        tracepoint: "mount",
        nr: NR_MOUNT,
        dedup: Dedup::Dedup,
    },
    // Syscall nr 166 (umount2) is defined as SYSCALL_DEFINE2(umount, ...),
    // so its kernel tracepoints are named umount, not umount2.
    Tier2 {
        name: "umount2",
        tracepoint: "umount",
        nr: NR_UMOUNT2,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "sendto",
        tracepoint: "sendto",
        nr: NR_SENDTO,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "recvfrom",
        tracepoint: "recvfrom",
        nr: NR_RECVFROM,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "dup",
        tracepoint: "dup",
        nr: NR_DUP,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "dup2",
        tracepoint: "dup2",
        nr: NR_DUP2,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "dup3",
        tracepoint: "dup3",
        nr: NR_DUP3,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "pread64",
        tracepoint: "pread64",
        nr: NR_PREAD64,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "pwrite64",
        tracepoint: "pwrite64",
        nr: NR_PWRITE64,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "readv",
        tracepoint: "readv",
        nr: NR_READV,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "writev",
        tracepoint: "writev",
        nr: NR_WRITEV,
        dedup: Dedup::Dedup,
    },
    Tier2 {
        name: "mmap",
        tracepoint: "mmap",
        nr: NR_MMAP,
        dedup: Dedup::Dedup,
    },
    // Rich fcntl only captures F_DUPFD/F_DUPFD_CLOEXEC; other commands need raw capture.
    Tier2 {
        name: "fcntl",
        tracepoint: "fcntl",
        nr: NR_FCNTL,
        dedup: Dedup::NoDedup,
    },
    // Disabled by default (issue #9); raw capture remains until explicitly enabled.
    // x86_64 syscall 40 dispatches sys_sendfile64 (SYSCALL_DEFINE4(sendfile64)),
    // so the kernel tracepoint is sendfile64 while the public event stays sendfile.
    Tier2 {
        name: "sendfile",
        tracepoint: "sendfile64",
        nr: NR_SENDFILE,
        dedup: Dedup::OptIn,
    },
    Tier2 {
        name: "splice",
        tracepoint: "splice",
        nr: NR_SPLICE,
        dedup: Dedup::OptIn,
    },
];

// Bitmap size: 512 entries covers all syscalls on x86_64 (max ~450)
pub const BITMAP_SIZE: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── EventKind: bijective u8 mapping ──────────────────────────────────

    /// Every EventKind variant must survive a u8 roundtrip.
    /// This guarantees the BPF-side kind byte and userspace parser agree.
    #[test]
    fn event_kind_roundtrip_all_variants() {
        for byte in 0..=u8::MAX {
            if let Some(variant) = EventKind::from_u8(byte) {
                assert!(
                    EventKind::ALL.contains(&variant),
                    "Decoded EventKind::{:?} (u8={}) is missing from the variant list",
                    variant,
                    byte,
                );
            }
        }

        for variant in EventKind::ALL {
            let byte = *variant as u8;
            let recovered = EventKind::from_u8(byte);
            assert_eq!(
                recovered,
                Some(*variant),
                "EventKind::{:?} (u8={}) did not roundtrip",
                variant,
                byte,
            );
        }
    }

    /// Unknown u8 values must return None, not panic.
    #[test]
    fn event_kind_unknown_returns_none() {
        for byte in 0..=u8::MAX {
            if !EventKind::ALL.iter().any(|&variant| variant as u8 == byte) {
                assert_eq!(
                    EventKind::from_u8(byte),
                    None,
                    "Expected None for unassigned kind byte {}",
                    byte,
                );
            }
        }
    }

    #[test]
    fn event_kind_reserved_and_all_are_disjoint() {
        for &byte in EventKind::RESERVED {
            assert!(
                !EventKind::ALL.iter().any(|&variant| variant as u8 == byte),
                "Reserved wire ID {} is assigned to an EventKind",
                byte,
            );
            assert_eq!(EventKind::from_u8(byte), None);
        }
    }

    /// All variant discriminants must be unique (no collisions).
    #[test]
    fn event_kind_discriminants_unique() {
        let mut seen = [false; 256];
        for v in EventKind::ALL {
            let b = *v as u8;
            assert!(!seen[b as usize], "Duplicate discriminant: {}", b);
            seen[b as usize] = true;
        }
    }

    // ── Struct sizes: binary protocol stability ──────────────────────────
    // These sizes are part of the BPF↔userspace wire protocol.
    // If any size changes, the deserializer will produce garbage.

    #[test]
    fn event_header_size_is_stable() {
        // repr(C) layout: kind(1) + capture(3) + 4 bytes alignment padding
        // + timestamp_ns(8) + auid(4) + sessionid(4)
        // + pid(4) + ppid(4) + process_start_boottime_ns(8)
        // + comm(16) + tid(4) + ns(36) = 96
        assert_eq!(EventHeader::SIZE, 96);
        assert_eq!(EventHeader::SIZE, mem::size_of::<EventHeader>());
    }

    #[test]
    fn packet_event_header_size_is_stable() {
        // repr(C) layout: kind(1) + _pad(3) + 4 bytes alignment padding
        // + timestamp_ns(8) + ifindex(4) + data_len(4) = 24
        assert_eq!(PacketEventHeader::SIZE, mem::size_of::<PacketEventHeader>());
    }

    #[test]
    fn payload_sizes_match_mem_size() {
        assert_eq!(ExecViewPayload::SIZE, 24);
        assert_eq!(EventKind::from_u8(224), Some(EventKind::ExecView));
        assert_eq!(ExecvePayload::SIZE, mem::size_of::<ExecvePayload>());
        assert_eq!(RawSyscallPayload::SIZE, mem::size_of::<RawSyscallPayload>());
        assert_eq!(TtyPayload::SIZE, mem::size_of::<TtyPayload>());
        assert_eq!(OpenatPayload::SIZE, mem::size_of::<OpenatPayload>());
        assert_eq!(ReadWritePayload::SIZE, mem::size_of::<ReadWritePayload>());
        assert_eq!(ConnectBindPayload::SIZE, mem::size_of::<ConnectBindPayload>());
        assert_eq!(SocketPayload::SIZE, mem::size_of::<SocketPayload>());
        assert_eq!(ClonePayload::SIZE, mem::size_of::<ClonePayload>());
        assert_eq!(ProcessForkPayload::SIZE, 32);
        assert_eq!(
            ProcessForkPayload::SIZE,
            mem::size_of::<ProcessForkPayload>()
        );
        assert_eq!(ProcessExitPayload::SIZE, 8);
        assert_eq!(
            ProcessExitPayload::SIZE,
            mem::size_of::<ProcessExitPayload>()
        );
        assert_eq!(SignalGeneratePayload::SIZE, 24);
        assert_eq!(
            SignalGeneratePayload::SIZE,
            mem::size_of::<SignalGeneratePayload>()
        );
        assert_eq!(PathPayload::SIZE, mem::size_of::<PathPayload>());
        assert_eq!(TwoPathPayload::SIZE, mem::size_of::<TwoPathPayload>());
        assert_eq!(ChmodPayload::SIZE, mem::size_of::<ChmodPayload>());
        assert_eq!(FchmodPayload::SIZE, mem::size_of::<FchmodPayload>());
        assert_eq!(ChownPayload::SIZE, mem::size_of::<ChownPayload>());
        assert_eq!(FchownPayload::SIZE, mem::size_of::<FchownPayload>());
        assert_eq!(TruncatePayload::SIZE, mem::size_of::<TruncatePayload>());
        assert_eq!(FtruncatePayload::SIZE, mem::size_of::<FtruncatePayload>());
        assert_eq!(MountPayload::SIZE, mem::size_of::<MountPayload>());
        assert_eq!(Umount2Payload::SIZE, mem::size_of::<Umount2Payload>());
        assert_eq!(
            SendtoRecvfromPayload::SIZE,
            mem::size_of::<SendtoRecvfromPayload>()
        );
        assert_eq!(FdPayload::SIZE, mem::size_of::<FdPayload>());
        assert_eq!(ListenPayload::SIZE, mem::size_of::<ListenPayload>());
        assert_eq!(
            LsmFileOpenPayload::SIZE,
            mem::size_of::<LsmFileOpenPayload>()
        );
        assert_eq!(
            LsmTaskKillPayload::SIZE,
            mem::size_of::<LsmTaskKillPayload>()
        );
        assert_eq!(LsmBpfPayload::SIZE, mem::size_of::<LsmBpfPayload>());
        assert_eq!(LsmPtracePayload::SIZE, mem::size_of::<LsmPtracePayload>());
        assert_eq!(LsmInodePayload::SIZE, mem::size_of::<LsmInodePayload>());
        assert_eq!(
            LsmInodeRenamePayload::SIZE,
            mem::size_of::<LsmInodeRenamePayload>()
        );
        assert_eq!(LsmSetuidPayload::SIZE, mem::size_of::<LsmSetuidPayload>());
        assert_eq!(DupPayload::SIZE, mem::size_of::<DupPayload>());
        assert_eq!(PreadPwritePayload::SIZE, mem::size_of::<PreadPwritePayload>());
        assert_eq!(ReadvWritevPayload::SIZE, mem::size_of::<ReadvWritevPayload>());
        assert_eq!(MmapPayload::SIZE, mem::size_of::<MmapPayload>());
        assert_eq!(
            SendfileSplicePayload::SIZE,
            mem::size_of::<SendfileSplicePayload>()
        );
    }

    #[test]
    fn process_exit_status_uses_the_group_leader_without_group_exit() {
        assert_eq!(select_process_exit_status(9, 42 << 8), 9);
        assert_eq!(select_process_exit_status(0, 42 << 8), 42 << 8);
    }

    // ── Syscall metadata correctness ─────────────────────────────────────

    /// Excluded and Tier2 sets must be disjoint.
    /// A syscall cannot be both excluded and handled by rich extraction.
    #[test]
    fn excluded_and_tier2_are_disjoint() {
        for nr in EXCLUDED_SYSCALLS {
            assert!(
                !TIER2.iter().any(|syscall| syscall.nr == *nr),
                "Syscall NR {} is in both EXCLUDED and TIER2",
                nr,
            );
        }
    }

    /// All referenced syscall NRs must fit within the bitmap.
    #[test]
    fn all_syscall_nrs_fit_in_bitmap() {
        for nr in EXCLUDED_SYSCALLS
            .iter()
            .copied()
            .chain(TIER2.iter().map(|syscall| syscall.nr))
            .chain(EXEC_DEDUP.iter().map(|(nr, _)| *nr))
        {
            assert!(
                (nr as usize) < BITMAP_SIZE,
                "Syscall NR {} exceeds BITMAP_SIZE {}",
                nr,
                BITMAP_SIZE,
            );
        }
    }

    #[test]
    fn tier2_numbers_are_unique_and_leave_tier1_only_calls_visible() {
        for (i, syscall) in TIER2.iter().enumerate() {
            assert!(!TIER2[..i]
                .iter()
                .any(|other| other.nr == syscall.nr || other.name == syscall.name));
            assert!(![NR_EXIT_GROUP, 3, 60, NR_EXECVE, NR_EXECVEAT].contains(&syscall.nr));
            // close, exit and Layer 2
        }
        for nr in [NR_EXECVE, NR_EXECVEAT] {
            assert!(!EXCLUDED_SYSCALLS.contains(&nr));
        }
    }

    // The full pre-migration attach-set oracle is preserved in the test-first
    // commit; retain only semantic edge cases, not a second maintained list.
    #[test]
    fn tier2_special_tracepoint_and_partial_capture_policies() {
        let umount = TIER2
            .iter()
            .find(|syscall| syscall.nr == NR_UMOUNT2)
            .unwrap();
        assert_eq!((umount.name, umount.tracepoint), ("umount2", "umount"));
        let policy = |nr| TIER2.iter().find(|syscall| syscall.nr == nr).unwrap().dedup;
        assert_eq!(policy(NR_FCNTL), Dedup::NoDedup);
        let sendfile = TIER2.iter().find(|syscall| syscall.nr == NR_SENDFILE).unwrap();
        assert_eq!((sendfile.name, sendfile.tracepoint), ("sendfile", "sendfile64"));
        assert_eq!(policy(NR_SENDFILE), Dedup::OptIn);
        assert_eq!(policy(NR_SPLICE), Dedup::OptIn);
    }

    /// Spot-check a few well-known x86_64 syscall numbers.
    #[test]
    fn well_known_syscall_numbers() {
        assert_eq!(NR_READ, 0);
        assert_eq!(NR_WRITE, 1);
        assert_eq!(NR_OPENAT, 257);
        assert_eq!(NR_EXECVE, 59);
        assert_eq!(NR_CLONE, 56);
        assert_eq!(NR_CONNECT, 42);
        assert_eq!(NR_SOCKET, 41);
        assert_eq!(NR_FUTEX, 202);
    }
}

/// Exec-entry filesystem context, paired by immutable actor and header timestamp.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecViewPayload {
    pub root_inode: u64,
    pub root_dev: u32,
    pub mount_namespace: u32,
    pub root_mount_id: u32,
    pub version: u8,
    pub status: u8,
    pub _pad: [u8; 2],
}
impl ExecViewPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Ordered direct-member offsets for the bounded exec view pointer traversal.
pub const EXEC_VIEW_FIELDS: [(&str, &str); 14] = [
    ("task_struct", "fs"),
    ("task_struct", "nsproxy"),
    ("fs_struct", "root"),
    ("path", "mnt"),
    ("path", "dentry"),
    ("dentry", "d_inode"),
    ("inode", "i_ino"),
    ("inode", "i_sb"),
    ("super_block", "s_dev"),
    ("nsproxy", "mnt_ns"),
    ("mnt_namespace", "ns"),
    ("ns_common", "inum"),
    ("mount", "mnt"),
    ("mount", "mnt_id"),
];

/// Additional fd traversal members. Identity endpoints reuse EXEC_VIEW_FIELDS[6..9].
pub const FD_CHAIN_FIELDS: [(&str, &str); 5] = [
    ("task_struct", "files"),
    ("files_struct", "fdt"),
    ("fdtable", "max_fds"),
    ("fdtable", "fd"),
    ("file", "f_inode"),
];

/// Ordered direct-member offsets for PTY slave classification.
pub const TTY_FIELDS: [(&str, &str); 3] = [
    ("tty_struct", "driver"),
    ("tty_driver", "type"),
    ("tty_driver", "subtype"),
];

// ── Namespace membership snapshot ────────────────────────────────────────────

/// Header slots, in output order: mnt, net, uts, ipc, cgroup, user, pid.
pub const NS_SLOTS: usize = 7;
pub const NS_SLOT_NAMES: [&str; NS_SLOTS] = ["mnt", "net", "uts", "ipc", "cgroup", "user", "pid"];
/// Support bit for the PID namespace of future children (`setns`/`unshare`).
pub const NS_PID_FOR_CHILDREN_BIT: u32 = 1 << NS_SLOTS;

pub const NS_STATUS_COMPLETE: u8 = 1;
pub const NS_STATUS_UNSUPPORTED: u8 = 2;
pub const NS_STATUS_UNAVAILABLE: u8 = 3;

/// Namespace identities of one task read at one hook moment. `inum[i]` is
/// meaningful only when `status[i]` is `NS_STATUS_COMPLETE`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NsSnapshot {
    pub inum: [u32; NS_SLOTS],
    pub status: [u8; NS_SLOTS],
    pub _pad: u8,
}

/// Ordered direct-member offsets for namespace reads. Index `NS_FIELDS.len()`
/// of the offset table carries `sizeof(struct upid)` instead of an offset.
pub const NS_FIELDS: [(&str, &str); 21] = [
    ("task_struct", "nsproxy"),         // 0
    ("nsproxy", "mnt_ns"),              // 1
    ("nsproxy", "net_ns"),              // 2
    ("nsproxy", "uts_ns"),              // 3
    ("nsproxy", "ipc_ns"),              // 4
    ("nsproxy", "cgroup_ns"),           // 5
    ("task_struct", "real_cred"),       // 6
    ("cred", "user_ns"),                // 7
    ("task_struct", "thread_pid"),      // 8
    ("pid", "level"),                   // 9
    ("pid", "numbers"),                 // 10
    ("upid", "ns"),                     // 11
    ("nsproxy", "pid_ns_for_children"), // 12
    ("ns_common", "inum"),              // 13
    ("mnt_namespace", "ns"),            // 14
    ("net", "ns"),                      // 15
    ("uts_namespace", "ns"),            // 16
    ("ipc_namespace", "ns"),            // 17
    ("cgroup_namespace", "ns"),         // 18
    ("user_namespace", "ns"),           // 19
    ("pid_namespace", "ns"),            // 20
];
pub const NS_OFFSETS_LEN: usize = NS_FIELDS.len() + 1;
pub const NS_UPID_SIZE_INDEX: usize = NS_FIELDS.len();

/// `NS_FIELDS` indexes each slot needs; bit `i` of the support mask is set
/// only when every one resolves. The PID slots also need `sizeof(upid)`.
pub const NS_SLOT_FIELDS: [&[usize]; NS_SLOTS + 1] = [
    &[0, 1, 14, 13],
    &[0, 2, 15, 13],
    &[0, 3, 16, 13],
    &[0, 4, 17, 13],
    &[0, 5, 18, 13],
    &[6, 7, 19, 13],
    &[8, 9, 10, 11, 20, 13],
    &[0, 12, 20, 13],
];

#[cfg(test)]
mod ns_tests {
    use super::*;

    #[test]
    fn header_layout_has_no_implicit_tail_padding() {
        assert_eq!(core::mem::size_of::<NsSnapshot>(), 36);
        assert_eq!(EventHeader::SIZE, 96);
        assert_eq!(core::mem::offset_of!(EventHeader, tid), 56);
        assert_eq!(core::mem::offset_of!(EventHeader, ns), 60);
    }

    #[test]
    fn every_slot_names_resolvable_fields() {
        for fields in NS_SLOT_FIELDS {
            assert!(fields.iter().all(|&index| index < NS_FIELDS.len()));
            assert!(fields.contains(&13), "every slot ends at ns_common.inum");
        }
    }
}
