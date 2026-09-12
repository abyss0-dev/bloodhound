#![no_std]
#![no_main]

mod fd_ident;
mod filter;
mod exec_view;
mod exec_stdio;
mod fork_files;
mod helpers;
mod layer1_tty;
mod layer2_exec;
mod layer3_raw;
mod layer3_rich;
mod lifecycle;
mod lsm_hooks;
mod maps;
mod packet_tc;
mod signal;
mod usdt;
mod vmlinux;

// ── Global Variables ─────────────────────────────────────────────────────────

#[no_mangle]
pub static mut TARGET_AUID: u32 = u32::MAX;

#[no_mangle]
pub static mut DAEMON_PID: u32 = 0;

// ── Runtime-resolved task_struct field offsets ───────────────────────────────
//
// These byte offsets are resolved from the *running* kernel's BTF by
// userspace (`bloodhound::btf_offsets`) and injected via `set_global`
// before the programs load. This is "manual CO-RE": it sidesteps rustc's
// lack of `preserve_access_index` by treating the offset as a runtime
// value instead of baking it at compile time (see issue #37).
//
// Userspace resolves every required offset before load and fails closed if
// BTF is unavailable or incomplete.

/// Byte offset of `task_struct::loginuid` (a `kuid_t`, whose first field
/// is the `u32` audit login UID). Read by `filter::get_current_auid`.
#[no_mangle]
pub static mut OFF_LOGINUID: u32 = 0;

/// Byte offset of `task_struct::sessionid` (`u32`). Read by
/// `filter::get_current_sessionid`.
#[no_mangle]
pub static mut OFF_SESSIONID: u32 = 0;

/// Byte offset of `task_struct::tgid` (`i32`, == userspace PID for the
/// thread-group leader). Read by the LSM `task_kill` hook.
#[no_mangle]
pub static mut OFF_TGID: u32 = 0;

#[no_mangle]
pub static mut OFF_PID: u32 = 0;

#[no_mangle]
pub static mut OFF_GROUP_LEADER: u32 = 0;

#[no_mangle]
pub static mut OFF_START_BOOTTIME: u32 = 0;

#[no_mangle]
pub static mut OFF_SIGNAL: u32 = 0;

#[no_mangle]
pub static mut OFF_EXIT_CODE: u32 = 0;

#[no_mangle]
pub static mut OFF_COMM: u32 = 0;

#[no_mangle]
pub static mut OFF_SIGNAL_LIVE: u32 = 0;

#[no_mangle]
pub static mut OFF_SIGNAL_GROUP_EXIT_CODE: u32 = 0;

// ── Panic Handler ────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[no_mangle]
pub static mut OFF_EXEC_VIEW: [u32;14] = [0;14];
#[no_mangle]
pub static mut EXEC_VIEW_SUPPORTED: u32 = 0;

#[no_mangle]
pub static mut OFF_EXEC_STDIO: [u32; 6] = [0; 6];
#[no_mangle]
pub static mut EXEC_STDIO_SUPPORTED: u32 = 0;
