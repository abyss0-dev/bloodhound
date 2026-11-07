use std::{ffi::CString, fs, io, os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd}, path::Path};

use anyhow::{Context, Result};

// Aya 0.13's safe UProbe API does not expose the kernel's `ref_ctr_offset`
// field. Linux encodes it in config[32..63] for the fd-based uprobe PMU. Keep
// this minimal adapter here so the rest of the collector stays on Aya's normal
// program lifecycle, while the kernel owns the increment/decrement semantics.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    // Keep the advertised size identical to the 128-byte perf_event_attr ABI
    // supported by the target guest. All fields after config2 remain zero; the
    // ref-counter offset itself is encoded in the upper half of config.
    _reserved: [u64; 7],
}

const _: [(); 128] = [(); std::mem::size_of::<PerfEventAttr>()];

const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;
const PERF_EVENT_IOC_ENABLE: std::ffi::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: std::ffi::c_ulong = 0x4004_2408;
// Bloodhound's collector and fixture are x86_64-only. Keeping this syscall
// declaration local avoids turning Aya's transitive libc dependency into a
// second public dependency merely to fill the API gap in Aya 0.13.
const SYS_PERF_EVENT_OPEN_X86_64: std::ffi::c_long = 298;

unsafe extern "C" {
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

pub(super) fn attach_uprobe_with_semaphore(
    program: &mut aya::programs::UProbe,
    target: &Path,
    probe_offset: u64,
    semaphore_offset: u32,
) -> Result<OwnedFd> {
    let pmu_type = fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")
        .context("reading uprobe PMU type")?
        .trim()
        .parse::<u32>()
        .context("parsing uprobe PMU type")?;
    let target = CString::new(target.as_os_str().as_encoded_bytes())
        .context("encoding verified USDT target path")?;
    let attr = PerfEventAttr {
        type_: pmu_type,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: u64::from(semaphore_offset) << 32,
        config1: target.as_ptr() as u64,
        config2: probe_offset,
        ..Default::default()
    };
    let raw_fd = unsafe {
        syscall(
            SYS_PERF_EVENT_OPEN_X86_64,
            &attr,
            -1_i32,
            0_i32,
            -1_i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error()).context("opening semaphore-backed uprobe");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
    let program_fd = program.fd()?.as_fd().as_raw_fd();
    if unsafe { ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, program_fd) } < 0 {
        return Err(io::Error::last_os_error())
            .context("attaching BPF program to semaphore-backed uprobe");
    }
    if unsafe { ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0) } < 0 {
        return Err(io::Error::last_os_error()).context("enabling semaphore-backed uprobe");
    }
    Ok(fd)
}
