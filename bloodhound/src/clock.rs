//! Clock helpers shared by userspace-synthesized events.

/// Return the VM's `CLOCK_MONOTONIC` value in integer nanoseconds.
///
/// BPF records use `bpf_ktime_get_ns()`, which is the same clock domain.
/// Failing to read this clock is fatal: emitting a zero or wall-clock fallback
/// would silently mix timestamp domains in one BehaviorEvent stream.
pub fn monotonic_now_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
    if rc != 0 {
        panic!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let seconds = u64::try_from(value.tv_sec).expect("CLOCK_MONOTONIC returned negative seconds");
    let nanos =
        u64::try_from(value.tv_nsec).expect("CLOCK_MONOTONIC returned negative nanoseconds");
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .expect("CLOCK_MONOTONIC nanoseconds overflowed u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_advances_in_nanoseconds() {
        let first = monotonic_now_ns();
        let second = monotonic_now_ns();
        assert!(first > 0);
        assert!(second >= first);
    }
}
