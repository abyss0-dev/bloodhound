//! Internal map contract, not a wire event. Never evict a live exit claim.

pub const EXIT_CLAIM_CAPACITY: u32 = 10240;
pub const EXIT_FAILURE_REASONS: [&str; 4] = [
    "exit_capture_failed",
    "exit_claim_failed",
    "cleanup_capture_failed",
    "cleanup_delete_failed",
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitClaimKey {
    pub tgid: u32,
    pub padding: u32,
    pub start_boottime_ns: u64,
}

impl ExitClaimKey {
    pub const fn new(tgid: u32, start_boottime_ns: u64) -> Self {
        Self {
            tgid,
            padding: 0,
            start_boottime_ns,
        }
    }

    // Read the freed task itself, never its potentially freed group leader.
    // de_thread exchanges TIDs: the former leader no longer has pid == tgid.
    pub const fn for_freed_task(pid: u32, tgid: u32, start: u64) -> Option<Self> {
        if pid == tgid && tgid != 0 && start != 0 {
            Some(Self::new(tgid, start))
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Emit,
    Duplicate,
    Failed,
}

pub fn claim_outcome(result: Result<(), i64>) -> ClaimOutcome {
    match result {
        Ok(()) => ClaimOutcome::Emit,
        Err(-17) => ClaimOutcome::Duplicate, // EEXIST from BPF_NOEXIST
        Err(_) => ClaimOutcome::Failed,
    }
}

pub fn cleanup_failed(result: Result<(), i64>) -> bool {
    !matches!(result, Ok(()) | Err(-2)) // ENOENT: untraced / never claimed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_successful_atomic_claim_can_emit() {
        assert_eq!(claim_outcome(Ok(())), ClaimOutcome::Emit);
        assert_eq!(claim_outcome(Err(-17)), ClaimOutcome::Duplicate);
        for errno in [-7, -12, -22, -16] {
            assert_eq!(claim_outcome(Err(errno)), ClaimOutcome::Failed);
        }
    }

    #[test]
    fn identity_survives_pid_reuse_and_has_no_implicit_padding() {
        assert_eq!(core::mem::size_of::<ExitClaimKey>(), 16);
        assert_eq!(core::mem::offset_of!(ExitClaimKey, start_boottime_ns), 8);
        let old = ExitClaimKey::new(42, 100);
        assert_eq!(old.padding, 0);
        assert_ne!(old, ExitClaimKey::new(42, 200));
    }

    #[test]
    fn worker_and_dethread_former_leader_cannot_remove_claim() {
        assert_eq!(ExitClaimKey::for_freed_task(43, 42, 100), None);
        assert_eq!(
            ExitClaimKey::for_freed_task(42, 42, 100),
            Some(ExitClaimKey::new(42, 100))
        );
        assert_eq!(ExitClaimKey::for_freed_task(42, 42, 0), None);
        assert!(!cleanup_failed(Err(-2)));
        assert!(!cleanup_failed(Ok(())));
        assert!(cleanup_failed(Err(-22)));
    }
}
