//! Map-operation outcomes shared by Tier-2 rich/path capture and host tests.

use crate::{SYSCALL_ENTRY_CLEANUP_FAILED, SYSCALL_ENTRY_SAVE_FAILED};

#[inline(always)]
pub fn save_outcome(result: Result<(), i64>) -> Option<u32> {
    match result {
        Ok(()) => None,
        Err(_) => Some(SYSCALL_ENTRY_SAVE_FAILED),
    }
}

#[inline(always)]
pub fn cleanup_outcome(result: Result<(), i64>) -> Option<u32> {
    match result {
        // An unrecorded invocation or an already removed entry is not loss.
        Ok(()) | Err(-2) => None, // ENOENT
        Err(_) => Some(SYSCALL_ENTRY_CLEANUP_FAILED),
    }
}
