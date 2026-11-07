//! Map-operation outcomes shared by raw syscall capture and host tests.

use crate::{SYSCALL_ENTRY_CLEANUP_FAILED, SYSCALL_ENTRY_SAVE_FAILED};

pub fn save_outcome(result: Result<(), i32>) -> Option<u32> {
    match result {
        Ok(()) => None,
        Err(_) => Some(SYSCALL_ENTRY_SAVE_FAILED),
    }
}

pub fn cleanup_outcome(result: Result<(), i32>) -> Option<u32> {
    match result {
        // Rich collectors and filtered entries legitimately leave no raw state.
        Ok(()) | Err(-2) => None, // ENOENT
        Err(_) => Some(SYSCALL_ENTRY_CLEANUP_FAILED),
    }
}
