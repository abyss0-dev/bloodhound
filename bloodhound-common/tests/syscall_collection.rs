use bloodhound_common::{
    syscall_collection::{cleanup_outcome, save_outcome},
    SYSCALL_ENTRY_CAPTURE_FAILED, SYSCALL_ENTRY_CLEANUP_FAILED, SYSCALL_ENTRY_SAVE_FAILED,
    SYSCALL_EXIT_CAPTURE_FAILED, SYSCALL_FAILURE_COUNT, SYSCALL_FAILURE_REASONS,
    SYSCALL_INVOCATION_INTERRUPTED,
};

#[test]
fn save_reports_every_error_including_enoent() {
    for (result, expected) in [
        (Ok(()), None),
        (Err(-2), Some(SYSCALL_ENTRY_SAVE_FAILED)), // ENOENT
        (Err(-7), Some(SYSCALL_ENTRY_SAVE_FAILED)), // E2BIG: full map
        (Err(-12), Some(SYSCALL_ENTRY_SAVE_FAILED)), // ENOMEM
        (Err(-17), Some(SYSCALL_ENTRY_SAVE_FAILED)), // EEXIST
        (Err(-22), Some(SYSCALL_ENTRY_SAVE_FAILED)), // EINVAL
        (Err(i32::MIN), Some(SYSCALL_ENTRY_SAVE_FAILED)),
        (Err(0), Some(SYSCALL_ENTRY_SAVE_FAILED)),
    ] {
        assert_eq!(save_outcome(result), expected, "save {result:?}");
    }
}

#[test]
fn cleanup_absence_is_normal_but_other_errors_are_loss() {
    for (result, expected) in [
        (Ok(()), None),
        (Err(-2), None), // ENOENT: rich collector or filtered entry
        (Err(-7), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
        (Err(-12), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
        (Err(-17), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
        (Err(-22), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
        (Err(2), Some(SYSCALL_ENTRY_CLEANUP_FAILED)), // not negative ENOENT
        (Err(i32::MIN), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
        (Err(0), Some(SYSCALL_ENTRY_CLEANUP_FAILED)),
    ] {
        assert_eq!(cleanup_outcome(result), expected, "cleanup {result:?}");
    }
}

#[test]
fn reason_indices_cover_the_counter_map_without_holes() {
    let reasons = [
        (SYSCALL_ENTRY_CAPTURE_FAILED, "entry_capture_failed"),
        (SYSCALL_ENTRY_SAVE_FAILED, "entry_save_failed"),
        (SYSCALL_EXIT_CAPTURE_FAILED, "exit_capture_failed"),
        (SYSCALL_INVOCATION_INTERRUPTED, "invocation_interrupted"),
        (SYSCALL_ENTRY_CLEANUP_FAILED, "entry_cleanup_failed"),
    ];
    assert_eq!(SYSCALL_FAILURE_COUNT as usize, SYSCALL_FAILURE_REASONS.len());
    assert_eq!(reasons.len(), SYSCALL_FAILURE_REASONS.len());
    for (index, (reason, name)) in reasons.into_iter().enumerate() {
        assert_eq!(reason as usize, index);
        assert_eq!(SYSCALL_FAILURE_REASONS[index], name);
    }
}
