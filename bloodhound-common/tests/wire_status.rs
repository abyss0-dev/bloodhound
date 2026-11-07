use bloodhound_common::{exit_claim::*, *};

#[test]
fn capture_status_round_trips_every_wire_byte() {
    for byte in u8::MIN..=u8::MAX {
        match CaptureStatus::try_from(byte) {
            Ok(status) => {
                assert_eq!(status as u8, byte);
                assert!((1..=3).contains(&byte));
            }
            Err(()) => assert!(!(1..=3).contains(&byte)),
        }
    }
    assert_eq!(CaptureStatus::Complete as u8, 1);
    assert_eq!(CaptureStatus::Truncated as u8, 2);
    assert_eq!(CaptureStatus::ReadError as u8, 3);
}

#[test]
fn reason_tables_cover_the_map_indices() {
    for (reasons, indices) in [
        (
            EXEC_FAILURE_REASONS.as_slice(),
            [
                EXEC_ENTRY_CAPTURE_FAILED,
                EXEC_ENTRY_SAVE_FAILED,
                EXEC_EXIT_CAPTURE_FAILED,
                EXEC_INVOCATION_INTERRUPTED,
                EXEC_ENTRY_CLEANUP_FAILED,
            ]
            .as_slice(),
        ),
        (
            OPENAT_FAILURE_REASONS.as_slice(),
            [
                OPENAT_ENTRY_CAPTURE_FAILED,
                OPENAT_ENTRY_SAVE_FAILED,
                OPENAT_EXIT_CAPTURE_FAILED,
                OPENAT_INVOCATION_INTERRUPTED,
            ]
            .as_slice(),
        ),
        (
            EXIT_FAILURE_REASONS.as_slice(),
            [
                EXIT_CAPTURE_FAILED,
                EXIT_CLAIM_FAILED,
                CLEANUP_CAPTURE_FAILED,
                CLEANUP_DELETE_FAILED,
            ]
            .as_slice(),
        ),
    ] {
        assert_eq!(reasons.len(), indices.len());
        for (index, &code) in indices.iter().enumerate() {
            assert_eq!(code as usize, index);
            assert!(!reasons[index].is_empty());
        }
    }
}

#[test]
fn capture_metadata_preserves_header_layout() {
    assert_eq!(core::mem::size_of::<CaptureStatus>(), 1);
    assert_eq!(core::mem::size_of::<HeaderCapture>(), 3);
    assert_eq!(core::mem::align_of::<HeaderCapture>(), 1);
    assert_eq!(core::mem::offset_of!(EventHeader, capture), 1);
    assert_eq!(core::mem::size_of::<EventHeader>(), 96);
}

#[test]
fn openat_flags_preserve_wire_bits() {
    assert_eq!(DEV_VALID, 1);
    assert_eq!(INO_VALID, 2);
    assert_eq!(PATH_COMPLETE, 4);
    assert_eq!(PATH_READ_FAILED, 8);
}
