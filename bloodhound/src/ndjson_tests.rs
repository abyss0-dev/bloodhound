use super::*;
use insta::assert_snapshot;

fn snapshot(name: &str, bytes: Vec<u8>) {
    let event = deserialize(&bytes).expect("synthetic wire fixture must deserialize");
    let encoded = serde_json::to_string(&event).unwrap();
    // to_value would sort struct fields and hide output-byte regressions.
    let mut output = Vec::new();
    crate::serializer::Serializer::with_writer(&mut output)
        .write_event(&event)
        .unwrap();
    assert_eq!(output, format!("{encoded}\n").as_bytes());
    assert_snapshot!(name, encoded);
}

#[test]
fn packet_egress_bytes() {
    use base64::Engine;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(include_str!("../testdata/qemu/packet_ingress.b64").trim())
        .unwrap();
    bytes[0] = EventKind::PacketEgress as u8;
    snapshot("packet_egress_bytes", bytes);
}

#[test]
fn path_status_bytes() {
    for two in [false, true] {
        for status in [
            CaptureStatus::Complete,
            CaptureStatus::Truncated,
            CaptureStatus::ReadError,
        ] {
            let mut bytes = path_capture_record(two, b"/one", b"/two");
            bytes[1..4].copy_from_slice(&[1, status as u8, if two { status as u8 } else { 0 }]);
            snapshot(
                &format!(
                    "path_{}_{}_bytes",
                    if two { "two" } else { "single" },
                    status as u8
                ),
                bytes,
            );
        }
    }
}

#[test]
fn lifecycle_and_signal_bytes() {
    snapshot(
        "process_start_bytes",
        header_bytes(&make_event_header(EventKind::ProcessStart)),
    );
    snapshot(
        "process_fork_bytes",
        build_event(
            EventKind::ProcessFork,
            &ProcessForkPayload {
                parent_tgid: 1234,
                child_tgid: 4321,
                parent_start_boottime_ns: 99,
                child_start_boottime_ns: 100,
                clone_flags: 0x0002_0000,
            },
        ),
    );
    for (name, raw_status) in [
        ("process_exit_code_bytes", 42 << 8),
        ("process_exit_signal_bytes", 9 | 0x80),
    ] {
        snapshot(
            name,
            build_event(
                EventKind::ProcessExit,
                &ProcessExitPayload {
                    raw_status,
                    _pad: 0,
                },
            ),
        );
    }
    snapshot(
        "signal_generate_bytes",
        build_event(
            EventKind::SignalGenerate,
            &SignalGeneratePayload {
                target_tgid: 4321,
                signal: 15,
                target_start_boottime_ns: 100,
                group: 1,
                result: SIGNAL_RESULT_DELIVERED,
            },
        ),
    );
}

#[test]
fn path_and_fd_family_bytes() {
    for kind in [
        EventKind::Chdir,
        EventKind::Unlink,
        EventKind::Unlinkat,
        EventKind::Mkdir,
        EventKind::Mkdirat,
        EventKind::Rmdir,
        EventKind::Chmod,
        EventKind::Fchmodat,
        EventKind::Chown,
        EventKind::Fchownat,
        EventKind::Truncate,
        EventKind::Umount2,
    ] {
        let mut bytes = build_event_with_vardata(
            kind,
            &PathPayload {
                path_len: 4,
                _pad: [0; 2],
                return_code: -13,
            },
            b"/one",
        );
        bytes[1..4].copy_from_slice(&[1, CaptureStatus::Complete as u8, 0]);
        snapshot(&format!("{kind:?}_bytes"), bytes);
    }
    for kind in [
        EventKind::Rename,
        EventKind::Renameat2,
        EventKind::Symlink,
        EventKind::Symlinkat,
        EventKind::Link,
        EventKind::Linkat,
        EventKind::Mount,
    ] {
        let mut bytes = build_event_with_vardata(
            kind,
            &TwoPathPayload {
                path1_len: 4,
                path2_len: 4,
                return_code: 0,
            },
            b"/one/two",
        );
        bytes[1..4].copy_from_slice(&[
            1,
            CaptureStatus::Complete as u8,
            CaptureStatus::Complete as u8,
        ]);
        snapshot(&format!("{kind:?}_bytes"), bytes);
    }
    for kind in [
        EventKind::Fchdir,
        EventKind::Fchmod,
        EventKind::Fchown,
        EventKind::Ftruncate,
    ] {
        snapshot(
            &format!("{kind:?}_bytes"),
            build_event(
                kind,
                &FdPayload {
                    fd: 7,
                    return_code: -9,
                },
            ),
        );
    }
}

#[test]
fn remaining_syscall_and_lsm_bytes() {
    macro_rules! family {
        ($payload:expr; $($kind:ident),+ $(,)?) => {
            $(snapshot(concat!(stringify!($kind), "_bytes"), build_event(EventKind::$kind, &$payload));)+
        };
    }
    family!(ExecvePayload { filename_len: 0, argv_len: 0, return_code: -2 }; Execveat);
    family!(ReadWritePayload { fd: 7, fd_type: 1, _pad: [0; 3], requested_size: 42, return_code: -9 }; Write);
    family!(ConnectBindPayload { family: 2, port: 8080, addr_v4: 0x0100007f, addr_v6: [0; 16], return_code: 0 }; Bind);
    family!(ListenPayload { fd: 7, backlog: 128, return_code: 0 }; Listen);
    family!(SocketPayload { domain: 2, sock_type: 1, protocol: 6, return_code: 7 }; Socket);
    family!(ClonePayload { flags: 0x0002_0000, return_code: 4321 }; Clone3);
    family!(SendtoRecvfromPayload { fd: 7, family: 2, port: 8080, addr_v4: 0x0100007f, addr_v6: [0; 16], size: 42, return_code: 21 }; Recvfrom);
    family!(DupPayload { oldfd: 7, newfd: 9, cloexec: 1, _pad: [0; 3], return_code: 9 }; Dup, Dup2, Dup3, Fcntl);
    family!(PreadPwritePayload { fd: 7, fd_type: 0, _pad: [0; 3], requested_size: 42, offset: 1024, return_code: 21 }; Pread64, Pwrite64);
    family!(ReadvWritevPayload { fd: 7, fd_type: 2, iov_truncated: 1, _pad: [0; 2], iov_count: 9, _pad2: [0; 4], requested_size: 42, return_code: 21 }; Readv, Writev);
    family!(MmapPayload { fd: 7, prot: 3, flags: 2, _pad: [0; 4], length: 4096, offset: 0, dev: 8 << 20, ino: 99, return_code: 8192 }; Mmap);
    family!(SendfileSplicePayload { in_fd: 7, out_fd: 9, in_fd_type: 0, out_fd_type: 1, _pad: [0; 6], size: 42, return_code: 21 }; Sendfile, Splice);
    // These hooks currently share the simple LSM decoder, not the richer wire payloads.
    family!(LsmBpfPayload { cmd: 7, return_code: -13 }; LsmFileOpen, LsmInodeUnlink, LsmInodeRename);
}

#[test]
fn exec_view_bytes() {
    for (status, name) in [
        (0, "unsupported"),
        (1, "complete"),
        (2, "unavailable"),
        (3, "changed"),
    ] {
        let payload = if status == 1 {
            ExecViewPayload {
                version: 1,
                status,
                root_inode: 81,
                root_dev: (259 << 20) | 513,
                mount_namespace: 4026531840,
                root_mount_id: 27,
                _pad: [0; 2],
            }
        } else {
            ExecViewPayload {
                version: 1,
                status,
                ..Default::default()
            }
        };
        snapshot(
            &format!("exec_view_{name}_bytes"),
            build_event(EventKind::ExecView, &payload),
        );
    }
}

#[test]
fn usdt_bytes() {
    use bloodhound_common::{
        UsdtTrainingPeerPayload, UsdtTrainingShellCaptureErrorPayload, UsdtTrainingShellPayload,
    };
    snapshot(
        "usdt_shell_bytes",
        build_event_with_vardata(
            EventKind::UsdtTrainingShellV3,
            &UsdtTrainingShellPayload {
                attach_point_id: 1,
                shell_pid: 1234,
                command_id: 99,
                command_kind: 1,
                semantic_flags: 1,
                exit_status: 2,
                command_name_len: 4,
                command_name_truncated: 0,
                _pad: 0,
            },
            b"echo",
        ),
    );
    snapshot(
        "usdt_peer_bytes",
        build_event(
            EventKind::UsdtTrainingPeerV1,
            &UsdtTrainingPeerPayload {
                attach_point_id: 2,
                _pad: 0,
                task_id: 99,
                result: 1,
                _pad2: 0,
            },
        ),
    );
    snapshot(
        "usdt_capture_error_bytes",
        build_event(
            EventKind::UsdtTrainingShellV3CaptureError,
            &UsdtTrainingShellCaptureErrorPayload {
                attach_point_id: 1,
                field_id: 3,
                read_error_code: 1,
                _pad: [0; 2],
            },
        ),
    );
}

#[test]
fn tty_v1_bytes() {
    for kind in [EventKind::TtyRead, EventKind::TtyWrite] {
        for (status, bytes) in [
            (CaptureStatus::Complete, b"ok\xff\0\r\n".to_vec()),
            (CaptureStatus::Truncated, vec![b'x'; MAX_TTY_DATA - 1]),
            (CaptureStatus::ReadError, vec![]),
        ] {
            snapshot(
                &format!("{kind:?}_{status:?}_bytes"),
                tty_capture_record(
                    kind,
                    HeaderCapture {
                        version: 1,
                        primary: status as u8,
                        secondary: 0,
                    },
                    &bytes,
                ),
            );
        }
    }
}
