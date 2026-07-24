//! eBPF programs owned by the trusted in-tree USDT collectors.
//!
//! These programs are never loaded from the VM. Userspace validates the
//! collector's fixed path, architecture, Build ID, provider/probe and note ABI
//! before attaching one of these programs at an exact static-note location.

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::uprobe,
    programs::ProbeContext,
};
use bloodhound_common::*;

use crate::{filter::get_task_info, helpers::emit_event, maps::ASSEMBLY_BUF};

const COMMAND_NAME_LIMIT: usize = 64;

#[inline(always)]
unsafe fn emit_shell(
    attach_point_id: u32,
    shell_pid: u32,
    command_id: u64,
    command_kind: u32,
    command_name: *const u8,
    semantic_flags: u32,
    exit_status: i32,
) {
    // A required pointer that cannot be read must not become a guessed value.
    // The userspace attachment layer treats an incompatible declared ABI as a
    // collector failure; this probe simply declines to emit an unsafe event.
    if command_name.is_null() {
        emit_shell_capture_error(attach_point_id, 3, 1);
        return;
    }
    let mut name = [0u8; COMMAND_NAME_LIMIT];
    let length = match bpf_probe_read_user_str_bytes(command_name, &mut name) {
        Ok(read) => read.len(),
        Err(_) => {
            emit_shell_capture_error(attach_point_id, 3, 1);
            return;
        }
    };
    let header = get_task_info(EventKind::UsdtTrainingShellV3 as u8);
    let payload = UsdtTrainingShellPayload {
        attach_point_id,
        shell_pid,
        command_id,
        command_kind,
        semantic_flags,
        exit_status,
        command_name_len: length as u16,
        // Aya's byte helper removes the terminating NUL. At the capture
        // boundary we cannot distinguish an exactly-63-byte string from one
        // that was truncated, so report the bounded, conservative result.
        command_name_truncated: (length == COMMAND_NAME_LIMIT - 1) as u8,
        _pad: 0,
    };
    let total = EventHeader::SIZE + UsdtTrainingShellPayload::SIZE + length;
    let assembly = match ASSEMBLY_BUF.get_ptr_mut(0) {
        Some(value) => &mut (*value).buf,
        None => return,
    };
    if total > assembly.len() {
        return;
    }
    core::ptr::copy_nonoverlapping(
        &header as *const EventHeader as *const u8,
        assembly.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        &payload as *const UsdtTrainingShellPayload as *const u8,
        assembly.as_mut_ptr().add(EventHeader::SIZE),
        UsdtTrainingShellPayload::SIZE,
    );
    if length != 0 {
        // `bpf_probe_read_kernel` cannot copy *from the BPF stack*.  Write
        // this small, collector-owned capture directly into the map value;
        // the fixed loop keeps both source and destination bounds visible to
        // the verifier.
        let destination = EventHeader::SIZE + UsdtTrainingShellPayload::SIZE;
        for index in 0..COMMAND_NAME_LIMIT {
            if index >= length {
                break;
            }
            assembly[destination + index] = name[index];
        }
    }
    emit_event(&assembly[..total]);
}

/// Report a required collector argument that could not be captured without
/// sending any pointer or process-memory detail across the BPF boundary.
#[inline(always)]
unsafe fn emit_shell_capture_error(attach_point_id: u32, field_id: u8, read_error_code: u8) {
    let header = get_task_info(EventKind::UsdtTrainingShellV3CaptureError as u8);
    let payload = UsdtTrainingShellCaptureErrorPayload {
        attach_point_id,
        field_id,
        read_error_code,
        _pad: [0; 2],
    };
    let total = EventHeader::SIZE + UsdtTrainingShellCaptureErrorPayload::SIZE;
    let mut bytes = [0u8; 128];
    core::ptr::copy_nonoverlapping(
        &header as *const EventHeader as *const u8,
        bytes.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        &payload as *const UsdtTrainingShellCaptureErrorPayload as *const u8,
        bytes.as_mut_ptr().add(EventHeader::SIZE),
        UsdtTrainingShellCaptureErrorPayload::SIZE,
    );
    emit_event(&bytes[..total]);
}

macro_rules! shell_attach_point {
    ($function:ident, $id:expr) => {
        #[uprobe]
        pub fn $function(ctx: ProbeContext) -> u32 {
            unsafe {
                emit_shell(
                    $id,
                    ctx.arg::<u64>(0).unwrap_or(0) as u32,
                    ctx.arg::<u64>(1).unwrap_or(0),
                    ctx.arg::<u64>(2).unwrap_or(u64::MAX) as u32,
                    ctx.arg::<u64>(3).unwrap_or(0) as *const u8,
                    ctx.arg::<u64>(4).unwrap_or(0) as u32,
                    ctx.arg::<i64>(5).unwrap_or(0) as i32,
                );
            }
            0
        }
    };
}

macro_rules! peer_attach_point {
    ($function:ident, $id:expr) => {
        #[uprobe]
        pub fn $function(ctx: ProbeContext) -> u32 {
            unsafe {
                let header = get_task_info(EventKind::UsdtTrainingPeerV1 as u8);
                let payload = UsdtTrainingPeerPayload {
                    attach_point_id: $id,
                    _pad: 0,
                    task_id: ctx.arg::<u64>(0).unwrap_or(0),
                    result: ctx.arg::<u64>(1).unwrap_or(u64::MAX) as u32,
                    _pad2: 0,
                };
                let total = EventHeader::SIZE + UsdtTrainingPeerPayload::SIZE;
                let mut bytes = [0u8; 128];
                core::ptr::copy_nonoverlapping(&header as *const EventHeader as *const u8, bytes.as_mut_ptr(), EventHeader::SIZE);
                core::ptr::copy_nonoverlapping(&payload as *const UsdtTrainingPeerPayload as *const u8, bytes.as_mut_ptr().add(EventHeader::SIZE), UsdtTrainingPeerPayload::SIZE);
                emit_event(&bytes[..total]);
            }
            0
        }
    };
}

// The maximum is collector-owned (not configuration) and gives each static
// note a stable `attach_point_id` without inspecting a runtime instruction
// pointer. A collector whose ABI legitimately needs more points must declare
// and compile more functions as part of its source change.
shell_attach_point!(usdt_training_shell_v3_0, 0);
shell_attach_point!(usdt_training_shell_v3_1, 1);
shell_attach_point!(usdt_training_shell_v3_2, 2);
shell_attach_point!(usdt_training_shell_v3_3, 3);
shell_attach_point!(usdt_training_shell_v3_4, 4);
shell_attach_point!(usdt_training_shell_v3_5, 5);
shell_attach_point!(usdt_training_shell_v3_6, 6);
shell_attach_point!(usdt_training_shell_v3_7, 7);

peer_attach_point!(usdt_training_peer_v1_0, 0);
peer_attach_point!(usdt_training_peer_v1_1, 1);
peer_attach_point!(usdt_training_peer_v1_2, 2);
peer_attach_point!(usdt_training_peer_v1_3, 3);
peer_attach_point!(usdt_training_peer_v1_4, 4);
peer_attach_point!(usdt_training_peer_v1_5, 5);
peer_attach_point!(usdt_training_peer_v1_6, 6);
peer_attach_point!(usdt_training_peer_v1_7, 7);
