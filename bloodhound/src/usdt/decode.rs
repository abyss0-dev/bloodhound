use anyhow::{anyhow, bail, Result};
use bloodhound_common::{EventKind, UsdtTrainingPeerPayload, UsdtTrainingShellCaptureErrorPayload, UsdtTrainingShellPayload, TRAINING_SHELL_COMMAND_NAME_LIMIT};
use serde_json::json;

use crate::deserializer::{EventClass, EventTypeJson, Layer, Payload};
use super::registry::{ReasonCode, TRAINING_SHELL_V3_ID};

/// Convert a collector-owned fixed ring-buffer payload to a canonical event.
/// The core deserializer delegates here generically and contains no collector
/// IDs, provider/probe names, or field definitions.
pub(crate) fn decode_payload(kind: EventKind, payload: &[u8]) -> Result<Payload> {
    match kind {
        EventKind::UsdtTrainingShellV3 => decode_training_shell_payload(payload),
        EventKind::UsdtTrainingPeerV1 => decode_training_peer_payload(payload),
        EventKind::UsdtTrainingShellV3CaptureError => decode_training_shell_capture_error(payload),
        _ => bail!("not a registered USDT event kind"),
    }
}

fn decode_training_shell_capture_error(payload: &[u8]) -> Result<Payload> {
    if payload.len() != UsdtTrainingShellCaptureErrorPayload::SIZE {
        bail!("USDT training-shell capture-error payload has an invalid size");
    }
    let fixed = unsafe {
        core::ptr::read_unaligned(payload.as_ptr() as *const UsdtTrainingShellCaptureErrorPayload)
    };
    let field = match fixed.field_id {
        3 => "command_name",
        _ => bail!("USDT training-shell capture-error field is unknown"),
    };
    let read_error_code = match fixed.read_error_code {
        1 => "unreadable_user_memory",
        _ => bail!("USDT training-shell capture-error reason is unknown"),
    };
    Ok(Payload {
        event: EventTypeJson {
            event_type: EventClass::Diagnostic,
            name: "usdt.collector".into(),
            layer: Layer::Behavior,
        },
        args: Some(json!({
            "collector_id": TRAINING_SHELL_V3_ID,
            "reason_code": ReasonCode::AbiIncompatible.as_str(),
            "attach_point_id": fixed.attach_point_id,
            "argument": field,
            "read_error_code": read_error_code,
        })),
        return_code: None,
    })
}

fn decode_training_shell_payload(payload: &[u8]) -> Result<Payload> {
    if payload.len() < UsdtTrainingShellPayload::SIZE {
        bail!("USDT training-shell payload too short");
    }
    let fixed =
        unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const UsdtTrainingShellPayload) };
    let command_name_len = fixed.command_name_len as usize;
    if command_name_len > TRAINING_SHELL_COMMAND_NAME_LIMIT {
        bail!("USDT command-name exceeds its compiled capture limit");
    }
    if fixed.command_name_truncated > 1 {
        bail!("USDT command-name truncation flag is invalid");
    }
    let name_end = UsdtTrainingShellPayload::SIZE
        .checked_add(command_name_len)
        .ok_or_else(|| anyhow!("USDT command-name length overflow"))?;
    if payload.len() != name_end {
        bail!("USDT training-shell payload has invalid length");
    }
    let command_name = payload
        .get(UsdtTrainingShellPayload::SIZE..name_end)
        .ok_or_else(|| anyhow!("USDT command-name exceeds payload"))?;
    let command_name =
        std::str::from_utf8(command_name).map_err(|_| anyhow!("USDT command-name is not UTF-8"))?;
    let command_name_bytes = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(command_name.as_bytes())
    };
    let command_kind = match fixed.command_kind {
        0 => "builtin",
        1 => "external",
        2 => "function",
        _ => "other",
    };
    let mut flags = Vec::new();
    if fixed.semantic_flags & 1 != 0 {
        flags.push("SELF_PID_EXPANDED");
    }
    Ok(Payload {
        event: EventTypeJson {
            event_type: EventClass::Usdt,
            name: "abyss0_shell.simple_command_completed".into(),
            layer: Layer::Behavior,
        },
        args: Some(json!({
            "attach_point_id": fixed.attach_point_id,
            "shell_pid": fixed.shell_pid,
            "command_id": fixed.command_id,
            "command_kind": command_kind,
            "command_name": { "value": command_name, "capture_limit": TRAINING_SHELL_COMMAND_NAME_LIMIT, "truncated": fixed.command_name_truncated != 0 },
            "command_name_bytes": { "base64": command_name_bytes, "capture_limit": TRAINING_SHELL_COMMAND_NAME_LIMIT, "observed_length": fixed.command_name_len, "truncated": fixed.command_name_truncated != 0 },
            "semantic_flags": flags,
            "exit_status": fixed.exit_status,
        })),
        return_code: None,
    })
}

fn decode_training_peer_payload(payload: &[u8]) -> Result<Payload> {
    if payload.len() != UsdtTrainingPeerPayload::SIZE {
        bail!("USDT training-peer payload has invalid length");
    }
    let fixed =
        unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const UsdtTrainingPeerPayload) };
    Ok(Payload {
        event: EventTypeJson {
            event_type: EventClass::Usdt,
            name: "abyss0_peer.task_finished".into(),
            layer: Layer::Behavior,
        },
        args: Some(json!({
            "attach_point_id": fixed.attach_point_id,
            "task_id": fixed.task_id,
            "result": match fixed.result { 0 => "ok", 1 => "failed", _ => "other" },
        })),
        return_code: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_owned_shell_decode_preserves_bounded_values() {
        let fixed = UsdtTrainingShellPayload {
            attach_point_id: 3,
            shell_pid: 412,
            command_id: 17,
            command_kind: 0,
            semantic_flags: 1,
            exit_status: 0,
            command_name_len: 4,
            command_name_truncated: 0,
            _pad: 0,
        };
        let mut payload = unsafe {
            std::slice::from_raw_parts(
                &fixed as *const UsdtTrainingShellPayload as *const u8,
                UsdtTrainingShellPayload::SIZE,
            )
            .to_vec()
        };
        payload.extend_from_slice(b"echo");
        let decoded = decode_payload(EventKind::UsdtTrainingShellV3, &payload).unwrap();
        assert_eq!(decoded.event.name, "abyss0_shell.simple_command_completed");
        let args = decoded.args.unwrap();
        assert_eq!(args["attach_point_id"], 3);
        assert_eq!(args["command_name"]["value"], "echo");
        assert_eq!(args["command_name_bytes"]["base64"], "ZWNobw==");
    }

    #[test]
    fn shell_decode_rejects_noncanonical_payload_lengths_and_bounds() {
        let fixed = UsdtTrainingShellPayload {
            attach_point_id: 0,
            shell_pid: 1,
            command_id: 1,
            command_kind: 0,
            semantic_flags: 0,
            exit_status: 0,
            command_name_len: 4,
            command_name_truncated: 0,
            _pad: 0,
        };
        let mut payload = unsafe {
            std::slice::from_raw_parts(
                &fixed as *const UsdtTrainingShellPayload as *const u8,
                UsdtTrainingShellPayload::SIZE,
            )
            .to_vec()
        };
        payload.extend_from_slice(b"echo");
        payload.push(0);
        assert!(decode_training_shell_payload(&payload).is_err());

        let mut oversized = fixed;
        oversized.command_name_len = (TRAINING_SHELL_COMMAND_NAME_LIMIT + 1) as u16;
        let payload = unsafe {
            std::slice::from_raw_parts(
                &oversized as *const UsdtTrainingShellPayload as *const u8,
                UsdtTrainingShellPayload::SIZE,
            )
        };
        assert!(decode_training_shell_payload(payload).is_err());

        let mut invalid_flag = fixed;
        invalid_flag.command_name_truncated = 2;
        let payload = unsafe {
            std::slice::from_raw_parts(
                &invalid_flag as *const UsdtTrainingShellPayload as *const u8,
                UsdtTrainingShellPayload::SIZE,
            )
        };
        assert!(decode_training_shell_payload(payload).is_err());
    }

    #[test]
    fn collector_owned_capture_error_becomes_a_bounded_diagnostic() {
        let fixed = UsdtTrainingShellCaptureErrorPayload {
            attach_point_id: 2,
            field_id: 3,
            read_error_code: 1,
            _pad: [0; 2],
        };
        let payload = unsafe {
            std::slice::from_raw_parts(
                &fixed as *const UsdtTrainingShellCaptureErrorPayload as *const u8,
                UsdtTrainingShellCaptureErrorPayload::SIZE,
            )
        };
        let Payload { event, args, .. } =
            decode_payload(EventKind::UsdtTrainingShellV3CaptureError, payload).unwrap();
        assert_eq!(event.event_type, EventClass::Diagnostic);
        assert_eq!(event.name, "usdt.collector");
        assert_eq!(event.layer, Layer::Behavior);
        assert_eq!(
            args.unwrap(),
            json!({
                "collector_id": TRAINING_SHELL_V3_ID,
                "reason_code": "abi_incompatible",
                "attach_point_id": 2,
                "argument": "command_name",
                "read_error_code": "unreadable_user_memory",
            })
        );
    }
}
