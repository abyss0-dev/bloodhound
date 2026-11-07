use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::deserializer::{BehaviorEvent, EventClass, EventHeaderJson, EventTypeJson, Layer};

pub(super) const TRAINING_SHELL_V3_ID: &str = "training-shell-v3";
const TRAINING_PEER_V1_ID: &str = "training-peer-v1";

/// Metadata that is trusted because it is compiled into Bloodhound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CollectorMetadata {
    pub(super) id: &'static str,
    pub(super) architecture: Architecture,
    pub(super) target_path: &'static str,
    pub(super) build_ids: &'static [&'static str],
    pub(super) provider: &'static str,
    pub(super) probe: &'static str,
    program_prefix: &'static str,
    pub(super) maximum_attach_points: usize,
    /// Exact, build-time-declared operand form accepted from the USDT note.
    pub(super) operands: &'static str,
}

impl CollectorMetadata {
    pub(super) fn program_name(&self, attach_point_id: usize) -> String {
        format!("{}_{attach_point_id}", self.program_prefix)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Architecture {
    X86_64,
}

impl Architecture {
    pub(super) fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
        }
    }
}

// These IDs are intentionally fixed with `-Wl,--build-id=0x...` in
// e2e/fixtures/Makefile.  They are not values read from configuration.
const TRAINING_SHELL_V3_BUILD_IDS: &[&str] = &["11223344556677889900aabbccddeeff00112233"];
const TRAINING_PEER_V1_BUILD_IDS: &[&str] = &["44556677889900aabbccddeeff00112233445566"];

const REGISTRY: &[CollectorMetadata] = &[
    CollectorMetadata {
        id: TRAINING_SHELL_V3_ID,
        architecture: Architecture::X86_64,
        target_path: "/opt/bloodhound/usdt-fixtures/training-shell-v3",
        build_ids: TRAINING_SHELL_V3_BUILD_IDS,
        provider: "abyss0_shell",
        probe: "simple_command_completed",
        program_prefix: "usdt_training_shell_v3",
        maximum_attach_points: 8,
        operands: "8@%rdi 8@%rsi 8@%rdx 8@%rcx 8@%r8 8@%r9",
    },
    CollectorMetadata {
        id: TRAINING_PEER_V1_ID,
        architecture: Architecture::X86_64,
        target_path: "/opt/bloodhound/usdt-fixtures/training-peer-v1",
        build_ids: TRAINING_PEER_V1_BUILD_IDS,
        provider: "abyss0_peer",
        probe: "task_finished",
        program_prefix: "usdt_training_peer_v1",
        maximum_attach_points: 8,
        operands: "8@%rdi 8@%rsi",
    },
];

#[cfg(test)]
fn registered_collectors() -> &'static [CollectorMetadata] {
    REGISTRY
}

pub(super) fn collector(id: &str) -> Option<&'static CollectorMetadata> {
    REGISTRY.iter().find(|candidate| candidate.id == id)
}

/// The only configuration accepted from the training VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Selection {
    pub(super) collector_id: String,
    pub(super) enabled: bool,
}

#[derive(Debug)]
enum SelectionRejected {
    UnknownCollector(String),
    Malformed(String),
}

impl std::fmt::Display for SelectionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCollector(id) => write!(f, "unknown registered collector {id:?}"),
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for SelectionRejected {}

/// Reject repeated IDs, including enabled/disabled conflicts, before attachment.
/// Otherwise a later failed attempt could overwrite an already-true availability.
pub(crate) fn validate_selections(selections: &[Selection]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for selection in selections {
        if !ids.insert(&selection.collector_id) {
            bail!("duplicate USDT collector selection {:?}", selection.collector_id);
        }
    }
    Ok(())
}

/// Read and strictly validate a trusted collector-selection file.
///
/// It is intentionally not a generic TOML decode: rejecting every unknown key
/// is part of the security boundary and makes accidental expansion visible.
pub(crate) fn load_selection(path: &Path) -> Result<Selection> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading trusted USDT configuration {}", path.display()))?;
    parse_selection(&text)
        .with_context(|| format!("validating trusted USDT configuration {}", path.display()))
}

/// Render a failed selection validation without losing the configured ID.
/// This is intentionally best-effort *only for diagnostic attribution*: the
/// configuration remains rejected and is never used to select a target.
pub(crate) fn selection_failure_diagnostic(path: &Path, error: &anyhow::Error) -> BehaviorEvent {
    let configured_id = fs::read_to_string(path)
        .ok()
        .and_then(|text| configured_collector_id(&text))
        .unwrap_or_else(|| "configuration".to_owned());
    let reason = match error.downcast_ref::<SelectionRejected>() {
        Some(SelectionRejected::UnknownCollector(_)) => ReasonCode::UnknownCollector,
        Some(SelectionRejected::Malformed(_)) | None => ReasonCode::AbiIncompatible,
    };
    diagnostic(&configured_id, reason, None, crate::clock::monotonic_now_ns())
}

fn configured_collector_id(text: &str) -> Option<String> {
    text.lines().find_map(|raw_line| {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before)
            .trim();
        let (key, value) = line.split_once('=')?;
        if key.trim() != "collector" {
            return None;
        }
        value
            .trim()
            .strip_prefix('"')?
            .strip_suffix('"')
            .map(str::to_owned)
    })
}

fn parse_selection(text: &str) -> Result<Selection, SelectionRejected> {
    let mut collector_id = None;
    let mut enabled = None;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SelectionRejected::Malformed(format!("line {} is not key = value", line_no + 1)))?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "collector" => {
                if collector_id.is_some() {
                    return Err(SelectionRejected::Malformed("collector is declared more than once".into()));
                }
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .ok_or_else(|| SelectionRejected::Malformed("collector must be a quoted registered ID".into()))?;
                if value.is_empty() || value.chars().any(|ch| matches!(ch, '/' | '\\' | '\0')) {
                    return Err(SelectionRejected::Malformed("collector must be a registered ID".into()));
                }
                collector_id = Some(value.to_owned());
            }
            "enabled" => {
                if enabled.is_some() {
                    return Err(SelectionRejected::Malformed("enabled is declared more than once".into()));
                }
                enabled = Some(match value {
                    "true" => true,
                    "false" => false,
                    _ => return Err(SelectionRejected::Malformed("enabled must be true or false".into())),
                });
            }
            // In particular this rejects bpf object paths, native code paths,
            // offsets, provider/probe overrides, argument definitions and field
            // mappings. Do not add a permissive catch-all here.
            _ => return Err(SelectionRejected::Malformed(format!("configuration key {key:?} is not permitted"))),
        }
    }

    let selection = Selection {
        collector_id: collector_id.ok_or_else(|| SelectionRejected::Malformed("missing collector".into()))?,
        enabled: enabled.ok_or_else(|| SelectionRejected::Malformed("missing enabled".into()))?,
    };
    if collector(&selection.collector_id).is_none() {
        return Err(SelectionRejected::UnknownCollector(selection.collector_id));
    }
    Ok(selection)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReasonCode {
    Disabled,
    UnknownCollector,
    UnsupportedArchitecture,
    TargetBuildIdMismatch,
    ProbeNotFound,
    AbiIncompatible,
    SemaphoreUnavailable,
    AttachFailed,
}

impl ReasonCode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UnknownCollector => "unknown_collector",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::TargetBuildIdMismatch => "target_build_id_mismatch",
            Self::ProbeNotFound => "probe_not_found",
            Self::AbiIncompatible => "abi_incompatible",
            Self::SemaphoreUnavailable => "semaphore_unavailable",
            Self::AttachFailed => "attach_failed",
        }
    }
}

pub(super) fn diagnostic(collector_id: &str, reason: ReasonCode, context: Option<Value>, timestamp: u64) -> BehaviorEvent {
    let mut args = serde_json::Map::new();
    args.insert("collector_id".into(), Value::String(collector_id.into()));
    args.insert("reason_code".into(), Value::String(reason.as_str().into()));
    if let Some(Value::Object(extra)) = context {
        // Callers may only add metadata that is already bounded and documented.
        args.extend(extra);
    }
    BehaviorEvent {
        header: EventHeaderJson::unattributed(timestamp),
        event: EventTypeJson {
            event_type: EventClass::Diagnostic,
            name: "usdt.collector".into(),
            layer: Layer::Behavior,
        },
        args: Some(Value::Object(args)),
        return_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use serde_json::json;

    #[test]
    fn registry_has_two_distinct_real_collectors() {
        assert_eq!(registered_collectors().len(), 2);
        assert_ne!(
            registered_collectors()[0].provider,
            registered_collectors()[1].provider
        );
        assert_ne!(
            registered_collectors()[0].probe,
            registered_collectors()[1].probe
        );
    }

    #[test]
    fn selection_has_no_escape_hatches() {
        let parsed =
            parse_selection("collector = \"training-shell-v3\"\nenabled = true\n").unwrap();
        assert_eq!(parsed.collector_id, TRAINING_SHELL_V3_ID);
        for forbidden in [
            "bpf_object",
            "offset",
            "provider",
            "probe",
            "arguments",
            "field_mapping",
            "native_code",
        ] {
            let source = format!(
                "collector = \"training-shell-v3\"\nenabled = true\n{forbidden} = \"no\"\n"
            );
            assert!(
                parse_selection(&source).is_err(),
                "{forbidden} must fail closed"
            );
        }
    }

    #[test]
    fn every_rejected_selection_has_one_bounded_diagnostic() {
        for forbidden in [
            "bpf_object",
            "offset",
            "provider",
            "probe",
            "arguments",
            "field_mapping",
            "native_code",
        ] {
            let source = format!(
                "collector = \"training-shell-v3\"\nenabled = true\n{forbidden} = \"no\"\n"
            );
            let error = parse_selection(&source).unwrap_err().into();
            let path = std::env::temp_dir().join(format!(
                "bloodhound-usdt-selection-{forbidden}-{}",
                std::process::id()
            ));
            fs::write(&path, source).unwrap();
            let diagnostic = selection_failure_diagnostic(&path, &error);
            fs::remove_file(&path).unwrap();
            let args = diagnostic.args.unwrap();
            assert_eq!(args["collector_id"], TRAINING_SHELL_V3_ID);
            assert_eq!(args["reason_code"], ReasonCode::AbiIncompatible.as_str());
            assert_eq!(args.as_object().unwrap().len(), 2);
        }
    }

    #[test]
    fn duplicate_selections_cannot_overwrite_availability() {
        let enabled = Selection {
            collector_id: TRAINING_SHELL_V3_ID.into(),
            enabled: true,
        };
        let disabled = Selection {
            enabled: false,
            ..enabled.clone()
        };
        // All duplicate orders are rejected before the loader can attach, so
        // neither a second attach failure nor a disabled entry can mask success.
        for selections in [
            vec![enabled.clone(), enabled.clone()],
            vec![enabled.clone(), disabled.clone()],
            vec![disabled, enabled.clone()],
        ] {
            let error = validate_selections(&selections).unwrap_err();
            assert!(error.to_string().contains("duplicate USDT collector selection"));
        }
        assert!(validate_selections(&[
            enabled,
            Selection {
                collector_id: TRAINING_PEER_V1_ID.into(),
                enabled: true,
            },
        ])
        .is_ok());
        assert!(validate_selections(&[]).is_ok());
    }

    #[test]
    fn unknown_collector_fails_validation() {
        assert!(parse_selection("collector = \"not-built-in\"\nenabled = true\n").is_err());
    }

    #[test]
    fn selection_failure_diagnostic_keeps_the_unknown_collector_id() {
        let path = std::env::temp_dir().join(format!(
            "bloodhound-usdt-selection-{}-{}.toml",
            std::process::id(),
            crate::clock::monotonic_now_ns(),
        ));
        fs::write(&path, "collector = \"not-built-in\"\nenabled = true\n").unwrap();
        let error = load_selection(&path).unwrap_err();
        let event = selection_failure_diagnostic(&path, &error);
        fs::remove_file(&path).unwrap();
        let args = event.args.unwrap();
        assert_eq!(args["collector_id"], "not-built-in");
        assert_eq!(args["reason_code"], "unknown_collector");
    }

    #[test]
    fn selection_failure_diagnostic_keeps_the_id_after_an_earlier_malformed_line() {
        let path = std::env::temp_dir().join(format!(
            "bloodhound-usdt-unknown registered collector-{}-{}.toml",
            std::process::id(),
            crate::clock::monotonic_now_ns(),
        ));
        for first_line in ["not key value", "unknown registered collector = true"] {
            fs::write(&path, format!("{first_line}\ncollector = \"training-shell-v3\"\nenabled = true\n")).unwrap();
            let error = load_selection(&path).unwrap_err();
            let event = selection_failure_diagnostic(&path, &error);
            let args = event.args.unwrap();
            assert_eq!(args["collector_id"], TRAINING_SHELL_V3_ID);
            assert_eq!(args["reason_code"], "abi_incompatible");
            assert_eq!(args.as_object().unwrap().len(), 2);
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn selection_failure_diagnostic_keeps_io_errors_abi_incompatible() {
        let path = std::env::temp_dir().join(format!(
            "bloodhound-usdt-missing-unknown registered collector-{}-{}.toml",
            std::process::id(),
            crate::clock::monotonic_now_ns(),
        ));
        let error = load_selection(&path).unwrap_err();
        assert!(error.downcast_ref::<io::Error>().is_some());
        let args = selection_failure_diagnostic(&path, &error).args.unwrap();
        assert_eq!(args["collector_id"], "configuration");
        assert_eq!(args["reason_code"], "abi_incompatible");
        assert_eq!(args.as_object().unwrap().len(), 2);
    }

    #[test]
    fn derived_program_names_preserve_the_attach_contract() {
        for (id, prefix) in [
            (TRAINING_SHELL_V3_ID, "usdt_training_shell_v3"),
            (TRAINING_PEER_V1_ID, "usdt_training_peer_v1"),
        ] {
            let metadata = collector(id).unwrap();
            assert_eq!(metadata.program_prefix, prefix);
            for attach_point_id in 0..metadata.maximum_attach_points {
                assert_eq!(
                    metadata.program_name(attach_point_id),
                    format!("{prefix}_{attach_point_id}")
                );
            }
        }
    }

    #[test]
    fn diagnostic_has_the_canonical_shape() {
        let event = diagnostic(TRAINING_SHELL_V3_ID, ReasonCode::ProbeNotFound, None, 1_500_000_000);
        insta::assert_snapshot!("usdt_collector_bytes", serde_json::to_string(&event).unwrap());
        let contextual = diagnostic(TRAINING_SHELL_V3_ID, ReasonCode::AttachFailed,
            Some(json!({"attach_point_id": 1})), 1_500_000_000);
        insta::assert_snapshot!("usdt_collector_context_bytes", serde_json::to_string(&contextual).unwrap());
        assert_eq!(event.event.event_type, EventClass::Diagnostic);
        assert_eq!(event.event.name, "usdt.collector");
        assert_eq!(event.args.unwrap()["reason_code"], "probe_not_found");
    }
}
