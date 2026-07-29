//! Trusted, in-tree USDT collector registry.
//!
//! This module deliberately keeps the VM supplied configuration small.  A
//! configuration can select an ID compiled into this binary and turn it on or
//! off; it can never provide an ELF path, an offset, BPF object, probe name,
//! or a memory-read rule.  Those are all collector metadata below.

use std::{
    ffi::CString,
    fs, io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use bloodhound_common::{
    EventKind, UsdtTrainingPeerPayload, UsdtTrainingShellCaptureErrorPayload,
    UsdtTrainingShellPayload,
};
use serde_json::{json, Value};

use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};

pub const TRAINING_SHELL_V3_ID: &str = "training-shell-v3";
pub const TRAINING_PEER_V1_ID: &str = "training-peer-v1";

/// Metadata that is trusted because it is compiled into Bloodhound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectorMetadata {
    pub id: &'static str,
    pub architecture: Architecture,
    pub target_path: &'static str,
    pub build_ids: &'static [&'static str],
    pub provider: &'static str,
    pub probe: &'static str,
    pub schema_version: u16,
    pub maximum_attach_points: usize,
    /// Exact, build-time-declared operand form accepted from the USDT note.
    pub operands: &'static str,
    pub fields: &'static [FieldMetadata],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldMetadata {
    pub name: &'static str,
    pub source_type: &'static str,
    pub operand_form: &'static str,
    pub output_type: &'static str,
    pub maximum_size: Option<usize>,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
}

impl Architecture {
    fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
        }
    }
}

// These IDs are intentionally fixed with `-Wl,--build-id=0x...` in
// e2e/fixtures/Makefile.  They are not values read from configuration.
const TRAINING_SHELL_V3_BUILD_IDS: &[&str] = &["11223344556677889900aabbccddeeff00112233"];
const TRAINING_PEER_V1_BUILD_IDS: &[&str] = &["44556677889900aabbccddeeff00112233445566"];

const TRAINING_SHELL_FIELDS: &[FieldMetadata] = &[
    FieldMetadata {
        name: "shell_pid",
        source_type: "u32",
        operand_form: "8@%rdi",
        output_type: "u32",
        maximum_size: None,
        required: true,
    },
    FieldMetadata {
        name: "command_id",
        source_type: "u64",
        operand_form: "8@%rsi",
        output_type: "u64",
        maximum_size: None,
        required: true,
    },
    FieldMetadata {
        name: "command_kind",
        source_type: "enum",
        operand_form: "8@%rdx",
        output_type: "enum",
        maximum_size: None,
        required: true,
    },
    FieldMetadata {
        name: "command_name",
        source_type: "utf8_pointer",
        operand_form: "8@%rcx",
        output_type: "utf8",
        maximum_size: Some(64),
        required: true,
    },
    FieldMetadata {
        name: "semantic_flags",
        source_type: "u32",
        operand_form: "8@%r8",
        output_type: "enum",
        maximum_size: None,
        required: true,
    },
    FieldMetadata {
        name: "exit_status",
        source_type: "i32",
        operand_form: "8@%r9",
        output_type: "i32",
        maximum_size: None,
        required: true,
    },
];

const TRAINING_PEER_FIELDS: &[FieldMetadata] = &[
    FieldMetadata {
        name: "task_id",
        source_type: "u64",
        operand_form: "8@%rdi",
        output_type: "u64",
        maximum_size: None,
        required: true,
    },
    FieldMetadata {
        name: "result",
        source_type: "enum",
        operand_form: "8@%rsi",
        output_type: "enum",
        maximum_size: None,
        required: true,
    },
];

const REGISTRY: &[CollectorMetadata] = &[
    CollectorMetadata {
        id: TRAINING_SHELL_V3_ID,
        architecture: Architecture::X86_64,
        target_path: "/opt/bloodhound/usdt-fixtures/training-shell-v3",
        build_ids: TRAINING_SHELL_V3_BUILD_IDS,
        provider: "abyss0_shell",
        probe: "simple_command_completed",
        schema_version: 3,
        maximum_attach_points: 8,
        operands: "8@%rdi 8@%rsi 8@%rdx 8@%rcx 8@%r8 8@%r9",
        fields: TRAINING_SHELL_FIELDS,
    },
    CollectorMetadata {
        id: TRAINING_PEER_V1_ID,
        architecture: Architecture::X86_64,
        target_path: "/opt/bloodhound/usdt-fixtures/training-peer-v1",
        build_ids: TRAINING_PEER_V1_BUILD_IDS,
        provider: "abyss0_peer",
        probe: "task_finished",
        schema_version: 1,
        maximum_attach_points: 8,
        operands: "8@%rdi 8@%rsi",
        fields: TRAINING_PEER_FIELDS,
    },
];

pub fn registered_collectors() -> &'static [CollectorMetadata] {
    REGISTRY
}

pub fn collector(id: &str) -> Option<&'static CollectorMetadata> {
    REGISTRY.iter().find(|candidate| candidate.id == id)
}

/// The only configuration accepted from the training VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub collector_id: String,
    pub enabled: bool,
}

/// Read and strictly validate a trusted collector-selection file.
///
/// It is intentionally not a generic TOML decode: rejecting every unknown key
/// is part of the security boundary and makes accidental expansion visible.
pub fn load_selection(path: &Path) -> Result<Selection> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading trusted USDT configuration {}", path.display()))?;
    parse_selection(&text)
        .with_context(|| format!("validating trusted USDT configuration {}", path.display()))
}

/// Render a failed selection validation without losing the configured ID.
/// This is intentionally best-effort *only for diagnostic attribution*: the
/// configuration remains rejected and is never used to select a target.
pub fn selection_failure_diagnostic(path: &Path, error: &anyhow::Error) -> BehaviorEvent {
    let configured_id = fs::read_to_string(path)
        .ok()
        .and_then(|text| configured_collector_id(&text))
        .unwrap_or_else(|| "configuration".to_owned());
    let reason = if format!("{error:#}").contains("unknown registered collector") {
        ReasonCode::UnknownCollector
    } else {
        ReasonCode::AbiIncompatible
    };
    diagnostic(&configured_id, reason, None)
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

pub fn parse_selection(text: &str) -> Result<Selection> {
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
            .ok_or_else(|| anyhow!("line {} is not key = value", line_no + 1))?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "collector" => {
                if collector_id.is_some() {
                    bail!("collector is declared more than once");
                }
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .ok_or_else(|| anyhow!("collector must be a quoted registered ID"))?;
                if value.is_empty() || value.chars().any(|ch| matches!(ch, '/' | '\\' | '\0')) {
                    bail!("collector must be a registered ID");
                }
                collector_id = Some(value.to_owned());
            }
            "enabled" => {
                if enabled.is_some() {
                    bail!("enabled is declared more than once");
                }
                enabled = Some(match value {
                    "true" => true,
                    "false" => false,
                    _ => bail!("enabled must be true or false"),
                });
            }
            // In particular this rejects bpf object paths, native code paths,
            // offsets, provider/probe overrides, argument definitions and field
            // mappings. Do not add a permissive catch-all here.
            _ => bail!("configuration key {key:?} is not permitted"),
        }
    }

    let selection = Selection {
        collector_id: collector_id.ok_or_else(|| anyhow!("missing collector"))?,
        enabled: enabled.ok_or_else(|| anyhow!("missing enabled"))?,
    };
    if collector(&selection.collector_id).is_none() {
        bail!("unknown registered collector {:?}", selection.collector_id);
    }
    Ok(selection)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonCode {
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
    pub fn as_str(self) -> &'static str {
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

pub fn diagnostic(collector_id: &str, reason: ReasonCode, context: Option<Value>) -> BehaviorEvent {
    let mut args = serde_json::Map::new();
    args.insert("collector_id".into(), Value::String(collector_id.into()));
    args.insert("reason_code".into(), Value::String(reason.as_str().into()));
    if let Some(Value::Object(extra)) = context {
        // Callers may only add metadata that is already bounded and documented.
        args.extend(extra);
    }
    BehaviorEvent {
        header: EventHeaderJson {
            timestamp: now_seconds(),
            auid: 0,
            sessionid: 0,
            pid: 0,
            ppid: None,
            comm: String::new(),
        },
        event: EventTypeJson {
            event_type: "DIAGNOSTIC".into(),
            name: "usdt.collector".into(),
            layer: "behavior".into(),
        },
        proc: None,
        args: Some(Value::Object(args)),
        return_code: None,
    }
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

/// A static probe discovered exclusively in `.note.stapsdt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StapsdtProbe {
    pub provider: String,
    pub name: String,
    pub operands: String,
    /// File offset required by the uprobe API, never a symbol or a config value.
    pub file_offset: u64,
    pub semaphore_address: u64,
    /// File offset for Linux's uprobe ref-counter interface. `None` means the
    /// static note does not require a semaphore.
    pub semaphore_file_offset: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTarget {
    pub path: PathBuf,
    pub build_id: String,
    pub probes: Vec<StapsdtProbe>,
}

/// Validate path, architecture, Build ID and the collector's exact note ABI.
/// No attachment can be attempted unless this returns a verified target.
pub fn verify_target(
    metadata: &CollectorMetadata,
) -> std::result::Result<VerifiedTarget, ReasonCode> {
    let path = PathBuf::from(metadata.target_path);
    let data = fs::read(&path).map_err(|_| ReasonCode::TargetBuildIdMismatch)?;
    let elf = ElfView::parse(&data).map_err(|_| ReasonCode::AbiIncompatible)?;
    if elf.machine != metadata.architecture.elf_machine() {
        return Err(ReasonCode::UnsupportedArchitecture);
    }
    let build_id = elf.build_id().ok_or(ReasonCode::TargetBuildIdMismatch)?;
    if !metadata
        .build_ids
        .iter()
        .any(|expected| *expected == build_id)
    {
        return Err(ReasonCode::TargetBuildIdMismatch);
    }
    let probes = elf
        .stapsdt_probes()
        .map_err(|_| ReasonCode::AbiIncompatible)?;
    let matching: Vec<_> = probes
        .into_iter()
        .filter(|probe| probe.provider == metadata.provider && probe.name == metadata.probe)
        .collect();
    if matching.is_empty() {
        return Err(ReasonCode::ProbeNotFound);
    }
    if matching
        .iter()
        .any(|probe| probe.operands != metadata.operands)
    {
        return Err(ReasonCode::AbiIncompatible);
    }
    if matching
        .iter()
        .any(|probe| probe.semaphore_address != 0 && probe.semaphore_file_offset.is_none())
    {
        return Err(ReasonCode::SemaphoreUnavailable);
    }
    Ok(VerifiedTarget {
        path,
        build_id,
        probes: matching,
    })
}

/// Attach exactly the precompiled program selected by trusted configuration.
///
/// The target is resolved only after `verify_target`; we deliberately pass no
/// PID to Aya so a verified executable is observed for every process that
/// executes it. Links remain owned by Aya's `Ebpf` instance and are therefore
/// torn down on daemon shutdown.
/// Owns fd-based uprobe links whose reference counters are maintained by the
/// kernel. Dropping an fd detaches the link and decrements its USDT semaphore.
#[derive(Default)]
pub struct AttachmentLinks {
    semaphore_links: Vec<OwnedFd>,
}

impl AttachmentLinks {
    fn checkpoint(&self) -> usize {
        self.semaphore_links.len()
    }
    fn rollback(&mut self, checkpoint: usize) {
        self.semaphore_links.truncate(checkpoint);
    }
}

pub fn attach_selected(
    bpf: &mut aya::Ebpf,
    selection: &Selection,
    links: &mut AttachmentLinks,
) -> Vec<BehaviorEvent> {
    if !selection.enabled {
        return vec![diagnostic(
            &selection.collector_id,
            ReasonCode::Disabled,
            None,
        )];
    }
    let Some(metadata) = collector(&selection.collector_id) else {
        return vec![diagnostic(
            &selection.collector_id,
            ReasonCode::UnknownCollector,
            None,
        )];
    };
    let target = match verify_target(metadata) {
        Ok(target) => target,
        Err(reason) => {
            return vec![diagnostic(
                metadata.id,
                reason,
                Some(json!({"target_path": metadata.target_path})),
            )]
        }
    };
    let attach_result: Result<()> = (|| {
        use aya::programs::uprobe::UProbeLinkId;
        use aya::programs::UProbe;
        let semaphore_checkpoint = links.checkpoint();
        let mut aya_links: Vec<(String, UProbeLinkId)> = Vec::new();
        if target.probes.len() > metadata.maximum_attach_points {
            bail!("collector has more static locations than its compiled attach-point programs");
        }
        for (attach_point_id, probe) in target.probes.iter().enumerate() {
            let program_name = match metadata.id {
                TRAINING_SHELL_V3_ID => format!("usdt_training_shell_v3_{attach_point_id}"),
                TRAINING_PEER_V1_ID => format!("usdt_training_peer_v1_{attach_point_id}"),
                _ => bail!("unknown compiled collector"),
            };
            let program: &mut UProbe = bpf
                .program_mut(&program_name)
                .with_context(|| {
                    format!("USDT program {program_name} is not in the embedded object")
                })?
                .try_into()?;
            program.load()?;
            let attached: Result<()> = if let Some(semaphore_offset) = probe.semaphore_file_offset {
                attach_uprobe_with_semaphore(
                    program,
                    &target.path,
                    probe.file_offset,
                    semaphore_offset,
                )
                .map(|fd| {
                    links.semaphore_links.push(fd);
                })
            } else {
                program
                    .attach(None, probe.file_offset, &target.path, None)
                    .map(|link_id| {
                        aya_links.push((program_name.clone(), link_id));
                    })
                    .map_err(Into::into)
            };
            if let Err(error) = attached {
                for (attached_program, link_id) in aya_links.into_iter().rev() {
                    if let Some(program) = bpf.program_mut(&attached_program) {
                        if let Ok(program) = <&mut UProbe>::try_from(program) {
                            let _ = program.detach(link_id);
                        }
                    }
                }
                links.rollback(semaphore_checkpoint);
                return Err(error);
            }
        }
        Ok(())
    })();
    match attach_result {
        Ok(()) => Vec::new(),
        Err(error) => {
            // Keep the externally emitted diagnostic bounded and stable, but
            // retain Aya's verifier/attach error in the service journal.  An
            // attach failure otherwise looks indistinguishable from a probe
            // that attached successfully but never fired.
            log::warn!(
                "USDT collector {} failed to attach at {}: {error:#}",
                metadata.id,
                metadata.target_path,
            );
            vec![diagnostic(
                metadata.id,
                ReasonCode::AttachFailed,
                Some(json!({"target_path": metadata.target_path})),
            )]
        }
    }
}

// Aya 0.13's safe UProbe API does not expose the kernel's `ref_ctr_offset`
// field. Linux encodes it in config[32..63] for the fd-based uprobe PMU. Keep
// this minimal adapter here so the rest of the collector stays on Aya's normal
// program lifecycle, while the kernel owns the increment/decrement semantics.
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;
const PERF_EVENT_IOC_ENABLE: std::ffi::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: std::ffi::c_ulong = 0x4004_2408;
// Bloodhound's collector and fixture are x86_64-only. Keeping this syscall
// declaration local avoids turning Aya's transitive libc dependency into a
// second public dependency merely to fill the API gap in Aya 0.13.
const SYS_PERF_EVENT_OPEN_X86_64: std::ffi::c_long = 298;

unsafe extern "C" {
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

fn attach_uprobe_with_semaphore(
    program: &mut aya::programs::UProbe,
    target: &Path,
    probe_offset: u64,
    semaphore_offset: u32,
) -> Result<OwnedFd> {
    let pmu_type = fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")
        .context("reading uprobe PMU type")?
        .trim()
        .parse::<u32>()
        .context("parsing uprobe PMU type")?;
    let target = CString::new(target.as_os_str().as_encoded_bytes())
        .context("encoding verified USDT target path")?;
    let attr = PerfEventAttr {
        type_: pmu_type,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: u64::from(semaphore_offset) << 32,
        config1: target.as_ptr() as u64,
        config2: probe_offset,
        ..Default::default()
    };
    let raw_fd = unsafe {
        syscall(
            SYS_PERF_EVENT_OPEN_X86_64,
            &attr,
            -1_i32,
            0_i32,
            -1_i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error()).context("opening semaphore-backed uprobe");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
    let program_fd = program.fd()?.as_fd().as_raw_fd();
    if unsafe { ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, program_fd) } < 0 {
        return Err(io::Error::last_os_error())
            .context("attaching BPF program to semaphore-backed uprobe");
    }
    if unsafe { ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0) } < 0 {
        return Err(io::Error::last_os_error()).context("enabling semaphore-backed uprobe");
    }
    Ok(fd)
}

/// Decode a fixed, collector-owned byte field into the canonical safe form.
pub fn bounded_bytes(
    bytes: &[u8],
    capture_limit: usize,
    observed_length: Option<usize>,
    truncated: bool,
) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    json!({
        "base64": STANDARD.encode(bytes),
        "capture_limit": capture_limit,
        "observed_length": observed_length,
        "truncated": truncated,
    })
}

pub fn bounded_utf8(
    bytes: &[u8],
    capture_limit: usize,
    truncated: bool,
) -> std::result::Result<Value, ReasonCode> {
    let value = std::str::from_utf8(bytes).map_err(|_| ReasonCode::AbiIncompatible)?;
    Ok(json!({"value": value, "capture_limit": capture_limit, "truncated": truncated}))
}

/// Convert a collector-owned fixed ring-buffer payload to a canonical event.
/// The core deserializer delegates here generically and contains no collector
/// IDs, provider/probe names, or field definitions.
pub fn decode_payload(
    kind: EventKind,
    payload: &[u8],
) -> Result<(String, String, String, Option<Value>, Option<i64>)> {
    match kind {
        EventKind::UsdtTrainingShellV3 => decode_training_shell_payload(payload),
        EventKind::UsdtTrainingPeerV1 => decode_training_peer_payload(payload),
        EventKind::UsdtTrainingShellV3CaptureError => decode_training_shell_capture_error(payload),
        _ => bail!("not a registered USDT event kind"),
    }
}

fn decode_training_shell_capture_error(
    payload: &[u8],
) -> Result<(String, String, String, Option<Value>, Option<i64>)> {
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
    Ok((
        "DIAGNOSTIC".into(),
        "usdt.collector".into(),
        "behavior".into(),
        Some(json!({
            "collector_id": TRAINING_SHELL_V3_ID,
            "reason_code": ReasonCode::AbiIncompatible.as_str(),
            "attach_point_id": fixed.attach_point_id,
            "argument": field,
            "read_error_code": read_error_code,
        })),
        None,
    ))
}

fn decode_training_shell_payload(
    payload: &[u8],
) -> Result<(String, String, String, Option<Value>, Option<i64>)> {
    if payload.len() < UsdtTrainingShellPayload::SIZE {
        bail!("USDT training-shell payload too short");
    }
    let fixed =
        unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const UsdtTrainingShellPayload) };
    let name_end = UsdtTrainingShellPayload::SIZE
        .checked_add(fixed.command_name_len as usize)
        .ok_or_else(|| anyhow!("USDT command-name length overflow"))?;
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
    Ok((
        "USDT".into(),
        "abyss0_shell.simple_command_completed".into(),
        "behavior".into(),
        Some(json!({
            "attach_point_id": fixed.attach_point_id,
            "shell_pid": fixed.shell_pid,
            "command_id": fixed.command_id,
            "command_kind": command_kind,
            "command_name": { "value": command_name, "capture_limit": 64, "truncated": fixed.command_name_truncated != 0 },
            "command_name_bytes": { "base64": command_name_bytes, "capture_limit": 64, "observed_length": fixed.command_name_len, "truncated": fixed.command_name_truncated != 0 },
            "semantic_flags": flags,
            "exit_status": fixed.exit_status,
        })),
        None,
    ))
}

fn decode_training_peer_payload(
    payload: &[u8],
) -> Result<(String, String, String, Option<Value>, Option<i64>)> {
    if payload.len() != UsdtTrainingPeerPayload::SIZE {
        bail!("USDT training-peer payload has invalid length");
    }
    let fixed =
        unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const UsdtTrainingPeerPayload) };
    Ok((
        "USDT".into(),
        "abyss0_peer.task_finished".into(),
        "behavior".into(),
        Some(json!({
            "attach_point_id": fixed.attach_point_id,
            "task_id": fixed.task_id,
            "result": match fixed.result { 0 => "ok", 1 => "failed", _ => "other" },
        })),
        None,
    ))
}

// A deliberately small ELF parser: we only read the pieces that make a static
// USDT attach safe. It does not scan symbols, DSOs, or runtime process memory.
struct ElfView<'a> {
    data: &'a [u8],
    class: u8,
    little_endian: bool,
    machine: u16,
    section_offset: u64,
    section_size: u16,
    section_count: u16,
    section_strings: u16,
    program_offset: u64,
    program_size: u16,
    program_count: u16,
}

impl<'a> ElfView<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 64 || &data[..4] != b"\x7fELF" {
            bail!("not an ELF file");
        }
        let class = data[4];
        let little_endian = match data[5] {
            1 => true,
            2 => false,
            _ => bail!("unknown ELF endian"),
        };
        if !matches!(class, 1 | 2) {
            bail!("unknown ELF class");
        }
        let at = |offset: usize, width: usize| -> Result<&[u8]> {
            data.get(offset..offset + width)
                .ok_or_else(|| anyhow!("truncated ELF header"))
        };
        let u16_at = |offset| read_u16(at(offset, 2)?, little_endian);
        let u32_at = |offset| read_u32(at(offset, 4)?, little_endian);
        let u64_at = |offset| read_u64(at(offset, 8)?, little_endian);
        let (
            program_offset,
            section_offset,
            program_size,
            program_count,
            section_size,
            section_count,
            section_strings,
        ) = if class == 2 {
            (
                u64_at(32)?,
                u64_at(40)?,
                u16_at(54)?,
                u16_at(56)?,
                u16_at(58)?,
                u16_at(60)?,
                u16_at(62)?,
            )
        } else {
            (
                u32_at(28)? as u64,
                u32_at(32)? as u64,
                u16_at(42)?,
                u16_at(44)?,
                u16_at(46)?,
                u16_at(48)?,
                u16_at(50)?,
            )
        };
        Ok(Self {
            data,
            class,
            little_endian,
            machine: u16_at(18)?,
            section_offset,
            section_size,
            section_count,
            section_strings,
            program_offset,
            program_size,
            program_count,
        })
    }

    fn section(&self, index: u16) -> Result<Section> {
        if index >= self.section_count || self.section_size == 0 {
            bail!("section index out of range");
        }
        let offset = self
            .section_offset
            .checked_add(u64::from(index) * u64::from(self.section_size))
            .ok_or_else(|| anyhow!("section table overflow"))? as usize;
        let bytes = self
            .data
            .get(offset..offset + self.section_size as usize)
            .ok_or_else(|| anyhow!("truncated section table"))?;
        let u32_at = |offset| {
            read_u32(
                bytes
                    .get(offset..offset + 4)
                    .ok_or_else(|| anyhow!("truncated section"))?,
                self.little_endian,
            )
        };
        let u64_at = |offset| {
            read_u64(
                bytes
                    .get(offset..offset + 8)
                    .ok_or_else(|| anyhow!("truncated section"))?,
                self.little_endian,
            )
        };
        if self.class == 2 {
            Ok(Section {
                name: u32_at(0)?,
                offset: u64_at(24)?,
                size: u64_at(32)?,
            })
        } else {
            Ok(Section {
                name: u32_at(0)?,
                offset: u32_at(16)? as u64,
                size: u32_at(20)? as u64,
            })
        }
    }

    fn section_named(&self, wanted: &str) -> Result<Option<&'a [u8]>> {
        let strings = self.section(self.section_strings)?;
        let names = slice_at(self.data, strings.offset, strings.size)?;
        for index in 0..self.section_count {
            let section = self.section(index)?;
            let name = c_string(names.get(section.name as usize..).unwrap_or_default());
            if name == Some(wanted) {
                return Ok(Some(slice_at(self.data, section.offset, section.size)?));
            }
        }
        Ok(None)
    }

    fn build_id(&self) -> Option<String> {
        self.section_named(".note.gnu.build-id")
            .ok()
            .flatten()
            .and_then(|notes| {
                parse_notes(notes, self.little_endian)
                    .ok()?
                    .into_iter()
                    .find_map(|note| {
                        (note.name == "GNU" && note.kind == 3).then(|| hex(&note.desc))
                    })
            })
    }

    fn stapsdt_probes(&self) -> Result<Vec<StapsdtProbe>> {
        let notes = self
            .section_named(".note.stapsdt")?
            .ok_or_else(|| anyhow!("no .note.stapsdt"))?;
        parse_notes(notes, self.little_endian)?
            .into_iter()
            .filter(|note| note.name == "stapsdt")
            .map(|note| self.parse_stapsdt(note.desc))
            .collect()
    }

    fn parse_stapsdt(&self, desc: &'a [u8]) -> Result<StapsdtProbe> {
        let width = if self.class == 2 { 8 } else { 4 };
        if desc.len() < width * 3 {
            bail!("short stapsdt descriptor");
        }
        let number = |offset| {
            if width == 8 {
                read_u64(&desc[offset..offset + 8], self.little_endian)
            } else {
                Ok(read_u32(&desc[offset..offset + 4], self.little_endian)? as u64)
            }
        };
        let location = number(0)?;
        let _base = number(width)?;
        let semaphore_address = number(width * 2)?;
        let strings = &desc[width * 3..];
        let (provider, rest) = take_c_string(strings)?;
        let (name, rest) = take_c_string(rest)?;
        let (operands, _) = take_c_string(rest)?;
        let file_offset = self.virtual_to_file_offset(location)?;
        let semaphore_file_offset = if semaphore_address == 0 {
            None
        } else {
            Some(
                u32::try_from(self.virtual_to_file_offset(semaphore_address)?)
                    .map_err(|_| anyhow!("USDT semaphore offset exceeds kernel uprobe ABI"))?,
            )
        };
        Ok(StapsdtProbe {
            provider: provider.into(),
            name: name.into(),
            operands: operands.into(),
            file_offset,
            semaphore_address,
            semaphore_file_offset,
        })
    }

    fn virtual_to_file_offset(&self, address: u64) -> Result<u64> {
        for index in 0..self.program_count {
            let offset =
                self.program_offset
                    .checked_add(u64::from(index) * u64::from(self.program_size))
                    .ok_or_else(|| anyhow!("program table overflow"))? as usize;
            let entry = self
                .data
                .get(offset..offset + self.program_size as usize)
                .ok_or_else(|| anyhow!("truncated program table"))?;
            let typ = read_u32(&entry[..4], self.little_endian)?;
            if typ != 1 {
                continue;
            } // PT_LOAD
            let (file_offset, virtual_address, file_size) = if self.class == 2 {
                (
                    read_u64(&entry[8..16], self.little_endian)?,
                    read_u64(&entry[16..24], self.little_endian)?,
                    read_u64(&entry[32..40], self.little_endian)?,
                )
            } else {
                (
                    read_u32(&entry[4..8], self.little_endian)? as u64,
                    read_u32(&entry[8..12], self.little_endian)? as u64,
                    read_u32(&entry[16..20], self.little_endian)? as u64,
                )
            };
            if address >= virtual_address && address < virtual_address.saturating_add(file_size) {
                return Ok(file_offset + address - virtual_address);
            }
        }
        bail!("USDT location is outside a loadable ELF segment")
    }
}

struct Section {
    name: u32,
    offset: u64,
    size: u64,
}
struct Note<'a> {
    name: &'a str,
    kind: u32,
    desc: &'a [u8],
}

fn parse_notes(data: &[u8], little: bool) -> Result<Vec<Note<'_>>> {
    let mut notes = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < 12 {
            bail!("truncated note header");
        }
        let namesz = read_u32(&data[offset..offset + 4], little)? as usize;
        let descsz = read_u32(&data[offset + 4..offset + 8], little)? as usize;
        let kind = read_u32(&data[offset + 8..offset + 12], little)?;
        offset += 12;
        let name_end = offset
            .checked_add(namesz)
            .ok_or_else(|| anyhow!("note name overflow"))?;
        let name = c_string(
            data.get(offset..name_end)
                .ok_or_else(|| anyhow!("truncated note name"))?,
        )
        .ok_or_else(|| anyhow!("note name is not UTF-8"))?;
        offset = align4(name_end);
        let desc_end = offset
            .checked_add(descsz)
            .ok_or_else(|| anyhow!("note descriptor overflow"))?;
        let desc = data
            .get(offset..desc_end)
            .ok_or_else(|| anyhow!("truncated note descriptor"))?;
        offset = align4(desc_end);
        notes.push(Note { name, kind, desc });
    }
    Ok(notes)
}

fn slice_at(data: &[u8], offset: u64, len: u64) -> Result<&[u8]> {
    let start = usize::try_from(offset).map_err(|_| anyhow!("ELF offset too large"))?;
    let end = start
        .checked_add(usize::try_from(len).map_err(|_| anyhow!("ELF length too large"))?)
        .ok_or_else(|| anyhow!("ELF range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| anyhow!("truncated ELF data"))
}
fn align4(value: usize) -> usize {
    (value + 3) & !3
}
fn c_string(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes.split(|byte| *byte == 0).next()?).ok()
}
fn take_c_string(bytes: &[u8]) -> Result<(&str, &[u8])> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| anyhow!("unterminated USDT string"))?;
    Ok((std::str::from_utf8(&bytes[..end])?, &bytes[end + 1..]))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn read_u16(bytes: &[u8], little: bool) -> Result<u16> {
    let array: [u8; 2] = bytes.try_into().map_err(|_| anyhow!("short u16"))?;
    Ok(if little {
        u16::from_le_bytes(array)
    } else {
        u16::from_be_bytes(array)
    })
}
fn read_u32(bytes: &[u8], little: bool) -> Result<u32> {
    let array: [u8; 4] = bytes.try_into().map_err(|_| anyhow!("short u32"))?;
    Ok(if little {
        u32::from_le_bytes(array)
    } else {
        u32::from_be_bytes(array)
    })
}
fn read_u64(bytes: &[u8], little: bool) -> Result<u64> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| anyhow!("short u64"))?;
    Ok(if little {
        u64::from_le_bytes(array)
    } else {
        u64::from_be_bytes(array)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let error = parse_selection(&source).unwrap_err();
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
    fn unknown_collector_fails_validation() {
        assert!(parse_selection("collector = \"not-built-in\"\nenabled = true\n").is_err());
    }

    #[test]
    fn selection_failure_diagnostic_keeps_the_unknown_collector_id() {
        let path = std::env::temp_dir().join(format!(
            "bloodhound-usdt-selection-{}-{}.toml",
            std::process::id(),
            now_seconds().to_bits(),
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
    fn bounded_values_never_expose_pointers_or_unbounded_bytes() {
        let bytes = bounded_bytes(&[0, 1, 2], 8, Some(3), false);
        assert_eq!(bytes["base64"], "AAEC");
        assert_eq!(bytes["capture_limit"], 8);
        let string = bounded_utf8(b"echo", 64, false).unwrap();
        assert_eq!(string["value"], "echo");
        assert!(bounded_utf8(&[0xff], 64, false).is_err());
    }

    #[test]
    fn diagnostic_has_the_canonical_shape() {
        let event = diagnostic(TRAINING_SHELL_V3_ID, ReasonCode::ProbeNotFound, None);
        assert_eq!(event.event.event_type, "DIAGNOSTIC");
        assert_eq!(event.event.name, "usdt.collector");
        assert_eq!(event.args.unwrap()["reason_code"], "probe_not_found");
    }

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
        let (_, name, _, args, _) =
            decode_payload(EventKind::UsdtTrainingShellV3, &payload).unwrap();
        assert_eq!(name, "abyss0_shell.simple_command_completed");
        let args = args.unwrap();
        assert_eq!(args["attach_point_id"], 3);
        assert_eq!(args["command_name"]["value"], "echo");
        assert_eq!(args["command_name_bytes"]["base64"], "ZWNobw==");
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
        let (event_type, name, layer, args, _) =
            decode_payload(EventKind::UsdtTrainingShellV3CaptureError, payload).unwrap();
        assert_eq!(
            (event_type.as_str(), name.as_str(), layer.as_str()),
            ("DIAGNOSTIC", "usdt.collector", "behavior")
        );
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
