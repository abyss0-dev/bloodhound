//! Runtime `task_struct` field-offset resolution ("manual CO-RE").
//!
//! The eBPF programs read direct members of `task_struct` and
//! `signal_struct` for audit filtering and process lifecycle identity. rustc
//! does not emit `preserve_access_index`
//! BTF relocations, so a typed `addr_of!` deref bakes a **compile-time**
//! offset fixed to whatever kernel the eBPF object was built against. On
//! any other kernel build the field has drifted and the daemon silently
//! reads the wrong bytes — dropping every task-scoped event (issue #37).
//!
//! This module resolves the offsets from the **running** kernel's BTF at
//! daemon start and feeds them to the programs via `set_global`. It is a
//! deliberately minimal BTF reader: it walks the type section looking for
//! the required structs and returns their member byte offsets. It does **not**
//! implement full CO-RE (no type/enum/bitfield relocation).
//!
//! Nested-pointer chains (TTY device class, fd → inode → super_block) are
//! out of scope and remain compile-time fixed in `bloodhound-ebpf`'s
//! `vmlinux.rs`; their multi-hop layouts can't be expressed as one offset.

use anyhow::{bail, Context, Result};
use log::info;

/// Path to the running kernel's BTF, exposed by the kernel when built
/// with `CONFIG_DEBUG_INFO_BTF` (a hard requirement for bloodhound).
const SYS_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Byte offsets of the direct kernel struct members the eBPF programs read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStructOffsets {
    /// `task_struct::loginuid` (a `kuid_t`; its first member is the `u32`
    /// audit login UID).
    pub loginuid: u32,
    /// `task_struct::sessionid` (`u32`).
    pub sessionid: u32,
    /// `task_struct::tgid` (`i32`, == userspace PID for the group leader).
    pub tgid: u32,
    pub pid: u32,
    pub group_leader: u32,
    pub start_boottime: u32,
    pub signal: u32,
    pub exit_code: u32,
    pub signal_live: u32,
    pub signal_group_exit_code: u32,
}

/// Resolve every required lifecycle offset from the running kernel and fail
/// closed if BTF is unavailable or incomplete. Guessing an identity offset can
/// silently merge unrelated processes after PID reuse.
pub fn resolve() -> Result<TaskStructOffsets> {
    let offsets = read_and_parse(SYS_BTF)?;
    info!("Resolved process lifecycle offsets from {SYS_BTF}: {offsets:?}");
    Ok(offsets)
}

fn read_and_parse(path: &str) -> Result<TaskStructOffsets> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
    parse_task_offsets(&bytes).with_context(|| format!("parse BTF from {path}"))
}

// ── Minimal BTF reader ───────────────────────────────────────────────────────
//
// BTF binary layout (see Linux `Documentation/bpf/btf.rst`):
//
//   struct btf_header {
//       u16 magic;   // 0xeB9F
//       u8  version;
//       u8  flags;
//       u32 hdr_len;
//       u32 type_off; u32 type_len;   // both relative to end of header
//       u32 str_off;  u32 str_len;
//   };
//
// The type section is a sequence of `struct btf_type { u32 name_off; u32
// info; u32 size_or_type; }`, each optionally followed by kind-specific
// trailing records. `info` packs: vlen (bits 0..16), kind (bits 24..29),
// kind_flag (bit 31). Type ids start at 1 (id 0 is void).

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_HEADER_LEN: usize = 24;

// BTF kind discriminators (subset; only what the size walker needs).
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

/// Little/big-endian aware slice reader with bounds checking.
struct Reader<'a> {
    buf: &'a [u8],
    little_endian: bool,
}

impl<'a> Reader<'a> {
    fn u32(&self, off: usize) -> Result<u32> {
        let b: [u8; 4] = self
            .buf
            .get(off..off + 4)
            .context("u32 read out of bounds")?
            .try_into()
            .unwrap();
        Ok(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    /// Read a NUL-terminated string from the string section.
    fn str_at(&self, str_base: usize, name_off: u32) -> Result<&'a str> {
        let start = str_base
            .checked_add(name_off as usize)
            .context("string offset overflow")?;
        let tail = self
            .buf
            .get(start..)
            .context("string offset out of bounds")?;
        let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
        std::str::from_utf8(&tail[..end]).context("BTF string is not UTF-8")
    }
}

/// Parse the byte offsets of `task_struct::{loginuid, sessionid, tgid}`
/// from a raw BTF blob.
pub fn parse_task_offsets(buf: &[u8]) -> Result<TaskStructOffsets> {
    if buf.len() < BTF_HEADER_LEN {
        bail!("BTF blob shorter than header ({} bytes)", buf.len());
    }

    // Endianness from the magic; the kernel writes it in host byte order.
    let little_endian = match u16::from_le_bytes([buf[0], buf[1]]) {
        BTF_MAGIC => true,
        _ if u16::from_be_bytes([buf[0], buf[1]]) == BTF_MAGIC => false,
        other => bail!("bad BTF magic 0x{other:04x}"),
    };
    let r = Reader { buf, little_endian };

    let hdr_len = r.u32(4)? as usize;
    let type_off = r.u32(8)? as usize;
    let type_len = r.u32(12)? as usize;
    let str_off = r.u32(16)? as usize;

    let type_base = hdr_len
        .checked_add(type_off)
        .context("type section offset overflow")?;
    let type_end = type_base
        .checked_add(type_len)
        .context("type section length overflow")?;
    let str_base = hdr_len
        .checked_add(str_off)
        .context("string section offset overflow")?;
    if type_end > buf.len() {
        bail!("type section extends past end of BTF blob");
    }

    let mut task_offsets = None;
    let mut signal_offsets = None;
    let mut pos = type_base;
    while pos + 12 <= type_end {
        let name_off = r.u32(pos)?;
        let info = r.u32(pos + 4)?;
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;

        let members_pos = pos + 12;

        if kind == BTF_KIND_STRUCT && vlen > 0 {
            let struct_name = r.str_at(str_base, name_off)?;
            let struct_size = r.u32(pos + 8)?;
            if struct_name == "task_struct" {
                task_offsets = Some(read_task_members(
                    &r,
                    str_base,
                    members_pos,
                    vlen,
                    struct_size,
                )?);
            } else if struct_name == "signal_struct" {
                signal_offsets = Some((
                    read_named_member(&r, str_base, members_pos, vlen, struct_size, "live")?,
                    read_named_member(
                        &r,
                        str_base,
                        members_pos,
                        vlen,
                        struct_size,
                        "group_exit_code",
                    )?,
                ));
            }
        }

        let extra = trailing_len(kind, vlen)?;
        pos = members_pos
            .checked_add(extra)
            .context("type record length overflow")?;
    }

    let mut offsets = task_offsets.context("struct task_struct not found in BTF")?;
    let (live, group_exit_code) =
        signal_offsets.context("required signal_struct members not found in BTF")?;
    offsets.signal_live = live;
    offsets.signal_group_exit_code = group_exit_code;
    Ok(offsets)
}

/// Walk `task_struct` members and select the required direct fields.
///
/// `struct_size` is the struct's own byte size from BTF, used as a sanity
/// bound: a resolved offset at or past it means the sequential type walk
/// desynced (a miscounted trailing record) and produced garbage. Bailing
/// there turns that into the loud-fallback path in `resolve` rather than
/// silently feeding a wild offset to the eBPF programs.
fn read_task_members(
    r: &Reader,
    str_base: usize,
    members_pos: usize,
    vlen: usize,
    struct_size: u32,
) -> Result<TaskStructOffsets> {
    let mut loginuid = None;
    let mut sessionid = None;
    let mut tgid = None;
    let mut pid = None;
    let mut group_leader = None;
    let mut start_boottime = None;
    let mut signal = None;
    let mut exit_code = None;

    for i in 0..vlen {
        let m = members_pos + i * 12;
        let name = r.str_at(str_base, r.u32(m)?)?;
        let raw_offset = r.u32(m + 8)?;
        // If the struct uses bitfield encoding (kind_flag), the low 24 bits
        // hold the bit offset and the top 8 the bitfield size; otherwise the
        // whole word is the bit offset. Masking the low 24 bits is correct
        // either way for these plain scalar fields (their bit offsets are far
        // below 2^24).
        let byte_offset = (raw_offset & 0x00ff_ffff) / 8;

        match name {
            "loginuid" => loginuid = Some(byte_offset),
            "sessionid" => sessionid = Some(byte_offset),
            "tgid" => tgid = Some(byte_offset),
            "pid" => pid = Some(byte_offset),
            "group_leader" => group_leader = Some(byte_offset),
            "start_boottime" => start_boottime = Some(byte_offset),
            "signal" => signal = Some(byte_offset),
            "exit_code" => exit_code = Some(byte_offset),
            _ => {}
        }
    }

    let off = TaskStructOffsets {
        loginuid: loginuid.context("task_struct::loginuid not found in BTF")?,
        sessionid: sessionid.context("task_struct::sessionid not found in BTF")?,
        tgid: tgid.context("task_struct::tgid not found in BTF")?,
        pid: pid.context("task_struct::pid not found in BTF")?,
        group_leader: group_leader.context("task_struct::group_leader not found in BTF")?,
        start_boottime: start_boottime.context("task_struct::start_boottime not found in BTF")?,
        signal: signal.context("task_struct::signal not found in BTF")?,
        exit_code: exit_code.context("task_struct::exit_code not found in BTF")?,
        signal_live: 0,
        signal_group_exit_code: 0,
    };

    for (name, value) in [
        ("loginuid", off.loginuid),
        ("sessionid", off.sessionid),
        ("tgid", off.tgid),
        ("pid", off.pid),
        ("group_leader", off.group_leader),
        ("start_boottime", off.start_boottime),
        ("signal", off.signal),
        ("exit_code", off.exit_code),
    ] {
        if value >= struct_size {
            bail!(
                "resolved task_struct::{name} offset 0x{value:x} >= struct size \
                 0x{struct_size:x} — BTF type walk desynced",
            );
        }
    }

    Ok(off)
}

fn read_named_member(
    r: &Reader,
    str_base: usize,
    members_pos: usize,
    vlen: usize,
    struct_size: u32,
    wanted: &str,
) -> Result<u32> {
    for i in 0..vlen {
        let m = members_pos + i * 12;
        if r.str_at(str_base, r.u32(m)?)? == wanted {
            let offset = (r.u32(m + 8)? & 0x00ff_ffff) / 8;
            if offset >= struct_size {
                bail!("resolved member offset exceeds struct size");
            }
            return Ok(offset);
        }
    }
    bail!("member {wanted} not found")
}

/// Size in bytes of a type record's kind-specific trailing data, given
/// its kind and `vlen`. Types not listed carry no trailing records.
fn trailing_len(kind: u32, vlen: usize) -> Result<usize> {
    let len = match kind {
        BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => 4,
        BTF_KIND_ARRAY => 12,
        BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_DATASEC => vlen * 12,
        BTF_KIND_ENUM | BTF_KIND_FUNC_PROTO => vlen * 8,
        BTF_KIND_ENUM64 => vlen * 12,
        _ => 0,
    };
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builder for a synthetic BTF blob so the parser can be exercised
    /// without a live kernel.
    struct BtfBuilder {
        strings: Vec<u8>,
        types: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            // String section must start with a NUL (offset 0 == "").
            BtfBuilder {
                strings: vec![0],
                types: Vec::new(),
            }
        }

        fn add_string(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        /// Append a raw INT type (no members) to advance type ids and
        /// prove the walker skips trailing records correctly.
        fn add_int(&mut self, name: &str) {
            let name_off = self.add_string(name);
            let info = BTF_KIND_INT << 24; // vlen 0
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&4u32.to_le_bytes()); // size
            self.types.extend_from_slice(&0u32.to_le_bytes()); // INT trailing word
        }

        /// Append a struct with `(member_name, byte_offset)` entries,
        /// auto-sizing it to just past its last member.
        fn add_struct(&mut self, name: &str, members: &[(&str, u32)], kind_flag: bool) {
            let size = members.iter().map(|(_, o)| o + 8).max().unwrap_or(0);
            self.add_struct_sized(name, members, kind_flag, size);
        }

        /// Like `add_struct` but with an explicit declared size, to drive
        /// the offset-vs-size sanity guard.
        fn add_struct_sized(
            &mut self,
            name: &str,
            members: &[(&str, u32)],
            kind_flag: bool,
            size: u32,
        ) {
            let name_off = self.add_string(name);
            let vlen = members.len() as u32;
            let mut info = (BTF_KIND_STRUCT << 24) | vlen;
            if kind_flag {
                info |= 1 << 31;
            }
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes()); // struct byte size
            for (mname, byte_off) in members {
                let m_name_off = self.add_string(mname);
                let bit_off = byte_off * 8;
                self.types.extend_from_slice(&m_name_off.to_le_bytes());
                self.types.extend_from_slice(&1u32.to_le_bytes()); // member type id
                self.types.extend_from_slice(&bit_off.to_le_bytes());
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&(BTF_HEADER_LEN as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    fn add_lifecycle_structs(b: &mut BtfBuilder, task_members: &[(&str, u32)]) {
        b.add_struct("task_struct", task_members, false);
        b.add_struct(
            "signal_struct",
            &[("live", 0x20), ("group_exit_code", 0x30)],
            false,
        );
    }

    #[test]
    fn parses_offsets_from_synthetic_btf() {
        let mut b = BtfBuilder::new();
        // Leading noise types to ensure the walker skips trailing records.
        b.add_int("int");
        add_lifecycle_structs(
            &mut b,
            &[
                ("pid", 0x9a0),
                ("tgid", 0x9a4),
                ("group_leader", 0x9c8),
                ("start_boottime", 0xa20),
                ("signal", 0x8d0),
                ("exit_code", 0x9f0),
                ("loginuid", 0xc88),
                ("sessionid", 0xc8c),
            ],
        );

        let off = parse_task_offsets(&b.build()).expect("parse must succeed");
        assert_eq!(off.loginuid, 0xc88);
        assert_eq!(off.sessionid, 0xc8c);
        assert_eq!(off.tgid, 0x9a4);
    }

    #[test]
    fn resolves_drifted_offsets() {
        // The exact drift from issue #37 (6.8.0-117): loginuid/sessionid
        // shifted +24 bytes vs the build kernel.
        let mut b = BtfBuilder::new();
        add_lifecycle_structs(
            &mut b,
            &[
                ("pid", 0x9a0),
                ("tgid", 0x9a4),
                ("group_leader", 0x9c8),
                ("start_boottime", 0xa20),
                ("signal", 0x8d0),
                ("exit_code", 0x9f0),
                ("loginuid", 0xca0),
                ("sessionid", 0xca4),
            ],
        );
        let off = parse_task_offsets(&b.build()).unwrap();
        assert_eq!(off.loginuid, 0xca0, "must read the running kernel's offset");
        assert_eq!(off.sessionid, 0xca4);
    }

    #[test]
    fn masks_bitfield_encoded_offset() {
        // kind_flag set: the top 8 bits of a member offset encode bitfield
        // size and must be masked off before dividing to bytes.
        let mut b = BtfBuilder::new();
        b.add_struct(
            "task_struct",
            &[
                ("pid", 0x9a0),
                ("tgid", 0x9a4),
                ("group_leader", 0x9c8),
                ("start_boottime", 0xa20),
                ("signal", 0x8d0),
                ("exit_code", 0x9f0),
                ("loginuid", 0xc88),
                ("sessionid", 0xc8c),
            ],
            true,
        );
        b.add_struct(
            "signal_struct",
            &[("live", 0x20), ("group_exit_code", 0x30)],
            false,
        );
        let off = parse_task_offsets(&b.build()).unwrap();
        assert_eq!(off.loginuid, 0xc88);
    }

    #[test]
    fn errors_when_task_struct_absent() {
        let mut b = BtfBuilder::new();
        b.add_struct("mm_struct", &[("foo", 0)], false);
        let err = parse_task_offsets(&b.build()).unwrap_err();
        assert!(err.to_string().contains("task_struct not found"));
    }

    #[test]
    fn errors_when_field_missing() {
        let mut b = BtfBuilder::new();
        b.add_struct("task_struct", &[("loginuid", 0xc88)], false);
        let err = parse_task_offsets(&b.build()).unwrap_err();
        assert!(err.to_string().contains("sessionid"));
    }

    #[test]
    fn errors_when_offset_exceeds_struct_size() {
        // A desynced walk yields an offset past the struct's own size; the
        // sanity guard must reject it rather than feed garbage to eBPF.
        let mut b = BtfBuilder::new();
        b.add_struct_sized(
            "task_struct",
            &[
                ("pid", 0x9a0),
                ("tgid", 0x9a4),
                ("group_leader", 0x9c8),
                ("start_boottime", 0xa20),
                ("signal", 0x8d0),
                ("exit_code", 0x9f0),
                ("loginuid", 0xc88),
                ("sessionid", 0xc8c),
            ],
            false,
            0x100, // declared far smaller than the offsets
        );
        b.add_struct(
            "signal_struct",
            &[("live", 0x20), ("group_exit_code", 0x30)],
            false,
        );
        let err = parse_task_offsets(&b.build()).unwrap_err();
        assert!(err.to_string().contains("desynced"), "got: {err}");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = vec![0u8; BTF_HEADER_LEN];
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        let err = parse_task_offsets(&bytes).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn rejects_truncated_blob() {
        let err = parse_task_offsets(&[0x9f, 0xeb, 1]).unwrap_err();
        assert!(err.to_string().contains("shorter than header"));
    }

    #[test]
    fn parses_running_kernel_btf_when_available() {
        if !std::path::Path::new(SYS_BTF).exists() {
            return;
        }
        let offsets = read_and_parse(SYS_BTF).expect("running kernel BTF must satisfy contract");
        assert!(offsets.start_boottime > 0);
        assert!(offsets.signal_live > 0);
        assert!(offsets.signal_group_exit_code > 0);
    }
}
