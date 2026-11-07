use std::{fs, io::Read, os::fd::AsRawFd, path::PathBuf};

use anyhow::{anyhow, bail, Result};

use super::registry::{CollectorMetadata, ReasonCode};

/// A static probe discovered exclusively in `.note.stapsdt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StapsdtProbe {
    provider: String,
    name: String,
    operands: String,
    /// File offset required by the uprobe API, never a symbol or a config value.
    pub(super) file_offset: u64,
    semaphore_address: u64,
    /// File offset for Linux's uprobe ref-counter interface. `None` means the
    /// static note does not require a semaphore.
    pub(super) semaphore_file_offset: Option<u32>,
}

#[derive(Debug)]
pub(super) struct VerifiedTarget {
    pub(super) probes: Vec<StapsdtProbe>,
    file: fs::File,
}

impl VerifiedTarget {
    /// Address the already-open, already-verified inode during attachment.
    /// Keeping `file` alive prevents a replacement at `path` from changing the
    /// executable to which the uprobe is attached.
    pub(super) fn attachment_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

/// Validate path, architecture, Build ID and the collector's exact note ABI.
/// No attachment can be attempted unless this returns a verified target.
pub(super) fn verify_target(metadata: &CollectorMetadata) -> std::result::Result<VerifiedTarget, ReasonCode> {
    let path = PathBuf::from(metadata.target_path);
    let mut file = fs::File::open(&path).map_err(|_| ReasonCode::TargetBuildIdMismatch)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|_| ReasonCode::TargetBuildIdMismatch)?;
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
        probes: matching,
        file,
    })
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
            let end = offset
                .checked_add(width)
                .ok_or_else(|| anyhow!("ELF header range overflow"))?;
            data.get(offset..end)
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
        let offset = usize::try_from(
            self.section_offset
                .checked_add(u64::from(index) * u64::from(self.section_size))
                .ok_or_else(|| anyhow!("section table overflow"))?,
        )
        .map_err(|_| anyhow!("section table offset too large"))?;
        let end = offset
            .checked_add(self.section_size as usize)
            .ok_or_else(|| anyhow!("section table range overflow"))?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or_else(|| anyhow!("truncated section table"))?;
        let u32_at = |offset: usize| {
            let end = offset
                .checked_add(4)
                .ok_or_else(|| anyhow!("section field range overflow"))?;
            read_u32(
                bytes
                    .get(offset..end)
                    .ok_or_else(|| anyhow!("truncated section"))?,
                self.little_endian,
            )
        };
        let u64_at = |offset: usize| {
            let end = offset
                .checked_add(8)
                .ok_or_else(|| anyhow!("section field range overflow"))?;
            read_u64(
                bytes
                    .get(offset..end)
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
            let offset = usize::try_from(
                self.program_offset
                    .checked_add(u64::from(index) * u64::from(self.program_size))
                    .ok_or_else(|| anyhow!("program table overflow"))?,
            )
            .map_err(|_| anyhow!("program table offset too large"))?;
            let end = offset
                .checked_add(self.program_size as usize)
                .ok_or_else(|| anyhow!("program table range overflow"))?;
            let entry = self
                .data
                .get(offset..end)
                .ok_or_else(|| anyhow!("truncated program table"))?;
            let typ = read_u32(
                entry
                    .get(..4)
                    .ok_or_else(|| anyhow!("program header is too short"))?,
                self.little_endian,
            )?;
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
                return file_offset
                    .checked_add(address - virtual_address)
                    .ok_or_else(|| anyhow!("USDT file offset overflow"));
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
        offset = align4(name_end)?;
        let desc_end = offset
            .checked_add(descsz)
            .ok_or_else(|| anyhow!("note descriptor overflow"))?;
        let desc = data
            .get(offset..desc_end)
            .ok_or_else(|| anyhow!("truncated note descriptor"))?;
        offset = align4(desc_end)?;
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
fn align4(value: usize) -> Result<usize> {
    Ok(value
        .checked_add(3)
        .ok_or_else(|| anyhow!("ELF note alignment overflow"))?
        & !3)
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
    fn malformed_elf_table_offsets_fail_closed() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        data[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        data[58..60].copy_from_slice(&64u16.to_le_bytes());
        data[60..62].copy_from_slice(&1u16.to_le_bytes());

        let elf = ElfView::parse(&data).unwrap();
        assert!(elf.section(0).is_err());

        data[40..48].copy_from_slice(&0u64.to_le_bytes());
        data[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        let elf = ElfView::parse(&data).unwrap();
        assert!(elf.virtual_to_file_offset(0).is_err());
    }
}
