//! Pure zero-dependency ELF64 binary inspector (sections, dynamic flags, suspect and function symbols).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub(super) const MAX_AUDIT_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const EHDR64_SIZE: usize = 64;
pub(super) const SHDR64_SIZE: usize = 64;
pub(super) const SYM64_SIZE: usize = 24;
pub(super) const DYN64_SIZE: usize = 16;

pub(super) const ELFCLASS64: u8 = 2;
pub(super) const ELFDATA2LSB: u8 = 1;
pub(super) const SHN_UNDEF: u16 = 0;
pub(super) const SHN_XINDEX: u16 = 0xFFFF;

pub(super) const SHT_SYMTAB: u32 = 2;
pub(super) const SHT_STRTAB: u32 = 3;
pub(super) const SHT_DYNAMIC: u32 = 6;
pub(super) const SHT_NOBITS: u32 = 8;
pub(super) const SHT_DYNSYM: u32 = 11;
pub(super) const SHT_INIT_ARRAY: u32 = 14;

pub(super) const STB_WEAK: u8 = 2;
pub(super) const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;

pub(super) const DT_NULL: i64 = 0;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
pub(super) const DT_FLAGS_1: i64 = 0x6FFF_FFFB;
const DF_BIND_NOW: u64 = 0x8;
pub(super) const DF_1_NOW: u64 = 0x1;

const SUSPECT_SYMBOLS: &[&str] = &[
    "__cxa_guard_acquire",
    "__cxa_guard_release",
    "__tls_get_addr",
    "__dynamic_cast",
    "__cxa_throw",
];

struct Shdr64 {
    sh_name: u32,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

#[derive(Default)]
pub(super) struct SectionSizes {
    pub text: u64,
    pub rodata: u64,
    pub data_rel_ro: u64,
    pub bss: u64,
}

pub(super) struct ElfAudit {
    pub e_machine: u16,
    pub bind_now: bool,
    pub init_array_entries: u64,
    pub sections: SectionSizes,
    pub suspect_symbols: BTreeMap<&'static str, Vec<&'static str>>,
    pub defined_weak_function_count: usize,
    pub defined_func_sizes: BTreeMap<String, u64>,
}

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

#[inline]
fn read_i64_le(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn parse_shdr64(raw: &[u8]) -> Shdr64 {
    Shdr64 {
        sh_name: read_u32_le(raw, 0),
        sh_type: read_u32_le(raw, 4),
        sh_offset: read_u64_le(raw, 24),
        sh_size: read_u64_le(raw, 32),
        sh_link: read_u32_le(raw, 40),
        sh_entsize: read_u64_le(raw, 56),
    }
}

fn read_cstr(table: &[u8], offset: usize) -> Cow<'_, str> {
    if offset >= table.len() {
        return Cow::Borrowed("");
    }
    let slice = &table[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end])
}

fn section_bytes<'a>(data: &'a [u8], sec: &Shdr64) -> Result<&'a [u8], String> {
    if sec.sh_type == SHT_NOBITS {
        return Ok(&[]);
    }
    let off = usize::try_from(sec.sh_offset).map_err(|_| "ELF section offset overflow")?;
    let size = usize::try_from(sec.sh_size).map_err(|_| "ELF section size overflow")?;
    let end = off.checked_add(size).ok_or("ELF section payload overflow")?;
    if off > data.len() || end > data.len() {
        return Err("truncated ELF section payload".to_string());
    }
    Ok(&data[off..end])
}

fn scan_dynamic_bind_now(data: &[u8], sec: &Shdr64) -> Result<bool, String> {
    let dyn_bytes = section_bytes(data, sec)?;
    let entsize = if sec.sh_entsize == 0 {
        DYN64_SIZE
    } else {
        usize::try_from(sec.sh_entsize).map_err(|_| ".dynamic entry size overflow")?
    };
    if entsize < DYN64_SIZE {
        return Err(format!(".dynamic entry size {entsize} is smaller than Dyn64"));
    }
    let mut bind_now = false;
    let mut off = 0usize;
    while dyn_bytes.len().saturating_sub(off) >= DYN64_SIZE {
        let d_tag = read_i64_le(dyn_bytes, off);
        let d_val = read_u64_le(dyn_bytes, off + 8);
        if d_tag == DT_NULL {
            break;
        }
        if d_tag == DT_BIND_NOW
            || (d_tag == DT_FLAGS && (d_val & DF_BIND_NOW) != 0)
            || (d_tag == DT_FLAGS_1 && (d_val & DF_1_NOW) != 0)
        {
            bind_now = true;
        }
        let Some(next) = off.checked_add(entsize) else {
            break;
        };
        off = next;
    }
    Ok(bind_now)
}

pub(super) fn inspect_elf64_file(path: &Path) -> Result<ElfAudit, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("cannot stat ELF file {}: {}", path.display(), e))?;
    if !meta.is_file() {
        return Err(format!("ELF path is not a regular file: {}", path.display()));
    }
    if meta.len() > MAX_AUDIT_FILE_BYTES {
        return Err(format!(
            "ELF file exceeds {} bytes: {}",
            MAX_AUDIT_FILE_BYTES,
            path.display()
        ));
    }
    let data = fs::read(path)
        .map_err(|e| format!("cannot read ELF file {}: {}", path.display(), e))?;
    inspect_elf64_bytes(&data)
}

pub(super) fn inspect_elf64_bytes(data: &[u8]) -> Result<ElfAudit, String> {
    if data.len() < EHDR64_SIZE {
        return Err("file is smaller than an ELF64 header".to_string());
    }
    if &data[0..4] != b"\x7fELF" || data[4] != ELFCLASS64 || data[5] != ELFDATA2LSB {
        return Err("expected 64-bit little-endian ELF".to_string());
    }

    let e_machine = read_u16_le(data, 18);
    let e_shoff_u64 = read_u64_le(data, 40);
    let e_shentsize = read_u16_le(data, 58) as usize;
    let e_shnum_raw = read_u16_le(data, 60);
    let e_shstrndx_raw = read_u16_le(data, 62);
    if e_shoff_u64 == 0 || e_shentsize < SHDR64_SIZE {
        return Err("ELF has no valid section header table".to_string());
    }
    let e_shoff = usize::try_from(e_shoff_u64).map_err(|_| "ELF section header offset overflow")?;

    let e_shnum = if e_shnum_raw == 0 {
        let first_end = e_shoff
            .checked_add(e_shentsize)
            .ok_or("ELF section header table overflow")?;
        if first_end > data.len() {
            return Err("truncated ELF section header table".to_string());
        }
        let ext = parse_shdr64(&data[e_shoff..e_shoff + SHDR64_SIZE]).sh_size;
        let ext_usize = usize::try_from(ext).map_err(|_| "ELF extended section count overflow")?;
        if ext_usize == 0 {
            return Err("ELF has no valid section header table".to_string());
        }
        ext_usize
    } else {
        e_shnum_raw as usize
    };

    let sh_table_bytes = e_shnum
        .checked_mul(e_shentsize)
        .ok_or("ELF section header table overflow")?;
    let sh_table_end = e_shoff
        .checked_add(sh_table_bytes)
        .ok_or("ELF section header table overflow")?;
    if sh_table_end > data.len() {
        return Err("truncated ELF section header table".to_string());
    }

    let mut sections = Vec::with_capacity(e_shnum);
    for idx in 0..e_shnum {
        let base = e_shoff + idx * e_shentsize;
        sections.push(parse_shdr64(&data[base..base + SHDR64_SIZE]));
    }

    let shstrndx = if e_shstrndx_raw == SHN_XINDEX {
        sections[0].sh_link as usize
    } else {
        e_shstrndx_raw as usize
    };
    if shstrndx >= sections.len() {
        return Err("invalid ELF .shstrtab index".to_string());
    }
    let shstrtab = section_bytes(data, &sections[shstrndx])?;

    let mut sizes = SectionSizes::default();
    let mut bind_now = false;
    let mut init_array_entries = 0u64;
    let mut suspect_symbols: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    let mut weak_funcs: BTreeSet<String> = BTreeSet::new();
    let mut defined_func_sizes: BTreeMap<String, u64> = BTreeMap::new();
    let extra_suspects = crate::base::ext::policy().extra_elf_suspect_symbols();

    for sec in &sections {
        let sec_name = read_cstr(shstrtab, sec.sh_name as usize);
        match sec_name.as_ref() {
            ".text" => sizes.text = sizes.text.saturating_add(sec.sh_size),
            ".rodata" => sizes.rodata = sizes.rodata.saturating_add(sec.sh_size),
            ".data.rel.ro" => sizes.data_rel_ro = sizes.data_rel_ro.saturating_add(sec.sh_size),
            ".bss" => sizes.bss = sizes.bss.saturating_add(sec.sh_size),
            _ => {}
        }
        if sec.sh_type == SHT_INIT_ARRAY
            || sec_name == ".init_array"
            || sec_name.starts_with(".init_array.")
        {
            init_array_entries = init_array_entries.saturating_add(sec.sh_size >> 3);
        }
        if sec.sh_type == SHT_DYNAMIC && scan_dynamic_bind_now(data, sec)? {
            bind_now = true;
        }
        if sec.sh_type != SHT_SYMTAB && sec.sh_type != SHT_DYNSYM {
            continue;
        }

        let table_name = if sec.sh_type == SHT_SYMTAB { ".symtab" } else { ".dynsym" };
        let link = sec.sh_link as usize;
        if link >= sections.len() || sections[link].sh_type != SHT_STRTAB {
            return Err(format!("{table_name} has invalid string table link {link}"));
        }
        let strtab = section_bytes(data, &sections[link])?;
        let sym_bytes = section_bytes(data, sec)?;
        let entsize = if sec.sh_entsize == 0 {
            SYM64_SIZE
        } else {
            usize::try_from(sec.sh_entsize).map_err(|_| format!("{table_name} entry size overflow"))?
        };
        if entsize < SYM64_SIZE {
            return Err(format!("{table_name} entry size {entsize} is smaller than Sym64"));
        }

        let mut off = 0usize;
        while sym_bytes.len().saturating_sub(off) >= SYM64_SIZE {
            let st_name = read_u32_le(sym_bytes, off) as usize;
            let st_info = sym_bytes[off + 4];
            let st_shndx = read_u16_le(sym_bytes, off + 6);
            let st_size = read_u64_le(sym_bytes, off + 16);
            let raw_name = read_cstr(strtab, st_name);
            if !raw_name.is_empty() {
                let base_name = raw_name.split('@').next().unwrap_or("");
                if let Some(&canon) = SUSPECT_SYMBOLS
                    .iter()
                    .chain(extra_suspects.iter())
                    .find(|&&s| s == base_name)
                {
                    let tables = suspect_symbols.entry(canon).or_default();
                    if !tables.contains(&table_name) {
                        tables.push(table_name);
                    }
                }
                let bind = st_info >> 4;
                let sym_type = st_info & 0x0F;
                if st_shndx != SHN_UNDEF && (sym_type == STT_FUNC || sym_type == STT_GNU_IFUNC) {
                    if st_size > 0 && !base_name.is_empty() {
                        defined_func_sizes
                            .entry(base_name.to_owned())
                            .and_modify(|s| *s = (*s).max(st_size))
                            .or_insert(st_size);
                    }
                    if bind == STB_WEAK {
                        weak_funcs.insert(raw_name.into_owned());
                    }
                }
            }
            let Some(next) = off.checked_add(entsize) else {
                break;
            };
            off = next;
        }
    }

    Ok(ElfAudit {
        e_machine,
        bind_now,
        init_array_entries,
        sections: sizes,
        suspect_symbols,
        defined_weak_function_count: weak_funcs.len(),
        defined_func_sizes,
    })
}
