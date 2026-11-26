//! Pure zero-dependency Rust static ELF64 + disassembly inspector.

use crate::rpc::BrokerService;
use crate::store::resolve_input_path;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const MAX_AUDIT_FILE_BYTES: u64 = 512 * 1024 * 1024;
const EHDR64_SIZE: usize = 64;
const SHDR64_SIZE: usize = 64;
const SYM64_SIZE: usize = 24;
const DYN64_SIZE: usize = 16;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xFFFF;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;

const STB_WEAK: u8 = 2;
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;

const DT_NULL: i64 = 0;
const DT_BIND_NOW: i64 = 24;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6FFF_FFFB;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;

const SUSPECT_SYMBOLS: &[&str] = &[
    "__cxa_guard_acquire",
    "__cxa_guard_release",
    "__tls_get_addr",
    "__udivti3",
    "__umodti3",
    "__divti3",
    "__modti3",
    "snprintf",
    "vsnprintf",
    "__ctype_b_loc",
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
struct SectionSizes {
    text: u64,
    rodata: u64,
    data_rel_ro: u64,
    bss: u64,
}

#[derive(Default)]
struct AsmCounts {
    zmm: usize,
    divq_idivq: usize,
    tls_get_addr: usize,
    rep_stos: usize,
    indirect_callq: usize,
}

struct ElfAudit {
    e_machine: u16,
    bind_now: bool,
    init_array_entries: u64,
    sections: SectionSizes,
    suspect_symbols: BTreeMap<&'static str, Vec<&'static str>>,
    defined_weak_function_count: usize,
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
    let off = usize::try_from(sec.sh_offset)
        .map_err(|_| "ELF section offset overflow".to_string())?;
    let size = usize::try_from(sec.sh_size)
        .map_err(|_| "ELF section size overflow".to_string())?;
    let end = off
        .checked_add(size)
        .ok_or_else(|| "ELF section payload overflow".to_string())?;
    if off > data.len() || end > data.len() {
        return Err("truncated ELF section payload".to_string());
    }
    Ok(&data[off..end])
}

fn inspect_elf64_bytes(data: &[u8]) -> Result<ElfAudit, String> {
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
    let e_shoff = usize::try_from(e_shoff_u64)
        .map_err(|_| "ELF section header offset overflow".to_string())?;

    let e_shnum = if e_shnum_raw == 0 {
        let first_end = e_shoff
            .checked_add(e_shentsize)
            .ok_or_else(|| "ELF section header table overflow".to_string())?;
        if first_end > data.len() {
            return Err("truncated ELF section header table".to_string());
        }
        let ext = parse_shdr64(&data[e_shoff..e_shoff + SHDR64_SIZE]).sh_size;
        let ext_usize = usize::try_from(ext)
            .map_err(|_| "ELF extended section count overflow".to_string())?;
        if ext_usize == 0 {
            return Err("ELF has no valid section header table".to_string());
        }
        ext_usize
    } else {
        e_shnum_raw as usize
    };

    let sh_table_bytes = e_shnum
        .checked_mul(e_shentsize)
        .ok_or_else(|| "ELF section header table overflow".to_string())?;
    let sh_table_end = e_shoff
        .checked_add(sh_table_bytes)
        .ok_or_else(|| "ELF section header table overflow".to_string())?;
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

        if sec.sh_type == SHT_DYNAMIC {
            let dyn_bytes = section_bytes(data, sec)?;
            let dyn_entsize = if sec.sh_entsize == 0 {
                DYN64_SIZE
            } else {
                usize::try_from(sec.sh_entsize)
                    .map_err(|_| ".dynamic entry size overflow".to_string())?
            };
            if dyn_entsize < DYN64_SIZE {
                return Err(format!(
                    ".dynamic entry size {} is smaller than Dyn64",
                    dyn_entsize
                ));
            }
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
                let Some(next) = off.checked_add(dyn_entsize) else {
                    break;
                };
                off = next;
            }
        }

        if sec.sh_type != SHT_SYMTAB && sec.sh_type != SHT_DYNSYM {
            continue;
        }
        let table_name = if sec.sh_type == SHT_SYMTAB {
            ".symtab"
        } else {
            ".dynsym"
        };
        let link = sec.sh_link as usize;
        if link >= sections.len() || sections[link].sh_type != SHT_STRTAB {
            return Err(format!(
                "{} has invalid string table link {}",
                table_name, link
            ));
        }
        let strtab = section_bytes(data, &sections[link])?;
        let sym_bytes = section_bytes(data, sec)?;
        let entsize = if sec.sh_entsize == 0 {
            SYM64_SIZE
        } else {
            usize::try_from(sec.sh_entsize)
                .map_err(|_| format!("{} entry size overflow", table_name))?
        };
        if entsize < SYM64_SIZE {
            return Err(format!(
                "{} entry size {} is smaller than Sym64",
                table_name, entsize
            ));
        }

        let mut off = 0usize;
        while sym_bytes.len().saturating_sub(off) >= SYM64_SIZE {
            let st_name = read_u32_le(sym_bytes, off) as usize;
            let st_info = sym_bytes[off + 4];
            let st_shndx = read_u16_le(sym_bytes, off + 6);
            let raw_name = read_cstr(strtab, st_name);
            if !raw_name.is_empty() {
                let base_name = raw_name.split('@').next().unwrap_or("");
                if let Some(&canon) = SUSPECT_SYMBOLS.iter().find(|&&s| s == base_name) {
                    let tables = suspect_symbols.entry(canon).or_default();
                    if !tables.contains(&table_name) {
                        tables.push(table_name);
                    }
                }
                let bind = st_info >> 4;
                let sym_type = st_info & 0x0F;
                if bind == STB_WEAK
                    && st_shndx != SHN_UNDEF
                    && (sym_type == STT_FUNC || sym_type == STT_GNU_IFUNC)
                {
                    weak_funcs.insert(raw_name.into_owned());
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
    })
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn is_zmm_token(tok: &[u8]) -> bool {
    if tok.len() < 4 || tok.len() > 5 || !tok.starts_with(b"zmm") {
        return false;
    }
    let rest = &tok[3..];
    match rest.len() {
        1 => rest[0].is_ascii_digit(),
        2 => {
            ((rest[0] == b'1' || rest[0] == b'2') && rest[1].is_ascii_digit())
                || (rest[0] == b'3' && (rest[1] == b'0' || rest[1] == b'1'))
        }
        _ => false,
    }
}

fn scan_asm_line(line: &[u8], counts: &mut AsmCounts) {
    let len = line.len();
    let mut i = 0usize;
    while i < len {
        if !is_word_byte(line[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < len && is_word_byte(line[i]) {
            i += 1;
        }
        let tok = &line[start..i];
        if is_zmm_token(tok) {
            counts.zmm += 1;
        } else if tok == b"divq" || tok == b"idivq" {
            counts.divq_idivq += 1;
        } else if tok == b"__tls_get_addr" {
            counts.tls_get_addr += 1;
        } else if tok == b"rep" {
            let mut j = i;
            while j < len && line[j].is_ascii_whitespace() {
                j += 1;
            }
            if j > i && j < len && is_word_byte(line[j]) {
                let next_start = j;
                while j < len && is_word_byte(line[j]) {
                    j += 1;
                }
                let next_tok = &line[next_start..j];
                if matches!(
                    next_tok,
                    b"stos" | b"stosb" | b"stosw" | b"stosd" | b"stosq"
                ) {
                    counts.rep_stos += 1;
                }
            }
        } else if tok == b"call" || tok == b"callq" {
            let mut j = i;
            while j < len && line[j].is_ascii_whitespace() {
                j += 1;
            }
            if j > i && j < len && line[j] == b'*' {
                counts.indirect_callq += 1;
            }
        }
    }
}

fn scan_asm_file(path: &Path) -> Result<AsmCounts, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("cannot stat ASM file {}: {}", path.display(), e))?;
    if !meta.is_file() {
        return Err(format!("ASM path is not a regular file: {}", path.display()));
    }
    if meta.len() > MAX_AUDIT_FILE_BYTES {
        return Err(format!(
            "ASM file exceeds {} bytes: {}",
            MAX_AUDIT_FILE_BYTES,
            path.display()
        ));
    }
    let file = File::open(path)
        .map_err(|e| format!("cannot open ASM file {}: {}", path.display(), e))?;
    let mut reader = BufReader::new(file);
    let mut counts = AsmCounts::default();
    let mut buf = Vec::with_capacity(512);
    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("cannot read ASM file {}: {}", path.display(), e))?;
        if read == 0 {
            break;
        }
        scan_asm_line(&buf, &mut counts);
    }
    Ok(counts)
}

fn render_elf_audit(
    elf_path: &Path,
    audit: &ElfAudit,
    asm: Option<(&Path, &AsmCounts)>,
) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "static-only ELF64 audit");
    let _ = writeln!(out, "status: available");
    let _ = writeln!(
        out,
        "elf: {} (e_machine={})",
        elf_path.display(),
        audit.e_machine
    );
    let _ = writeln!(out, "bind_now: {}", audit.bind_now);
    let _ = writeln!(out, "init_array_entries: {}", audit.init_array_entries);
    let _ = writeln!(
        out,
        "sections: .text={}, .rodata={}, .data.rel.ro={}, .bss={}",
        audit.sections.text,
        audit.sections.rodata,
        audit.sections.data_rel_ro,
        audit.sections.bss
    );
    let _ = writeln!(out, "suspect symbols:");
    if audit.suspect_symbols.is_empty() {
        let _ = writeln!(out, "- none observed");
    } else {
        for (name, tables) in &audit.suspect_symbols {
            let _ = writeln!(out, "- {} ({})", name, tables.join(", "));
        }
    }
    let _ = writeln!(
        out,
        "defined STB_WEAK functions: {}",
        audit.defined_weak_function_count
    );
    if let Some((asm_path, counts)) = asm {
        let _ = writeln!(out, "asm: {}", asm_path.display());
        let _ = writeln!(
            out,
            "asm counts: zmm={}, divq_idivq={}, tls_get_addr={}, rep_stos={}, indirect_callq={}",
            counts.zmm,
            counts.divq_idivq,
            counts.tls_get_addr,
            counts.rep_stos,
            counts.indirect_callq
        );
    }
    let _ = writeln!(out, "not verified: build/test/runtime/live proof");
    out
}

pub fn op_elf_audit(
    svc: &BrokerService,
    elf_path: &str,
    asm_path: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if elf_path.trim().is_empty() {
        return Err("provide an ELF file path".to_string());
    }
    let root = cwd
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let resolved_elf = resolve_input_path(elf_path, Some(&root));
    let (canon_elf, _) = svc.allowlist.admit_file(&resolved_elf, Some(&root))?;

    let meta = fs::metadata(&canon_elf)
        .map_err(|e| format!("cannot stat ELF file {}: {}", canon_elf.display(), e))?;
    if !meta.is_file() {
        return Err(format!(
            "ELF path is not a regular file: {}",
            canon_elf.display()
        ));
    }
    if meta.len() > MAX_AUDIT_FILE_BYTES {
        return Err(format!(
            "ELF file exceeds {} bytes: {}",
            MAX_AUDIT_FILE_BYTES,
            canon_elf.display()
        ));
    }
    let data = fs::read(&canon_elf)
        .map_err(|e| format!("cannot read ELF file {}: {}", canon_elf.display(), e))?;
    let audit = inspect_elf64_bytes(&data)?;

    let asm_result = if let Some(asm_raw) = asm_path.map(str::trim).filter(|s| !s.is_empty()) {
        let resolved_asm = resolve_input_path(asm_raw, Some(&root));
        let (canon_asm, _) = svc.allowlist.admit_file(&resolved_asm, Some(&root))?;
        let counts = scan_asm_file(&canon_asm)?;
        Some((canon_asm, counts))
    } else {
        None
    };

    Ok(render_elf_audit(
        &canon_elf,
        &audit,
        asm_result.as_ref().map(|(p, c)| (p.as_path(), c)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_shdr(
        out: &mut Vec<u8>,
        sh_name: u32,
        sh_type: u32,
        sh_offset: u64,
        sh_size: u64,
        sh_link: u32,
        sh_entsize: u64,
    ) {
        out.extend_from_slice(&sh_name.to_le_bytes());
        out.extend_from_slice(&sh_type.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        out.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        out.extend_from_slice(&sh_offset.to_le_bytes());
        out.extend_from_slice(&sh_size.to_le_bytes());
        out.extend_from_slice(&sh_link.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        out.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
        out.extend_from_slice(&sh_entsize.to_le_bytes());
    }

    fn push_sym(out: &mut Vec<u8>, st_name: u32, st_info: u8, st_shndx: u16) {
        out.extend_from_slice(&st_name.to_le_bytes());
        out.push(st_info);
        out.push(0); // st_other
        out.extend_from_slice(&st_shndx.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // st_value
        out.extend_from_slice(&16u64.to_le_bytes()); // st_size
    }

    fn build_synthetic_elf(use_shn_xindex: bool) -> Vec<u8> {
        let mut shstrtab = Vec::new();
        shstrtab.push(0);
        let name_shstrtab = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");
        let name_text = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".text\0");
        let name_rodata = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".rodata\0");
        let name_relro = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".data.rel.ro\0");
        let name_bss = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".bss\0");
        let name_init_array = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".init_array\0");
        let name_dynamic = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".dynamic\0");
        let name_dynstr = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".dynstr\0");
        let name_dynsym = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".dynsym\0");

        let mut dynstr = Vec::new();
        dynstr.push(0);
        let sym_tls = dynstr.len() as u32;
        dynstr.extend_from_slice(b"__tls_get_addr@GLIBC_2.3\0");
        let sym_weak = dynstr.len() as u32;
        dynstr.extend_from_slice(b"custom_weak_fn\0");
        let sym_weak_undef = dynstr.len() as u32;
        dynstr.extend_from_slice(b"undef_weak_fn\0");

        let mut dynsym = Vec::new();
        push_sym(&mut dynsym, 0, 0, SHN_UNDEF);
        push_sym(&mut dynsym, sym_tls, (1 << 4) | STT_FUNC, SHN_UNDEF);
        push_sym(&mut dynsym, sym_weak, (STB_WEAK << 4) | STT_FUNC, 2);
        push_sym(&mut dynsym, sym_weak, (STB_WEAK << 4) | STT_FUNC, 2); // duplicate to verify dedup
        push_sym(
            &mut dynsym,
            sym_weak_undef,
            (STB_WEAK << 4) | STT_FUNC,
            SHN_UNDEF,
        );

        let mut dynamic = Vec::new();
        dynamic.extend_from_slice(&DT_FLAGS_1.to_le_bytes());
        dynamic.extend_from_slice(&DF_1_NOW.to_le_bytes());
        dynamic.extend_from_slice(&DT_NULL.to_le_bytes());
        dynamic.extend_from_slice(&0u64.to_le_bytes());

        let text_bytes = vec![0x90u8; 64];
        let rodata_bytes = vec![0x01u8; 32];
        let relro_bytes = vec![0x02u8; 16];
        let init_array_bytes = vec![0u8; 16]; // 2 entries

        let mut elf = vec![0u8; EHDR64_SIZE];
        let off_shstrtab = elf.len() as u64;
        elf.extend_from_slice(&shstrtab);
        let off_text = elf.len() as u64;
        elf.extend_from_slice(&text_bytes);
        let off_rodata = elf.len() as u64;
        elf.extend_from_slice(&rodata_bytes);
        let off_relro = elf.len() as u64;
        elf.extend_from_slice(&relro_bytes);
        let off_init_array = elf.len() as u64;
        elf.extend_from_slice(&init_array_bytes);
        let off_dynamic = elf.len() as u64;
        elf.extend_from_slice(&dynamic);
        let off_dynstr = elf.len() as u64;
        elf.extend_from_slice(&dynstr);
        let off_dynsym = elf.len() as u64;
        elf.extend_from_slice(&dynsym);

        let shoff = elf.len() as u64;
        let shnum: u16 = 10;
        let shdr0_link = if use_shn_xindex { 1 } else { 0 };
        // 0: SHT_NULL
        push_shdr(&mut elf, 0, 0, 0, 0, shdr0_link, 0);
        // 1: .shstrtab
        push_shdr(
            &mut elf,
            name_shstrtab,
            SHT_STRTAB,
            off_shstrtab,
            shstrtab.len() as u64,
            0,
            0,
        );
        // 2: .text
        push_shdr(&mut elf, name_text, 1, off_text, text_bytes.len() as u64, 0, 0);
        // 3: .rodata
        push_shdr(
            &mut elf,
            name_rodata,
            1,
            off_rodata,
            rodata_bytes.len() as u64,
            0,
            0,
        );
        // 4: .data.rel.ro
        push_shdr(
            &mut elf,
            name_relro,
            1,
            off_relro,
            relro_bytes.len() as u64,
            0,
            0,
        );
        // 5: .bss (SHT_NOBITS with large size > file size to prove file bytes are never sliced)
        push_shdr(&mut elf, name_bss, SHT_NOBITS, 0xFFFF_0000, 4096, 0, 0);
        // 6: .init_array
        push_shdr(
            &mut elf,
            name_init_array,
            SHT_INIT_ARRAY,
            off_init_array,
            init_array_bytes.len() as u64,
            0,
            8,
        );
        // 7: .dynamic
        push_shdr(
            &mut elf,
            name_dynamic,
            SHT_DYNAMIC,
            off_dynamic,
            dynamic.len() as u64,
            8,
            DYN64_SIZE as u64,
        );
        // 8: .dynstr
        push_shdr(
            &mut elf,
            name_dynstr,
            SHT_STRTAB,
            off_dynstr,
            dynstr.len() as u64,
            0,
            0,
        );
        // 9: .dynsym
        push_shdr(
            &mut elf,
            name_dynsym,
            SHT_DYNSYM,
            off_dynsym,
            dynsym.len() as u64,
            8,
            SYM64_SIZE as u64,
        );

        // Fill ELF64 header
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = ELFCLASS64;
        elf[5] = ELFDATA2LSB;
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[40..48].copy_from_slice(&shoff.to_le_bytes());
        elf[58..60].copy_from_slice(&(SHDR64_SIZE as u16).to_le_bytes());
        elf[60..62].copy_from_slice(&shnum.to_le_bytes());
        let shstrndx = if use_shn_xindex { SHN_XINDEX } else { 1u16 };
        elf[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        elf
    }

    #[test]
    fn native_elf64_and_asm_audit_inspects_sections_symbols_and_asm_counts() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-elf-audit-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let elf_file = dir.join("sample.elf");
        let asm_file = dir.join("sample.s");
        fs::write(&elf_file, build_synthetic_elf(true)).unwrap();
        fs::write(
            &asm_file,
            "\tvmovdqa64 %zmm0, %zmm31\n\
             \t# zmm32 and azmm1 must not count\n\
             \tdivq %rcx\n\
             \tidivq (%rax)\n\
             \tmy_divq %rax\n\
             \tcallq __tls_get_addr@PLT\n\
             \trep stosq\n\
             \trep   stosb\n\
             \tcall *%rax\n\
             \tcallq  *0x10(%rdi)\n",
        )
        .unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        svc.allowlist.register_hint(&dir, true).unwrap();
        let report = op_elf_audit(&svc, "sample.elf", Some("sample.s"), Some(&dir)).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert!(report.contains("static-only ELF64 audit\n"));
        assert!(report.contains("status: available\n"));
        assert!(report.contains("(e_machine=62)\n"));
        assert!(report.contains("bind_now: true\n"));
        assert!(report.contains("init_array_entries: 2\n"));
        assert!(report.contains("sections: .text=64, .rodata=32, .data.rel.ro=16, .bss=4096\n"));
        assert!(report.contains("- __tls_get_addr (.dynsym)\n"));
        assert!(report.contains("defined STB_WEAK functions: 1\n"));
        assert!(report.contains(
            "asm counts: zmm=2, divq_idivq=2, tls_get_addr=1, rep_stos=2, indirect_callq=2\n"
        ));
        assert!(report.contains("not verified: build/test/runtime/live proof\n"));
    }

    #[test]
    fn elf64_audit_rejects_non_elf_and_truncated_input() {
        assert!(inspect_elf64_bytes(b"short").is_err());
        let bad = vec![0u8; 64];
        assert!(inspect_elf64_bytes(&bad).is_err());
        let mut truncated = build_synthetic_elf(false);
        truncated.truncate(truncated.len() - 8);
        assert!(inspect_elf64_bytes(&truncated).is_err());
    }
}
