//! Pure zero-dependency Rust static ELF64 + disassembly inspector and baseline diff engine.

mod asm;
mod diff;
mod elf;

use crate::rpc::BrokerService;
use crate::store::resolve_input_path;
use asm::{scan_asm_file, AsmCounts};
use diff::{render_elf_diff, write_asm_counts, write_asm_diff};
use elf::{inspect_elf64_file, ElfAudit};
use std::fmt::Write;
use std::path::{Path, PathBuf};

fn admit_path(svc: &BrokerService, raw: &str, root: &Path) -> Result<PathBuf, String> {
    let resolved = resolve_input_path(raw, Some(root));
    let (canon, _) = svc.allowlist.admit_file(&resolved, Some(root))?;
    Ok(canon)
}

fn trim_non_empty(opt: Option<&str>) -> Option<&str> {
    opt.map(str::trim).filter(|s| !s.is_empty())
}

fn render_elf_audit(
    elf_path: &Path,
    audit: &ElfAudit,
    asm: Option<(&Path, &AsmCounts)>,
    baseline_asm: Option<(&Path, &AsmCounts)>,
) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "static-only ELF64 audit\nstatus: available");
    let _ = writeln!(out, "elf: {} (e_machine={})", elf_path.display(), audit.e_machine);
    let _ = writeln!(out, "bind_now: {}", audit.bind_now);
    let _ = writeln!(out, "init_array_entries: {}", audit.init_array_entries);
    let _ = writeln!(
        out,
        "sections: .text={}, .rodata={}, .data.rel.ro={}, .bss={}",
        audit.sections.text, audit.sections.rodata, audit.sections.data_rel_ro, audit.sections.bss
    );
    let _ = writeln!(out, "suspect symbols:");
    if audit.suspect_symbols.is_empty() {
        let _ = writeln!(out, "- none observed");
    } else {
        for (name, tables) in &audit.suspect_symbols {
            let _ = writeln!(out, "- {} ({})", name, tables.join(", "));
        }
    }
    let _ = writeln!(out, "defined STB_WEAK functions: {}", audit.defined_weak_function_count);
    match (baseline_asm, asm) {
        (Some((bp, bc)), Some((ap, ac))) => write_asm_diff(&mut out, bp, bc, ap, ac),
        (None, Some((ap, ac))) => write_asm_counts(&mut out, ap, ac),
        _ => {}
    }
    let _ = writeln!(out, "not verified: build/test/runtime/live proof");
    out
}

#[allow(dead_code)]
pub fn op_elf_audit(
    svc: &BrokerService,
    elf_path: &str,
    asm_path: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    op_elf_audit_with_baseline(svc, elf_path, asm_path, None, None, cwd)
}

pub fn op_elf_audit_with_baseline(
    svc: &BrokerService,
    elf_path: &str,
    asm_path: Option<&str>,
    baseline_elf_path: Option<&str>,
    baseline_asm_path: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if elf_path.trim().is_empty() {
        return Err("provide an ELF file path".to_string());
    }
    let root = cwd
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let canon_elf = admit_path(svc, elf_path, &root)?;
    let audit = inspect_elf64_file(&canon_elf)?;
    let asm_result = trim_non_empty(asm_path)
        .map(|raw| {
            let p = admit_path(svc, raw, &root)?;
            Ok::<_, String>((p.clone(), scan_asm_file(&p)?))
        })
        .transpose()?;
    let baseline_elf_result = trim_non_empty(baseline_elf_path)
        .map(|raw| {
            let p = admit_path(svc, raw, &root)?;
            Ok::<_, String>((p.clone(), inspect_elf64_file(&p)?))
        })
        .transpose()?;
    let baseline_asm_result = trim_non_empty(baseline_asm_path)
        .map(|raw| {
            if asm_result.is_none() {
                return Err("baseline_asm_path requires asm_path".to_string());
            }
            let p = admit_path(svc, raw, &root)?;
            Ok((p.clone(), scan_asm_file(&p)?))
        })
        .transpose()?;

    let asm_ref = asm_result.as_ref().map(|(p, c)| (p.as_path(), c));
    let base_asm_ref = baseline_asm_result.as_ref().map(|(p, c)| (p.as_path(), c));
    if let Some((ref base_path, ref base_audit)) = baseline_elf_result {
        Ok(render_elf_diff(base_path, base_audit, &canon_elf, &audit, base_asm_ref, asm_ref))
    } else {
        Ok(render_elf_audit(&canon_elf, &audit, asm_ref, base_asm_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::elf::*;
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    type SymSpec<'a> = (&'a str, u8, u16, u64);

    fn temp_test_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ctx-elf-audit-{tag}-{}-{}-{id}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn push_shdr(out: &mut Vec<u8>, name: u32, kind: u32, off: u64, sz: u64, link: u32, ent: u64) {
        for v in [name, kind] { out.extend_from_slice(&v.to_le_bytes()); }
        for v in [0u64, 0, off, sz] { out.extend_from_slice(&v.to_le_bytes()); }
        for v in [link, 0] { out.extend_from_slice(&v.to_le_bytes()); }
        for v in [8u64, ent] { out.extend_from_slice(&v.to_le_bytes()); }
    }

    fn build_sym_table(entries: &[SymSpec<'_>]) -> (Vec<u8>, Vec<u8>) {
        let (mut strtab, mut syms) = (vec![0u8], vec![0u8; SYM64_SIZE]);
        for &(name, info, shndx, size) in entries {
            let off = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            syms.extend_from_slice(&off.to_le_bytes());
            syms.extend_from_slice(&[info, 0]);
            syms.extend_from_slice(&shndx.to_le_bytes());
            for v in [0u64, size] { syms.extend_from_slice(&v.to_le_bytes()); }
        }
        (strtab, syms)
    }

    fn build_synthetic_elf(
        use_shn_xindex: bool,
        sec_lens: [u64; 4], // [text, rodata, relro, bss]
        init_entries: usize,
        dynsyms: &[SymSpec<'_>],
        symtabs: &[SymSpec<'_>],
    ) -> Vec<u8> {
        let mut shstrtab = vec![0u8];
        let mut add = |s: &[u8]| -> u32 {
            let off = shstrtab.len() as u32;
            shstrtab.extend_from_slice(s);
            shstrtab.push(0);
            off
        };
        let n = [
            add(b".shstrtab"), add(b".text"), add(b".rodata"), add(b".data.rel.ro"),
            add(b".bss"), add(b".init_array"), add(b".dynamic"), add(b".dynstr"),
            add(b".dynsym"), add(b".strtab"), add(b".symtab"),
        ];
        let ((dynstr, dynsym), (strtab, symtab)) = (build_sym_table(dynsyms), build_sym_table(symtabs));
        let mut dynamic = Vec::with_capacity(32);
        for v in [DT_FLAGS_1.to_le_bytes(), DF_1_NOW.to_le_bytes(), DT_NULL.to_le_bytes(), 0u64.to_le_bytes()] {
            dynamic.extend_from_slice(&v);
        }
        let init_bytes = vec![0u8; init_entries << 3];

        let mut elf = vec![0u8; EHDR64_SIZE];
        let mut put = |b: &[u8]| -> u64 { let o = elf.len() as u64; elf.extend_from_slice(b); o };
        let (o_shstr, o_text) = (put(&shstrtab), put(&vec![0x90u8; sec_lens[0] as usize]));
        let (o_ro, o_relro) = (put(&vec![1u8; sec_lens[1] as usize]), put(&vec![2u8; sec_lens[2] as usize]));
        let (o_init, o_dyn) = (put(&init_bytes), put(&dynamic));
        let (o_dynstr, o_dynsym) = (put(&dynstr), put(&dynsym));
        let (o_strtab, o_symtab) = (put(&strtab), put(&symtab));

        let shoff = elf.len() as u64;
        let has_symtab = !symtabs.is_empty();
        let shnum: u16 = if has_symtab { 12 } else { 10 };
        for (nm, ty, off, sz, lnk, ent) in [
            (0, 0, 0, 0, if use_shn_xindex { 1 } else { 0 }, 0),
            (n[0], SHT_STRTAB, o_shstr, shstrtab.len() as u64, 0, 0),
            (n[1], 1, o_text, sec_lens[0], 0, 0), (n[2], 1, o_ro, sec_lens[1], 0, 0),
            (n[3], 1, o_relro, sec_lens[2], 0, 0), (n[4], SHT_NOBITS, 0xFFFF_0000, sec_lens[3], 0, 0),
            (n[5], SHT_INIT_ARRAY, o_init, init_bytes.len() as u64, 0, 8),
            (n[6], SHT_DYNAMIC, o_dyn, dynamic.len() as u64, 8, DYN64_SIZE as u64),
            (n[7], SHT_STRTAB, o_dynstr, dynstr.len() as u64, 0, 0),
            (n[8], SHT_DYNSYM, o_dynsym, dynsym.len() as u64, 8, SYM64_SIZE as u64),
        ] {
            push_shdr(&mut elf, nm, ty, off, sz, lnk, ent);
        }
        if has_symtab {
            push_shdr(&mut elf, n[9], SHT_STRTAB, o_strtab, strtab.len() as u64, 0, 0);
            push_shdr(&mut elf, n[10], SHT_SYMTAB, o_symtab, symtab.len() as u64, 10, SYM64_SIZE as u64);
        }
        elf[0..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, 1]);
        elf[16..20].copy_from_slice(&[3, 0, 62, 0]);
        elf[40..48].copy_from_slice(&shoff.to_le_bytes());
        elf[58..60].copy_from_slice(&(SHDR64_SIZE as u16).to_le_bytes());
        elf[60..62].copy_from_slice(&shnum.to_le_bytes());
        elf[62..64].copy_from_slice(&(if use_shn_xindex { SHN_XINDEX } else { 1u16 }).to_le_bytes());
        elf
    }

    fn default_single_elf(use_shn_xindex: bool) -> Vec<u8> {
        let dynsyms = [
            ("__tls_get_addr@GLIBC_2.3", (1 << 4) | STT_FUNC, SHN_UNDEF, 16),
            ("custom_weak_fn", (STB_WEAK << 4) | STT_FUNC, 2, 16),
            ("custom_weak_fn", (STB_WEAK << 4) | STT_FUNC, 2, 16),
            ("undef_weak_fn", (STB_WEAK << 4) | STT_FUNC, SHN_UNDEF, 16),
        ];
        build_synthetic_elf(use_shn_xindex, [64, 32, 16, 4096], 2, &dynsyms, &[])
    }

    fn build_asm_dump(funcs: &[(&str, &[&str])]) -> String {
        let (mut out, mut addr) = (String::new(), 0x40_1000u32);
        for &(name, insns) in funcs {
            let _ = writeln!(out, "{addr:016x} <{name}>:");
            for &insn in insns {
                let _ = writeln!(out, "  {addr:x}:\t90\t{insn}");
                addr += 4;
            }
        }
        out
    }

    #[test]
    fn native_elf64_and_asm_audit_inspects_sections_symbols_and_asm_counts() {
        let dir = temp_test_dir("single");
        fs::write(dir.join("sample.elf"), default_single_elf(true)).unwrap();
        fs::write(
            dir.join("sample.s"),
            "\tvmovdqa64 %zmm0, %zmm31\n\t# zmm32 and azmm1 must not count\n\
             \tdivq %rcx\n\tidivq (%rax)\n\tmy_divq %rax\n\tcallq __tls_get_addr@PLT\n\
             \trep stosq\n\trep   stosb\n\tcall *%rax\n\tcallq  *0x10(%rdi)\n",
        ).unwrap();
        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        svc.allowlist.register_hint(&dir, true).unwrap();
        let report = op_elf_audit(&svc, "sample.elf", Some("sample.s"), Some(&dir)).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        for needle in [
            "static-only ELF64 audit\n", "status: available\n", "(e_machine=62)\n",
            "bind_now: true\n", "init_array_entries: 2\n",
            "sections: .text=64, .rodata=32, .data.rel.ro=16, .bss=4096\n",
            "- __tls_get_addr (.dynsym)\n", "defined STB_WEAK functions: 1\n",
            "asm counts: zmm=2, divq_idivq=2, tls_get_addr=1, rep_stos=2, indirect_callq=2\n",
            "not verified: build/test/runtime/live proof\n",
        ] {
            assert!(report.contains(needle), "missing `{needle}` in:\n{report}");
        }
    }

    #[test]
    fn elf64_audit_rejects_non_elf_and_truncated_input() {
        assert!(inspect_elf64_bytes(b"short").is_err());
        assert!(inspect_elf64_bytes(&vec![0u8; 64]).is_err());
        let mut truncated = default_single_elf(false);
        truncated.truncate(truncated.len() - 8);
        assert!(inspect_elf64_bytes(&truncated).is_err());
    }

    #[test]
    fn elf_and_asm_diff_reports_deltas_suspects_top_five_and_allowlist() {
        let (dir, outside) = (temp_test_dir("diff"), temp_test_dir("outside"));
        let (f, w) = ((1 << 4) | STT_FUNC, (STB_WEAK << 4) | STT_FUNC);
        let before_elf = build_synthetic_elf(
            false, [64, 32, 16, 4096], 2,
            &[("__tls_get_addr@GLIBC_2.3", f, SHN_UNDEF, 0), ("wk_a", w, 2, 16)],
            &[("fn_a", f, 2, 10), ("fn_b", f, 2, 20), ("fn_c", f, 2, 30),
              ("fn_d", f, 2, 40), ("fn_e", f, 2, 50), ("fn_f", f, 2, 60)],
        );
        let after_elf = build_synthetic_elf(
            false, [96, 24, 16, 4608], 3,
            &[("__cxa_throw", f, SHN_UNDEF, 0)],
            &[("fn_a", f, 2, 12), ("fn_b", f, 2, 36), ("fn_c", f, 2, 10),
              ("fn_d", f, 2, 80), ("fn_e", f, 2, 20), ("fn_f", f, 2, 160)],
        );
        fs::write(dir.join("before.elf"), &before_elf).unwrap();
        fs::write(dir.join("after.elf"), &after_elf).unwrap();
        fs::write(outside.join("leak.elf"), &before_elf).unwrap();
        fs::write(outside.join("leak.s"), "\tnop\n").unwrap();
        fs::write(dir.join("before.s"), build_asm_dump(&[
            ("a1", &["vzeroupper", "divq %rcx"]), ("a2", &["nop", "nop"]),
            ("a3", &["nop"; 3]), ("a4", &["nop"]), ("a5", &["nop"]), ("a6", &["nop"]),
        ])).unwrap();
        fs::write(dir.join("after.s"), build_asm_dump(&[
            ("a1", &["ret"]), ("a2", &["nop"; 4]), ("a3", &["nop"; 6]),
            ("a4", &["nop"; 5]), ("a5", &["nop"; 6]), ("a6", &["nop"; 7]),
        ])).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        svc.allowlist.register_hint(&dir, true).unwrap();
        let report = op_elf_audit_with_baseline(
            &svc, "after.elf", Some("after.s"), Some("before.elf"), Some("before.s"), Some(&dir),
        ).unwrap();
        let leak_elf = outside.join("leak.elf").to_string_lossy().into_owned();
        let leak_asm = outside.join("leak.s").to_string_lossy().into_owned();
        assert!(op_elf_audit_with_baseline(&svc, "after.elf", None, Some(&leak_elf), None, Some(&dir)).is_err());
        assert!(op_elf_audit_with_baseline(&svc, "after.elf", Some("after.s"), None, Some(&leak_asm), Some(&dir)).is_err());
        assert!(op_elf_audit_with_baseline(&svc, "after.elf", None, None, Some("before.s"), Some(&dir)).is_err());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);

        for needle in [
            "elf deltas: Δ.text=+32, Δ.rodata=-8, Δ.data.rel.ro=0, Δ.bss=+512\n",
            "Δinit_array_entries=+1, Δweak_funcs=-1\n",
            "- +added __cxa_throw (.dynsym)\n", "- -removed __tls_get_addr (.dynsym)\n",
            "- fn_f: +100 (60 -> 160)\n", "- fn_d: +40 (40 -> 80)\n",
            "asm deltas: Δinsns=+19, Δvzeroupper=-1, Δdivq_idivq=-1, Δzmm=0, Δtls_get_addr=0, Δrep_stos=0, Δindirect_callq=0\n",
            "- a6: +6 (1 -> 7)\n", "- a5: +5 (1 -> 6)\n",
        ] {
            assert!(report.contains(needle), "missing `{needle}` in:\n{report}");
        }
        assert!(!report.contains("- fn_a:") && !report.contains("- a1:"));
    }
}
