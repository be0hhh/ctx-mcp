//! Compact before/after diff renderer for ELF64 sections, symbols, and disassembly counters.

use super::asm::AsmCounts;
use super::elf::ElfAudit;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

const TOP_FN_LIMIT: usize = 5;

fn write_delta_u64(out: &mut String, before: u64, after: u64) {
    if after > before {
        let _ = write!(out, "+{}", after - before);
    } else if before > after {
        let _ = write!(out, "-{}", before - after);
    } else {
        out.push('0');
    }
}

#[inline]
fn write_delta_usize(out: &mut String, before: usize, after: usize) {
    write_delta_u64(out, before as u64, after as u64);
}

fn collect_u64_deltas<'a>(
    before: &'a BTreeMap<String, u64>,
    after: &'a BTreeMap<String, u64>,
) -> Vec<(&'a str, u64, u64, u64)> {
    let mut out = Vec::new();
    for (name, &b_val) in before {
        let a_val = after.get(name).copied().unwrap_or(0);
        if a_val != b_val {
            out.push((name.as_str(), b_val, a_val, a_val.abs_diff(b_val)));
        }
    }
    for (name, &a_val) in after {
        if !before.contains_key(name) && a_val != 0 {
            out.push((name.as_str(), 0, a_val, a_val));
        }
    }
    out
}

fn collect_usize_deltas<'a>(
    before: &'a BTreeMap<String, usize>,
    after: &'a BTreeMap<String, usize>,
) -> Vec<(&'a str, u64, u64, u64)> {
    let mut out = Vec::new();
    for (name, &b_val) in before {
        let a_val = after.get(name).copied().unwrap_or(0);
        if a_val != b_val {
            let (b, a) = (b_val as u64, a_val as u64);
            out.push((name.as_str(), b, a, a.abs_diff(b)));
        }
    }
    for (name, &a_val) in after {
        if !before.contains_key(name) && a_val != 0 {
            let a = a_val as u64;
            out.push((name.as_str(), 0, a, a));
        }
    }
    out
}

fn write_top_fn_deltas(out: &mut String, heading: &str, mut deltas: Vec<(&str, u64, u64, u64)>) {
    deltas.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(b.0)));
    deltas.truncate(TOP_FN_LIMIT);
    let _ = writeln!(out, "{heading}:");
    if deltas.is_empty() {
        let _ = writeln!(out, "- none");
        return;
    }
    for (name, before, after, _) in deltas {
        let _ = write!(out, "- {name}: ");
        write_delta_u64(out, before, after);
        let _ = writeln!(out, " ({before} -> {after})");
    }
}

pub(super) fn write_asm_counts(out: &mut String, asm_path: &Path, counts: &AsmCounts) {
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

pub(super) fn write_asm_diff(
    out: &mut String,
    baseline_asm_path: &Path,
    baseline: &AsmCounts,
    asm_path: &Path,
    after: &AsmCounts,
) {
    let _ = writeln!(out, "baseline_asm: {}", baseline_asm_path.display());
    let _ = writeln!(out, "asm: {}", asm_path.display());
    let _ = write!(out, "asm deltas: Δinsns=");
    write_delta_usize(out, baseline.total_insns, after.total_insns);
    let _ = write!(out, ", Δvzeroupper=");
    write_delta_usize(out, baseline.vzeroupper, after.vzeroupper);
    let _ = write!(out, ", Δdivq_idivq=");
    write_delta_usize(out, baseline.divq_idivq, after.divq_idivq);
    let _ = write!(out, ", Δzmm=");
    write_delta_usize(out, baseline.zmm, after.zmm);
    let _ = write!(out, ", Δtls_get_addr=");
    write_delta_usize(out, baseline.tls_get_addr, after.tls_get_addr);
    let _ = write!(out, ", Δrep_stos=");
    write_delta_usize(out, baseline.rep_stos, after.rep_stos);
    let _ = write!(out, ", Δindirect_callq=");
    write_delta_usize(out, baseline.indirect_callq, after.indirect_callq);
    out.push('\n');

    if !baseline.per_fn_insns.is_empty() || !after.per_fn_insns.is_empty() {
        write_top_fn_deltas(
            out,
            "top changed ASM functions",
            collect_usize_deltas(&baseline.per_fn_insns, &after.per_fn_insns),
        );
    }
}

pub(super) fn render_elf_diff(
    baseline_elf_path: &Path,
    baseline: &ElfAudit,
    elf_path: &Path,
    after: &ElfAudit,
    baseline_asm: Option<(&Path, &AsmCounts)>,
    asm: Option<(&Path, &AsmCounts)>,
) -> String {
    let mut out = String::with_capacity(768);
    let _ = writeln!(out, "static-only ELF64 audit diff");
    let _ = writeln!(out, "status: available");
    let _ = writeln!(
        out,
        "baseline_elf: {} (e_machine={})",
        baseline_elf_path.display(),
        baseline.e_machine
    );
    let _ = writeln!(out, "elf: {} (e_machine={})", elf_path.display(), after.e_machine);
    let _ = writeln!(out, "bind_now: {} -> {}", baseline.bind_now, after.bind_now);
    let _ = writeln!(
        out,
        "sections (after): .text={}, .rodata={}, .data.rel.ro={}, .bss={}",
        after.sections.text, after.sections.rodata, after.sections.data_rel_ro, after.sections.bss
    );

    let _ = write!(out, "elf deltas: Δ.text=");
    write_delta_u64(&mut out, baseline.sections.text, after.sections.text);
    let _ = write!(out, ", Δ.rodata=");
    write_delta_u64(&mut out, baseline.sections.rodata, after.sections.rodata);
    let _ = write!(out, ", Δ.data.rel.ro=");
    write_delta_u64(&mut out, baseline.sections.data_rel_ro, after.sections.data_rel_ro);
    let _ = write!(out, ", Δ.bss=");
    write_delta_u64(&mut out, baseline.sections.bss, after.sections.bss);
    out.push('\n');

    let _ = write!(out, "elf metadata deltas: Δinit_array_entries=");
    write_delta_u64(&mut out, baseline.init_array_entries, after.init_array_entries);
    let _ = write!(out, ", Δweak_funcs=");
    write_delta_usize(
        &mut out,
        baseline.defined_weak_function_count,
        after.defined_weak_function_count,
    );
    out.push('\n');

    let _ = writeln!(out, "suspect symbols diff:");
    let mut any_suspect_delta = false;
    for (name, tables) in &after.suspect_symbols {
        if !baseline.suspect_symbols.contains_key(name) {
            any_suspect_delta = true;
            let _ = writeln!(out, "- +added {} ({})", name, tables.join(", "));
        }
    }
    for (name, tables) in &baseline.suspect_symbols {
        if !after.suspect_symbols.contains_key(name) {
            any_suspect_delta = true;
            let _ = writeln!(out, "- -removed {} ({})", name, tables.join(", "));
        }
    }
    if !any_suspect_delta {
        let _ = writeln!(out, "- none (unchanged: {})", after.suspect_symbols.len());
    }

    if !baseline.defined_func_sizes.is_empty() || !after.defined_func_sizes.is_empty() {
        write_top_fn_deltas(
            &mut out,
            "top changed ELF functions",
            collect_u64_deltas(&baseline.defined_func_sizes, &after.defined_func_sizes),
        );
    }

    match (baseline_asm, asm) {
        (Some((b_path, b_counts)), Some((a_path, a_counts))) => {
            write_asm_diff(&mut out, b_path, b_counts, a_path, a_counts);
        }
        (None, Some((a_path, a_counts))) => write_asm_counts(&mut out, a_path, a_counts),
        _ => {}
    }

    let _ = writeln!(out, "not verified: build/test/runtime/live proof");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_deltas_handle_extremes_and_deterministic_tie_breaking() {
        let mut s = String::new();
        write_delta_u64(&mut s, 0, u64::MAX);
        assert_eq!(s, format!("+{}", u64::MAX));
        s.clear();
        write_delta_u64(&mut s, u64::MAX, 0);
        assert_eq!(s, format!("-{}", u64::MAX));
        s.clear();
        write_delta_u64(&mut s, 42, 42);
        assert_eq!(s, "0");

        let mut out = String::new();
        write_top_fn_deltas(
            &mut out,
            "top",
            vec![("zeta", 0, 10, 10), ("alpha", 20, 10, 10)],
        );
        let alpha_pos = out.find("- alpha: -10 (20 -> 10)").unwrap();
        let zeta_pos = out.find("- zeta: +10 (0 -> 10)").unwrap();
        assert!(alpha_pos < zeta_pos);
    }
}
