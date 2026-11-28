use super::{collect_target_files, DEFAULT_READ_MAX_BYTES};
use crate::base::simd::{push_u32, push_usize};
use crate::parser::SymbolKind;
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, CachedFile};
use std::path::Path;
use std::sync::Arc;

#[allow(dead_code)]
pub fn op_outline(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
    cwd: Option<&Path>,
) -> Result<String, String> {
    op_outline_with_options(svc, targets, max_files, max_bytes, 0, cwd)
}

pub fn op_outline_with_options(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
    max_symbols: usize,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if targets.is_empty() {
        return Err("provide at least one file or directory path".to_string());
    }
    let cap = max_files.clamp(1, 200);
    let files = collect_target_files(svc, targets, cwd, cap)?;
    if files.is_empty() {
        return Ok("No matching readable text source files found.".to_string());
    }

    let single_file = files.len() == 1;
    let many_files = files.len() > 10;
    let budget = if max_bytes > 0 {
        max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES)
    } else if many_files {
        9_500
    } else {
        65_536
    };
    let sym_cap = if max_symbols > 0 {
        max_symbols.clamp(1, 2_000)
    } else if single_file {
        usize::MAX
    } else if many_files {
        12
    } else {
        80
    };

    let mut out = String::with_capacity(budget.min(8192));
    let total_files = files.len();
    for (idx, (file, ws_root)) in files.into_iter().enumerate() {
        let mut block = String::with_capacity(256);
        let mut budget_hit = false;
        match svc.store.get_outline_entry(&file, Some(&ws_root)) {
            Ok(entry) => {
                block.push_str("## ");
                block.push_str(&entry.rel_path);
                block.push_str(" (");
                push_u32(&mut block, entry.line_count);
                block.push_str(" lines, ");
                push_u32(&mut block, entry.size_bytes);
                block.push_str(" bytes)\n");
                if entry.symbols.is_empty() {
                    block.push_str("  (no structural symbols extracted)\n");
                } else {
                    let mut emitted = 0usize;
                    let mut row = String::with_capacity(160);
                    for sym in entry.symbols.iter().take(sym_cap) {
                        row.clear();
                        row.push_str("  [L");
                        push_u32(&mut row, sym.start_line);
                        row.push_str("-L");
                        push_u32(&mut row, sym.end_line);
                        row.push_str("] ");
                        row.push_str(sym.kind.as_str());
                        row.push(' ');
                        row.push_str(&sym.name);
                        if !many_files && !sym.signature.is_empty() {
                            row.push_str(" — ");
                            row.push_str(&sym.signature);
                        }
                        row.push('\n');
                        if out.len() + block.len() + row.len() + 96 > budget && emitted > 0 {
                            budget_hit = true;
                            break;
                        }
                        block.push_str(&row);
                        emitted += 1;
                    }
                    if budget_hit && entry.symbols.len() > emitted {
                        block.push_str("  ... +");
                        push_usize(&mut block, entry.symbols.len() - emitted);
                        block.push_str(" more symbols omitted at ");
                        push_usize(&mut block, budget);
                        block.push_str("B budget; pass larger max_bytes\n");
                    } else if entry.symbols.len() > sym_cap {
                        block.push_str("  ... +");
                        push_usize(&mut block, entry.symbols.len() - sym_cap);
                        block.push_str(" more symbols (pass max_symbols to raise)\n");
                    }
                }
            }
            Err(err) => {
                block.push_str(&format!(
                    "## {} [skip: {}]\n",
                    display_workspace_path(&file, Some(&ws_root)),
                    err
                ));
            }
        }
        if !out.is_empty() && out.len() + block.len() + 96 > budget {
            out.push_str(&format!(
                "... (+{} more files omitted at {}B budget; use `ctx_inspect` for multi-folder triage)\n",
                total_files - idx,
                budget
            ));
            break;
        }
        out.push_str(&block);
        if budget_hit {
            if idx + 1 < total_files {
                out.push_str(&format!(
                    "... (+{} more files omitted at {}B budget; use `ctx_inspect` for multi-folder triage)\n",
                    total_files - idx - 1,
                    budget
                ));
            }
            break;
        }
    }
    Ok(out)
}

fn compact_include_label(raw: &str) -> String {
    let norm_owned: String;
    let clean: &str = if raw.contains('\\') {
        norm_owned = raw.replace('\\', "/");
        &norm_owned
    } else {
        raw
    };
    let mut rev_parts = clean.split('/').filter(|s| !s.is_empty()).rev();
    let Some(last) = rev_parts.next() else {
        return String::new();
    };
    if let Some(prev) = rev_parts.next() {
        let mut s = String::with_capacity(prev.len() + 1 + last.len());
        s.push_str(prev);
        s.push('/');
        s.push_str(last);
        s
    } else {
        last.to_string()
    }
}

fn extract_header_facts(entry: &CachedFile) -> (Vec<String>, Vec<String>) {
    let mut namespaces: Vec<String> = Vec::new();
    let mut local_inc: Vec<String> = Vec::new();
    let mut sys_inc: Vec<String> = Vec::new();
    let scan_lines = entry.line_count.min(300);

    for ln in 1..=scan_lines {
        let trimmed = entry.line_slice(ln).trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("#include") {
            let after = rest.trim_start();
            if let Some(q) = after.strip_prefix('"') {
                if let Some((inc, _)) = q.split_once('"') {
                    let lbl = compact_include_label(inc);
                    if !lbl.is_empty() && !local_inc.contains(&lbl) && local_inc.len() < 24 {
                        local_inc.push(lbl);
                    }
                }
            } else if let Some(a) = after.strip_prefix('<') {
                if let Some((inc, _)) = a.split_once('>') {
                    let inner = compact_include_label(inc);
                    let mut lbl = String::with_capacity(inner.len() + 2);
                    lbl.push('<');
                    lbl.push_str(&inner);
                    lbl.push('>');
                    if !sys_inc.contains(&lbl) && sys_inc.len() < 12 {
                        sys_inc.push(lbl);
                    }
                }
            }
            continue;
        }
        // Rust `use ...;`, Python `from ... import` / `import ...`, Java/JS/TS `import ...`, C# `using ...;`
        if local_inc.len() < 16 {
            if let Some(rest) = trimmed.strip_prefix("use ") {
                let target = rest.trim_end_matches(';').trim();
                let lbl = target
                    .split("::")
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("::");
                if !lbl.is_empty() && !local_inc.contains(&lbl) {
                    local_inc.push(lbl);
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("from ") {
                if let Some((module, _)) = rest.split_once(" import ") {
                    let lbl = module.trim().to_string();
                    if !lbl.is_empty() && !local_inc.contains(&lbl) {
                        local_inc.push(lbl);
                    }
                    continue;
                }
            }
            if let Some(rest) = trimmed.strip_prefix("import ") {
                let target = if let Some((_, from_part)) = rest.rsplit_once(" from ") {
                    from_part.trim().trim_end_matches(';').trim_matches('"').trim_matches('\'')
                } else {
                    rest.trim().trim_end_matches(';').trim_matches('"').trim_matches('\'')
                };
                let lbl = compact_include_label(target);
                if !lbl.is_empty() && !lbl.contains(' ') && !local_inc.contains(&lbl) {
                    local_inc.push(lbl);
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("using ") {
                if !rest.contains('=') && !rest.starts_with('(') {
                    let target = rest
                        .strip_prefix("static ")
                        .unwrap_or(rest)
                        .trim_end_matches(';')
                        .trim();
                    if !target.is_empty() && !target.contains(' ') {
                        let lbl = target.to_string();
                        if !local_inc.contains(&lbl) {
                            local_inc.push(lbl);
                        }
                    }
                    continue;
                }
            }
        }
        if namespaces.len() < 2 {
            if let Some(rest) = trimmed
                .strip_prefix("namespace ")
                .or_else(|| trimmed.strip_prefix("package "))
            {
                if !rest.contains('=') {
                    let after = rest.trim_start();
                    let nlen = after
                        .bytes()
                        .take_while(|&b| {
                            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.')
                        })
                        .count();
                    let ns = &after[..nlen];
                    if !ns.is_empty()
                        && ns != "detail"
                        && !ns.ends_with("_detail")
                        && !ns.ends_with("::detail")
                        && !namespaces.iter().any(|existing| existing == ns)
                    {
                        namespaces.push(ns.to_string());
                    }
                }
            }
        }
    }
    local_inc.extend(sys_inc);
    (namespaces, local_inc)
}

pub fn op_inspect(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
    warn_lines: usize,
    cwd: Option<&Path>,
) -> Result<String, String> {
    if targets.is_empty() {
        return Err("provide at least one file or directory path".to_string());
    }
    let cap = max_files.clamp(1, 250);
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES);
    let warn_l = warn_lines.clamp(50, 50_000);
    let files = collect_target_files(svc, targets, cwd, cap)?;
    if files.is_empty() {
        return Ok("No matching readable text source files found.".to_string());
    }

    struct InspectItem {
        entry: Arc<CachedFile>,
        namespaces: Vec<String>,
        includes: Vec<String>,
    }

    let mut items: Vec<InspectItem> = Vec::with_capacity(files.len());
    let mut skipped: Vec<String> = Vec::new();

    for (file, ws_root) in files {
        match svc.store.get_full_entry(&file, Some(&ws_root)) {
            Ok(entry) => {
                let (namespaces, includes) = extract_header_facts(&entry);
                items.push(InspectItem {
                    entry,
                    namespaces,
                    includes,
                });
            }
            Err(err) => {
                skipped.push(format!(
                    "{} [skip: {}]",
                    display_workspace_path(&file, Some(&ws_root)),
                    err
                ));
            }
        }
    }

    let mut flagged: Vec<(usize, &str)> = items
        .iter()
        .filter(|it| (it.entry.line_count as usize) >= warn_l)
        .map(|it| (it.entry.line_count as usize, &*it.entry.rel_path))
        .collect();
    flagged.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));

    let mut out = String::with_capacity(budget.min(8192));
    if flagged.is_empty() {
        out.push_str(&format!(
            "=== Slice Inspect: {} files (0 >= {}L) ===\n",
            items.len(),
            warn_l
        ));
    } else {
        let header_prefix = format!(
            "=== Slice Inspect: {} files ({} >= {}L: ",
            items.len(),
            flagged.len(),
            warn_l
        );
        let header_budget = (budget >> 2).max(160);
        let max_flag_items = if budget <= 12_288 { 5 } else { 10 };
        let mut top_flags: Vec<String> = Vec::with_capacity(max_flag_items + 1);
        let mut used = header_prefix.len();
        let mut shown = 0usize;
        for (lc, path) in flagged.iter().take(max_flag_items) {
            let entry = if *lc > 800 {
                format!("{} ({}L [OVER 800L])", path, lc)
            } else {
                format!("{} ({}L)", path, lc)
            };
            let sep = if shown > 0 { 2 } else { 0 };
            // Reserve 24 bytes for `, +NNN more) ===\n`.
            if used + sep + entry.len() + 24 > header_budget {
                break;
            }
            used += sep + entry.len();
            top_flags.push(entry);
            shown += 1;
        }
        if flagged.len() > shown {
            if shown == 0 {
                top_flags.push(format!("{} flagged", flagged.len()));
            } else {
                top_flags.push(format!("+{} more", flagged.len() - shown));
            }
        }
        out.push_str(&header_prefix);
        out.push_str(&top_flags.join(", "));
        out.push_str(") ===\n");
    }

    let sym_show = if items.len() > 35 { 4 } else { 6 };
    let inc_show = if items.len() > 35 { 4 } else { 6 };

    for (idx, it) in items.iter().enumerate() {
        let lc = it.entry.line_count as usize;
        let mut row = String::with_capacity(224);
        row.push_str("- ");
        row.push_str(&it.entry.rel_path);
        row.push_str(" (");
        push_usize(&mut row, lc);
        row.push_str("L, ");
        push_u32(&mut row, it.entry.size_bytes);
        row.push('B');
        row.push(')');
        if lc > 800 {
            row.push_str(" [OVER 800L]");
        } else if lc >= warn_l {
            row.push_str(" [>=");
            push_usize(&mut row, warn_l);
            row.push_str("L]");
        }
        if !it.namespaces.is_empty() {
            row.push_str(" | ns: ");
            for (i, ns) in it.namespaces.iter().enumerate() {
                if i > 0 {
                    row.push_str(", ");
                }
                row.push_str(ns);
            }
        }
        if !it.includes.is_empty() {
            row.push_str(" | inc: ");
            for (i, inc) in it.includes.iter().take(inc_show).enumerate() {
                if i > 0 {
                    row.push_str(", ");
                }
                row.push_str(inc);
            }
            if it.includes.len() > inc_show {
                row.push_str(" (+");
                push_usize(&mut row, it.includes.len() - inc_show);
                row.push(')');
            }
        }
        if !it.entry.symbols.is_empty() {
            let has_primary = it
                .entry
                .symbols
                .iter()
                .any(|s| s.kind != SymbolKind::Namespace && s.kind != SymbolKind::Using);
            let mut count_matching = 0usize;
            for s in it.entry.symbols.iter() {
                let keep = if has_primary {
                    s.kind != SymbolKind::Namespace && s.kind != SymbolKind::Using
                } else {
                    s.kind != SymbolKind::Namespace
                };
                if !keep {
                    continue;
                }
                if count_matching == 0 {
                    row.push_str(" | ");
                } else if count_matching < sym_show {
                    row.push_str(", ");
                }
                if count_matching < sym_show {
                    row.push_str(s.kind.as_str());
                    row.push(' ');
                    row.push_str(&s.name);
                    row.push_str(" [L");
                    push_u32(&mut row, s.start_line);
                    row.push_str("-L");
                    push_u32(&mut row, s.end_line);
                    row.push(']');
                }
                count_matching += 1;
            }
            if count_matching > sym_show {
                row.push_str(" (+");
                push_usize(&mut row, count_matching - sym_show);
                row.push(')');
            }
        }
        row.push('\n');

        let reserve = if idx + 1 < items.len() { 96 } else { 0 };
        if out.len() + row.len() + reserve > budget {
            out.push_str(&format!(
                "... (+{} more files omitted at {}B budget; pass narrower paths or larger max_bytes)\n",
                items.len() - idx,
                budget
            ));
            return Ok(out);
        }
        out.push_str(&row);
    }

    for sk in skipped {
        let line = format!("- {}\n", sk);
        if out.len() + line.len() > budget {
            break;
        }
        out.push_str(&line);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn single_file_outline_lists_over_80_symbols_and_honors_max_symbols_and_budget() {
        let ws = std::env::temp_dir().join(format!(
            "ctx-outline-cap-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&ws).unwrap();
        let src: String = (1..=144)
            .map(|i| format!("pub fn sym_{i:03}(x: u64) -> u64 {{ x + {i} }}\n"))
            .collect();
        fs::write(ws.join("exit.rs"), src).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        // Single file with default max_symbols=0 emits all 144 symbols up to budget.
        let full = op_outline_with_options(&svc, &["exit.rs".into()], 40, 0, 0, Some(&ws)).unwrap();
        assert!(full.contains("sym_001") && full.contains("sym_144"), "{full}");
        assert!(!full.contains("more symbols"), "{full}");

        // Explicit max_symbols=10 caps cleanly with hint.
        let limited = op_outline_with_options(&svc, &["exit.rs".into()], 40, 0, 10, Some(&ws)).unwrap();
        assert!(limited.contains("sym_010") && !limited.contains("sym_011"));
        assert!(limited.contains("+134 more symbols"), "{limited}");

        // Tight max_bytes caps per-symbol cleanly with continuation guidance.
        let budgeted = op_outline_with_options(&svc, &["exit.rs".into()], 40, 1024, 0, Some(&ws)).unwrap();
        assert!(budgeted.len() <= 1024 + 128, "len={}", budgeted.len());
        assert!(budgeted.contains("omitted at 1024B budget"), "{budgeted}");

        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn op_inspect_caps_header_and_total_output_on_many_long_flagged_paths() {
        let ws = std::env::temp_dir().join(format!(
            "ctx-inspect-cap-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        let deep = ws.join("very_long_subsystem_directory_name_alpha/nested_module_segment_beta/component_gamma");
        fs::create_dir_all(&deep).unwrap();
        let body: String = (1..=650).map(|i| format!("pub fn f_{i:03}() {{}}\n")).collect();
        for idx in 0..30 {
            let fname = format!("extremely_descriptive_implementation_unit_file_number_{idx:02}.rs");
            fs::write(deep.join(fname), &body).unwrap();
        }

        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();

        for budget in [1024usize, 9_200usize] {
            let out = op_inspect(&svc, &[".".into()], 80, budget, 600, Some(&ws)).unwrap();
            assert!(
                out.len() <= budget + 128,
                "budget={budget} exceeded: len={}",
                out.len()
            );
            let header = out.lines().next().unwrap_or("");
            assert!(
                header.len() <= (budget >> 2) + 64,
                "budget={budget} header too large ({}B): {header}",
                header.len()
            );
            assert!(
                header.contains("30 >= 600L:"),
                "header missing flagged count: {header}"
            );
            // At tight budgets, top_flags must list <= 5 entries and summarize remaining.
            assert!(
                header.matches("(650L)").count() <= 5,
                "too many top_flags at budget={budget}: {header}"
            );
            assert!(
                header.contains("more)") || header.contains("flagged)"),
                "header should summarize omitted flagged files: {header}"
            );
        }

        let _ = fs::remove_dir_all(&ws);
    }
}
