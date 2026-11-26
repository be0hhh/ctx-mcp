use super::{collect_target_files, DEFAULT_READ_MAX_BYTES};
use crate::base::simd::{push_u32, push_usize};
use crate::parser::SymbolKind;
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, CachedFile};
use std::path::Path;
use std::sync::Arc;

pub fn op_outline(
    svc: &BrokerService,
    targets: &[String],
    max_files: usize,
    max_bytes: usize,
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

    let many_files = files.len() > 10;
    let budget = if max_bytes > 0 {
        max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES)
    } else if many_files {
        9_500
    } else {
        65_536
    };
    let sym_cap = if many_files { 12 } else { 80 };

    let mut out = String::with_capacity(budget.min(8192));
    let total_files = files.len();
    for (idx, (file, ws_root)) in files.into_iter().enumerate() {
        let mut block = String::with_capacity(256);
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
                    for sym in entry.symbols.iter().take(sym_cap) {
                        block.push_str("  [L");
                        push_u32(&mut block, sym.start_line);
                        block.push_str("-L");
                        push_u32(&mut block, sym.end_line);
                        block.push_str("] ");
                        block.push_str(sym.kind.as_str());
                        block.push(' ');
                        block.push_str(&sym.name);
                        if !many_files && !sym.signature.is_empty() {
                            block.push_str(" — ");
                            block.push_str(&sym.signature);
                        }
                        block.push('\n');
                    }
                    if entry.symbols.len() > sym_cap {
                        block.push_str("  ... +");
                        push_usize(&mut block, entry.symbols.len() - sym_cap);
                        block.push_str(" more symbols\n");
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
        let mut top_flags: Vec<String> = flagged
            .iter()
            .take(10)
            .map(|(lc, path)| {
                if *lc > 800 {
                    format!("{} ({}L [OVER 800L])", path, lc)
                } else {
                    format!("{} ({}L)", path, lc)
                }
            })
            .collect();
        if flagged.len() > 10 {
            top_flags.push(format!("+{} more", flagged.len() - 10));
        }
        out.push_str(&format!(
            "=== Slice Inspect: {} files ({} >= {}L: {}) ===\n",
            items.len(),
            flagged.len(),
            warn_l,
            top_flags.join(", ")
        ));
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
