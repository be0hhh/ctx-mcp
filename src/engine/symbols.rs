use super::compact::{compact_lines_for_ext, is_doc_or_config_ext};
use super::{is_safe_shorthand_candidate, DEFAULT_READ_MAX_BYTES};
use crate::base::security::is_sensitive_path;
use crate::base::simd::{decimal_digits, line_hash3, push_usize};
use crate::parser::{SymbolKind, SymbolSpan};
use crate::rpc::BrokerService;
use crate::store::{resolve_input_path, RamStore};
use std::path::{Path, PathBuf};

const COMPACT_SYMBOL_MAX_LINES: usize = 48;

#[derive(Clone, Copy)]
enum KindFilter {
    Exact(SymbolKind),
    Callable,
}

impl KindFilter {
    fn matches(self, kind: SymbolKind) -> bool {
        match self {
            Self::Exact(k) => kind == k,
            Self::Callable => matches!(
                kind,
                SymbolKind::Fn
                    | SymbolKind::Func
                    | SymbolKind::Function
                    | SymbolKind::Def
                    | SymbolKind::AsyncDef
            ),
        }
    }
}

fn parse_kind_filter(raw: &str) -> (Option<KindFilter>, &str) {
    let t = raw.trim();
    if let Some((prefix, rest)) = t.split_once(':') {
        if !rest.starts_with(':') && !rest.trim().is_empty() {
            let filter = match prefix.trim().to_ascii_lowercase().as_str() {
                "struct" => Some(KindFilter::Exact(SymbolKind::Struct)),
                "class" => Some(KindFilter::Exact(SymbolKind::Class)),
                "enum" => Some(KindFilter::Exact(SymbolKind::Enum)),
                "trait" => Some(KindFilter::Exact(SymbolKind::Trait)),
                "interface" => Some(KindFilter::Exact(SymbolKind::Interface)),
                "record" => Some(KindFilter::Exact(SymbolKind::Record)),
                "type" => Some(KindFilter::Exact(SymbolKind::Type)),
                "impl" => Some(KindFilter::Exact(SymbolKind::Impl)),
                "mod" => Some(KindFilter::Exact(SymbolKind::Mod)),
                "macro" => Some(KindFilter::Exact(SymbolKind::Macro)),
                "fn" | "func" | "function" | "def" => Some(KindFilter::Callable),
                _ => None,
            };
            if filter.is_some() {
                return (filter, rest.trim());
            }
        }
    }
    (None, t)
}

fn is_primary_type_kind(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Struct
            | SymbolKind::Enum
            | SymbolKind::Trait
            | SymbolKind::Type
            | SymbolKind::Class
            | SymbolKind::Interface
            | SymbolKind::Record
    )
}

fn split_owner_member(query: &str) -> Option<(&str, &str)> {
    let (owner, member) = match (query.rfind("::"), query.rfind('.')) {
        (Some(ci), Some(di)) => {
            if ci >= di {
                (&query[..ci], &query[ci + 2..])
            } else {
                (&query[..di], &query[di + 1..])
            }
        }
        (Some(ci), None) => (&query[..ci], &query[ci + 2..]),
        (None, Some(di)) => (&query[..di], &query[di + 1..]),
        (None, None) => return None,
    };
    let owner = owner.rsplit("::").next().unwrap_or(owner).trim();
    let member = member.trim();
    (!owner.is_empty() && !member.is_empty()).then_some((owner, member))
}

fn enclosing_owner<'a>(symbols: &'a [SymbolSpan], sym: &SymbolSpan) -> Option<&'a str> {
    symbols
        .iter()
        .filter(|c| {
            matches!(
                c.kind,
                SymbolKind::Impl
                    | SymbolKind::Struct
                    | SymbolKind::Class
                    | SymbolKind::Trait
                    | SymbolKind::Interface
            ) && c.start_line < sym.start_line
                && c.end_line >= sym.end_line
        })
        .min_by_key(|c| c.end_line.saturating_sub(c.start_line))
        .map(|c| c.name.as_ref())
}

fn symbol_matches_in_file(
    symbols: &[SymbolSpan],
    sym: &SymbolSpan,
    query: &str,
    kind_filter: Option<KindFilter>,
) -> bool {
    if let Some(kf) = kind_filter {
        if !kf.matches(sym.kind) {
            return false;
        }
    }
    if symbol_matches_query(&sym.name, query) {
        return true;
    }
    if let Some((owner, member)) = split_owner_member(query) {
        if symbol_matches_query(&sym.name, member)
            && enclosing_owner(symbols, sym).is_some_and(|enc| symbol_matches_query(enc, owner))
        {
            return true;
        }
    }
    false
}

fn ext_lower_buf<'a>(path: &Path, buf: &'a mut [u8; 16]) -> &'a str {
    let Some(raw) = path.extension().and_then(|s| s.to_str()) else {
        return "";
    };
    if raw.len() > buf.len() || !raw.is_ascii() {
        return "";
    }
    for (i, b) in raw.bytes().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    std::str::from_utf8(&buf[..raw.len()]).unwrap_or("")
}

pub(super) fn symbol_matches_query(sym_name: &str, query: &str) -> bool {
    if sym_name == query || sym_name.eq_ignore_ascii_case(query) {
        return true;
    }
    if sym_name.len() > query.len() {
        let split = sym_name.len() - query.len();
        if sym_name[split..].eq_ignore_ascii_case(query) {
            if sym_name[..split].ends_with("::") || sym_name[..split].ends_with('.') {
                return true;
            }
        }
        if sym_name.ends_with(']') && sym_name.len() >= query.len() + 2 {
            let inner_start = sym_name.len() - 1 - query.len();
            if sym_name.as_bytes()[inner_start.saturating_sub(1)] == b'['
                && sym_name[inner_start..sym_name.len() - 1].eq_ignore_ascii_case(query)
            {
                return true;
            }
        }
    }
    false
}

#[allow(dead_code)]
pub fn op_symbols(
    svc: &BrokerService,
    requests: &[String],
    max_bytes: usize,
    compact: bool,
    session_key: Option<&str>,
    cwd: Option<&Path>,
    hashes: bool,
) -> Result<String, String> {
    op_symbols_with_options(svc, requests, max_bytes, compact, session_key, cwd, hashes, false)
}

pub fn op_symbols_with_options(
    svc: &BrokerService,
    requests: &[String],
    max_bytes: usize,
    compact: bool,
    session_key: Option<&str>,
    cwd: Option<&Path>,
    hashes: bool,
    raw: bool,
) -> Result<String, String> {
    if requests.is_empty() {
        return Err("provide at least one `path#SymbolName` request".to_string());
    }
    let budget = max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES);
    let cap_note = "... [truncated at max_bytes]\n";
    let limit = budget - cap_note.len();
    let mut out = String::new();
    let mut any_ok = false;

    for req in requests {
        if out.len() >= limit {
            if out.len() == limit {
                out.push_str(cap_note);
            }
            break;
        }
        let Some((raw_path, sym_query)) = req.split_once('#') else {
            out.push_str(&format!(
                "=== {} [ERROR: expected format path#SymbolName] ===\n",
                req
            ));
            continue;
        };
        let (kind_filter, query) = parse_kind_filter(sym_query);
        let mut resolved = resolve_input_path(raw_path, cwd);
        if !resolved.exists()
            && is_safe_shorthand_candidate(raw_path)
            && !is_sensitive_path(&resolved)
        {
            if let Some(ws_hint) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
                let found = svc.store.find_workspace_paths(raw_path, &ws_hint, 6);
                if found.len() == 1 {
                    if let Some(first) = found.into_iter().next() {
                        resolved = first;
                    }
                } else if found.len() > 1 {
                    let mut matched_cand: Option<PathBuf> = None;
                    for cand in &found {
                        if let Ok((cf, wr)) = svc.allowlist.admit_file(cand, cwd) {
                            if let Ok(entry) = svc.store.get_outline_entry(&cf, Some(&wr)) {
                                let has_sym = entry.symbols.iter().any(|s| {
                                    symbol_matches_in_file(&entry.symbols, s, query, kind_filter)
                                });
                                if has_sym {
                                    let is_impl = cf
                                        .extension()
                                        .and_then(|e| e.to_str())
                                        .is_some_and(|e| matches!(e, "cpp" | "cc" | "cxx" | "c"));
                                    if matched_cand.is_none() || is_impl {
                                        matched_cand = Some(cand.clone());
                                        if is_impl {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(chosen) = matched_cand.or_else(|| found.into_iter().next()) {
                        resolved = chosen;
                    }
                }
            }
        }
        let (canon, ws_root) = match svc.allowlist.admit_file(&resolved, cwd) {
            Ok(pair) => pair,
            Err(msg) => {
                out.push_str(&format!("=== {} [{}] ===\n", raw_path, msg));
                continue;
            }
        };

        match svc.store.get_full_entry(&canon, Some(&ws_root)) {
            Ok(entry) => {
                any_ok = true;
                let mut ext_buf = [0u8; 16];
                let ext = ext_lower_buf(&canon, &mut ext_buf);
                let compact_doc = !hashes && !raw && is_doc_or_config_ext(ext);
                let raw_matches: Vec<&SymbolSpan> = entry
                    .symbols
                    .iter()
                    .filter(|s| symbol_matches_in_file(&entry.symbols, s, query, kind_filter))
                    .collect();

                if raw_matches.is_empty() {
                    let avail = RamStore::format_outline_compact(&entry, 15);
                    out.push_str(&format!(
                        "=== {}#{} [NOT FOUND] ===\nAvailable: {}\n\n",
                        entry.rel_path, sym_query.trim(), avail
                    ));
                    continue;
                }

                // When an unqualified query matches BOTH a type definition (`struct`/`enum`/`trait`)
                // and Rust `impl` block(s) of the same name, emit the type definition only and list
                // the `impl` blocks in a compact 1-line summary (fetch via `#impl:Type` / `#Type::method`).
                let split_impls = kind_filter.is_none()
                    && raw_matches.iter().any(|s| is_primary_type_kind(s.kind))
                    && raw_matches.iter().any(|s| s.kind == SymbolKind::Impl);
                let (matches, omitted_impls): (Vec<&SymbolSpan>, Vec<&SymbolSpan>) = if split_impls {
                    raw_matches
                        .into_iter()
                        .partition(|s| s.kind != SymbolKind::Impl)
                } else {
                    (raw_matches, Vec::new())
                };

                let total_lines = entry.line_count as usize;
                let mut spans_to_record = Vec::new();
                let mut clipped = false;

                for sym in matches {
                    let s = (sym.start_line as usize).max(1);
                    let end = (sym.end_line as usize).min(total_lines);
                    let requested_end = if compact {
                        end.min(s.saturating_add(COMPACT_SYMBOL_MAX_LINES - 1))
                    } else {
                        end
                    };
                    let header = |last: usize| {
                        let continuation = if last < end {
                            format!("; continue with {}:{}-{}", entry.rel_path, last + 1, end)
                        } else {
                            String::new()
                        };
                        format!(
                            "=== {}#{} ({} [L{}-L{}]{}) ===\n",
                            entry.rel_path,
                            sym.name,
                            sym.kind.as_str(),
                            s,
                            last,
                            continuation
                        )
                    };
                    let header_reserve = if end > s {
                        header(end - 1).len()
                    } else {
                        header(end).len()
                    };
                    let mut body =
                        String::with_capacity((requested_end.saturating_sub(s) + 1) * 48);
                    let mut actual_end = None;
                    let prefix_extra = if hashes { 6 } else { 2 };
                    if compact_doc {
                        let raw_rows: Vec<(usize, &str)> = (s..=requested_end)
                            .map(|ln| (ln, entry.line_slice(ln as u32)))
                            .collect();
                        let compacted = compact_lines_for_ext(ext, &raw_rows, false);
                        let mut overflowed = false;
                        for (ln, line) in &compacted {
                            let row_len = decimal_digits(*ln) + 2 + line.len() + 1;
                            if out.len() + header_reserve + body.len() + row_len + 1 > limit {
                                overflowed = true;
                                break;
                            }
                            push_usize(&mut body, *ln);
                            body.push_str(": ");
                            body.push_str(line);
                            body.push('\n');
                            actual_end = Some(*ln);
                        }
                        if !overflowed {
                            actual_end = Some(requested_end);
                        }
                    } else {
                        for ln in s..=requested_end {
                            let line = entry.line_slice(ln as u32);
                            let row_len = decimal_digits(ln) + prefix_extra + line.len() + 1;
                            if out.len() + header_reserve + body.len() + row_len + 1 > limit {
                                break;
                            }
                            push_usize(&mut body, ln);
                            if hashes {
                                let h3 = line_hash3(line);
                                body.push(':');
                                body.push(h3[0] as char);
                                body.push(h3[1] as char);
                                body.push(h3[2] as char);
                                body.push_str("| ");
                            } else {
                                body.push_str(": ");
                            }
                            body.push_str(line);
                            body.push('\n');
                            actual_end = Some(ln);
                        }
                    }
                    if let Some(last) = actual_end {
                        out.push_str(&header(last));
                        out.push_str(&body);
                        out.push('\n');
                        spans_to_record.push((s, last));
                    }
                    if actual_end != Some(requested_end) {
                        out.push_str(cap_note);
                        clipped = true;
                        break;
                    }
                }

                if !clipped && !omitted_impls.is_empty() {
                    let mut parts: Vec<String> = Vec::with_capacity(omitted_impls.len());
                    for imp in &omitted_impls {
                        let fn_cnt = entry
                            .symbols
                            .iter()
                            .filter(|m| {
                                m.start_line > imp.start_line
                                    && m.end_line <= imp.end_line
                                    && KindFilter::Callable.matches(m.kind)
                            })
                            .count();
                        if fn_cnt > 0 {
                            parts.push(format!("L{}-L{} ({} fns)", imp.start_line, imp.end_line, fn_cnt));
                        } else {
                            parts.push(format!("L{}-L{}", imp.start_line, imp.end_line));
                        }
                    }
                    let summary = format!(
                        "[impl blocks for {}: {}; fetch via {}#impl:{} or {}#{}::<method>]\n\n",
                        query,
                        parts.join(", "),
                        entry.rel_path,
                        query,
                        entry.rel_path,
                        query
                    );
                    if out.len() + summary.len() <= limit {
                        out.push_str(&summary);
                    }
                }

                if let Some(sk) = session_key {
                    for (s, e) in spans_to_record {
                        svc.store.record_read(sk, &canon, Some(&ws_root), s, e);
                    }
                }
                if clipped {
                    return Ok(out);
                }
            }
            Err(err) => {
                out.push_str(&format!("=== {} [ERROR: {}] ===\n", raw_path, err));
            }
        }
        if out.len() >= budget {
            break;
        }
    }
    if out.len() > limit {
        let mut end = limit;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str(cap_note);
    }
    if !any_ok {
        return Err(out.trim().to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn op_symbols_hashes_formats_line_anchors_and_preserves_plain_output() {
        let workspace = std::env::temp_dir().join(format!(
            "ctx-sym-hashes-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("math.rs"),
            "fn compute(x: i32) -> i32 {\n    x + 1\n}\n",
        )
        .unwrap();
        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();

        let plain = op_symbols(
            &svc,
            &["math.rs#compute".into()],
            4096,
            false,
            None,
            Some(&workspace),
            false,
        )
        .unwrap();
        assert!(plain.contains("1: fn compute(x: i32) -> i32 {\n2:     x + 1\n3: }\n"));

        let hashed = op_symbols(
            &svc,
            &["math.rs#compute".into()],
            4096,
            false,
            None,
            Some(&workspace),
            true,
        )
        .unwrap();
        let h1 = line_hash3("fn compute(x: i32) -> i32 {");
        let h2 = line_hash3("    x + 1");
        let h3 = line_hash3("}");
        let expected = format!(
            "1:{}| fn compute(x: i32) -> i32 {{\n2:{}|     x + 1\n3:{}| }}\n",
            std::str::from_utf8(&h1).unwrap(),
            std::str::from_utf8(&h2).unwrap(),
            std::str::from_utf8(&h3).unwrap(),
        );
        assert!(hashed.contains(&expected));
        fs::remove_dir_all(&workspace).unwrap();
    }

    #[test]
    fn rust_type_separates_impl_blocks_supports_qualified_methods_and_48l_compact() {
        let workspace = std::env::temp_dir().join(format!(
            "ctx-sym-rust-impl-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&workspace).unwrap();
        let mut src = String::from(
            "pub struct AccountReconciler {\n    pub equity: i64,\n    pub lots: i64,\n}\n\n\
             impl AccountReconciler {\n    pub fn reconcile(&mut self) -> i64 {\n        self.equity + self.lots\n    }\n    pub fn reset(&mut self) {\n        self.lots = 0;\n    }\n}\n\n\
             impl Default for AccountReconciler {\n    fn default() -> Self {\n        Self { equity: 0, lots: 0 }\n    }\n}\n\n\
             pub fn quantize_budget_lots_down(budget: i64) -> i64 {\n",
        );
        for i in 1..=35 {
            src.push_str(&format!("    let _s{i} = budget + {i};\n"));
        }
        src.push_str("    budget\n}\n\npub fn very_long_fn(x: i64) -> i64 {\n");
        for i in 1..=58 {
            src.push_str(&format!("    let _v{i} = x + {i};\n"));
        }
        src.push_str("    x\n}\n");
        fs::write(workspace.join("reconciler.rs"), &src).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(workspace.join("snapshot"));
        svc.allowlist.register_hint(&workspace, true).unwrap();

        // 1. `#AccountReconciler` returns ONLY the struct body + compact impl summary (not the impl bodies).
        let ty = op_symbols(&svc, &["reconciler.rs#AccountReconciler".into()], 16_384, false, None, Some(&workspace), false).unwrap();
        assert!(ty.contains("pub struct AccountReconciler"), "{ty}");
        assert!(ty.contains("pub lots: i64,"), "{ty}");
        assert!(!ty.contains("self.equity + self.lots"), "impl body should be omitted: {ty}");
        assert!(ty.contains("[impl blocks for AccountReconciler:"), "{ty}");
        assert!(ty.contains("#impl:AccountReconciler"), "{ty}");

        // 2. `#impl:AccountReconciler` returns the impl blocks explicitly.
        let im = op_symbols(&svc, &["reconciler.rs#impl:AccountReconciler".into()], 16_384, false, None, Some(&workspace), false).unwrap();
        assert!(im.contains("impl AccountReconciler {") && im.contains("impl Default for AccountReconciler"), "{im}");
        assert!(!im.contains("pub struct AccountReconciler"), "{im}");

        // 3. `#AccountReconciler::reconcile` resolves method via enclosing `impl` owner.
        let m = op_symbols(&svc, &["reconciler.rs#AccountReconciler::reconcile".into()], 16_384, false, None, Some(&workspace), false).unwrap();
        assert!(m.contains("pub fn reconcile") && m.contains("self.equity + self.lots"), "{m}");
        assert!(!m.contains("pub fn reset"), "{m}");

        // 4. `compact=true` allows up to 48 lines (37-line fn completes in 1 call; 60-line fn cuts at 48L).
        let q37 = op_symbols(&svc, &["reconciler.rs#quantize_budget_lots_down".into()], 16_384, true, None, Some(&workspace), false).unwrap();
        assert!(q37.contains("let _s35 = budget + 35;") && !q37.contains("continue with"), "{q37}");
        let q60 = op_symbols(&svc, &["reconciler.rs#very_long_fn".into()], 16_384, true, None, Some(&workspace), false).unwrap();
        assert!(q60.contains("continue with reconciler.rs:"), "{q60}");

        let _ = fs::remove_dir_all(&workspace);
    }
}
