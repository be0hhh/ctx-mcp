//! Single-call symbol body + local context + word-bounded callers + related tests/manifests
//! (`ctx_impact`), with edit-ready `<ln>:<h3>| <line>` hash anchors.

use super::hashline::push_hashed_line;
use super::{cap_utf8, enclosing_scope, ext_lower_buf, line_count_flag};
use crate::base::security::{is_sensitive_path, is_sensitive_path_with_ws};
use crate::base::simd::{
    bloom128_may_contain, line_slice_at, push_u32, push_usize, search_lines_literals,
    trigram_bloom128_ascii_lower, FastHashMap,
};
use crate::engine::{is_safe_shorthand_candidate, DEFAULT_READ_MAX_BYTES};
use crate::parser::{is_ident_char, SymbolKind, SymbolSpan};
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, resolve_input_path, CachedFile, RamStore};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const MAX_BODY_LINES: usize = 80;
const MAX_IMPORTS: usize = 8;
const MAX_RELATED_FILES: usize = 16;
const MAX_IMPACT_TARGETS: usize = 6;
const IMPACT_SCAN_BUDGET: Duration = Duration::from_secs(4);
const IMPACT_GIT_TIMEOUT: Duration = Duration::from_millis(500);
const IMPACT_GIT_STDOUT_LIMIT: usize = 16 * 1024;

#[allow(dead_code)]
pub fn op_impact(svc: &BrokerService, targets: &[String], max_callers: usize, include_tests: bool, max_bytes: usize, cwd: Option<&Path>) -> Result<String, String> {
    op_impact_with_git(svc, targets, max_callers, include_tests, max_bytes, cwd, true)
}

#[allow(dead_code)]
pub fn op_impact_with_git(
    svc: &BrokerService, targets: &[String], max_callers: usize, include_tests: bool, max_bytes: usize,
    cwd: Option<&Path>, include_git_status: bool,
) -> Result<String, String> {
    if targets.is_empty() || targets.len() > MAX_IMPACT_TARGETS { return Err("provide 1..=6 `path#Symbol` targets".to_string()); }
    let (caller_cap, budget, deadline) = (max_callers.clamp(1, 50), max_bytes.clamp(1024, DEFAULT_READ_MAX_BYTES), Instant::now() + IMPACT_SCAN_BUDGET);
    let (mut slots, mut resolved) = (Vec::with_capacity(targets.len()), Vec::with_capacity(targets.len()));
    for raw_target in targets {
        let (raw_path, mode) = parse_impact_spec(raw_target);
        let query_hint = match &mode { ImpactSpec::Sym(q) => q.as_str(), _ => "" };
        if matches!(&mode, ImpactSpec::Sym(q) if q.is_empty()) {
            slots.push(TargetSlot::Error(format!("=== {raw_target} [ERROR: empty symbol name] ===\n"))); continue;
        }
        let (canon, ws_root) = match svc.allowlist.admit_file(&resolve_target_file(svc, raw_path, query_hint, cwd), cwd) {
            Ok(pair) => pair,
            Err(msg) => { slots.push(TargetSlot::Error(format!("=== {raw_path} [{msg}] ===\n"))); continue; }
        };
        let entry = match svc.store.get_full_entry(&canon, Some(&ws_root)) {
            Ok(e) => e,
            Err(err) => { slots.push(TargetSlot::Error(format!("=== {raw_path} [ERROR: {err}] ===\n"))); continue; }
        };
        let (sym_idx, window_range) = match mode {
            ImpactSpec::Sym(query) => match match_symbol_idx(&entry, &query) {
                Some(idx) => (Some(idx), None),
                None => { slots.push(TargetSlot::Error(format!("=== {}#{query} [NOT FOUND] ===\nAvailable: {}\n\n", entry.rel_path, RamStore::format_outline_compact(&entry, 15)))); continue; }
            },
            ImpactSpec::Line(ln) => enclosing_symbol_idx(&entry, ln).map_or_else(|| {
                let tot = (entry.line_count as usize).max(1);
                let focus = ln.clamp(1, tot);
                (None, Some((focus.saturating_sub(10).max(1), focus.saturating_add(10).min(tot))))
            }, |idx| (Some(idx), None)),
            ImpactSpec::WholeFile if entry.line_count <= 120 => (None, Some((1, (entry.line_count as usize).max(1)))),
            ImpactSpec::WholeFile => {
                slots.push(TargetSlot::Error(format!("=== {} ({}L — pass path#Symbol or path:line) ===\nAvailable: {}\n\n", entry.rel_path, entry.line_count, RamStore::format_outline_compact(&entry, 20))));
                continue;
            }
        };
        let ident = sym_idx.map(|i| bare_identifier(&entry.symbols[i].name).to_string()).unwrap_or_default();
        let stem = canon.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
        slots.push(TargetSlot::Resolved(resolved.len()));
        resolved.push(ResolvedTarget { canon, ws_root, entry, sym_idx, window_range, ident, stem, scan: ImpactScan::default(), git_badge: String::new() });
    }
    if resolved.is_empty() {
        return Err(slots.into_iter().filter_map(|s| match s { TargetSlot::Error(m) => Some(m), _ => None }).collect::<String>().trim().to_string());
    }
    let mut ws_groups: Vec<(PathBuf, Vec<usize>)> = Vec::new();
    for (idx, t) in resolved.iter().enumerate() {
        if let Some((_, list)) = ws_groups.iter_mut().find(|(w, _)| w == &t.ws_root) { list.push(idx); } else { ws_groups.push((t.ws_root.clone(), vec![idx])); }
    }
    for (ws_root, idxs) in &ws_groups {
        if include_git_status {
            let mut rels: Vec<&str> = Vec::with_capacity(idxs.len());
            for &i in idxs { let r = &*resolved[i].entry.rel_path; if !rels.contains(&r) { rels.push(r); } }
            if let Some(git_map) = query_git_status_batch(svc, ws_root, &rels, deadline) {
                for &i in idxs { resolved[i].git_badge = format!(" [git: {}]", git_map.get(&*resolved[i].entry.rel_path).map(String::as_str).unwrap_or("clean")); }
            }
        }
        scan_workspace_impact_batch(svc, ws_root, &mut resolved, idxs, caller_cap, include_tests, deadline);
    }
    let n_res = resolved.len().max(1);
    let body_cap = if budget <= 12_288 { match n_res { 1 => MAX_BODY_LINES, 2 => 48, 3 => 36, 4 => 28, _ => 22 } } else { MAX_BODY_LINES };
    let (mut seen_imports, mut heads, mut head_bytes) = (FastHashMap::<PathBuf, ()>::default(), Vec::with_capacity(slots.len()), 0usize);
    for slot in &slots {
        let mut h = String::new();
        match slot {
            TargetSlot::Error(msg) => h.push_str(msg),
            TargetSlot::Resolved(i) => {
                let t = &resolved[*i];
                if let Some(si) = t.sym_idx {
                    append_target_body(&mut h, &t.entry, &t.entry.symbols[si], &t.git_badge, body_cap, budget);
                    append_local_context(&mut h, &t.entry, &t.entry.symbols[si], seen_imports.insert(t.canon.clone(), ()).is_none(), budget);
                } else if let Some((ws, we)) = t.window_range {
                    append_window_body(&mut h, &t.entry, ws, we, &t.git_badge, budget);
                }
            }
        }
        head_bytes = head_bytes.saturating_add(h.len()); heads.push(h);
    }
    let (mut extras_left, mut rem_targets, mut out) = (budget.saturating_sub(head_bytes.saturating_add(n_res)), n_res, String::with_capacity(budget.min(8192)));
    for (slot, head) in slots.into_iter().zip(heads) {
        if out.len() >= budget { break; }
        out.push_str(&head);
        if let TargetSlot::Resolved(i) = slot {
            let t = &resolved[i];
            if t.sym_idx.is_some() {
                let lim = out.len().saturating_add(fair_share(extras_left, rem_targets)).min(budget);
                let before = out.len();
                append_callers(&mut out, &t.scan.callers, t.scan.total_callers, lim);
                append_related(&mut out, &t.scan.related, include_tests, lim);
                extras_left = extras_left.saturating_sub(out.len().saturating_sub(before));
            }
            rem_targets = rem_targets.saturating_sub(1); out.push('\n');
        }
    }
    Ok(cap_utf8(&out, budget))
}

#[inline]
fn fair_share(rem: usize, n: usize) -> usize {
    match n { 0 | 1 => rem, 2 => rem >> 1, 3 => (rem.saturating_mul(341)) >> 10, 4 => rem >> 2, 5 => (rem.saturating_mul(205)) >> 10, _ => (rem.saturating_mul(171)) >> 10 }
}

enum ImpactSpec { Sym(String), Line(usize), WholeFile }

fn parse_impact_spec(raw: &str) -> (&str, ImpactSpec) {
    let t = raw.trim();
    if let Some((p, sym)) = t.split_once('#') { return (p.trim(), ImpactSpec::Sym(sym.trim().to_string())); }
    if let Some((p, tail)) = t.rsplit_once(':') {
        if p.len() > 1 && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(ln) = tail.parse::<usize>() { return (p.trim(), ImpactSpec::Line(ln.max(1))); }
        }
    }
    (t, ImpactSpec::WholeFile)
}

fn enclosing_symbol_idx(entry: &CachedFile, line: usize) -> Option<usize> {
    entry.symbols.iter().enumerate()
        .filter(|(_, s)| s.kind != SymbolKind::Namespace && (s.start_line as usize..=s.end_line as usize).contains(&line))
        .min_by_key(|(_, s)| s.end_line.saturating_sub(s.start_line)).map(|(i, _)| i)
}

fn append_window_body(out: &mut String, entry: &CachedFile, start: usize, end: usize, git_badge: &str, limit: usize) {
    let total = entry.line_count as usize;
    if total == 0 { return; }
    out.push_str(&format!("=== {} (lines {start}-{end} of {total}L{}){} ===\n", entry.rel_path, line_count_flag(total), git_badge));
    for ln in start..=end.min(total) {
        if out.len() >= limit { break; }
        push_hashed_line(out, ln, entry.line_slice(ln as u32));
    }
}

enum TargetSlot { Error(String), Resolved(usize) }
struct ResolvedTarget {
    canon: PathBuf, ws_root: PathBuf, entry: Arc<CachedFile>, sym_idx: Option<usize>,
    window_range: Option<(usize, usize)>, ident: String, stem: String, scan: ImpactScan, git_badge: String,
}

fn resolve_target_file(svc: &BrokerService, raw_path: &str, query: &str, cwd: Option<&Path>) -> PathBuf {
    let mut resolved = resolve_input_path(raw_path, cwd);
    if !resolved.exists() && is_safe_shorthand_candidate(raw_path) && !is_sensitive_path(&resolved) {
        if let Some(ws_hint) = cwd.and_then(|c| svc.allowlist.register_hint(c, false)) {
            let found = svc.store.find_workspace_paths(raw_path, &ws_hint, 6);
            if found.len() == 1 {
                if let Some(first) = found.into_iter().next() { resolved = first; }
            } else if found.len() > 1 {
                let mut best: Option<PathBuf> = None;
                for cand in &found {
                    if let Ok((cf, wr)) = svc.allowlist.admit_file(cand, cwd) {
                        if svc.store.get_outline_entry(&cf, Some(&wr)).is_ok_and(|e| match_symbol_idx(&e, query).is_some()) {
                            let is_impl = cf.extension().and_then(|e| e.to_str()).is_some_and(|e| matches!(e, "cpp" | "cc" | "cxx" | "c" | "rs"));
                            if best.is_none() || is_impl { best = Some(cand.clone()); if is_impl { break; } }
                        }
                    }
                }
                if let Some(chosen) = best.or_else(|| found.into_iter().next()) { resolved = chosen; }
            }
        }
    }
    resolved
}

fn split_last_qual(s: &str) -> (Option<&str>, &str) {
    match (s.rfind("::").map(|i| (i, i + 2)), s.rfind('.').map(|i| (i, i + 1))) {
        (Some((ci, cn)), Some((di, dn))) => if ci >= di { (Some(&s[..ci]), &s[cn..]) } else { (Some(&s[..di]), &s[dn..]) },
        (Some((i, n)), None) | (None, Some((i, n))) => (Some(&s[..i]), &s[n..]),
        (None, None) => (None, s),
    }
}

fn go_receiver_type(sig: &str) -> Option<&str> {
    let recv = sig.strip_prefix("func ")?.trim_start().strip_prefix('(')?.split_once(')')?.0.trim();
    let base = recv.split_once('[').map_or(recv, |(b, _)| b).trim();
    let ty = base.rsplit_once(char::is_whitespace).map_or(base, |(_, t)| t).trim_start_matches('*');
    let ty = ty.rsplit_once('.').map_or(ty, |(_, t)| t);
    let end = ty.bytes().position(|b| !is_ident_char(b)).unwrap_or(ty.len());
    (end > 0).then_some(&ty[..end])
}

fn has_qual_suffix(name: &str, query: &str, ci: bool) -> bool {
    if name.len() <= query.len() { return false; }
    let cut = name.len() - query.len();
    let ok = if ci { name[cut..].eq_ignore_ascii_case(query) } else { &name[cut..] == query };
    ok && (name[..cut].ends_with("::") || name[..cut].ends_with('.'))
}

fn enclosing_owner<'a>(entry: &'a CachedFile, sym: &SymbolSpan) -> Option<&'a str> {
    entry.symbols.iter().filter(|c| {
        matches!(c.kind, SymbolKind::Impl | SymbolKind::Struct | SymbolKind::Class | SymbolKind::Trait | SymbolKind::Interface)
            && c.start_line < sym.start_line && c.end_line >= sym.end_line
    }).min_by_key(|c| c.end_line.saturating_sub(c.start_line)).map(|c| bare_identifier(&c.name))
}

fn match_symbol_idx(entry: &CachedFile, query: &str) -> Option<usize> {
    let qual = split_last_qual(query);
    let q_pair = qual.0.map(|o| (bare_identifier(o), qual.1)).filter(|(o, m)| !o.is_empty() && !m.is_empty());
    let owner_matches = |s: &SymbolSpan, owner: &str, ci: bool| -> bool {
        let eq = |a: &str| if ci { a.eq_ignore_ascii_case(owner) } else { a == owner };
        go_receiver_type(&s.signature).is_some_and(eq) || enclosing_owner(entry, s).is_some_and(eq)
            || split_last_qual(&s.name).0.map(bare_identifier).is_some_and(eq)
    };
    let (mut qual_exact, mut ci_hit, mut qual_ci) = (None, None, None);
    for (i, s) in entry.symbols.iter().enumerate() {
        if &*s.name == query || has_qual_suffix(&s.name, query, false) { return Some(i); }
        if let Some((owner, member)) = q_pair {
            let sm = bare_identifier(&s.name);
            if qual_exact.is_none() && sm == member && owner_matches(s, owner, false) { qual_exact = Some(i); }
            else if qual_ci.is_none() && sm.eq_ignore_ascii_case(member) && owner_matches(s, owner, true) { qual_ci = Some(i); }
        }
        if ci_hit.is_none() && (s.name.eq_ignore_ascii_case(query) || has_qual_suffix(&s.name, query, true)) { ci_hit = Some(i); }
    }
    qual_exact.or(ci_hit).or(qual_ci)
}

fn bare_identifier(name: &str) -> &str {
    let tail = split_last_qual(name).1.trim();
    &tail[..tail.bytes().position(|b| !is_ident_char(b)).unwrap_or(tail.len())]
}

fn append_target_body(out: &mut String, entry: &CachedFile, sym: &SymbolSpan, git_badge: &str, max_lines: usize, limit: usize) {
    let total = entry.line_count as usize;
    if total == 0 { return; }
    let s = (sym.start_line as usize).max(1).min(total);
    let end = (sym.end_line as usize).min(total).max(s);
    let show_end = end.min(s.saturating_add(max_lines.saturating_sub(1)));
    let cont = if show_end < end { format!("; continue with {}:{}-{}", entry.rel_path, show_end + 1, end) } else { String::new() };
    out.push_str(&format!("=== {}#{} ({} [L{s}-L{show_end}], {total}L{}{cont}){} ===\n", entry.rel_path, sym.name, sym.kind.as_str(), line_count_flag(total), git_badge));
    for ln in s..=show_end {
        if out.len() >= limit { break; }
        push_hashed_line(out, ln, entry.line_slice(ln as u32));
    }
}

fn append_local_context(out: &mut String, entry: &CachedFile, sym: &SymbolSpan, show_imports: bool, limit: usize) {
    if out.len() >= limit { return; }
    if let Some(p) = entry.symbols.iter().filter(|c| {
        matches!(c.kind, SymbolKind::Struct | SymbolKind::Class | SymbolKind::Trait | SymbolKind::Impl | SymbolKind::Interface)
            && c.start_line < sym.start_line && c.end_line >= sym.end_line
    }).min_by_key(|c| c.end_line.saturating_sub(c.start_line)) {
        out.push_str("Enclosing:\n  "); push_hashed_line(out, p.start_line as usize, entry.line_slice(p.start_line));
    }
    if !show_imports { return; }
    let mut imports = Vec::new();
    for ln in 1..=entry.line_count.min(200) {
        let t = entry.line_slice(ln).trim();
        if t.starts_with("#include ") || t.starts_with("#include<") || t.starts_with("#include\"") || t.starts_with("use ")
            || t.starts_with("pub use ") || t.starts_with("import ") || (t.starts_with("from ") && t.contains(" import "))
            || (t.starts_with("using ") && !t.contains('='))
        {
            imports.push(t); if imports.len() >= MAX_IMPORTS { break; }
        }
    }
    if !imports.is_empty() && out.len() < limit {
        out.push_str("Imports:\n");
        for imp in imports { if out.len() + imp.len() + 4 > limit { break; } out.push_str("  "); out.push_str(imp); out.push('\n'); }
    }
}

struct CallerHit { rel_path: String, scope: String, line: u32, snippet: String }
#[derive(Default)]
struct ImpactScan { callers: Vec<CallerHit>, total_callers: usize, related: Vec<String> }

fn push_group(groups: &mut Vec<(String, Vec<usize>)>, needle: &str, k: usize) {
    if let Some((_, list)) = groups.iter_mut().find(|(n, _)| n == needle) { if !list.contains(&k) { list.push(k); } }
    else { groups.push((needle.to_string(), vec![k])); }
}

fn scan_workspace_impact_batch(
    svc: &BrokerService, ws_root: &Path, resolved: &mut [ResolvedTarget], idxs: &[usize],
    caller_cap: usize, include_tests: bool, deadline: Instant,
) {
    let n = idxs.len();
    let mut rel_seen: Vec<FastHashMap<String, ()>> = (0..n).map(|_| FastHashMap::default()).collect();
    let (mut ident_groups, mut rel_groups, mut has_any_stem) = (Vec::with_capacity(n), Vec::with_capacity(n * 2), false);
    for (k, &ti) in idxs.iter().enumerate() {
        let t = &mut resolved[ti];
        for extra in crate::base::ext::policy().extra_impact_paths(&t.entry.rel_path, ws_root) {
            if !extra.exists() || is_sensitive_path_with_ws(&extra, Some(ws_root), false) { continue; }
            let rel = display_workspace_path(&extra, Some(ws_root));
            if rel.as_str() != &*t.entry.rel_path && rel_seen[k].insert(rel.clone(), ()).is_none() { t.scan.related.push(format!("{rel} [policy]")); }
        }
        if t.ident.len() >= 2 { push_group(&mut ident_groups, &t.ident, k); push_group(&mut rel_groups, &t.ident, k); }
        if t.stem.len() >= 3 && !is_generic_stem(&t.stem) { has_any_stem = true; if t.stem != t.ident { push_group(&mut rel_groups, &t.stem, k); } }
    }
    let has_any_ident = !ident_groups.is_empty();
    if !has_any_ident && !(include_tests && has_any_stem) { return; }
    let ws_idx = svc.store.workspace_index(ws_root);
    for it in ws_idx.entries.iter() {
        if Instant::now() >= deadline { break; }
        let (rel, fname) = (ws_idx.rel_str(it), ws_idx.file_name(it));
        let (is_test, is_manifest) = (is_test_path(rel), is_manifest_file(fname));
        let non_code = fname.eq_ignore_ascii_case("CMakeLists.txt") || fname.eq_ignore_ascii_case("Cargo.toml");
        if (!has_any_ident && !(include_tests && (is_test || is_manifest) && has_any_stem)) || (!include_tests && (is_test || non_code)) { continue; }
        let need_rel = include_tests && (is_test || is_manifest) && (0..n).any(|k| resolved[idxs[k]].scan.related.len() < MAX_RELATED_FILES && !rel_seen[k].contains_key(rel));
        if (!has_any_ident || non_code) && !need_rel { continue; }
        let abs = ws_idx.abs_path(it);
        if is_sensitive_path_with_ws(&abs, Some(ws_root), false) { continue; }
        let Ok(fe) = svc.store.get_full_entry(&abs, Some(ws_root)) else { continue; };
        let Some(text) = fe.content.as_deref() else { continue; };
        if has_any_ident && !non_code {
            let mut cleaned: Option<Arc<str>> = None;
            for (ident, group) in &ident_groups {
                if is_test && !group.iter().any(|&k| include_tests && resolved[idxs[k]].scan.related.len() < MAX_RELATED_FILES && !rel_seen[k].contains_key(rel)) { continue; }
                if ident.len() >= 3 && ident.is_ascii() && fe.content_bloom != [0, 0] {
                    if !bloom128_may_contain(fe.content_bloom, trigram_bloom128_ascii_lower(ident.as_bytes())) { continue; }
                }
                let raw_lines = search_lines_literals(text, &fe.line_offsets, &[ident.as_str()], true, 64);
                if raw_lines.is_empty() { continue; }
                let cbuf_arc = cleaned.get_or_insert_with(|| {
                    let mut eb = [0u8; 16];
                    fe.cleaned_code_for_ext(ext_lower_buf(&abs, &mut eb), &svc.store).unwrap_or_else(|| Arc::from(text))
                });
                let cbuf: &str = cbuf_arc.as_ref();
                for ln in raw_lines {
                    if !contains_ident_word(line_slice_at(cbuf, &fe.line_offsets, ln), ident, true) { continue; }
                    if is_test {
                        let mut all_done = true;
                        for &k in group {
                            let t = &mut resolved[idxs[k]];
                            if !include_tests || t.scan.related.len() >= MAX_RELATED_FILES || rel_seen[k].contains_key(rel) { continue; }
                            if t.sym_idx.is_some_and(|si| { let s = &t.entry.symbols[si]; abs.as_path() == t.canon.as_path() && ln >= s.start_line && ln <= s.end_line }) { all_done = false; continue; }
                            if rel_seen[k].insert(rel.to_string(), ()).is_none() { t.scan.related.push(format!("{rel} [test]")); }
                        }
                        if all_done { break; }
                    } else {
                        let (mut sc, mut sn) = (None, None);
                        for &k in group {
                            let t = &mut resolved[idxs[k]];
                            if t.sym_idx.is_some_and(|si| { let s = &t.entry.symbols[si]; abs.as_path() == t.canon.as_path() && ln >= s.start_line && ln <= s.end_line }) { continue; }
                            t.scan.total_callers += 1;
                            if t.scan.callers.len() < caller_cap {
                                let scope = sc.get_or_insert_with(|| enclosing_scope(&fe, ln as usize).map(|s| s.name.trim_start_matches("::").to_string()).unwrap_or_default());
                                let snippet = sn.get_or_insert_with(|| fe.line_slice(ln).trim().chars().take(140).collect::<String>());
                                t.scan.callers.push(CallerHit { rel_path: fe.rel_path.to_string(), scope: scope.clone(), line: ln, snippet: snippet.clone() });
                            }
                        }
                    }
                }
            }
        }
        if include_tests && (is_test || is_manifest) {
            let tag = if is_manifest { "manifest" } else { "test" };
            for (needle, group) in &rel_groups {
                if !group.iter().any(|&k| resolved[idxs[k]].scan.related.len() < MAX_RELATED_FILES && !rel_seen[k].contains_key(rel)) { continue; }
                let hits = search_lines_literals(text, &fe.line_offsets, &[needle.as_str()], !is_manifest, 4);
                if hits.iter().any(|&ln| contains_ident_word(fe.line_slice(ln), needle, !is_manifest)) {
                    for &k in group {
                        let t = &mut resolved[idxs[k]];
                        if t.scan.related.len() < MAX_RELATED_FILES && rel_seen[k].insert(rel.to_string(), ()).is_none() { t.scan.related.push(format!("{rel} [{tag}]")); }
                    }
                }
            }
        }
    }
}

struct KillChild(Child);
impl Drop for KillChild { fn drop(&mut self) { if !matches!(self.0.try_wait(), Ok(Some(_))) { let _ = self.0.kill(); let _ = self.0.wait(); } } }

fn git_cmd() -> Command {
    crate::base::platform::hidden_command(crate::base::platform::resolve_tool("git"))
}

fn parse_git_porcelain(raw: &str, valid: &[&str]) -> FastHashMap<String, String> {
    let mut map = FastHashMap::default();
    for line in raw.lines() {
        let b = line.as_bytes();
        if b.len() < 4 || b[2] != b' ' { continue; }
        let code = line[..2].trim();
        if code.is_empty() { continue; }
        let p_raw = line[3..].trim();
        let p = p_raw.rsplit_once(" -> ").map_or(p_raw, |(_, dst)| dst).trim_matches('"');
        let matched = valid.iter().find(|&&r| p == r)
            .or_else(|| valid.iter().filter(|&&r| p.len() > r.len() && p.ends_with(r) && p.as_bytes()[p.len() - r.len() - 1] == b'/').max_by_key(|r| r.len()));
        if let Some(&rel) = matched { map.insert(rel.to_string(), code.to_string()); }
    }
    map
}

fn query_git_status_batch(svc: &BrokerService, ws_root: &Path, rel_paths: &[&str], overall_deadline: Instant) -> Option<FastHashMap<String, String>> {
    let valid: Vec<&str> = rel_paths.iter().copied().filter(|p| !p.is_empty() && !p.starts_with('-') && !p.bytes().any(|b| b < 0x20 || b == 0x7f)).collect();
    if valid.is_empty() { return None; }
    let deadline = (Instant::now() + IMPACT_GIT_TIMEOUT).min(overall_deadline);
    let _permit = svc.subproc_sem.acquire_until(deadline).ok().flatten()?;
    let mut proc = KillChild(git_cmd().arg("-C").arg(ws_root).args(["-c", "core.quotePath=false", "--no-pager", "status", "--porcelain=v1", "-uall", "--"])
        .args(&valid).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?);
    let mut stdout = proc.0.stdout.take()?;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
    thread::Builder::new().spawn(move || {
        let (mut out, mut buf) = (Vec::new(), [0u8; 2048]);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 { break; }
            let keep = n.min(IMPACT_GIT_STDOUT_LIMIT.saturating_sub(out.len()));
            if keep > 0 { out.extend_from_slice(&buf[..keep]); }
        }
        let _ = tx.send(out);
    }).ok()?;
    let bytes = rx.recv_timeout(deadline.checked_duration_since(Instant::now())?).ok()?;
    let status = loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        match proc.0.try_wait() { Ok(Some(st)) => break st, Ok(None) => thread::sleep(left.min(Duration::from_millis(5))), Err(_) => return None }
    };
    status.success().then(|| parse_git_porcelain(&String::from_utf8_lossy(&bytes), &valid))
}

fn append_callers(out: &mut String, callers: &[CallerHit], total: usize, limit: usize) {
    if out.len() >= limit { return; }
    if callers.is_empty() { out.push_str("Callers (0):\n"); return; }
    if total > callers.len() { out.push_str(&format!("Callers ({} of {total}):\n", callers.len())); } else { out.push_str(&format!("Callers ({}):\n", callers.len())); }
    let (mut last_file, mut last_scope) = ("", "");
    for hit in callers {
        if out.len() >= limit { break; }
        if hit.rel_path != last_file { out.push_str("  "); out.push_str(&hit.rel_path); out.push('\n'); last_file = &hit.rel_path; last_scope = ""; }
        if !hit.scope.is_empty() && hit.scope != last_scope { out.push_str("    @"); out.push_str(&hit.scope); out.push('\n'); last_scope = &hit.scope; }
        out.push_str("    "); push_u32(out, hit.line); out.push_str(": "); out.push_str(&hit.snippet); out.push('\n');
    }
}

fn append_related(out: &mut String, related: &[String], include_tests: bool, limit: usize) {
    if related.is_empty() || out.len() >= limit { return; }
    out.push_str(if include_tests { "Related tests & manifests (" } else { "Related (" });
    push_usize(out, related.len()); out.push_str("):\n");
    for item in related { if out.len() + item.len() + 4 > limit { break; } out.push_str("  "); out.push_str(item); out.push('\n'); }
}

fn contains_ident_word(line: &str, needle: &str, case_sensitive: bool) -> bool {
    let (hay, ndl) = (line.as_bytes(), needle.as_bytes());
    if ndl.is_empty() || ndl.len() > hay.len() { return false; }
    for i in 0..=(hay.len() - ndl.len()) {
        let eq = if case_sensitive { &hay[i..i + ndl.len()] == ndl } else { hay[i..i + ndl.len()].eq_ignore_ascii_case(ndl) };
        if eq && (i == 0 || !is_ident_char(hay[i - 1])) && (i + ndl.len() == hay.len() || !is_ident_char(hay[i + ndl.len()])) { return true; }
    }
    false
}

fn is_test_path(rel: &str) -> bool { rel.as_bytes().windows(4).any(|w| w.eq_ignore_ascii_case(b"test")) }
fn is_manifest_file(name: &str) -> bool { name.eq_ignore_ascii_case("CMakeLists.txt") || name.eq_ignore_ascii_case("Cargo.toml") || name.eq_ignore_ascii_case("mod.rs") }
fn is_generic_stem(stem: &str) -> bool { matches!(stem.to_ascii_lowercase().as_str(), "mod" | "lib" | "main" | "index" | "types" | "config" | "util" | "utils" | "common") }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::line_hash3;
    use crate::edit::hashline::hash3_str;
    use std::fs;

    #[test]
    fn impact_filters_noise_context_tests_manifests_and_qualified_dot_colon_methods() {
        let ws = std::env::temp_dir().join(format!("ctx-impact-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(ws.join("src")).unwrap(); fs::create_dir_all(ws.join("tests")).unwrap();
        fs::write(ws.join("src/calc.rs"), "use std::cmp::max;\n\npub struct Engine { pub v: i32 }\nimpl Engine {\n    pub fn compute_fee(x: i32) -> i32 {\n        max(x, 0)\n    }\n}\n").unwrap();
        fs::write(ws.join("src/caller.rs"), "// compute_fee in comment\nfn run_order() -> i32 {\n    let _ = \"compute_fee in string\";\n    let _ = compute_fee_extra(1);\n    compute_fee(7)\n}\n").unwrap();
        fs::write(ws.join("src/store.go"), "package db\ntype Cache struct{}\nfunc (c *Cache) Update() int { return 0 }\ntype Store struct{}\nfunc (s *Store) Update(k string) int {\n\treturn len(k)\n}\n").unwrap();
        fs::write(ws.join("tests/calc_test.rs"), "fn test_cf() { compute_fee(1); }\n").unwrap();
        fs::write(ws.join("src/mod.rs"), "pub mod calc;\n").unwrap();
        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();
        let out = op_impact(&svc, &["calc#compute_fee".into()], 20, true, 16_384, Some(&ws)).unwrap();
        assert!(out.contains(&format!("5:{}|     pub fn compute_fee", hash3_str(&line_hash3("    pub fn compute_fee(x: i32) -> i32 {")))));
        assert!(out.contains("Enclosing:") && out.contains("impl Engine") && out.contains("use std::cmp::max;"));
        assert!(out.contains("src/caller.rs") && out.contains("@run_order") && out.contains("5: compute_fee(7)"));
        assert!(!out.contains("in comment") && !out.contains("in string") && !out.contains("compute_fee_extra"));
        assert!(out.contains("tests/calc_test.rs [test]") && out.contains("src/mod.rs [manifest]"));
        let no_t = op_impact(&svc, &["calc#compute_fee".into()], 20, false, 16_384, Some(&ws)).unwrap();
        assert!(!no_t.contains("tests/calc_test.rs") && !no_t.contains("src/mod.rs"));
        assert_eq!(bare_identifier("Store.Update"), "Update");
        assert_eq!(bare_identifier("ns::Store::Update"), "Update");
        for spec in ["src/store.go#Store.Update", "src/store.go#Store::Update"] {
            let r = op_impact_with_git(&svc, &[spec.into()], 10, false, 8192, Some(&ws), false).unwrap();
            assert!(r.contains("func (s *Store) Update"), "wrong Go receiver for {spec}: {r}");
        }
        for spec in ["src/calc.rs#Engine.compute_fee", "src/calc.rs#Engine::compute_fee"] {
            let r = op_impact_with_git(&svc, &[spec.into()], 10, false, 8192, Some(&ws), false).unwrap();
            assert!(r.contains("pub fn compute_fee"), "failed Rust impl match for {spec}: {r}");
        }
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn impact_batch_five_targets_single_pass_and_git_status_badges() {
        let parsed = parse_git_porcelain(" M src/b.rs\n?? src/c.rs\nM  sub/src/d.rs\n", &["b.rs", "src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs"]);
        assert_eq!(parsed.get("b.rs"), None); assert_eq!(parsed.get("src/a.rs"), None);
        assert_eq!(parsed.get("src/b.rs").map(String::as_str), Some("M"));
        assert_eq!(parsed.get("src/c.rs").map(String::as_str), Some("??"));
        assert_eq!(parsed.get("src/d.rs").map(String::as_str), Some("M"));
        let ws = std::env::temp_dir().join(format!("ctx-impact-batch-{}-{}", std::process::id(), crate::store::now_ms_u64()));
        fs::create_dir_all(ws.join("src")).unwrap(); fs::create_dir_all(ws.join("tests")).unwrap();
        for (rel, body) in [
            ("src/alpha.rs", "pub fn fn_a() -> i32 { 1 }\npub fn fn_b() -> i32 { fn_a() }\n"),
            ("src/beta.rs", "pub fn fn_c() -> i32 { 3 }\n"), ("src/gamma.rs", "pub fn fn_d() -> i32 { 4 }\n"),
            ("src/delta.rs", "pub fn fn_e() -> i32 { 5 }\n"), ("src/use_all.rs", "fn main_call() -> i32 { fn_a() + fn_b() + fn_c() + fn_d() + fn_e() }\n"),
            ("tests/all_test.rs", "fn t() { fn_a(); fn_c(); fn_e(); }\n"), ("src/mod.rs", "pub mod alpha; pub mod beta; pub mod gamma; pub mod delta;\n"),
        ] { fs::write(ws.join(rel), body).unwrap(); }
        let git_ok = git_cmd().arg("-C").arg(&ws).args(["init", "-q"]).status().is_ok_and(|s| s.success());
        if git_ok {
            let run = |args: &[&str]| git_cmd().arg("-C").arg(&ws).args(args).status().unwrap().success();
            assert!(run(&["config", "user.email", "t@example.com"]) && run(&["config", "user.name", "T"]));
            assert!(run(&["add", "src/alpha.rs", "src/beta.rs", "src/gamma.rs", "src/use_all.rs", "tests/all_test.rs", "src/mod.rs"]) && run(&["commit", "-q", "-m", "init"]));
            fs::write(ws.join("src/beta.rs"), "pub fn fn_c() -> i32 { 33 }\n").unwrap();
        }
        let svc = BrokerService::new_ephemeral_inproc(ws.join("snap.bin"));
        svc.allowlist.register_hint(&ws, true).unwrap();
        assert!(op_impact(&svc, &(0..7).map(|_| "src/alpha.rs#fn_a".into()).collect::<Vec<_>>(), 10, true, 16_384, Some(&ws)).unwrap_err().contains("1..=6"));
        let five: Vec<String> = ["src/alpha.rs#fn_a", "src/alpha.rs#fn_b", "src/beta.rs#fn_c", "src/gamma.rs#fn_d", "src/delta.rs#fn_e"].into_iter().map(str::to_string).collect();
        let out = op_impact(&svc, &five, 10, true, 32_768, Some(&ws)).unwrap();
        for sym in &five { assert!(out.contains(sym.as_str()), "missing target {sym}"); }
        assert_eq!(out.matches("src/use_all.rs").count(), 5);
        assert!(out.contains("2: pub fn fn_b() -> i32 { fn_a() }") && out.contains("tests/all_test.rs [test]") && out.contains("src/mod.rs [manifest]"));
        if git_ok { assert!(out.contains(") [git: clean] ===") && out.contains("src/beta.rs#fn_c (fn [L1-L1], 1L) [git: M] ===") && out.contains("src/delta.rs#fn_e (fn [L1-L1], 1L) [git: ??] ===")); }
        assert!(!op_impact_with_git(&svc, &five, 10, false, 32_768, Some(&ws), false).unwrap().contains("[git:"));
        fs::write(ws.join("src/alpha.rs"), "use std::cmp::max;\npub fn fn_a() -> i32 { max(1, 2) }\npub fn fn_b() -> i32 { fn_a() }\n").unwrap();
        let agy_pack = op_impact_with_git(&svc, &five, 20, false, 9000, Some(&ws), false).unwrap();
        for sym in &five { assert!(agy_pack.contains(sym.as_str()), "9KB cap lost {sym}"); }
        assert_eq!(agy_pack.matches("use std::cmp::max;").count(), 1);
        let _ = fs::remove_dir_all(&ws);
    }
}
