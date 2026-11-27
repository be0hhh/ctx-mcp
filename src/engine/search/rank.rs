//! Universal search hit classification, policy-weighted file ordering, and zero-division
//! 2-level (`file -> enclosing_scope`) round-robin selection with omitted-scope summaries.

use super::SearchHit;
use crate::base::ext::policy;
use crate::parser::{SymbolKind, SymbolSpan};
use crate::rpc::BrokerService;
use crate::store::{display_workspace_path, CachedFile};
use std::cmp::Reverse;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(super) enum HitKind {
    Definition = 0,
    WriteOrCall = 1,
    Code = 2,
    ImportOrDecl = 3,
    Comment = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OmittedScope {
    pub label: String,
    pub first_line: usize,
    pub count: usize,
}

pub(super) struct SearchHitSet {
    pub hits: Vec<SearchHit>,
    pub total_found: usize,
    pub scan_truncated: bool,
    pub incomplete_note: Option<&'static str>,
    pub omitted_scopes: Vec<OmittedScope>,
}

pub(super) fn enclosing_scope(outline: &CachedFile, line: usize) -> Option<(usize, &SymbolSpan)> {
    outline
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, sym)| {
            sym.kind != SymbolKind::Namespace
                && (sym.start_line as usize..=sym.end_line as usize).contains(&line)
        })
        .min_by_key(|(_, sym)| sym.end_line.saturating_sub(sym.start_line))
}

#[inline]
fn is_comment_only_line(path: &Path, snippet: &str) -> bool {
    let t = snippet.trim_start();
    if t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with("*/")
        || t == "*"
        || t.starts_with("* ")
        || t.starts_with("*\t")
        || t.starts_with("-- ")
    {
        return true;
    }
    if t.starts_with('#') {
        let is_md = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
            e.eq_ignore_ascii_case("md")
                || e.eq_ignore_ascii_case("mdx")
                || e.eq_ignore_ascii_case("markdown")
        });
        // Preserve Markdown headings (`# Title`) and C/C++ preprocessor directives / Rust attrs.
        if !is_md
            && !t.starts_with("#include")
            && !t.starts_with("#define")
            && !t.starts_with("#pragma")
            && !t.starts_with("#if")
            && !t.starts_with("#endif")
            && !t.starts_with("#[")
            && !t.starts_with("#![")
        {
            return true;
        }
    }
    false
}

fn is_ascii_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_bare_reexport_line(trimmed: &str) -> bool {
    let Some(core) = trimmed.strip_suffix(',') else {
        return false;
    };
    let core = core.trim();
    if is_ascii_ident(core) {
        return true;
    }
    if core.len() >= 3 {
        let bytes = core.as_bytes();
        let quoted = (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'');
        if quoted && is_ascii_ident(&core[1..core.len() - 1]) {
            return true;
        }
    }
    if let Some((lhs, rhs)) = core.split_once(" as ") {
        return is_ascii_ident(lhs.trim()) && is_ascii_ident(rhs.trim());
    }
    false
}

fn is_import_or_decl(path: &Path, trimmed: &str, enclosing: Option<&SymbolSpan>) -> bool {
    if trimmed.starts_with("#include")
        || trimmed.starts_with("import ")
        || (trimmed.starts_with("from ")
            && (trimmed.contains(" import ") || trimmed.contains(" import(")))
        || trimmed.starts_with("use ")
        || trimmed.starts_with("pub use ")
        || (trimmed.starts_with("pub(") && trimmed.contains(") use "))
        || trimmed.starts_with("using ")
        || trimmed.starts_with("extern ")
    {
        return true;
    }
    if enclosing.is_none() {
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if (fname == "__init__.py" || fname == "mod.rs") && is_bare_reexport_line(trimmed) {
            return true;
        }
    }
    false
}

fn strip_decl_qualifiers(mut s: &str) -> &str {
    for _ in 0..3 {
        let next = if let Some(rest) = s.strip_prefix("pub(") {
            match rest.find(')') {
                Some(idx) => rest[idx + 1..].trim_start(),
                None => s,
            }
        } else if let Some(rest) = s.strip_prefix("pub ") {
            rest.trim_start()
        } else if let Some(rest) = s.strip_prefix("export default ") {
            rest.trim_start()
        } else if let Some(rest) = s.strip_prefix("export ") {
            rest.trim_start()
        } else if let Some(rest) = s.strip_prefix("async ") {
            rest.trim_start()
        } else if let Some(rest) = s.strip_prefix("unsafe ") {
            rest.trim_start()
        } else {
            s
        };
        if next.len() == s.len() {
            break;
        }
        s = next;
    }
    s
}

fn starts_declaration(trimmed: &str) -> bool {
    let s = strip_decl_qualifiers(trimmed);
    let s = s.strip_prefix("const ").filter(|rest| rest.starts_with("fn ")).unwrap_or(s);
    s.starts_with("fn ")
        || s.starts_with("def ")
        || s.starts_with("class ")
        || s.starts_with("struct ")
        || s.starts_with("enum ")
        || s.starts_with("trait ")
        || s == "impl"
        || s.starts_with("impl ")
        || s.starts_with("impl<")
        || s.starts_with("func ")
        || s.starts_with("interface ")
        || s.starts_with("type ")
        || s.starts_with("function ")
        || s.starts_with("function<")
        || s.starts_with("message ")
        || s.starts_with("service ")
}

fn has_assignment_or_call(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => return true,
            b'=' => {
                let prev = if i > 0 { bytes[i - 1] } else { 0 };
                let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
                let non_assign = prev == b'='
                    || prev == b'!'
                    || prev == b'<'
                    || prev == b'>'
                    || next == b'='
                    || next == b'>';
                if !non_assign {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn classify_hit(
    path: &Path,
    line: usize,
    snippet: &str,
    enclosing: Option<&SymbolSpan>,
) -> HitKind {
    // Strict order: Comment -> ImportOrDecl -> Definition -> WriteOrCall -> Code.
    if is_comment_only_line(path, snippet) {
        return HitKind::Comment;
    }
    let trimmed = snippet.trim();
    if is_import_or_decl(path, trimmed, enclosing) {
        return HitKind::ImportOrDecl;
    }
    if enclosing.is_some_and(|sym| sym.start_line as usize == line) || starts_declaration(trimmed) {
        return HitKind::Definition;
    }
    if has_assignment_or_call(trimmed) {
        return HitKind::WriteOrCall;
    }
    HitKind::Code
}

struct ScopeBucket {
    key: Option<usize>,
    label: String,
    hit_indices: Vec<usize>,
    cursor: usize,
    best_tier: HitKind,
    earliest_line: usize,
}

struct RankedFile {
    orig_idx: usize,
    bonus: i8,
    best_tier: HitKind,
    hits: Vec<SearchHit>,
    kinds: Vec<HitKind>,
    picked: Vec<bool>,
    scopes: Vec<ScopeBucket>,
    next_scope: usize,
}

impl RankedFile {
    fn take_one(&mut self, max_tier: HitKind) -> Option<usize> {
        let n = self.scopes.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = self.next_scope;
            self.next_scope += 1;
            if self.next_scope == n {
                self.next_scope = 0;
            }
            let scope = &mut self.scopes[idx];
            if let Some(&hit_idx) = scope.hit_indices.get(scope.cursor) {
                if self.kinds[hit_idx] <= max_tier {
                    scope.cursor += 1;
                    return Some(hit_idx);
                }
            }
        }
        None
    }
}

/// Ranks hits across files and enclosing scopes using compile-time `ProjectPolicy::path_rank_bonus`
/// and zero-division 2-level (`file -> enclosing_scope`) round-robin selection.
pub(super) fn rank_and_select_hits(
    svc: &BrokerService,
    per_file: Vec<Vec<SearchHit>>,
    cap: usize,
    scan_truncated: bool,
) -> SearchHitSet {
    let total_found: usize = per_file.iter().map(Vec::len).sum();
    if total_found == 0 {
        return SearchHitSet {
            hits: Vec::new(),
            total_found: 0,
            scan_truncated,
            incomplete_note: None,
            omitted_scopes: Vec::new(),
        };
    }

    let pol = policy();
    let mut files: Vec<RankedFile> = Vec::with_capacity(per_file.len());
    for (orig_idx, mut group) in per_file.into_iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        group.sort_by_key(|h| h.line);
        let rel_path = display_workspace_path(&group[0].path, Some(&group[0].workspace));
        let bonus = pol.path_rank_bonus(&rel_path, &group[0].workspace);
        let outline = svc
            .store
            .get_outline_entry(&group[0].path, Some(&group[0].workspace))
            .ok();

        let mut kinds = Vec::with_capacity(group.len());
        let mut scopes: Vec<ScopeBucket> = Vec::new();
        for (idx, hit) in group.iter().enumerate() {
            let enc = outline.as_deref().and_then(|o| enclosing_scope(o, hit.line));
            let kind = classify_hit(&hit.path, hit.line, &hit.snippet, enc.map(|(_, s)| s));
            kinds.push(kind);
            let scope_key = enc.map(|(pos, _)| pos);
            if let Some(bucket) = scopes.iter_mut().find(|b| b.key == scope_key) {
                bucket.hit_indices.push(idx);
                if kind < bucket.best_tier {
                    bucket.best_tier = kind;
                }
                if hit.line < bucket.earliest_line {
                    bucket.earliest_line = hit.line;
                }
            } else {
                let label = enc
                    .map(|(_, s)| s.name.trim_start_matches("::"))
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        hit.path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&rel_path)
                            .to_string()
                    });
                scopes.push(ScopeBucket {
                    key: scope_key,
                    label,
                    hit_indices: vec![idx],
                    cursor: 0,
                    best_tier: kind,
                    earliest_line: hit.line,
                });
            }
        }
        for bucket in &mut scopes {
            bucket
                .hit_indices
                .sort_by_key(|&idx| (kinds[idx], group[idx].line));
        }
        scopes.sort_by_key(|b| (b.best_tier, b.earliest_line));
        let best_tier = scopes[0].best_tier;
        let hit_count = group.len();
        files.push(RankedFile {
            orig_idx,
            bonus,
            best_tier,
            hits: group,
            kinds,
            picked: vec![false; hit_count],
            scopes,
            next_scope: 0,
        });
    }

    files.sort_by_key(|f| (f.best_tier, Reverse(f.bonus), f.orig_idx));

    if total_found <= cap {
        let mut out = Vec::with_capacity(total_found);
        for mut file in files {
            out.append(&mut file.hits);
        }
        return SearchHitSet {
            hits: out,
            total_found,
            scan_truncated,
            incomplete_note: None,
            omitted_scopes: Vec::new(),
        };
    }

    let mut picked = 0usize;
    for max_tier in [HitKind::Code, HitKind::ImportOrDecl, HitKind::Comment] {
        while picked < cap {
            let mut advanced = false;
            for file in &mut files {
                if let Some(hit_idx) = file.take_one(max_tier) {
                    file.picked[hit_idx] = true;
                    picked += 1;
                    advanced = true;
                    if picked >= cap {
                        break;
                    }
                }
            }
            if !advanced {
                break;
            }
        }
        if picked >= cap {
            break;
        }
    }

    let mut omitted_cands: Vec<(bool, bool, HitKind, Reverse<i8>, usize, usize, OmittedScope)> =
        Vec::new();
    for (file_order, file) in files.iter().enumerate() {
        for scope in &file.scopes {
            let rem = &scope.hit_indices[scope.cursor..];
            if rem.is_empty() {
                continue;
            }
            let best_rem_tier = file.kinds[rem[0]];
            let first_line = rem.iter().map(|&i| file.hits[i].line).min().unwrap_or(0);
            omitted_cands.push((
                best_rem_tier == HitKind::Comment,
                scope.cursor > 0,
                best_rem_tier,
                Reverse(file.bonus),
                file_order,
                first_line,
                OmittedScope {
                    label: scope.label.clone(),
                    first_line,
                    count: rem.len(),
                },
            ));
        }
    }
    omitted_cands.sort_by_key(|c| (c.0, c.1, c.2, c.3, c.4, c.5));
    let omitted_scopes = omitted_cands.into_iter().take(4).map(|c| c.6).collect();

    let mut out = Vec::with_capacity(picked);
    for file in files {
        for (idx, hit) in file.hits.into_iter().enumerate() {
            if file.picked[idx] {
                out.push(hit);
            }
        }
    }
    SearchHitSet { hits: out, total_found, scan_truncated, incomplete_note: None, omitted_scopes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn classify_hit_strict_order_and_comment_guard() {
        let (rs, py, mod_rs, ts, cpp) = (
            Path::new("src/engine.rs"),
            Path::new("pkg/__init__.py"),
            Path::new("src/mod.rs"),
            Path::new("web/api.ts"),
            Path::new("core/book.hpp"),
        );

        // Comment checked FIRST so `// struct Foo` is never Definition.
        assert_eq!(classify_hit(rs, 1, "// struct Foo", None), HitKind::Comment);
        assert_eq!(classify_hit(cpp, 2, "/* fn bar() */", None), HitKind::Comment);
        assert_eq!(classify_hit(py, 3, "# def helper():", None), HitKind::Comment);

        // Imports & bare re-exports.
        assert_eq!(classify_hit(cpp, 4, "#include \"Foo.hpp\"", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(py, 5, "from pkg import Foo", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(py, 6, "    \"Foo\",", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(mod_rs, 7, "pub use inner::Foo;", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(mod_rs, 8, "    Foo,", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(cpp, 9, "using namespace foo;", None), HitKind::ImportOrDecl);
        assert_eq!(classify_hit(cpp, 10, "extern \"C\" void foo();", None), HitKind::ImportOrDecl);

        // Definitions (declaration keywords or enclosing sym.start_line).
        assert_eq!(classify_hit(rs, 11, "pub(crate) fn run() {", None), HitKind::Definition);
        assert_eq!(classify_hit(rs, 12, "async fn serve() {", None), HitKind::Definition);
        assert_eq!(classify_hit(rs, 13, "impl<T> Store<T> {", None), HitKind::Definition);
        assert_eq!(classify_hit(ts, 14, "export interface Config {", None), HitKind::Definition);
        assert_eq!(classify_hit(py, 15, "async def fetch():", None), HitKind::Definition);
        let sym = SymbolSpan {
            name: "custom".into(),
            signature: "".into(),
            start_line: 20,
            end_line: 30,
            kind: SymbolKind::Fn,
        };
        assert_eq!(classify_hit(cpp, 20, "inline int custom(int x) {", Some(&sym)), HitKind::Definition);

        // WriteOrCall vs Code.
        assert_eq!(classify_hit(rs, 21, "let x = foo;", Some(&sym)), HitKind::WriteOrCall);
        assert_eq!(classify_hit(rs, 22, "dispatch(target);", Some(&sym)), HitKind::WriteOrCall);
        assert_eq!(classify_hit(rs, 23, "if a == b || c != d && e <= f && g >= h {", Some(&sym)), HitKind::Code);
        assert_eq!(classify_hit(rs, 24, "    Some(x) => target,", Some(&sym)), HitKind::WriteOrCall);
        assert_eq!(classify_hit(rs, 25, "    x => target,", Some(&sym)), HitKind::Code);
        assert_eq!(classify_hit(rs, 26, "    return target;", Some(&sym)), HitKind::Code);

        // Tier priority ordering: Definition > WriteOrCall > Code > ImportOrDecl > Comment.
        assert!(HitKind::Definition < HitKind::WriteOrCall);
        assert!(HitKind::WriteOrCall < HitKind::Code);
        assert!(HitKind::Code < HitKind::ImportOrDecl);
        assert!(HitKind::ImportOrDecl < HitKind::Comment);
    }

    #[test]
    fn two_level_scope_spread_surfaces_late_function_and_reports_omitted_scopes() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-rank-scope-{}-{}",
            std::process::id(),
            crate::store::now_ms_u64()
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("flow.rs");

        // L1: comment, L2: fn early_scope, L3..=L17: 15 hits, L18-19: body close,
        // L20..=L293: blank filler, L294: fn late_scope, L295..=L297: 3 hits,
        // L298: close, L299: fn third_scope, L300..=L301: 2 hits, L302: close.
        let mut src = String::from("// struct needle comment\nfn early_scope(mut v: i32) -> i32 {\n");
        let mut raw_hits: Vec<(usize, String)> = vec![(1, "// struct needle comment".into())];
        for i in 0..15 {
            let text = format!("    v = needle_step({i});");
            src.push_str(&text);
            src.push('\n');
            raw_hits.push((3 + i, text.trim().into()));
        }
        src.push_str("    v\n}\n");
        for _ in 20..294 {
            src.push('\n');
        }
        src.push_str("fn late_scope() {\n    needle_late(1);\n    needle_late(2);\n    needle_late(3);\n}\n");
        src.push_str("fn third_scope() {\n    needle_third(1);\n    needle_third(2);\n}\n");
        assert_eq!(src.lines().nth(293), Some("fn late_scope() {"));
        assert_eq!(src.lines().nth(294), Some("    needle_late(1);"));
        assert_eq!(src.lines().nth(299), Some("    needle_third(1);"));
        fs::write(&file, &src).unwrap();

        let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot"));
        let ws = svc.allowlist.register_hint(&dir, true).unwrap();
        let canon = ws.join("flow.rs");
        for (ln, txt) in [
            (295, "needle_late(1);"),
            (296, "needle_late(2);"),
            (297, "needle_late(3);"),
            (300, "needle_third(1);"),
            (301, "needle_third(2);"),
        ] {
            raw_hits.push((ln, txt.into()));
        }
        let hits: Vec<SearchHit> = raw_hits
            .into_iter()
            .map(|(line, snippet)| SearchHit {
                path: canon.clone(),
                workspace: ws.clone(),
                line,
                snippet,
            })
            .collect();

        let set = rank_and_select_hits(&svc, vec![hits], 2, false);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(set.total_found, 21);
        assert!(!set.scan_truncated);
        assert_eq!(set.hits.len(), 2);
        assert_eq!(set.hits[0].line, 3);
        assert_eq!(set.hits[1].line, 295);
        assert_eq!(
            set.omitted_scopes[0],
            OmittedScope { label: "third_scope".into(), first_line: 300, count: 2 }
        );
        assert!(set.omitted_scopes.iter().any(|s| {
            s.label == "early_scope" && s.first_line == 4 && s.count == 14
        }));
        assert!(set.omitted_scopes.iter().any(|s| {
            s.label == "late_scope" && s.first_line == 296 && s.count == 2
        }));
    }
}
