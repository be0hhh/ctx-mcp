//! Zero-dependency JSON & NDJSON diagnostic compactor (`ctx diag`).
//! Uses `crate::base::json::parse`, extracts buried error/status fields, summarizes
//! large arrays with schema + first/last samples, and bounds output strictly to `max_bytes`.

use super::logs::{clip_str, compress_generic_logs, truncate_utf8_bytes};
use crate::base::json::{parse, Json, JsonKey};
use crate::base::simd::{fast_hash64, push_i64, push_usize, FastHashMap};

const MAX_NDJSON_LINES: usize = 4096;
const MAX_WALK_NODES: usize = 32768;
const MAX_ERRORS_COLLECTED: usize = 12;
const MAX_NDJSON_GROUPS: usize = 128;

pub fn looks_like_large_json_or_ndjson(raw: &str) -> bool {
    raw.len() > 1024 && matches!(raw.trim_start().as_bytes().first(), Some(b'{' | b'['))
}

pub fn compress_json_output(raw: &str, max_bytes: usize) -> String {
    if let Ok(doc) = parse(raw) { return format_single_json(&doc, raw.len(), max_bytes); }
    try_format_ndjson(raw, max_bytes).unwrap_or_else(|| compress_generic_logs(raw, max_bytes))
}

fn push_schema_fields(fields: &[(JsonKey, Json)], out: &mut String, limit: usize, parens: bool) {
    for (i, (k, v)) in fields.iter().take(limit).enumerate() {
        if i > 0 { out.push_str(", "); }
        out.push_str(k.as_ref()); out.push(if parens { '(' } else { ':' });
        push_type_tag(v, out);
        if parens { out.push(')'); }
    }
    if fields.len() > limit { out.push_str(", ...(+"); push_usize(out, fields.len() - limit); out.push(')'); }
}

fn format_single_json(doc: &Json, raw_bytes: usize, max_bytes: usize) -> String {
    let mut out = String::with_capacity(max_bytes.min(2048));
    out.push_str("[ctx diag: JSON ("); push_usize(&mut out, raw_bytes); out.push_str("B)]\n");
    let (mut errors, mut visited, mut path) = (Vec::new(), 0usize, String::with_capacity(64));
    collect_error_fields(doc, &mut path, 0, &mut visited, &mut errors);

    match doc {
        Json::Obj(fields) => {
            out.push_str("keys: "); push_schema_fields(fields, &mut out, 24, true); out.push('\n');
            append_extracted_errors(&mut out, &errors, max_bytes);
            if let Some((k, a)) = fields.iter().find_map(|(k, v)| match v {
                Json::Arr(a) if a.len() >= 3 => Some((k.as_ref(), a.as_slice())), _ => None,
            }) { append_array_summary(&mut out, k, a, max_bytes); }
        }
        Json::Arr(items) => {
            out.push_str("type: arr["); push_usize(&mut out, items.len()); out.push_str("]\n");
            append_extracted_errors(&mut out, &errors, max_bytes);
            append_array_summary(&mut out, "items", items, max_bytes);
        }
        other => { out.push_str("value: "); fmt_compact(other, &mut out, 200, 0); out.push('\n'); }
    }
    truncate_utf8_bytes(&mut out, max_bytes);
    out
}

fn append_extracted_errors(out: &mut String, errors: &[String], max_bytes: usize) {
    if errors.is_empty() { return; }
    out.push_str("errors:\n");
    for e in errors {
        if out.len().saturating_add(e.len() + 3) > max_bytes { break; }
        out.push_str("  "); out.push_str(e); out.push('\n');
    }
}

fn append_array_summary(out: &mut String, label: &str, items: &[Json], max_bytes: usize) {
    if items.is_empty() || out.len().saturating_add(64) >= max_bytes { return; }
    if let Some(f) = items[0].as_obj() {
        out.push_str(label); out.push_str(" schema: {"); push_schema_fields(f, out, 16, false); out.push_str("}\n");
    }
    if out.len().saturating_add(32) < max_bytes { out.push_str("first: "); fmt_compact(&items[0], out, 180, 0); out.push('\n'); }
    if items.len() > 1 && out.len().saturating_add(32) < max_bytes {
        out.push_str("last: "); fmt_compact(&items[items.len() - 1], out, 180, 0); out.push('\n');
    }
}

fn try_format_ndjson(raw: &str, max_bytes: usize) -> Option<String> {
    let (mut parsed, mut capped) = (0usize, false);
    let (mut schema, mut first_s, mut last_s) = (String::new(), String::new(), String::new());
    let (mut groups, mut gmap) = (Vec::<(String, usize)>::new(), FastHashMap::<u64, usize>::default());

    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if parsed >= MAX_NDJSON_LINES { capped = true; break; }
        let Ok(doc) = parse(t) else { continue; };
        parsed += 1;
        if parsed == 1 {
            if let Some(f) = doc.as_obj() { push_schema_fields(f, &mut schema, 16, false); }
            fmt_compact(&doc, &mut first_s, 180, 0);
        }
        last_s.clear(); fmt_compact(&doc, &mut last_s, 180, 0);
        if let Some(summary) = extract_ndjson_error(&doc) {
            let h = fast_hash64(summary.as_bytes());
            if let Some(&slot) = gmap.get(&h) { groups[slot].1 += 1; }
            else if groups.len() < MAX_NDJSON_GROUPS { gmap.insert(h, groups.len()); groups.push((summary, 1)); }
        }
    }
    if parsed == 0 { return None; }
    groups.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    let mut out = String::with_capacity(max_bytes.min(2048));
    out.push_str("[ctx diag: NDJSON ("); push_usize(&mut out, raw.len());
    out.push_str("B, "); push_usize(&mut out, parsed);
    out.push_str(if capped { "+ records)]\n" } else { " records)]\n" });
    if !schema.is_empty() { out.push_str("schema: {"); out.push_str(&schema); out.push_str("}\n"); }
    if !groups.is_empty() {
        out.push_str("error/status records:\n");
        for (line, count) in groups.iter().take(16) {
            if out.len().saturating_add(line.len() + 20) > max_bytes.saturating_sub(240) { break; }
            out.push_str("  "); out.push_str(line);
            if *count > 1 { out.push_str(" (\u{00d7}"); push_usize(&mut out, *count); out.push(')'); }
            out.push('\n');
        }
    }
    if !first_s.is_empty() && out.len().saturating_add(first_s.len() + 10) <= max_bytes {
        out.push_str("first: "); out.push_str(&first_s); out.push('\n');
    }
    if parsed > 1 && out.len().saturating_add(last_s.len() + 9) <= max_bytes {
        out.push_str("last: "); out.push_str(&last_s); out.push('\n');
    }
    truncate_utf8_bytes(&mut out, max_bytes);
    Some(out)
}

fn extract_ndjson_error(doc: &Json) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in doc.as_obj()? {
        let kl = k.as_ref();
        if is_error_key(kl) && is_notable(kl, v, false) {
            let mut s = format!("{kl}="); fmt_compact(v, &mut s, 120, 0); parts.push(s);
        } else if (kl.eq_ignore_ascii_case("level") || kl.eq_ignore_ascii_case("severity"))
            && v.as_str().is_some_and(is_err_level)
        {
            parts.push(format!("{kl}={}", v.as_str().unwrap_or("")));
        }
    }
    if parts.is_empty() { return None; }
    if parts.len() == 1 {
        if let Some(m) = doc.get("message").or_else(|| doc.get("msg")) {
            let mut s = "msg=".to_string(); fmt_compact(m, &mut s, 120, 0); parts.push(s);
        }
    }
    Some(parts.join(" "))
}

fn collect_error_fields(val: &Json, path: &mut String, depth: usize, visited: &mut usize, out: &mut Vec<String>) {
    if depth > 12 || *visited >= MAX_WALK_NODES || out.len() >= MAX_ERRORS_COLLECTED { return; }
    *visited += 1;
    match val {
        Json::Obj(fields) => {
            let has_sib = fields.iter().any(|(k, v)| {
                let kl = k.as_ref();
                ["error", "errors", "failed", "status"].iter().any(|&w| kl.eq_ignore_ascii_case(w)) && is_notable(kl, v, false)
            });
            for (k, v) in fields {
                if *visited >= MAX_WALK_NODES || out.len() >= MAX_ERRORS_COLLECTED { break; }
                let saved = path.len();
                if !path.is_empty() { path.push('.'); }
                path.push_str(k.as_ref());
                let kl = k.as_ref();
                let take = is_error_key(kl) && if kl.eq_ignore_ascii_case("message") { depth == 0 || has_sib } else { is_notable(kl, v, depth == 0) };
                if take { let mut line = format!("{path}: "); fmt_compact(v, &mut line, 180, 0); out.push(line); }
                else if matches!(v, Json::Obj(_) | Json::Arr(_)) { collect_error_fields(v, path, depth + 1, visited, out); }
                path.truncate(saved);
            }
        }
        Json::Arr(items) => {
            for (idx, item) in items.iter().enumerate() {
                if *visited >= MAX_WALK_NODES || out.len() >= MAX_ERRORS_COLLECTED { break; }
                if !matches!(item, Json::Obj(_) | Json::Arr(_)) { continue; }
                let saved = path.len();
                path.push('['); push_usize(path, idx); path.push(']');
                collect_error_fields(item, path, depth + 1, visited, out);
                path.truncate(saved);
            }
        }
        _ => {}
    }
}

fn is_error_key(k: &str) -> bool { ["error", "errors", "message", "status", "failed", "detail"].iter().any(|&w| k.eq_ignore_ascii_case(w)) }
fn is_err_level(s: &str) -> bool { ["error", "err", "fatal", "panic", "critical", "warn"].iter().any(|&w| s.eq_ignore_ascii_case(w)) }

fn is_notable(key: &str, v: &Json, top: bool) -> bool {
    match v {
        Json::Null | Json::Bool(false) => false,
        Json::Str(s) if s.trim().is_empty() => false,
        Json::Arr(a) if a.is_empty() => false,
        Json::Obj(o) if o.is_empty() => false,
        Json::Str(s) if key.eq_ignore_ascii_case("status") && !top => !s.eq_ignore_ascii_case("ok") && !s.eq_ignore_ascii_case("success"),
        Json::Int(200) if key.eq_ignore_ascii_case("status") && !top => false,
        _ => true,
    }
}

fn push_type_tag(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(_) => out.push_str("bool"),
        Json::Int(_) | Json::NumberToken(_) => out.push_str("num"),
        Json::Str(_) => out.push_str("str"),
        Json::Arr(a) => { out.push_str("arr["); push_usize(out, a.len()); out.push(']'); }
        Json::Obj(o) => { out.push_str("obj{"); push_usize(out, o.len()); out.push('}'); }
    }
}

fn fmt_compact(v: &Json, out: &mut String, cap: usize, depth: usize) {
    let limit = out.len().saturating_add(cap);
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(n) => push_i64(out, *n),
        Json::NumberToken(s) => out.push_str(clip_str(s, cap)),
        Json::Str(s) => {
            out.push('"'); let bc = cap.saturating_sub(2); out.push_str(clip_str(s, bc));
            if s.len() > bc { out.push_str("..."); } out.push('"');
        }
        Json::Arr(a) if depth >= 2 => { out.push_str("[.."); push_usize(out, a.len()); out.push(']'); }
        Json::Arr(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if out.len() >= limit { out.push_str(",..."); break; }
                if i > 0 { out.push(','); }
                fmt_compact(item, out, limit.saturating_sub(out.len()), depth + 1);
            }
            out.push(']');
        }
        Json::Obj(f) if depth >= 2 => { out.push_str("{.."); push_usize(out, f.len()); out.push('}'); }
        Json::Obj(f) => {
            out.push('{');
            for (i, (k, val)) in f.iter().enumerate() {
                if out.len() >= limit { out.push_str(",..."); break; }
                if i > 0 { out.push(','); }
                out.push_str(k.as_ref()); out.push(':');
                fmt_compact(val, out, limit.saturating_sub(out.len()), depth + 1);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_json_array_extracts_buried_errors_and_samples() {
        let (mut raw, pad) = (String::from("["), "a".repeat(100));
        for i in 0..450 {
            if i > 0 { raw.push(','); }
            if i == 312 { raw.push_str(&format!(r#"{{"id":312,"status":"failed","error":"upstream 504","detail":"gateway timeout","payload":"{pad}"}}"#)); }
            else { raw.push_str(&format!(r#"{{"id":{i},"status":"ok","payload":"{pad}"}}"#)); }
        }
        raw.push(']');
        assert!(raw.len() > 60_000 && looks_like_large_json_or_ndjson(&raw));
        let out = compress_json_output(&raw, 4096);
        assert!(out.starts_with("[ctx diag: JSON (") && out.contains("type: arr[450]"));
        assert!(out.contains("[312].error: \"upstream 504\"") && out.contains("[312].detail: \"gateway timeout\""));
        assert!(out.contains("first:") && out.contains("last:") && out.len() <= 4096);
    }

    #[test]
    fn ndjson_stream_groups_errors_and_bounds_output() {
        let mut raw = String::new();
        for i in 0..40 { raw.push_str(&format!("{{\"ts\":{i},\"level\":\"info\",\"msg\":\"tick {i}\",\"pad\":\"0123456789abcdef\"}}\n")); }
        for i in 0..6 { raw.push_str(&format!("{{\"ts\":{i},\"level\":\"error\",\"error\":\"rate_limit\",\"status\":429}}\n")); }
        assert!(looks_like_large_json_or_ndjson(&raw));
        let out = compress_json_output(&raw, 2048);
        assert!(out.starts_with("[ctx diag: NDJSON (") && out.contains("46 records)]"));
        assert!(out.contains("rate_limit") && out.contains("(\u{00d7}6)") && out.len() <= 2048);
    }
}
