//! Compact and pretty RFC 8259 JSON serialization backed by hoisted SIMD escaping
//! and zero-allocation stack integer formatting.

use super::Json;
use crate::base::simd::{escape_json_str, push_i64};

impl Json {
    pub fn to_json_string(&self) -> String {
        let mut out = String::with_capacity(128);
        self.write_to(&mut out);
        out
    }

    pub fn write_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(n) => push_i64(out, *n),
            Json::NumberToken(s) => out.push_str(s),
            Json::Str(s) => escape_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_str(k.as_ref(), out);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }
}

#[inline]
pub fn escape_str(s: &str, out: &mut String) {
    escape_json_str(s, out);
}

pub fn format_pretty_json(val: &Json, indent: usize) -> String {
    let mut out = String::with_capacity(128);
    write_pretty_json(val, indent, &mut out);
    out
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_pretty_json(val: &Json, indent: usize, out: &mut String) {
    match val {
        Json::Obj(items) if items.is_empty() => out.push_str("{}"),
        Json::Obj(items) => {
            out.push_str("{\n");
            for (i, (k, v)) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                push_indent(out, indent + 1);
                escape_str(k.as_ref(), out);
                out.push_str(": ");
                write_pretty_json(v, indent + 1, out);
            }
            out.push('\n');
            push_indent(out, indent);
            out.push('}');
        }
        Json::Arr(items) if items.is_empty() => out.push_str("[]"),
        Json::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                push_indent(out, indent + 1);
                write_pretty_json(item, indent + 1, out);
            }
            out.push('\n');
            push_indent(out, indent);
            out.push(']');
        }
        other => other.write_to(out),
    }
}
