//! Minimal zero-dependency RFC 8259 JSON parser and serializer (0 `f64` floats,
//! SIMD safe-span escaping, and stack integer formatting).

use crate::simd::{next_json_escape_pos, push_i64};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    NumberToken(Box<str>), // Retain exact decimals and out-of-range integers without f64.
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(entries: Vec<(&str, Json)>) -> Self {
        Json::Obj(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(items) => items.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(v) => Some(*v),
            Json::NumberToken(s) => s
                .parse::<i64>()
                .ok()
                .or_else(|| s.split_once('.').and_then(|(int_part, _)| int_part.parse::<i64>().ok())),
            Json::Str(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn as_usize(&self) -> Option<usize> {
        self.as_i64().and_then(|v| if v >= 0 { Some(v as usize) } else { None })
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            Json::Str(s) => match s.trim() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(o) => Some(o.as_slice()),
            _ => None,
        }
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }

    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.get(key).and_then(|v| v.as_usize())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

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
                    escape_str(k, out);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn escape_str(s: &str, out: &mut String) {
    out.reserve(s.len() + 2);
    out.push('"');
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let next = next_json_escape_pos(bytes, i);
        if next > i {
            out.push_str(&s[i..next]);
            i = next;
            if i >= bytes.len() {
                break;
            }
        }
        let b = bytes[i];
        i += 1;
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0C => out.push_str("\\f"),
            ctrl => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let esc = [
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[((ctrl >> 4) & 0x0f) as usize],
                    HEX[(ctrl & 0x0f) as usize],
                ];
                // SAFETY: `esc` is pure ASCII.
                out.push_str(unsafe { std::str::from_utf8_unchecked(&esc) });
            }
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Json, String> {
    parse_with(input, false)
}

pub fn parse_config(input: &str) -> Result<Json, String> {
    parse_with(input, true)
}

fn parse_with(input: &str, strict_config: bool) -> Result<Json, String> {
    let mut p = Parser {
        strict_config,
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let val = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing characters at byte {}", p.pos));
    }
    Ok(val)
}

struct Parser<'a> {
    strict_config: bool,
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        if self.depth > 96 {
            return Err("JSON nesting depth exceeded".to_string());
        }
        self.skip_ws();
        let b = self.peek().ok_or_else(|| "unexpected end of JSON".to_string())?;
        match b {
            b'n' => self.parse_literal(b"null", Json::Null),
            b't' => self.parse_literal(b"true", Json::Bool(true)),
            b'f' => self.parse_literal(b"false", Json::Bool(false)),
            b'"' => self.parse_string().map(Json::Str),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(format!("unexpected byte 0x{:02x} at {}", b, self.pos)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], out: Json) -> Result<Json, String> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(out)
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\u escape".to_string());
        }
        let mut val: u16 = 0;
        for _ in 0..4 {
            let b = self.bytes[self.pos];
            self.pos += 1;
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return Err("invalid hex digit in \\u escape".to_string()),
            };
            val = (val << 4) | digit;
        }
        Ok(val)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"'".to_string());
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self.peek().ok_or_else(|| "truncated escape".to_string())?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{08}'),
                    b'f' => out.push('\u{0C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let first = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&first) {
                            if self.bytes.get(self.pos..self.pos + 2) == Some(b"\\u") {
                                self.pos += 2;
                                let second = self.parse_hex4()?;
                                if (0xDC00..=0xDFFF).contains(&second) {
                                    let combined = 0x10000
                                        + (((first as u32 - 0xD800) << 10)
                                            | (second as u32 - 0xDC00));
                                    if let Some(ch) = char::from_u32(combined) {
                                        out.push(ch);
                                        continue;
                                    }
                                }
                            }
                            if self.strict_config { return Err("unpaired unicode surrogate".into()); }
                            out.push('\u{FFFD}');
                        } else if let Some(ch) = char::from_u32(first as u32) {
                            out.push(ch);
                        } else {
                            if self.strict_config { return Err("unpaired unicode surrogate".into()); }
                            out.push('\u{FFFD}');
                        }
                    }
                    _ => return Err(format!("invalid escape \\{}", esc as char)),
                }
            } else {
                let start = self.pos;
                while self.pos < self.bytes.len() {
                    let c = self.bytes[self.pos];
                    if c == b'"' || c == b'\\' {
                        break;
                    }
                    if c < 0x20 {
                        return Err("unescaped control character in JSON string".to_string());
                    }
                    self.pos += 1;
                }
                let slice = std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                out.push_str(slice);
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        let mut is_decimal = false;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else {
            self.take_digits()?;
        }
        if self.peek() == Some(b'.') {
            is_decimal = true;
            self.pos += 1;
            self.take_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_decimal = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.take_digits()?;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        if !is_decimal {
            if let Ok(i) = s.parse::<i64>() {
                return Ok(Json::Int(i));
            }
        }
        Ok(Json::NumberToken(s.into()))
    }

    fn take_digits(&mut self) -> Result<(), String> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.pos += 1; }
        if start == self.pos { return Err(format!("missing digit at {}", start)); }
        Ok(())
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.pos += 1;
        self.depth += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.pos += 1;
        self.depth += 1;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value()?;
            if self.strict_config && fields.iter().any(|(k, _)| k == &key) {
                return Err("duplicate configuration key".into());
            }
            fields.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }
}
