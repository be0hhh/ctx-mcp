//! RFC 8259 JSON parser backed by direct `&str` slicing (0 redundant `from_utf8`)
//! and AVX2+BMI1 escape-free string fast path.

use super::{Json, JsonKey};
use crate::base::simd::next_json_escape_pos;

pub fn parse(input: &str) -> Result<Json, String> {
    parse_with(input, false)
}

pub fn parse_config(input: &str) -> Result<Json, String> {
    parse_with(input, true)
}

fn parse_with(input: &str, strict_config: bool) -> Result<Json, String> {
    let mut p = Parser {
        strict_config,
        src: input,
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
    src: &'a str,
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
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of JSON".to_string())?;
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
        let start = self.pos;
        let next = next_json_escape_pos(self.bytes, start);
        if next >= self.bytes.len() {
            return Err("unterminated JSON string".to_string());
        }
        let stop = self.bytes[next];
        if stop == b'"' {
            self.pos = next + 1;
            return Ok(self.src[start..next].to_owned());
        }
        if stop < 0x20 {
            return Err("unescaped control character in JSON string".to_string());
        }

        let mut out = String::with_capacity((next - start).saturating_add(16));
        if next > start {
            out.push_str(&self.src[start..next]);
        }
        self.pos = next;

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
                                let saved_pos = self.pos;
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
                                self.pos = saved_pos;
                            }
                            if self.strict_config {
                                return Err("unpaired unicode surrogate".into());
                            }
                            out.push('\u{FFFD}');
                        } else if let Some(ch) = char::from_u32(first as u32) {
                            out.push(ch);
                        } else {
                            if self.strict_config {
                                return Err("unpaired unicode surrogate".into());
                            }
                            out.push('\u{FFFD}');
                        }
                    }
                    _ => return Err(format!("invalid escape \\{}", esc as char)),
                }
            } else {
                let seg_start = self.pos;
                let seg_next = next_json_escape_pos(self.bytes, seg_start);
                if seg_next >= self.bytes.len() {
                    return Err("unterminated JSON string".to_string());
                }
                if self.bytes[seg_next] < 0x20 {
                    return Err("unescaped control character in JSON string".to_string());
                }
                out.push_str(&self.src[seg_start..seg_next]);
                self.pos = seg_next;
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
        let s = &self.src[start..self.pos];
        if !is_decimal {
            if let Ok(i) = s.parse::<i64>() {
                return Ok(Json::Int(i));
            }
        }
        Ok(Json::NumberToken(s.into()))
    }

    fn take_digits(&mut self) -> Result<(), String> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(format!("missing digit at {}", start));
        }
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
        let mut fields: Vec<(JsonKey, Json)> = Vec::new();
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
            if self.strict_config && fields.iter().any(|(k, _)| k.as_ref() == key.as_str()) {
                return Err("duplicate configuration key".into());
            }
            fields.push((JsonKey::Owned(key), val));
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
