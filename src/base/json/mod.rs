//! Minimal zero-dependency RFC 8259 JSON DOM, parser, and serializer
//! (0 `f64` floats, `Cow<'static, str>` keys, SIMD safe-span escaping, and stack integer formatting).

pub mod encode;
pub mod parse;

use std::borrow::Cow;

pub use encode::format_pretty_json;
pub use parse::{parse, parse_config};

pub type JsonKey = Cow<'static, str>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    NumberToken(Box<str>), // Retain exact decimals and out-of-range integers without f64.
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(JsonKey, Json)>),
}

impl Json {
    pub fn obj(entries: Vec<(&'static str, Json)>) -> Self {
        Json::Obj(entries.into_iter().map(|(k, v)| (Cow::Borrowed(k), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(items) => items
                .iter()
                .rev()
                .find(|(k, _)| k.as_ref() == key)
                .map(|(_, v)| v),
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
        self.as_i64()
            .and_then(|v| if v >= 0 { Some(v as usize) } else { None })
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

    pub fn as_obj(&self) -> Option<&[(JsonKey, Json)]> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_escape_free_fast_path_and_unicode() {
        let raw = r#"{"plain":"a clean string longer than thirty two bytes without escapes","utf8":"привет мир 🚀","empty":""}"#;
        let doc = parse(raw).unwrap();
        assert_eq!(
            doc.get_str("plain"),
            Some("a clean string longer than thirty two bytes without escapes")
        );
        assert_eq!(doc.get_str("utf8"), Some("привет мир 🚀"));
        assert_eq!(doc.get_str("empty"), Some(""));
    }

    #[test]
    fn parse_rejects_unescaped_control_chars() {
        assert!(parse("\"hello\nworld\"").is_err());
        assert!(parse("\"hello\x00world\"").is_err());
        assert!(parse("\"hello\\nstill\x1fbad\"").is_err());
    }

    #[test]
    fn parse_surrogate_pairs_and_strict_config() {
        let ok = parse(r#""\uD83D\uDE80""#).unwrap();
        assert_eq!(ok.as_str(), Some("🚀"));

        // Non-strict replaces unpaired surrogate with U+FFFD; strict rejects it.
        let non_strict = parse(r#""\uD800""#).unwrap();
        assert_eq!(non_strict.as_str(), Some("\u{FFFD}"));
        assert!(parse_config(r#""\uD800""#).is_err());
        assert!(parse_config(r#""\uDC00""#).is_err());

        // Duplicate keys allowed in `parse` (last wins), rejected in `parse_config`.
        let dup_raw = r#"{"k":1,"k":2}"#;
        assert_eq!(parse(dup_raw).unwrap().get_i64("k"), Some(2));
        assert!(parse_config(dup_raw).is_err());
    }

    #[test]
    fn parse_numbers_and_decimal_token() {
        let doc = parse(r#"{"i":-42,"dec":123.456,"big":99999999999999999999999}"#).unwrap();
        assert_eq!(doc.get("i"), Some(&Json::Int(-42)));
        assert_eq!(doc.get("dec"), Some(&Json::NumberToken("123.456".into())));
        assert_eq!(doc.get_i64("dec"), Some(123));
        assert_eq!(
            doc.get("big"),
            Some(&Json::NumberToken("99999999999999999999999".into()))
        );
    }

    #[test]
    fn escape_str_and_pretty_round_trip() {
        let original = "line1\n\"quoted\"\\path\\\t\r\u{0008}\u{000C}\u{0001} and long clean suffix 0123456789abcdef0123456789abcdef";
        let obj = Json::obj(vec![
            ("text", Json::Str(original.to_string())),
            ("num", Json::Int(-9876543210)),
            ("arr", Json::Arr(vec![Json::Bool(true), Json::Null])),
        ]);
        let compact = obj.to_json_string();
        let reparsed = parse(&compact).unwrap();
        assert_eq!(reparsed.get_str("text"), Some(original));
        assert_eq!(reparsed.get_i64("num"), Some(-9876543210));

        let pretty = format_pretty_json(&obj, 0);
        let reparsed_pretty = parse(&pretty).unwrap();
        assert_eq!(reparsed_pretty, reparsed);
    }
}
