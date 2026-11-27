//! Fast zero-dependency structural outline extractor for C/C++26 (`.c/.h/.cpp/.hpp/.ipp/...`),
//! Rust, Python, Java, C#, Go, TypeScript/JS, Kotlin, Swift, Zig, Shell, Proto, SQL,
//! CMake, Makefile, Dockerfile, Markdown, JSON/JSONC, YAML, and TOML using compact `SymbolKind`
//! tokens and precomputed `line_offsets` (`0` per-line `String` allocations).

pub mod clean;
mod cpp;
mod infra;
mod langs;
mod structured;

pub use clean::build_cleaned_code_buffer_for_ext;

use std::path::Path;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind {
    Namespace = 1,
    Struct = 2,
    Class = 3,
    Enum = 4,
    Concept = 5,
    Using = 6,
    Fn = 7,
    Def = 8,
    AsyncDef = 9,
    Trait = 10,
    Impl = 11,
    Func = 12,
    Type = 13,
    Interface = 14,
    Function = 15,
    Macro = 16,
    AddLibrary = 17,
    AddExecutable = 18,
    AddCustomTarget = 19,
    H1 = 20,
    H2 = 21,
    H3 = 22,
    Table = 23,
    Sym = 24,
    Key = 25,
    Record = 26,
    Mod = 27,
    H4 = 28,
}

impl SymbolKind {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Enum => "enum",
            Self::Concept => "concept",
            Self::Using => "using",
            Self::Fn => "fn",
            Self::Def => "def",
            Self::AsyncDef => "async def",
            Self::Trait => "trait",
            Self::Impl => "impl",
            Self::Func => "func",
            Self::Type => "type",
            Self::Interface => "interface",
            Self::Function => "function",
            Self::Macro => "macro",
            Self::AddLibrary => "add_library",
            Self::AddExecutable => "add_executable",
            Self::AddCustomTarget => "add_custom_target",
            Self::H1 => "h1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::Table => "table",
            Self::Sym => "sym",
            Self::Key => "key",
            Self::Record => "record",
            Self::Mod => "mod",
            Self::H4 => "h4",
        }
    }

    #[inline]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Namespace),
            2 => Some(Self::Struct),
            3 => Some(Self::Class),
            4 => Some(Self::Enum),
            5 => Some(Self::Concept),
            6 => Some(Self::Using),
            7 => Some(Self::Fn),
            8 => Some(Self::Def),
            9 => Some(Self::AsyncDef),
            10 => Some(Self::Trait),
            11 => Some(Self::Impl),
            12 => Some(Self::Func),
            13 => Some(Self::Type),
            14 => Some(Self::Interface),
            15 => Some(Self::Function),
            16 => Some(Self::Macro),
            17 => Some(Self::AddLibrary),
            18 => Some(Self::AddExecutable),
            19 => Some(Self::AddCustomTarget),
            20 => Some(Self::H1),
            21 => Some(Self::H2),
            22 => Some(Self::H3),
            23 => Some(Self::Table),
            24 => Some(Self::Sym),
            25 => Some(Self::Key),
            26 => Some(Self::Record),
            27 => Some(Self::Mod),
            28 => Some(Self::H4),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolSpan {
    pub name: Box<str>,
    pub signature: Box<str>,
    pub start_line: u32,
    pub end_line: u32,
    pub kind: SymbolKind,
}

#[cfg(target_pointer_width = "64")]
const _: [(); 48] = [(); std::mem::size_of::<SymbolSpan>()];

/// Unified file parser classifier matching `extract_symbols` (handles `CMakeLists.txt`,
/// `Makefile`/`GNUmakefile`/`makefile`, `Dockerfile`/`Containerfile`, and all extensions).
/// Returns distinct non-zero tags so `CMakeLists.txt`, `notes.txt`, `Makefile`, and `Dockerfile`
/// never collide in content-addressed body deduplication.
pub(crate) fn file_parser_kind(path: &Path) -> u8 {
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut ext_buf = [0u8; 16];
    let ext = lower_ext(path, &mut ext_buf);
    file_parser_kind_from_parts(fname, ext)
}

#[inline]
fn file_parser_kind_from_parts(fname: &str, ext: &str) -> u8 {
    if fname == "CMakeLists.txt" || ext == "cmake" {
        1
    } else if matches!(fname, "Makefile" | "GNUmakefile" | "makefile") || ext == "mk" {
        2
    } else if matches!(fname, "Dockerfile" | "Containerfile")
        || fname.starts_with("Dockerfile.")
        || fname.starts_with("Containerfile.")
        || ext == "dockerfile"
    {
        3
    } else {
        match ext {
            "h" | "hpp" | "ipp" | "hh" | "hxx" | "c" | "cc" | "cpp" | "cxx" | "inl" | "tpp"
            | "cu" | "cuh" | "ixx" | "cppm" => 4,
            "py" | "pyi" => 5,
            "java" => 6,
            "cs" => 7,
            "rs" => 8,
            "ts" | "tsx" => 9,
            "js" | "jsx" | "mjs" | "cjs" => 10,
            "go" => 11,
            "kt" | "kts" => 12,
            "swift" => 13,
            "zig" => 14,
            "proto" => 15,
            "sh" | "bash" | "zsh" => 16,
            "sql" => 17,
            "md" | "mdx" | "markdown" => 18,
            "toml" => 19,
            "json" | "jsonc" => 20,
            "yml" | "yaml" => 21,
            _ => 22,
        }
    }
}

/// Returns `true` strictly for code source extensions (excludes `.md`/`.json`/`.toml`/`.yaml`/
/// `.cmake`/`Makefile`/`Dockerfile`/unknown).
pub fn is_code_source_ext(path: &Path) -> bool {
    matches!(file_parser_kind(path), 4..=17)
}

/// Matches `clean::classify_ext` (plus Go backtick escaping distinction) for dedup key safety.
pub(crate) fn clean_lang_tag(path: &Path) -> u8 {
    let mut ext_buf = [0u8; 16];
    let ext = lower_ext(path, &mut ext_buf);
    match ext {
        "rs" => 1,
        "py" | "pyi" => 2,
        "go" => 3,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => 4,
        _ => 0,
    }
}

pub fn extract_symbols(path: &Path, text: &str, line_offsets: &[u32]) -> Box<[SymbolSpan]> {
    if text.is_empty() || line_offsets.is_empty() {
        return Box::new([]);
    }
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut ext_buf = [0u8; 16];
    let ext = lower_ext(path, &mut ext_buf);

    let vec = match file_parser_kind_from_parts(fname, ext) {
        1 => structured::parse_cmake(text, line_offsets),
        2 => infra::parse_makefile(text, line_offsets),
        3 => infra::parse_dockerfile(text, line_offsets),
        4 => cpp::parse_cpp(text, line_offsets),
        5 => langs::parse_python(text, line_offsets),
        6 => langs::parse_java_cs(text, line_offsets, false),
        7 => langs::parse_java_cs(text, line_offsets, true),
        8..=15 => langs::parse_brace_lang(text, line_offsets, ext),
        16 => langs::parse_shell(text, line_offsets),
        17 => structured::parse_sql(text, line_offsets),
        18 => structured::parse_markdown(text, line_offsets),
        19 => structured::parse_toml(text, line_offsets),
        20 => structured::parse_json(text, line_offsets),
        21 => structured::parse_yaml(text, line_offsets),
        _ => Vec::new(),
    };
    vec.into_boxed_slice()
}

fn lower_ext<'a>(path: &Path, buf: &'a mut [u8; 16]) -> &'a str {
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

fn compact_ws(s: &str, max_len: usize) -> Box<str> {
    let trimmed = s.trim();
    let mut out = String::with_capacity(trimmed.len().min(max_len + 3));
    let mut prev_ws = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
        if out.len() >= max_len {
            out.push_str("...");
            break;
        }
    }
    out.into_boxed_str()
}

#[inline]
pub fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::scan_source_bytes;

    #[test]
    fn extracts_symbols_across_multi_language_and_config_formats() {
        let java = "package demo;\npublic class OrderBook {\n  public final int bestBid(int px) {\n    return px;\n  }\n}\n";
        let js = scan_source_bytes(java.as_bytes().to_vec()).unwrap();
        let jsyms = extract_symbols(Path::new("OrderBook.java"), &js.text, &js.line_offsets);
        assert!(jsyms.iter().any(|s| s.kind == SymbolKind::Class && &*s.name == "OrderBook"));
        assert!(jsyms.iter().any(|s| s.kind == SymbolKind::Fn && &*s.name == "bestBid"));

        let cs = "namespace Demo.Core {\n  public sealed record Tick(long Px);\n  public class Engine {\n    public async Task RunAsync() {\n      return;\n    }\n  }\n}\n";
        let css = scan_source_bytes(cs.as_bytes().to_vec()).unwrap();
        let cssyms = extract_symbols(Path::new("Engine.cs"), &css.text, &css.line_offsets);
        assert!(cssyms.iter().any(|s| s.kind == SymbolKind::Namespace && &*s.name == "Demo.Core"));
        assert!(cssyms.iter().any(|s| s.kind == SymbolKind::Record && &*s.name == "Tick"));
        assert!(cssyms.iter().any(|s| s.kind == SymbolKind::Class && &*s.name == "Engine"));
        assert!(cssyms.iter().any(|s| s.kind == SymbolKind::Fn && &*s.name == "RunAsync"));

        let rs = "pub async fn serve() {}\nimpl<T> Cache<T> {\n  pub(crate) fn get(&self) {}\n}\n";
        let rss = scan_source_bytes(rs.as_bytes().to_vec()).unwrap();
        let rssyms = extract_symbols(Path::new("cache.rs"), &rss.text, &rss.line_offsets);
        assert!(rssyms.iter().any(|s| s.kind == SymbolKind::Fn && &*s.name == "serve"));
        assert!(rssyms.iter().any(|s| s.kind == SymbolKind::Impl && &*s.name == "Cache"));
        assert!(rssyms.iter().any(|s| s.kind == SymbolKind::Fn && &*s.name == "get"));

        let json_doc = "{\n  \"mcpServers\": {\n    \"agent_ctx\": {}\n  },\n  \"version\": 2\n}\n";
        let jns = scan_source_bytes(json_doc.as_bytes().to_vec()).unwrap();
        let jnsyms = extract_symbols(Path::new("mcp.json"), &jns.text, &jns.line_offsets);
        assert!(jnsyms.iter().any(|s| s.kind == SymbolKind::Key && &*s.name == "mcpServers" && s.start_line == 2 && s.end_line == 4));
        assert!(jnsyms.iter().any(|s| s.kind == SymbolKind::Key && &*s.name == "version" && s.start_line == 5));

        let yaml_doc = "name: CI\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest\n";
        let yms = scan_source_bytes(yaml_doc.as_bytes().to_vec()).unwrap();
        let ymsyms = extract_symbols(Path::new("ci.yml"), &yms.text, &yms.line_offsets);
        assert!(ymsyms.iter().any(|s| s.kind == SymbolKind::Key && &*s.name == "jobs" && s.start_line == 4 && s.end_line == 6));

        assert_eq!(SymbolKind::from_tag(28), Some(SymbolKind::H4));
        assert_eq!(SymbolKind::H4.as_str(), "h4");

        let mk = scan_source_bytes(b"build:\n\t@echo ok\n".to_vec()).unwrap();
        assert!(extract_symbols(Path::new("Makefile"), &mk.text, &mk.line_offsets)
            .iter()
            .any(|s| s.kind == SymbolKind::Sym && &*s.name == "build"));
        let df = scan_source_bytes(b"FROM rust:1.80 AS builder\nRUN true\n".to_vec()).unwrap();
        assert!(extract_symbols(Path::new("Dockerfile.prod"), &df.text, &df.line_offsets)
            .iter()
            .any(|s| s.kind == SymbolKind::Mod && &*s.name == "builder"));

        // Unified file_parser_kind & is_code_source_ext checks
        assert_ne!(
            file_parser_kind(Path::new("CMakeLists.txt")),
            file_parser_kind(Path::new("notes.txt"))
        );
        assert_ne!(
            file_parser_kind(Path::new("Makefile")),
            file_parser_kind(Path::new("Dockerfile"))
        );
        assert_ne!(file_parser_kind(Path::new("notes.txt")), 0);
        assert!(is_code_source_ext(Path::new("src/main.rs")));
        assert!(is_code_source_ext(Path::new("OrderBook.hpp")));
        assert!(is_code_source_ext(Path::new("query.sql")));
        assert!(!is_code_source_ext(Path::new("README.md")));
        assert!(!is_code_source_ext(Path::new("config.json")));
        assert!(!is_code_source_ext(Path::new("CMakeLists.txt")));
        assert!(!is_code_source_ext(Path::new("Makefile")));
        assert!(!is_code_source_ext(Path::new("Dockerfile")));
        assert!(!is_code_source_ext(Path::new("notes.txt")));
    }
}
