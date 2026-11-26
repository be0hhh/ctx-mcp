//! Public-API integration tests for the `ctx` library crate.

use ctx::base::json::{self, Json};
use ctx::base::simd::{
    decimal_digits, fast_hash64, line_slice_at, push_i64, scan_source_bytes,
    search_lines_literals, trigram_bloom64_ascii_lower, ScanError,
};
use ctx::engine::op_elf_audit;
use ctx::parser::{extract_symbols, SymbolKind};
use ctx::rpc::BrokerService;
use ctx::store::{now_ms, RamStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ctx-it-{prefix}-{}-{}-{id}",
        std::process::id(),
        now_ms()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn simd_search_scan_hash_bloom_and_integer_formatting() {
    for n in [0i64, 1, -1, 42, -999_999, i64::MAX, i64::MIN] {
        let mut s = String::new();
        push_i64(&mut s, n);
        assert_eq!(s, n.to_string());
    }
    assert_eq!(decimal_digits(0), 1);
    assert_eq!(decimal_digits(9), 1);
    assert_eq!(decimal_digits(10), 2);
    assert_eq!(decimal_digits(999), 3);
    assert_eq!(decimal_digits(1_000), 4);
    assert_eq!(decimal_digits(usize::MAX), usize::MAX.to_string().len());

    assert_eq!(fast_hash64(b"OrderTable.hpp"), fast_hash64(b"OrderTable.hpp"));
    assert_ne!(fast_hash64(b"OrderTable.hpp"), fast_hash64(b"OrderTable.cpp"));

    let path_bloom = trigram_bloom64_ascii_lower(b"src/src/Runtime/Hot/Position/PositionTable.hpp");
    let query_bloom = trigram_bloom64_ascii_lower(b"positiontable.hpp");
    assert_eq!(path_bloom & query_bloom, query_bloom);

    let sample = "// header padding........................................\r\n\
                  void alpha() { applyFillHot(1); applyFillHot(2); }\r\n\
                  void beta() { APPLYFILLHOT(3); }\r\n\
                  void gamma() { other_call(); }\r\n";
    let scanned = scan_source_bytes(sample.as_bytes().to_vec()).unwrap();
    assert_eq!(scanned.line_count, 4);
    assert_eq!(
        line_slice_at(&scanned.text, &scanned.line_offsets, 2),
        "void alpha() { applyFillHot(1); applyFillHot(2); }"
    );
    assert_eq!(
        search_lines_literals(&scanned.text, &scanned.line_offsets, &["applyFillHot"], true, 10),
        vec![2]
    );
    assert_eq!(
        search_lines_literals(&scanned.text, &scanned.line_offsets, &["applyfillhot"], false, 10),
        vec![2, 3]
    );
    assert_eq!(
        search_lines_literals(
            &scanned.text,
            &scanned.line_offsets,
            &["applyFillHot", "other_call"],
            true,
            10
        ),
        vec![2, 4]
    );

    let mut binary = vec![b'a'; 4096];
    binary[1024] = 0;
    assert_eq!(scan_source_bytes(binary).err(), Some(ScanError::Binary));
}

#[test]
fn json_round_trip_control_rejection_and_exact_number_tokens() {
    let raw = r#"{"text":"line1\n\"quoted\"\\path\t\u0001","i":-42,"dec":0.1234567890123456789,"big":99999999999999999999999,"ok":true,"nil":null}"#;
    let doc = json::parse(raw).unwrap();
    assert_eq!(doc.get_i64("i"), Some(-42));
    assert_eq!(
        doc.get("dec"),
        Some(&Json::NumberToken("0.1234567890123456789".into()))
    );
    assert_eq!(
        doc.get("big"),
        Some(&Json::NumberToken("99999999999999999999999".into()))
    );

    let encoded = doc.to_json_string();
    assert!(encoded.contains("0.1234567890123456789"));
    assert!(encoded.contains("99999999999999999999999"));
    assert_eq!(json::parse(&encoded).unwrap(), doc);

    let pretty = json::format_pretty_json(&doc, 0);
    assert_eq!(json::parse(&pretty).unwrap(), doc);

    assert!(json::parse("\"unescaped\nnewline\"").is_err());
    assert!(json::parse("\"unescaped\x00nul\"").is_err());
    assert!(json::parse("\"unescaped\x1fctrl\"").is_err());
}

#[test]
fn parser_extracts_symbols_across_supported_languages_and_configs() {
    let check = |file: &str, src: &str, expected: &[(SymbolKind, &str)]| {
        let scanned = scan_source_bytes(src.as_bytes().to_vec()).unwrap();
        let syms = extract_symbols(Path::new(file), &scanned.text, &scanned.line_offsets);
        for &(kind, name) in expected {
            assert!(
                syms.iter().any(|s| s.kind == kind && &*s.name == name),
                "missing ({kind:?}, {name}) in {file}; got: {syms:?}"
            );
        }
    };

    check(
        "engine.cpp",
        "namespace demo {\nstruct Engine {\n  int run(int x) {\n    return x;\n  }\n};\n}\n",
        &[
            (SymbolKind::Namespace, "demo"),
            (SymbolKind::Struct, "Engine"),
            (SymbolKind::Fn, "run"),
        ],
    );
    check(
        "quote.hpp",
        "#pragma once\nnamespace engine {\nusing Px = long;\nstruct Quote {\n  int bid() const { return 1; }\n};\n}\n",
        &[
            (SymbolKind::Namespace, "engine"),
            (SymbolKind::Using, "Px"),
            (SymbolKind::Struct, "Quote"),
            (SymbolKind::Fn, "bid"),
        ],
    );
    check(
        "math.ipp",
        "template <typename T>\ninline T add_val(T a, T b) {\n  return a + b;\n}\n",
        &[(SymbolKind::Fn, "add_val")],
    );
    check(
        "native.h",
        "struct CHdr {\n  int v;\n};\nstatic inline int hdr_get(int x) {\n  return x;\n}\n",
        &[(SymbolKind::Struct, "CHdr"), (SymbolKind::Fn, "hdr_get")],
    );
    check(
        "kernel.c",
        "struct CRec {\n  int a;\n};\nint c_compute(int x) {\n  return x + 1;\n}\n",
        &[(SymbolKind::Struct, "CRec"), (SymbolKind::Fn, "c_compute")],
    );
    check(
        "cache.rs",
        "pub struct Cache {}\nimpl Cache {\n  pub fn get(&self) -> usize { 0 }\n}\n",
        &[
            (SymbolKind::Struct, "Cache"),
            (SymbolKind::Impl, "Cache"),
            (SymbolKind::Fn, "get"),
        ],
    );
    check(
        "worker.py",
        "class Worker:\n    def run(self):\n        return 1\n    async def poll(self):\n        return 2\n",
        &[
            (SymbolKind::Class, "Worker"),
            (SymbolKind::Def, "run"),
            (SymbolKind::AsyncDef, "poll"),
        ],
    );
    check(
        "OrderBook.java",
        "package demo;\npublic class OrderBook {\n  public final int bestBid(int px) {\n    return px;\n  }\n}\n",
        &[
            (SymbolKind::Class, "OrderBook"),
            (SymbolKind::Fn, "bestBid"),
        ],
    );
    check(
        "Engine.cs",
        "namespace Demo.Core {\n  public sealed record Tick(long Px);\n  public class Engine {\n    public async Task RunAsync() {\n      return;\n    }\n  }\n}\n",
        &[
            (SymbolKind::Namespace, "Demo.Core"),
            (SymbolKind::Record, "Tick"),
            (SymbolKind::Class, "Engine"),
            (SymbolKind::Fn, "RunAsync"),
        ],
    );
    check(
        "README.md",
        "# Title\nbody\n## Section\nbody\n### Detail\nbody\n",
        &[
            (SymbolKind::H1, "Title"),
            (SymbolKind::H2, "Section"),
            (SymbolKind::H3, "Detail"),
        ],
    );
    check(
        "mcp.json",
        "{\n  \"mcpServers\": {\n    \"agent_ctx\": {}\n  },\n  \"version\": 2\n}\n",
        &[(SymbolKind::Key, "mcpServers"), (SymbolKind::Key, "version")],
    );
    check(
        "ci.yml",
        "name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        &[(SymbolKind::Key, "name"), (SymbolKind::Key, "jobs")],
    );
    check(
        "Cargo.toml",
        "[package]\nname = \"ctx\"\n[profile.release]\nlto = true\n",
        &[
            (SymbolKind::Table, "package"),
            (SymbolKind::Table, "profile.release"),
        ],
    );
}

#[test]
fn ram_store_find_workspace_dirs_resolves_nested_directory_suffixes() {
    let dir = unique_temp_dir("ws-dirs");
    let binance_dir = dir.join("src").join("src").join("Exchanges").join("Binance");
    let math_dir = dir.join("src").join("src").join("Core").join("Math");
    fs::create_dir_all(&binance_dir).unwrap();
    fs::create_dir_all(&math_dir).unwrap();
    fs::write(binance_dir.join("Bbo.hpp"), "struct Bbo {};\n").unwrap();
    fs::write(math_dir.join("Divisor.hpp"), "struct Divisor {};\n").unwrap();

    let canon_dir = fs::canonicalize(&dir).unwrap();
    let store = RamStore::new(dir.join("snapshot.bin"));

    let found_binance = store.find_workspace_dirs("Exchanges/Binance", &dir, 8);
    assert_eq!(
        found_binance,
        vec![canon_dir
            .join("src")
            .join("src")
            .join("Exchanges")
            .join("Binance")]
    );

    let found_math = store.find_workspace_dirs("Core/Math/**", &dir, 8);
    assert_eq!(
        found_math,
        vec![canon_dir.join("src").join("src").join("Core").join("Math")]
    );
    assert!(store
        .find_workspace_dirs("Exchanges/Unknown", &dir, 8)
        .is_empty());

    fs::remove_dir_all(&dir).unwrap();
}

fn push_shdr64(
    out: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
) {
    out.extend_from_slice(&sh_name.to_le_bytes());
    out.extend_from_slice(&sh_type.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
    out.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
    out.extend_from_slice(&sh_offset.to_le_bytes());
    out.extend_from_slice(&sh_size.to_le_bytes());
    out.extend_from_slice(&sh_link.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // sh_info
    out.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
    out.extend_from_slice(&sh_entsize.to_le_bytes());
}

fn push_sym64(out: &mut Vec<u8>, st_name: u32, st_info: u8, st_shndx: u16) {
    out.extend_from_slice(&st_name.to_le_bytes());
    out.push(st_info);
    out.push(0); // st_other
    out.extend_from_slice(&st_shndx.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // st_value
    out.extend_from_slice(&16u64.to_le_bytes()); // st_size
}

fn build_synthetic_elf64() -> Vec<u8> {
    const EHDR64_SIZE: usize = 64;
    const SHDR64_SIZE: usize = 64;
    const SYM64_SIZE: usize = 24;
    const DYN64_SIZE: usize = 16;
    const SHT_STRTAB: u32 = 3;
    const SHT_DYNAMIC: u32 = 6;
    const SHT_NOBITS: u32 = 8;
    const SHT_DYNSYM: u32 = 11;
    const SHT_INIT_ARRAY: u32 = 14;
    const STB_WEAK: u8 = 2;
    const STT_FUNC: u8 = 2;
    const DT_NULL: i64 = 0;
    const DT_FLAGS_1: i64 = 0x6FFF_FFFB;
    const DF_1_NOW: u64 = 0x1;

    let mut shstrtab = vec![0u8];
    let name_shstrtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let name_text = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let name_rodata = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".rodata\0");
    let name_relro = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".data.rel.ro\0");
    let name_bss = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".bss\0");
    let name_init_array = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".init_array\0");
    let name_dynamic = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".dynamic\0");
    let name_dynstr = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".dynstr\0");
    let name_dynsym = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".dynsym\0");

    let mut dynstr = vec![0u8];
    let sym_tls = dynstr.len() as u32;
    dynstr.extend_from_slice(b"__tls_get_addr@GLIBC_2.3\0");
    let sym_weak = dynstr.len() as u32;
    dynstr.extend_from_slice(b"weak_hot_fn\0");

    let mut dynsym = Vec::new();
    push_sym64(&mut dynsym, 0, 0, 0);
    push_sym64(&mut dynsym, sym_tls, (1 << 4) | STT_FUNC, 0);
    push_sym64(&mut dynsym, sym_weak, (STB_WEAK << 4) | STT_FUNC, 2);

    let mut dynamic = Vec::new();
    dynamic.extend_from_slice(&DT_FLAGS_1.to_le_bytes());
    dynamic.extend_from_slice(&DF_1_NOW.to_le_bytes());
    dynamic.extend_from_slice(&DT_NULL.to_le_bytes());
    dynamic.extend_from_slice(&0u64.to_le_bytes());

    let text_bytes = vec![0x90u8; 64];
    let rodata_bytes = vec![0x01u8; 32];
    let relro_bytes = vec![0x02u8; 16];
    let init_array_bytes = vec![0u8; 16]; // 2 entries

    let mut elf = vec![0u8; EHDR64_SIZE];
    let off_shstrtab = elf.len() as u64;
    elf.extend_from_slice(&shstrtab);
    let off_text = elf.len() as u64;
    elf.extend_from_slice(&text_bytes);
    let off_rodata = elf.len() as u64;
    elf.extend_from_slice(&rodata_bytes);
    let off_relro = elf.len() as u64;
    elf.extend_from_slice(&relro_bytes);
    let off_init_array = elf.len() as u64;
    elf.extend_from_slice(&init_array_bytes);
    let off_dynamic = elf.len() as u64;
    elf.extend_from_slice(&dynamic);
    let off_dynstr = elf.len() as u64;
    elf.extend_from_slice(&dynstr);
    let off_dynsym = elf.len() as u64;
    elf.extend_from_slice(&dynsym);

    let shoff = elf.len() as u64;
    push_shdr64(&mut elf, 0, 0, 0, 0, 0, 0);
    push_shdr64(
        &mut elf,
        name_shstrtab,
        SHT_STRTAB,
        off_shstrtab,
        shstrtab.len() as u64,
        0,
        0,
    );
    push_shdr64(&mut elf, name_text, 1, off_text, text_bytes.len() as u64, 0, 0);
    push_shdr64(
        &mut elf,
        name_rodata,
        1,
        off_rodata,
        rodata_bytes.len() as u64,
        0,
        0,
    );
    push_shdr64(
        &mut elf,
        name_relro,
        1,
        off_relro,
        relro_bytes.len() as u64,
        0,
        0,
    );
    push_shdr64(&mut elf, name_bss, SHT_NOBITS, 0xFFFF_0000, 4096, 0, 0);
    push_shdr64(
        &mut elf,
        name_init_array,
        SHT_INIT_ARRAY,
        off_init_array,
        init_array_bytes.len() as u64,
        0,
        8,
    );
    push_shdr64(
        &mut elf,
        name_dynamic,
        SHT_DYNAMIC,
        off_dynamic,
        dynamic.len() as u64,
        8,
        DYN64_SIZE as u64,
    );
    push_shdr64(
        &mut elf,
        name_dynstr,
        SHT_STRTAB,
        off_dynstr,
        dynstr.len() as u64,
        0,
        0,
    );
    push_shdr64(
        &mut elf,
        name_dynsym,
        SHT_DYNSYM,
        off_dynsym,
        dynsym.len() as u64,
        8,
        SYM64_SIZE as u64,
    );

    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf[40..48].copy_from_slice(&shoff.to_le_bytes());
    elf[58..60].copy_from_slice(&(SHDR64_SIZE as u16).to_le_bytes());
    elf[60..62].copy_from_slice(&10u16.to_le_bytes());
    elf[62..64].copy_from_slice(&1u16.to_le_bytes());
    elf
}

#[test]
fn engine_op_elf_audit_inspects_synthetic_elf64_and_asm() {
    let dir = unique_temp_dir("elf-audit");
    fs::write(dir.join("sample.elf"), build_synthetic_elf64()).unwrap();
    fs::write(
        dir.join("sample.s"),
        "\tvmovdqa64 %zmm0, %zmm31\n\
         \tdivq %rcx\n\
         \tcallq __tls_get_addr@PLT\n\
         \trep stosq\n\
         \tcallq *%rax\n",
    )
    .unwrap();

    let svc = BrokerService::new_ephemeral_inproc(dir.join("snapshot.bin"));
    svc.allowlist.register_hint(&dir, true).unwrap();
    let report = op_elf_audit(&svc, "sample.elf", Some("sample.s"), Some(&dir)).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert!(report.contains("static-only ELF64 audit\n"));
    assert!(report.contains("status: available\n"));
    assert!(report.contains("(e_machine=62)\n"));
    assert!(report.contains("bind_now: true\n"));
    assert!(report.contains("init_array_entries: 2\n"));
    assert!(report.contains("sections: .text=64, .rodata=32, .data.rel.ro=16, .bss=4096\n"));
    assert!(report.contains("- __tls_get_addr (.dynsym)\n"));
    assert!(report.contains("defined STB_WEAK functions: 1\n"));
    assert!(report.contains(
        "asm counts: zmm=2, divq_idivq=1, tls_get_addr=1, rep_stos=1, indirect_callq=1\n"
    ));
}
