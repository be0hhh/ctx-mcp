use super::*;

#[test]
fn stack_integer_formatters_cover_extremes() {
    for n in [0i64, 1, -1, 42, -999_999, i64::MAX, i64::MIN] {
        let mut s = String::new();
        push_i64(&mut s, n);
        assert_eq!(s, n.to_string());
    }
}

#[test]
fn simd_scanner_matches_str_lines_and_catches_nul() {
    let sample = (0..150)
        .map(|i| format!("constexpr int line_{i} = {}; // comment", i * 3))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n";
    let scanned = scan_source_bytes(sample.clone().into_bytes()).unwrap();
    let expected: Vec<&str> = sample.lines().collect();
    assert_eq!(scanned.line_count as usize, expected.len());
    for (idx, &exp) in expected.iter().enumerate() {
        assert_eq!(line_slice_at(&scanned.text, &scanned.line_offsets, (idx + 1) as u32), exp);
    }

    let mut binary = vec![b'a'; 4096];
    binary[2047] = 0;
    assert_eq!(scan_source_bytes(binary).err(), Some(ScanError::Binary));
}

#[test]
fn trigram_bloom_and_simd_search_preserve_exact_semantics() {
    let path_bloom = trigram_bloom64_ascii_lower(b"src/src/Runtime/Hot/Position/PositionTable.hpp");
    let q_bloom = trigram_bloom64_ascii_lower(b"positiontable.hpp");
    assert_eq!(path_bloom & q_bloom, q_bloom);

    let body = "// header padding........................................\n\
                void alpha() { applyFillHot(1); applyFillHot(2); }\n\
                void beta() { APPLYFILLHOT(3); }\n\
                void gamma() { other_call(); }\n";
    let scanned = scan_source_bytes(body.as_bytes().to_vec()).unwrap();
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
}
