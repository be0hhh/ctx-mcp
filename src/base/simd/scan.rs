//! Single-pass 2-phase AVX2+BMI1 source file scanner (NUL binary check,
//! ASCII fast-UTF8 validation, line-offset indexing) and hoisted AVX2+BMI1 JSON escaper.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    Binary,
    NonUtf8,
}

pub struct ScannedText {
    pub text: String,
    pub line_offsets: Box<[u32]>,
    pub line_count: u32,
}

pub fn scan_source_bytes(raw: Vec<u8>) -> Result<ScannedText, ScanError> {
    if raw.is_empty() {
        return Ok(ScannedText {
            text: String::new(),
            line_offsets: Box::from([0u32]),
            line_count: 0,
        });
    }

    let mut offsets = Vec::with_capacity((raw.len() >> 5).max(16));
    offsets.push(0u32);

    let is_ascii = scan_newlines_and_binary(&raw, &mut offsets)?;
    let text = if is_ascii {
        // SAFETY: Every byte in `raw` was verified `< 0x80` (pure 7-bit ASCII).
        unsafe { String::from_utf8_unchecked(raw) }
    } else {
        String::from_utf8(raw).map_err(|_| ScanError::NonUtf8)?
    };

    let line_count = offsets.len() as u32;
    Ok(ScannedText {
        text,
        line_offsets: offsets.into_boxed_slice(),
        line_count,
    })
}

#[inline]
pub fn line_slice_at<'a>(text: &'a str, line_offsets: &[u32], line_1based: u32) -> &'a str {
    if line_1based == 0 {
        return "";
    }
    let idx = (line_1based - 1) as usize;
    if idx >= line_offsets.len() {
        return "";
    }
    let bytes = text.as_bytes();
    let start = line_offsets[idx] as usize;
    let mut end = line_offsets
        .get(idx + 1)
        .map_or(bytes.len(), |&next| (next as usize).saturating_sub(1));
    if end > start && bytes[end - 1] == b'\n' {
        end -= 1;
    }
    if end > start && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    &text[start..end]
}

fn scan_newlines_and_binary(raw: &[u8], offsets: &mut Vec<u32>) -> Result<bool, ScanError> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi1")
        {
            // SAFETY: Guarded by runtime `avx2` + `bmi1` feature detection.
            return unsafe { scan_newlines_and_binary_avx2(raw, offsets) };
        }
    }
    scan_newlines_and_binary_scalar(raw, offsets)
}

fn scan_newlines_and_binary_scalar(raw: &[u8], offsets: &mut Vec<u32>) -> Result<bool, ScanError> {
    let len = raw.len();
    let nul_limit = len.min(8192);
    if raw[..nul_limit].contains(&0) {
        return Err(ScanError::Binary);
    }
    let mut non_ascii = 0u8;
    for (i, &b) in raw.iter().enumerate() {
        non_ascii |= b & 0x80;
        if b == b'\n' && i + 1 < len {
            offsets.push((i + 1) as u32);
        }
    }
    Ok(non_ascii == 0)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cold]
#[inline(never)]
fn grow_offsets_cold(offsets: &mut Vec<u32>) {
    offsets.reserve(offsets.len().max(64));
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
#[inline]
unsafe fn flush_nl_mask(offsets: &mut Vec<u32>, base_i: usize, mut nl_mask: u32) {
    let old_len = offsets.len();
    if offsets.capacity() - old_len < 32 {
        grow_offsets_cold(offsets);
    }
    let mut dst = offsets.as_mut_ptr().add(old_len);
    let base_next = (base_i + 1) as u32;
    let mut written = 0usize;
    while nl_mask != 0 {
        let bit = nl_mask.trailing_zeros();
        dst.write(base_next + bit);
        dst = dst.add(1);
        written += 1;
        nl_mask &= nl_mask - 1;
    }
    offsets.set_len(old_len + written);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
unsafe fn scan_newlines_and_binary_avx2(
    raw: &[u8],
    offsets: &mut Vec<u32>,
) -> Result<bool, ScanError> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let len = raw.len();
    let ptr = raw.as_ptr();
    let v_zero = _mm256_setzero_si256();
    let v_nl = _mm256_set1_epi8(b'\n' as i8);
    let mut v_ascii_or = _mm256_setzero_si256();

    let phase1_end = len.min(8192) & !31usize;
    let vec_end = len & !31usize;
    let mut i = 0usize;

    // Phase 1: check NUL bytes in the first 8192 bytes, accumulate ASCII high bits, index newlines.
    while i < phase1_end {
        let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        if _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_zero)) != 0 {
            return Err(ScanError::Binary);
        }
        v_ascii_or = _mm256_or_si256(v_ascii_or, chunk);
        let mut nl_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_nl)) as u32;
        if nl_mask != 0 {
            if i + 32 == len {
                nl_mask &= !(1u32 << 31);
            }
            if nl_mask != 0 {
                flush_nl_mask(offsets, i, nl_mask);
            }
        }
        i += 32;
    }

    // Phase 2: past byte 8192 — zero NUL checks and zero `< 8192` branches.
    while i < vec_end {
        let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        v_ascii_or = _mm256_or_si256(v_ascii_or, chunk);
        let mut nl_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_nl)) as u32;
        if nl_mask != 0 {
            if i + 32 == len {
                nl_mask &= !(1u32 << 31);
            }
            if nl_mask != 0 {
                flush_nl_mask(offsets, i, nl_mask);
            }
        }
        i += 32;
    }

    let mut non_ascii_tail = 0u8;
    while i < len {
        let b = *ptr.add(i);
        if i < 8192 && b == 0 {
            return Err(ScanError::Binary);
        }
        non_ascii_tail |= b & 0x80;
        if b == b'\n' && i + 1 < len {
            offsets.push((i + 1) as u32);
        }
        i += 1;
    }

    Ok(_mm256_movemask_epi8(v_ascii_or) == 0 && non_ascii_tail == 0)
}

// --- AVX2+BMI1 JSON Escape Span Finder & Hoisted String Escaper ---

/// Finds the next byte index in `bytes[start..]` that requires JSON string escaping
/// (`b'"'`, `b'\\'`, or `< 0x20`). Returns `bytes.len()` when the remainder is clean.
#[inline]
pub fn next_json_escape_pos(bytes: &[u8], start: usize) -> usize {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if bytes.len().saturating_sub(start) >= 32
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi1")
        {
            // SAFETY: Guarded by runtime `avx2` + `bmi1` detection and bounds check.
            return unsafe { next_json_escape_pos_avx2(bytes, start) };
        }
    }
    next_json_escape_pos_scalar(bytes, start)
}

#[inline]
fn next_json_escape_pos_scalar(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == b'"' || b == b'\\' {
            return i;
        }
        i += 1;
    }
    bytes.len()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
unsafe fn next_json_escape_pos_avx2(bytes: &[u8], mut i: usize) -> usize {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let len = bytes.len();
    let ptr = bytes.as_ptr();
    let v_quote = _mm256_set1_epi8(b'"' as i8);
    let v_bslash = _mm256_set1_epi8(b'\\' as i8);
    let v_ctrl_mask = _mm256_set1_epi8(0x1f);
    let v_zero = _mm256_setzero_si256();

    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        // Unsigned `< 0x20` <=> `(b & ~0x1f) == 0`.
        let is_ctrl = _mm256_cmpeq_epi8(_mm256_andnot_si256(v_ctrl_mask, chunk), v_zero);
        let is_quote = _mm256_cmpeq_epi8(chunk, v_quote);
        let is_bslash = _mm256_cmpeq_epi8(chunk, v_bslash);
        let combined = _mm256_or_si256(is_ctrl, _mm256_or_si256(is_quote, is_bslash));
        let mask = _mm256_movemask_epi8(combined) as u32;
        if mask != 0 {
            return i + mask.trailing_zeros() as usize;
        }
        i += 32;
    }
    next_json_escape_pos_scalar(bytes, i)
}

#[inline(always)]
fn push_escaped_byte(b: u8, out: &mut String) {
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cold]
#[inline(never)]
fn grow_escape_buf_cold(
    buf: &mut Vec<u8>,
    orig_len: usize,
    written_len: usize,
    extra: usize,
) -> (*mut u8, usize) {
    // SAFETY: `written_len <= buf.capacity()` and bytes `[..written_len]` are initialized.
    // On allocation failure we restore `orig_len` (guaranteed valid UTF-8) before panicking.
    unsafe { buf.set_len(written_len) };
    if buf.try_reserve(extra).is_err() {
        unsafe { buf.set_len(orig_len) };
        panic!("json escape buffer allocation failed");
    }
    (buf.as_mut_ptr(), buf.capacity())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn write_escaped_byte_unchecked(b: u8, dst: *mut u8) -> usize {
    match b {
        b'"' => {
            *dst = b'\\';
            *dst.add(1) = b'"';
            2
        }
        b'\\' => {
            *dst = b'\\';
            *dst.add(1) = b'\\';
            2
        }
        b'\n' => {
            *dst = b'\\';
            *dst.add(1) = b'n';
            2
        }
        b'\r' => {
            *dst = b'\\';
            *dst.add(1) = b'r';
            2
        }
        b'\t' => {
            *dst = b'\\';
            *dst.add(1) = b't';
            2
        }
        0x08 => {
            *dst = b'\\';
            *dst.add(1) = b'b';
            2
        }
        0x0C => {
            *dst = b'\\';
            *dst.add(1) = b'f';
            2
        }
        ctrl => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            *dst = b'\\';
            *dst.add(1) = b'u';
            *dst.add(2) = b'0';
            *dst.add(3) = b'0';
            *dst.add(4) = HEX[((ctrl >> 4) & 0x0f) as usize];
            *dst.add(5) = HEX[(ctrl & 0x0f) as usize];
            6
        }
    }
}

/// Appends `s` as a quoted, RFC 8259 JSON-escaped string into `out`.
/// Uses a single-pass streaming AVX2+BMI1 load-check-store loop when `s.len() >= 32`.
#[inline]
pub fn escape_json_str(s: &str, out: &mut String) {
    out.reserve(s.len().saturating_add(s.len() >> 4).saturating_add(64));
    out.push('"');
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if s.len() >= 32
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi1")
        {
            // SAFETY: Guarded by runtime `avx2` + `bmi1` feature detection.
            unsafe { escape_json_body_avx2(s, out) };
            out.push('"');
            return;
        }
    }
    escape_json_body_scalar(s, out);
    out.push('"');
}

#[inline]
fn escape_json_body_scalar(s: &str, out: &mut String) {
    let bytes = s.as_bytes();
    let mut clean_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x20 || b == b'"' || b == b'\\' {
            if i > clean_start {
                out.push_str(&s[clean_start..i]);
            }
            push_escaped_byte(b, out);
            clean_start = i + 1;
        }
        i += 1;
    }
    if clean_start < bytes.len() {
        out.push_str(&s[clean_start..]);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
unsafe fn escape_json_body_avx2(s: &str, out: &mut String) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let bytes = s.as_bytes();
    let len = bytes.len();
    let src = bytes.as_ptr();

    let v_quote = _mm256_set1_epi8(b'"' as i8);
    let v_bslash = _mm256_set1_epi8(b'\\' as i8);
    let v_ctrl_mask = _mm256_set1_epi8(0x1f);
    let v_zero = _mm256_setzero_si256();

    let buf = out.as_mut_vec();
    let orig_len = buf.len();
    let mut out_ptr = buf.as_mut_ptr();
    let mut out_cap = buf.capacity();
    let mut out_len = orig_len;
    let mut i = 0usize;

    // Single-pass streaming AVX2 loop: load 32B, classify escapes, store 32B directly into
    // `out`'s spare capacity (zero `memcpy`, zero `vzeroupper` inside the hot loop).
    while i + 32 <= len {
        if out_cap - out_len < 38 {
            let (p, c) = grow_escape_buf_cold(
                buf,
                orig_len,
                out_len,
                (len - i).saturating_add(64),
            );
            out_ptr = p;
            out_cap = c;
        }
        let chunk = _mm256_loadu_si256(src.add(i) as *const __m256i);
        let is_ctrl = _mm256_cmpeq_epi8(_mm256_andnot_si256(v_ctrl_mask, chunk), v_zero);
        let is_quote = _mm256_cmpeq_epi8(chunk, v_quote);
        let is_bslash = _mm256_cmpeq_epi8(chunk, v_bslash);
        let combined = _mm256_or_si256(is_ctrl, _mm256_or_si256(is_quote, is_bslash));
        let mask = _mm256_movemask_epi8(combined) as u32;
        _mm256_storeu_si256(out_ptr.add(out_len) as *mut __m256i, chunk);
        if mask == 0 {
            out_len += 32;
            i += 32;
        } else {
            let k = mask.trailing_zeros() as usize;
            out_len += k;
            let esc_pos = i + k;
            // `out_cap - out_len >= 38 - 31 = 7 >= 6` (fits even `\u00XX`).
            out_len += write_escaped_byte_unchecked(*src.add(esc_pos), out_ptr.add(out_len));
            i = esc_pos + 1;
        }
    }

    let rem = len - i;
    if rem > 0 {
        let needed = rem * 6 + 1;
        if out_cap - out_len < needed {
            let (p, c) = grow_escape_buf_cold(buf, orig_len, out_len, needed);
            out_ptr = p;
            out_cap = c;
        }
        let _ = out_cap;
        while i < len {
            let b = *src.add(i);
            if b < 0x20 || b == b'"' || b == b'\\' {
                out_len += write_escaped_byte_unchecked(b, out_ptr.add(out_len));
            } else {
                *out_ptr.add(out_len) = b;
                out_len += 1;
            }
            i += 1;
        }
    }

    // SAFETY: Every unescaped span comes verbatim from valid UTF-8 `s` split only on ASCII
    // bytes (`< 0x80`), and every escape sequence is pure ASCII.
    buf.set_len(out_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_scan_parity(raw: &[u8]) {
        let mut off_scalar = vec![0u32];
        let res_scalar = scan_newlines_and_binary_scalar(raw, &mut off_scalar);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi1")
        {
            let mut off_avx2 = vec![0u32];
            let res_avx2 = unsafe { scan_newlines_and_binary_avx2(raw, &mut off_avx2) };
            assert_eq!(res_avx2, res_scalar, "ascii/err mismatch for len={}", raw.len());
            if res_scalar.is_ok() {
                assert_eq!(off_avx2, off_scalar, "offsets mismatch for len={}", raw.len());
            }
        }
    }

    #[test]
    fn scan_trailing_newlines_and_boundaries() {
        let empty = scan_source_bytes(Vec::new()).unwrap();
        assert_eq!(empty.line_count, 0);
        assert_eq!(&*empty.line_offsets, &[0]);

        for &len in &[1usize, 31, 32, 64, 8192, 8224] {
            let mut buf = vec![b'a'; len];
            buf[len - 1] = b'\n';
            assert_scan_parity(&buf);
            let scanned = scan_source_bytes(buf).unwrap();
            assert_eq!(scanned.line_count, 1, "trailing \\n must not add empty line for len={len}");
            assert_eq!(&*scanned.line_offsets, &[0]);
            assert_eq!(line_slice_at(&scanned.text, &scanned.line_offsets, 1).len(), len - 1);
        }
    }

    #[test]
    fn scan_nul_window_8192() {
        for &nul_pos in &[0usize, 31, 32, 8191] {
            let mut buf = vec![b'x'; 8256];
            buf[nul_pos] = 0;
            assert_scan_parity(&buf);
            assert_eq!(scan_source_bytes(buf).err(), Some(ScanError::Binary));
        }

        // NUL at 8192 is outside the 8 KiB probe window and valid UTF-8.
        let mut buf = vec![b'x'; 8256];
        buf[8192] = 0;
        assert_scan_parity(&buf);
        let scanned = scan_source_bytes(buf).unwrap();
        assert_eq!(scanned.line_count, 1);
    }

    #[test]
    fn scan_many_consecutive_newlines_and_non_ascii() {
        // >32 consecutive newlines forces cold Vec growth inside AVX2 loop.
        let nl_buf = vec![b'\n'; 128];
        assert_scan_parity(&nl_buf);
        let scanned = scan_source_bytes(nl_buf).unwrap();
        assert_eq!(scanned.line_count, 128);
        assert_eq!(*scanned.line_offsets.last().unwrap(), 127);

        // Non-ASCII valid UTF-8 in Phase 1, Phase 2, and scalar tail.
        for &pos in &[5usize, 8200, 8230] {
            let mut buf = vec![b'a'; 8235];
            buf[pos] = 0xD0;
            buf[pos + 1] = 0x90; // 'А'
            assert_scan_parity(&buf);
            let scanned = scan_source_bytes(buf).unwrap();
            assert!(scanned.text.contains('А'));
        }

        // Invalid UTF-8 in Phase 2 returns NonUtf8.
        let mut bad = vec![b'a'; 8235];
        bad[8200] = 0xFF;
        assert_eq!(scan_source_bytes(bad).err(), Some(ScanError::NonUtf8));
    }

    #[test]
    fn escape_json_str_matches_scalar_on_multiline_and_controls() {
        let mut sample = String::new();
        sample.push_str("clean prefix longer than thirty two bytes for avx2 fast skip\n");
        sample.push_str("line with \"quotes\" and \\backslashes\\\r\n\t");
        sample.push('\u{0000}');
        sample.push('\u{0008}');
        sample.push('\u{000C}');
        sample.push('\u{001F}');
        sample.push_str("привет мир tail\"\\");

        let mut got = String::new();
        escape_json_str(&sample, &mut got);

        let mut expected = String::from("\"");
        escape_json_body_scalar(&sample, &mut expected);
        expected.push('"');

        assert_eq!(got, expected);
        assert!(got.contains("\\u0000"));
        assert!(got.contains("\\b"));
        assert!(got.contains("\\f"));
        assert!(got.contains("\\u001f"));

        // Stress cold buffer growth (6x expansion) and UTF-8 codepoints straddling 32B boundaries.
        let mut dense = String::new();
        for _ in 0..80 {
            dense.push('\u{0001}');
        }
        dense.push_str(&"a".repeat(31));
        dense.push('🚀'); // 4-byte UTF-8 straddling byte 31..35
        dense.push_str(&"b".repeat(31));
        dense.push('\n');
        dense.push_str("tail_\"\\_\u{001e}");

        let mut got_dense = String::new();
        escape_json_str(&dense, &mut got_dense);
        let mut exp_dense = String::from("\"");
        escape_json_body_scalar(&dense, &mut exp_dense);
        exp_dense.push('"');
        assert_eq!(got_dense, exp_dense);
    }
}
