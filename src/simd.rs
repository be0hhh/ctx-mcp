//! Zero-dependency SIMD (`AVX2` with runtime detection + portable scalar fallback),
//! 64-byte cache-line padding, fast 64-bit hashing, 64-bit trigram Bloom filtering,
//! and zero-allocation integer formatting for `ctx`.

use std::fmt;
use std::ops::{Deref, DerefMut};

/// Aligns inner state or locks to an isolated 64-byte cache line to prevent false sharing
/// across concurrent daemon worker threads.
#[repr(align(64))]
#[derive(Clone, Copy, Default)]
pub struct CachePadded<T>(pub T);

impl<T> CachePadded<T> {
    #[inline]
    pub const fn new(val: T) -> Self {
        Self(val)
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for CachePadded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// --- Stack Integer Formatting (Fixed Power-of-10 Scale, 0 Heap Allocations) ---

#[inline]
pub fn push_u64(out: &mut String, mut val: u64) {
    if val == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    while val > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    // SAFETY: digits are strictly ASCII '0'..='9'.
    let s = unsafe { std::str::from_utf8_unchecked(&buf[pos..]) };
    out.push_str(s);
}

#[inline]
pub fn push_u32(out: &mut String, val: u32) {
    push_u64(out, val as u64);
}

#[inline]
pub fn push_usize(out: &mut String, val: usize) {
    push_u64(out, val as u64);
}

#[inline]
pub fn push_i64(out: &mut String, val: i64) {
    if val < 0 {
        out.push('-');
    }
    push_u64(out, val.unsigned_abs());
}

// --- Word-Wise 64-Bit Hashing & Trigram Bloom Filter ---

#[inline]
fn mix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[inline]
pub fn fast_hash64(bytes: &[u8]) -> u64 {
    let mut acc = 0x9e3779b97f4a7c15u64 ^ (bytes.len() as u64).wrapping_mul(0x517cc1b727220a95);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        acc = mix64(acc ^ word);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail = 0u64;
        for (i, &b) in rem.iter().enumerate() {
            tail |= (b as u64) << (i << 3);
        }
        acc = mix64(acc ^ tail);
    }
    acc
}

#[inline]
fn ascii_lower_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b | 0x20
    } else if b == b'\\' {
        b'/'
    } else {
        b
    }
}

#[inline]
pub fn fast_hash64_ascii_lower(bytes: &[u8]) -> u64 {
    let mut acc = 0x9e3779b97f4a7c15u64 ^ (bytes.len() as u64).wrapping_mul(0x517cc1b727220a95);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut folded = [0u8; 8];
        for i in 0..8 {
            folded[i] = ascii_lower_byte(chunk[i]);
        }
        acc = mix64(acc ^ u64::from_le_bytes(folded));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail = 0u64;
        for (i, &b) in rem.iter().enumerate() {
            tail |= (ascii_lower_byte(b) as u64) << (i << 3);
        }
        acc = mix64(acc ^ tail);
    }
    acc
}

/// Computes a 64-bit 2-bit-per-trigram Bloom filter on ASCII-lowercased path bytes.
/// Guarantees zero false negatives: if `needle` is a substring of `path`,
/// `(bloom(path) & bloom(needle)) == bloom(needle)` always holds.
#[inline]
pub fn trigram_bloom64_ascii_lower(bytes: &[u8]) -> u64 {
    if bytes.len() < 3 {
        return 0;
    }
    let mut mask = 0u64;
    let mut c0 = ascii_lower_byte(bytes[0]) as u32;
    let mut c1 = ascii_lower_byte(bytes[1]) as u32;
    for &raw in &bytes[2..] {
        let c2 = ascii_lower_byte(raw) as u32;
        let tri = c0 | (c1 << 8) | (c2 << 16);
        let h = tri.wrapping_mul(0x9e3779b1);
        mask |= (1u64 << (h >> 26)) | (1u64 << ((h >> 20) & 63));
        c0 = c1;
        c1 = c2;
    }
    mask
}

// --- Single-Pass Source File Scanner (NUL Binary Check + ASCII Fast-UTF8 + Line Offsets) ---

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
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Guarded by runtime `avx2` feature detection.
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
#[target_feature(enable = "avx2")]
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
    let mut non_ascii_mask = 0i32;
    let mut i = 0usize;

    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        if i < 8192 {
            let zmask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_zero));
            if zmask != 0 {
                let first_zero = i + (zmask as u32).trailing_zeros() as usize;
                if first_zero < 8192 {
                    return Err(ScanError::Binary);
                }
            }
        }
        non_ascii_mask |= _mm256_movemask_epi8(chunk);
        let mut nl_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, v_nl)) as u32;
        while nl_mask != 0 {
            let bit = nl_mask.trailing_zeros() as usize;
            let next_start = i + bit + 1;
            if next_start < len {
                offsets.push(next_start as u32);
            }
            nl_mask &= nl_mask - 1;
        }
        i += 32;
    }

    while i < len {
        let b = *ptr.add(i);
        if i < 8192 && b == 0 {
            return Err(ScanError::Binary);
        }
        if (b & 0x80) != 0 {
            non_ascii_mask |= 1;
        }
        if b == b'\n' && i + 1 < len {
            offsets.push((i + 1) as u32);
        }
        i += 1;
    }

    Ok(non_ascii_mask == 0)
}

// --- AVX2 Fast JSON Escape Span Finder ---

/// Finds the next byte index in `bytes[start..]` that requires JSON string escaping
/// (`b'"'`, `b'\\'`, or `< 0x20`). Returns `bytes.len()` when the remainder is clean.
#[inline]
pub fn next_json_escape_pos(bytes: &[u8], start: usize) -> usize {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if bytes.len().saturating_sub(start) >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Guarded by runtime `avx2` feature detection and bounds check.
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
#[target_feature(enable = "avx2")]
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
        // Unsigned `< 0x20` <=> `(b & ~0x1f) == 0`, i.e. `_mm256_andnot_si256(v_ctrl_mask, chunk) == 0`.
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

// --- AVX2 Substring & Smart-Case Line Matcher ---

/// Searches `text` for 1-based line numbers matching any literal in `needles`,
/// jumping straight to the start of the next line after each match.
pub fn search_lines_literals(
    text: &str,
    line_offsets: &[u32],
    needles: &[&str],
    case_sensitive: bool,
    max_hits: usize,
) -> Vec<u32> {
    if text.is_empty() || line_offsets.is_empty() || needles.is_empty() || max_hits == 0 {
        return Vec::new();
    }
    if needles.len() == 1 {
        let mut out = Vec::with_capacity(max_hits.min(16));
        search_single_literal(text, line_offsets, needles[0], case_sensitive, max_hits, &mut out);
        return out;
    }

    let mut merged = Vec::new();
    for &needle in needles {
        if needle.is_empty() {
            continue;
        }
        search_single_literal(text, line_offsets, needle, case_sensitive, max_hits, &mut merged);
    }
    merged.sort_unstable();
    merged.dedup();
    if merged.len() > max_hits {
        merged.truncate(max_hits);
    }
    merged
}

fn search_single_literal(
    text: &str,
    line_offsets: &[u32],
    needle: &str,
    case_sensitive: bool,
    max_hits: usize,
    out: &mut Vec<u32>,
) {
    if needle.is_empty() {
        return;
    }
    if !case_sensitive && !needle.is_ascii() {
        let needle_low = needle.to_lowercase();
        for ln in 1..=(line_offsets.len() as u32) {
            let line = line_slice_at(text, line_offsets, ln);
            if line.to_lowercase().contains(&needle_low) {
                out.push(ln);
                if out.len() >= max_hits {
                    break;
                }
            }
        }
        return;
    }

    let hay = text.as_bytes();
    let ndl = needle.as_bytes();
    if ndl.len() > hay.len() {
        return;
    }

    let mut pos = 0usize;
    while pos + ndl.len() <= hay.len() {
        let found = if case_sensitive {
            find_bytes_exact(hay, ndl, pos)
        } else {
            find_bytes_ascii_ci(hay, ndl, pos)
        };
        let Some(hit_byte) = found else {
            break;
        };
        let ln = line_offsets.partition_point(|&off| (off as usize) <= hit_byte) as u32;
        out.push(ln.max(1));
        if out.len() >= max_hits {
            break;
        }
        pos = line_offsets
            .get(ln as usize)
            .map_or(hay.len(), |&next_off| next_off as usize);
    }
}

#[inline]
fn find_bytes_exact(hay: &[u8], ndl: &[u8], start: usize) -> Option<usize> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if hay.len().saturating_sub(start) >= ndl.len() + 32
            && std::arch::is_x86_feature_detected!("avx2")
        {
            // SAFETY: Guarded by runtime `avx2` check and explicit bounds.
            return unsafe { find_bytes_exact_avx2(hay, ndl, start) };
        }
    }
    find_bytes_exact_scalar(hay, ndl, start)
}

#[inline]
fn find_bytes_exact_scalar(hay: &[u8], ndl: &[u8], mut i: usize) -> Option<usize> {
    let first = ndl[0];
    let last = ndl[ndl.len() - 1];
    let last_off = ndl.len() - 1;
    let limit = hay.len() - ndl.len();
    while i <= limit {
        if hay[i] == first && hay[i + last_off] == last && &hay[i..i + ndl.len()] == ndl {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn find_bytes_exact_avx2(hay: &[u8], ndl: &[u8], mut i: usize) -> Option<usize> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let ptr = hay.as_ptr();
    let nlen = ndl.len();
    let last_off = nlen - 1;
    let v_first = _mm256_set1_epi8(ndl[0] as i8);
    let v_last = _mm256_set1_epi8(ndl[last_off] as i8);

    while i + last_off + 32 <= hay.len() {
        let c_first = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        let c_last = _mm256_loadu_si256(ptr.add(i + last_off) as *const __m256i);
        let eq = _mm256_and_si256(
            _mm256_cmpeq_epi8(c_first, v_first),
            _mm256_cmpeq_epi8(c_last, v_last),
        );
        let mut mask = _mm256_movemask_epi8(eq) as u32;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            let cand = i + bit;
            if &hay[cand..cand + nlen] == ndl {
                return Some(cand);
            }
            mask &= mask - 1;
        }
        i += 32;
    }
    find_bytes_exact_scalar(hay, ndl, i)
}

#[inline]
fn find_bytes_ascii_ci(hay: &[u8], ndl: &[u8], start: usize) -> Option<usize> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if hay.len().saturating_sub(start) >= ndl.len() + 32
            && std::arch::is_x86_feature_detected!("avx2")
        {
            // SAFETY: Guarded by runtime `avx2` check and explicit bounds.
            return unsafe { find_bytes_ascii_ci_avx2(hay, ndl, start) };
        }
    }
    find_bytes_ascii_ci_scalar(hay, ndl, start)
}

#[inline]
fn find_bytes_ascii_ci_scalar(hay: &[u8], ndl: &[u8], mut i: usize) -> Option<usize> {
    let f_low = ndl[0].to_ascii_lowercase();
    let l_low = ndl[ndl.len() - 1].to_ascii_lowercase();
    let last_off = ndl.len() - 1;
    let limit = hay.len() - ndl.len();
    while i <= limit {
        if hay[i].to_ascii_lowercase() == f_low
            && hay[i + last_off].to_ascii_lowercase() == l_low
            && hay[i..i + ndl.len()].eq_ignore_ascii_case(ndl)
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn find_bytes_ascii_ci_avx2(hay: &[u8], ndl: &[u8], mut i: usize) -> Option<usize> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let ptr = hay.as_ptr();
    let nlen = ndl.len();
    let last_off = nlen - 1;
    let f_low = ndl[0].to_ascii_lowercase();
    let l_low = ndl[last_off].to_ascii_lowercase();
    let f_mask = if f_low.is_ascii_alphabetic() { 0x20i8 } else { 0 };
    let l_mask = if l_low.is_ascii_alphabetic() { 0x20i8 } else { 0 };
    let v_f = _mm256_set1_epi8(f_low as i8);
    let v_l = _mm256_set1_epi8(l_low as i8);
    let v_f_fold = _mm256_set1_epi8(f_mask);
    let v_l_fold = _mm256_set1_epi8(l_mask);

    while i + last_off + 32 <= hay.len() {
        let c_first = _mm256_or_si256(_mm256_loadu_si256(ptr.add(i) as *const __m256i), v_f_fold);
        let c_last = _mm256_or_si256(
            _mm256_loadu_si256(ptr.add(i + last_off) as *const __m256i),
            v_l_fold,
        );
        let eq = _mm256_and_si256(_mm256_cmpeq_epi8(c_first, v_f), _mm256_cmpeq_epi8(c_last, v_l));
        let mut mask = _mm256_movemask_epi8(eq) as u32;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            let cand = i + bit;
            if hay[cand..cand + nlen].eq_ignore_ascii_case(ndl) {
                return Some(cand);
            }
            mask &= mask - 1;
        }
        i += 32;
    }
    find_bytes_ascii_ci_scalar(hay, ndl, i)
}

#[cfg(test)]
mod tests {
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
}
