//! Zero-spill AVX2+BMI1 literal line search (exact and ASCII case-insensitive)
//! with single runtime dispatch per file, inline stepped verification, and monotonic line cursor.

use super::scan::line_slice_at;

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

enum PreparedAsciiCi {
    Stack {
        low: [u8; 64],
        mask: [u8; 64],
        len: usize,
    },
    Heap {
        low: Vec<u8>,
        mask: Vec<u8>,
    },
}

impl PreparedAsciiCi {
    #[inline]
    fn new(ndl: &[u8]) -> Self {
        let nlen = ndl.len();
        if nlen <= 64 {
            let mut low = [0u8; 64];
            let mut mask = [0u8; 64];
            for (idx, &b) in ndl.iter().enumerate() {
                let l = b.to_ascii_lowercase();
                low[idx] = l;
                mask[idx] = if l.is_ascii_lowercase() { 0x20 } else { 0x00 };
            }
            Self::Stack { low, mask, len: nlen }
        } else {
            let mut low = Vec::with_capacity(nlen);
            let mut mask = Vec::with_capacity(nlen);
            for &b in ndl {
                let l = b.to_ascii_lowercase();
                low.push(l);
                mask.push(if l.is_ascii_lowercase() { 0x20 } else { 0x00 });
            }
            Self::Heap { low, mask }
        }
    }

    #[inline]
    fn slices(&self) -> (&[u8], &[u8]) {
        match self {
            Self::Stack { low, mask, len } => (&low[..*len], &mask[..*len]),
            Self::Heap { low, mask } => (low.as_slice(), mask.as_slice()),
        }
    }
}

#[cold]
#[inline(never)]
fn push_hit_cold(out: &mut Vec<u32>, ln: u32) {
    out.push(ln);
}

#[inline(always)]
fn push_hit(out: &mut Vec<u32>, ln: u32) {
    let len = out.len();
    if len < out.capacity() {
        // SAFETY: `len < capacity`, writing `u32` at `len` and bumping `len` by 1.
        unsafe {
            out.as_mut_ptr().add(len).write(ln);
            out.set_len(len + 1);
        }
    } else {
        push_hit_cold(out, ln);
    }
}

#[inline(always)]
fn advance_line(
    line_offsets: &[u32],
    line_cursor: &mut usize,
    hit_byte: usize,
    hay_len: usize,
) -> (u32, usize) {
    let n = line_offsets.len();
    let mut c = *line_cursor;
    // Fast path: check next 1-2 lines before inline binary search (zero YMM spills on sparse hits).
    if c + 1 < n && (line_offsets[c + 1] as usize) <= hit_byte {
        c += 1;
        if c + 1 < n && (line_offsets[c + 1] as usize) <= hit_byte {
            c += 1;
            if c + 1 < n && (line_offsets[c + 1] as usize) <= hit_byte {
                c += line_offsets[c + 1..].partition_point(|&off| (off as usize) <= hit_byte);
            }
        }
    }
    let ln = (c + 1) as u32;
    let next_idx = c + 1;
    *line_cursor = next_idx;
    let next_off = line_offsets
        .get(next_idx)
        .map_or(hay_len, |&off| off as usize);
    (ln, next_off)
}

#[inline(always)]
unsafe fn eq_bytes_inline(mut a: *const u8, mut b: *const u8, mut len: usize) -> bool {
    while len >= 8 {
        if (a as *const u64).read_unaligned() != (b as *const u64).read_unaligned() {
            return false;
        }
        a = a.add(8);
        b = b.add(8);
        len -= 8;
    }
    if len >= 4 {
        if (a as *const u32).read_unaligned() != (b as *const u32).read_unaligned() {
            return false;
        }
        a = a.add(4);
        b = b.add(4);
        len -= 4;
    }
    if len >= 2 {
        if (a as *const u16).read_unaligned() != (b as *const u16).read_unaligned() {
            return false;
        }
        a = a.add(2);
        b = b.add(2);
        len -= 2;
    }
    if len == 1 && *a != *b {
        return false;
    }
    true
}

#[inline(always)]
unsafe fn eq_ascii_ci_inline(
    mut a: *const u8,
    mut low: *const u8,
    mut mask: *const u8,
    mut len: usize,
) -> bool {
    while len >= 8 {
        let hv = (a as *const u64).read_unaligned();
        let mv = (mask as *const u64).read_unaligned();
        let lv = (low as *const u64).read_unaligned();
        if (hv | mv) != lv {
            return false;
        }
        a = a.add(8);
        low = low.add(8);
        mask = mask.add(8);
        len -= 8;
    }
    if len >= 4 {
        let hv = (a as *const u32).read_unaligned();
        let mv = (mask as *const u32).read_unaligned();
        let lv = (low as *const u32).read_unaligned();
        if (hv | mv) != lv {
            return false;
        }
        a = a.add(4);
        low = low.add(4);
        mask = mask.add(4);
        len -= 4;
    }
    if len >= 2 {
        let hv = (a as *const u16).read_unaligned();
        let mv = (mask as *const u16).read_unaligned();
        let lv = (low as *const u16).read_unaligned();
        if (hv | mv) != lv {
            return false;
        }
        a = a.add(2);
        low = low.add(2);
        mask = mask.add(2);
        len -= 2;
    }
    if len == 1 && (*a | *mask) != *low {
        return false;
    }
    true
}

fn search_single_literal(
    text: &str,
    line_offsets: &[u32],
    needle: &str,
    case_sensitive: bool,
    max_hits: usize,
    out: &mut Vec<u32>,
) {
    if needle.is_empty() || max_hits == 0 {
        return;
    }
    let limit_len = out.len().saturating_add(max_hits);
    if !case_sensitive && !needle.is_ascii() {
        let needle_low = needle.to_lowercase();
        for ln in 1..=(line_offsets.len() as u32) {
            let line = line_slice_at(text, line_offsets, ln);
            if line.to_lowercase().contains(&needle_low) {
                out.push(ln);
                if out.len() >= limit_len {
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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if hay.len() >= ndl.len() + 31
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi1")
        {
            if case_sensitive {
                // SAFETY: Guarded by runtime `avx2` + `bmi1` detection and `hay.len() >= ndl.len() + 31`.
                unsafe { search_exact_avx2(hay, line_offsets, ndl, limit_len, out) };
            } else {
                let prep = PreparedAsciiCi::new(ndl);
                let (low, fmask) = prep.slices();
                // SAFETY: Guarded by runtime `avx2` + `bmi1` detection and `hay.len() >= ndl.len() + 31`.
                unsafe { search_ascii_ci_avx2(hay, line_offsets, low, fmask, limit_len, out) };
            }
            return;
        }
    }

    if case_sensitive {
        search_exact_scalar(hay, line_offsets, ndl, 0, 0, limit_len, out);
    } else {
        let prep = PreparedAsciiCi::new(ndl);
        let (low, fmask) = prep.slices();
        search_ascii_ci_scalar(hay, line_offsets, low, fmask, 0, 0, limit_len, out);
    }
}

#[inline]
fn search_exact_scalar(
    hay: &[u8],
    line_offsets: &[u32],
    ndl: &[u8],
    mut i: usize,
    mut line_cursor: usize,
    limit_len: usize,
    out: &mut Vec<u32>,
) {
    let nlen = ndl.len();
    let hay_len = hay.len();
    if i + nlen > hay_len {
        return;
    }
    let last_off = nlen - 1;
    let first = ndl[0];
    let last = ndl[last_off];
    let limit = hay_len - nlen;
    let hay_ptr = hay.as_ptr();
    let ndl_ptr = ndl.as_ptr();

    while i <= limit {
        // SAFETY: `i <= hay_len - nlen`; first, last, and interior `1..last_off` are in bounds.
        let matched = unsafe {
            *hay_ptr.add(i) == first
                && *hay_ptr.add(i + last_off) == last
                && (nlen <= 2 || eq_bytes_inline(hay_ptr.add(i + 1), ndl_ptr.add(1), nlen - 2))
        };
        if matched {
            let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, i, hay_len);
            push_hit(out, ln);
            if out.len() >= limit_len {
                return;
            }
            i = next_off;
        } else {
            i += 1;
        }
    }
}

#[inline]
fn search_ascii_ci_scalar(
    hay: &[u8],
    line_offsets: &[u32],
    low: &[u8],
    fmask: &[u8],
    mut i: usize,
    mut line_cursor: usize,
    limit_len: usize,
    out: &mut Vec<u32>,
) {
    let nlen = low.len();
    let hay_len = hay.len();
    if i + nlen > hay_len {
        return;
    }
    let last_off = nlen - 1;
    let f_low = low[0];
    let f_mask = fmask[0];
    let l_low = low[last_off];
    let l_mask = fmask[last_off];
    let limit = hay_len - nlen;
    let hay_ptr = hay.as_ptr();
    let low_ptr = low.as_ptr();
    let fmask_ptr = fmask.as_ptr();

    while i <= limit {
        // SAFETY: `i <= hay_len - nlen` and `low.len() == fmask.len() == nlen`.
        let matched = unsafe {
            (*hay_ptr.add(i) | f_mask) == f_low
                && (*hay_ptr.add(i + last_off) | l_mask) == l_low
                && (nlen <= 2
                    || eq_ascii_ci_inline(
                        hay_ptr.add(i + 1),
                        low_ptr.add(1),
                        fmask_ptr.add(1),
                        nlen - 2,
                    ))
        };
        if matched {
            let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, i, hay_len);
            push_hit(out, ln);
            if out.len() >= limit_len {
                return;
            }
            i = next_off;
        } else {
            i += 1;
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
unsafe fn search_exact_avx2(
    hay: &[u8],
    line_offsets: &[u32],
    ndl: &[u8],
    limit_len: usize,
    out: &mut Vec<u32>,
) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let hay_len = hay.len();
    let nlen = ndl.len();
    if nlen == 0 || hay_len < nlen + 31 {
        return;
    }
    let hay_ptr = hay.as_ptr();
    let last_off = nlen - 1;
    let simd_end = hay_len - (last_off + 32);
    let v_first = _mm256_set1_epi8(ndl[0] as i8);
    let mut i = 0usize;
    let mut line_cursor = 0usize;

    if nlen == 1 {
        while i <= simd_end {
            let c0 = _mm256_loadu_si256(hay_ptr.add(i) as *const __m256i);
            let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, v_first)) as u32;
            if mask != 0 {
                let hit = i + mask.trailing_zeros() as usize;
                let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, hit, hay_len);
                push_hit(out, ln);
                if out.len() >= limit_len {
                    return;
                }
                i = next_off;
                continue;
            }
            i += 32;
        }
    } else if nlen == 2 {
        let v_last = _mm256_set1_epi8(ndl[1] as i8);
        while i <= simd_end {
            let c0 = _mm256_loadu_si256(hay_ptr.add(i) as *const __m256i);
            let c1 = _mm256_loadu_si256(hay_ptr.add(i + 1) as *const __m256i);
            let eq = _mm256_and_si256(_mm256_cmpeq_epi8(c0, v_first), _mm256_cmpeq_epi8(c1, v_last));
            let mask = _mm256_movemask_epi8(eq) as u32;
            if mask != 0 {
                let hit = i + mask.trailing_zeros() as usize;
                let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, hit, hay_len);
                push_hit(out, ln);
                if out.len() >= limit_len {
                    return;
                }
                i = next_off;
                continue;
            }
            i += 32;
        }
    } else {
        let v_last = _mm256_set1_epi8(ndl[last_off] as i8);
        let ndl_mid = ndl.as_ptr().add(1);
        let mid_len = nlen - 2;
        'outer: while i <= simd_end {
            let c_first = _mm256_loadu_si256(hay_ptr.add(i) as *const __m256i);
            let c_last = _mm256_loadu_si256(hay_ptr.add(i + last_off) as *const __m256i);
            let eq = _mm256_and_si256(
                _mm256_cmpeq_epi8(c_first, v_first),
                _mm256_cmpeq_epi8(c_last, v_last),
            );
            let mut mask = _mm256_movemask_epi8(eq) as u32;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = i + bit;
                if eq_bytes_inline(hay_ptr.add(cand + 1), ndl_mid, mid_len) {
                    let (ln, next_off) =
                        advance_line(line_offsets, &mut line_cursor, cand, hay_len);
                    push_hit(out, ln);
                    if out.len() >= limit_len {
                        return;
                    }
                    i = next_off;
                    continue 'outer;
                }
                mask &= mask - 1;
            }
            i += 32;
        }
    }

    if i + nlen <= hay_len {
        search_exact_scalar(hay, line_offsets, ndl, i, line_cursor, limit_len, out);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,bmi1")]
unsafe fn search_ascii_ci_avx2(
    hay: &[u8],
    line_offsets: &[u32],
    low: &[u8],
    fmask: &[u8],
    limit_len: usize,
    out: &mut Vec<u32>,
) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let hay_len = hay.len();
    let nlen = low.len();
    if nlen == 0 || fmask.len() != nlen || hay_len < nlen + 31 {
        return;
    }
    let hay_ptr = hay.as_ptr();
    let last_off = nlen - 1;
    let simd_end = hay_len - (last_off + 32);
    let v_f = _mm256_set1_epi8(low[0] as i8);
    let v_f_fold = _mm256_set1_epi8(fmask[0] as i8);
    let mut i = 0usize;
    let mut line_cursor = 0usize;

    if nlen == 1 {
        while i <= simd_end {
            let c0 =
                _mm256_or_si256(_mm256_loadu_si256(hay_ptr.add(i) as *const __m256i), v_f_fold);
            let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c0, v_f)) as u32;
            if mask != 0 {
                let hit = i + mask.trailing_zeros() as usize;
                let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, hit, hay_len);
                push_hit(out, ln);
                if out.len() >= limit_len {
                    return;
                }
                i = next_off;
                continue;
            }
            i += 32;
        }
    } else if nlen == 2 {
        let v_l = _mm256_set1_epi8(low[1] as i8);
        let v_l_fold = _mm256_set1_epi8(fmask[1] as i8);
        while i <= simd_end {
            let c0 =
                _mm256_or_si256(_mm256_loadu_si256(hay_ptr.add(i) as *const __m256i), v_f_fold);
            let c1 = _mm256_or_si256(
                _mm256_loadu_si256(hay_ptr.add(i + 1) as *const __m256i),
                v_l_fold,
            );
            let eq = _mm256_and_si256(_mm256_cmpeq_epi8(c0, v_f), _mm256_cmpeq_epi8(c1, v_l));
            let mask = _mm256_movemask_epi8(eq) as u32;
            if mask != 0 {
                let hit = i + mask.trailing_zeros() as usize;
                let (ln, next_off) = advance_line(line_offsets, &mut line_cursor, hit, hay_len);
                push_hit(out, ln);
                if out.len() >= limit_len {
                    return;
                }
                i = next_off;
                continue;
            }
            i += 32;
        }
    } else {
        let v_l = _mm256_set1_epi8(low[last_off] as i8);
        let v_l_fold = _mm256_set1_epi8(fmask[last_off] as i8);
        let low_mid = low.as_ptr().add(1);
        let fmask_mid = fmask.as_ptr().add(1);
        let mid_len = nlen - 2;
        'outer: while i <= simd_end {
            let c0 =
                _mm256_or_si256(_mm256_loadu_si256(hay_ptr.add(i) as *const __m256i), v_f_fold);
            let c1 = _mm256_or_si256(
                _mm256_loadu_si256(hay_ptr.add(i + last_off) as *const __m256i),
                v_l_fold,
            );
            let eq = _mm256_and_si256(_mm256_cmpeq_epi8(c0, v_f), _mm256_cmpeq_epi8(c1, v_l));
            let mut mask = _mm256_movemask_epi8(eq) as u32;
            while mask != 0 {
                let bit = mask.trailing_zeros() as usize;
                let cand = i + bit;
                if eq_ascii_ci_inline(hay_ptr.add(cand + 1), low_mid, fmask_mid, mid_len) {
                    let (ln, next_off) =
                        advance_line(line_offsets, &mut line_cursor, cand, hay_len);
                    push_hit(out, ln);
                    if out.len() >= limit_len {
                        return;
                    }
                    i = next_off;
                    continue 'outer;
                }
                mask &= mask - 1;
            }
            i += 32;
        }
    }

    if i + nlen <= hay_len {
        search_ascii_ci_scalar(hay, line_offsets, low, fmask, i, line_cursor, limit_len, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::simd::scan::scan_source_bytes;

    fn make_needle(len: usize) -> String {
        let mut s = String::with_capacity(len);
        for idx in 0..len {
            let ch = match idx % 7 {
                0 => 'A',
                1 => 'b',
                2 => '_',
                3 => '3',
                4 => 'Z',
                5 => 'q',
                _ => '-',
            };
            s.push(ch);
        }
        s
    }

    fn run_scalar(text: &str, offsets: &[u32], needle: &str, cs: bool, max_hits: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let hay = text.as_bytes();
        let ndl = needle.as_bytes();
        if cs {
            search_exact_scalar(hay, offsets, ndl, 0, 0, max_hits, &mut out);
        } else {
            let prep = PreparedAsciiCi::new(ndl);
            let (low, fmask) = prep.slices();
            search_ascii_ci_scalar(hay, offsets, low, fmask, 0, 0, max_hits, &mut out);
        }
        out
    }

    #[test]
    fn avx2_vs_scalar_parity_across_needle_lengths() {
        for &nlen in &[1usize, 2, 3, 7, 8, 9, 15, 16, 31, 32, 33, 70] {
            let needle = make_needle(nlen);
            let needle_flipped: String = needle
                .chars()
                .map(|c| {
                    if c.is_ascii_lowercase() {
                        c.to_ascii_uppercase()
                    } else if c.is_ascii_uppercase() {
                        c.to_ascii_lowercase()
                    } else {
                        c
                    }
                })
                .collect();

            // Build haystack with false-positive decoys, multi-hit same-line duplicates,
            // spaced lines (>3 lines apart to hit partition_point), and a trailing edge hit.
            let mut body = String::new();
            body.push_str("padding line zero with no matches at all 0123456789\n");
            // Same-line duplicate hits (must deduplicate to 1 hit for line 2).
            body.push_str(&format!("xx {needle} mid {needle} end {needle}\n"));
            // False-positive first+last decoy line when nlen >= 3.
            if nlen >= 3 {
                let mut decoy = needle.as_bytes().to_vec();
                decoy[nlen / 2] = b'!';
                let decoy_str = String::from_utf8(decoy).unwrap();
                body.push_str(&format!("decoy {decoy_str} and {decoy_str} here\n"));
            }
            // Flipped-case line (matches CI, not exact unless no alpha).
            body.push_str(&format!("flipped {needle_flipped} twice {needle_flipped}\n"));
            // Several clean lines to exercise partition_point branch in advance_line.
            for k in 0..8 {
                body.push_str(&format!("filler line number {k} without target bytes\n"));
            }
            // Trailing edge hit right at EOF without trailing newline.
            body.push_str(&format!("tail_prefix_{needle}"));

            let scanned = scan_source_bytes(body.into_bytes()).unwrap();
            for &cs in &[true, false] {
                let expected = run_scalar(&scanned.text, &scanned.line_offsets, &needle, cs, 64);
                let got = search_lines_literals(
                    &scanned.text,
                    &scanned.line_offsets,
                    &[needle.as_str()],
                    cs,
                    64,
                );
                assert_eq!(got, expected, "parity mismatch nlen={nlen} cs={cs}");
                // Ensure line 2 appears exactly once despite 3 matches on that line.
                assert_eq!(got.iter().filter(|&&ln| ln == 2).count(), 1);
                // Ensure trailing edge hit on last line is always detected.
                assert_eq!(got.last().copied(), Some(scanned.line_count));
            }
        }
    }

    #[test]
    fn non_ascii_ci_and_multi_needle() {
        let raw = "Первая строка\nВторая ПРИВЕТ строка\nТретья alpha\nЧетвертая привет\n";
        let scanned = scan_source_bytes(raw.as_bytes().to_vec()).unwrap();
        let hits = search_lines_literals(
            &scanned.text,
            &scanned.line_offsets,
            &["привет"],
            false,
            10,
        );
        assert_eq!(hits, vec![2, 4]);

        let multi = search_lines_literals(
            &scanned.text,
            &scanned.line_offsets,
            &["alpha", "привет"],
            false,
            2,
        );
        assert_eq!(multi, vec![2, 3]);
    }
}
