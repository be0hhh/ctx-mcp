//! SIMD-accelerated delimiter scanning for source comment/string cleaning
//! (`find_next_clean_delim`) and ANSI/CR stripping (`find_ansi_or_cr`), with
//! runtime AVX2 (32B/step) + SSE2 (16B/step) dispatch and portable scalar tail.

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub const CLEAN_LANG_CLIKE: u8 = 0;
pub const CLEAN_LANG_RUST: u8 = 1;
pub const CLEAN_LANG_BACKTICK: u8 = 2;
pub const CLEAN_LANG_PYTHON: u8 = 3;

#[inline(always)]
const fn lang_extra_delims(lang: u8) -> (u8, u8) {
    match lang {
        CLEAN_LANG_RUST => (b'/', b'r'),
        CLEAN_LANG_BACKTICK => (b'/', b'`'),
        CLEAN_LANG_PYTHON => (b'#', b'#'),
        _ => (b'/', b'R'),
    }
}

/// Finds the first byte index `>= start` matching `\n`, `\r`, `"`, `'`, or the per-lang
/// trigger (`/`/`R` C-like, `/`/`r` Rust, `/`/`` ` `` Backtick, `#` Python), or `bytes.len()`.
#[inline]
pub fn find_next_clean_delim(bytes: &[u8], start: usize, lang: u8) -> usize {
    let len = bytes.len();
    if start >= len { return len; }
    let (e1, e2) = lang_extra_delims(lang);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let rem = len - start;
        if rem >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Guarded by runtime `avx2` detection and `start < len`.
            return unsafe { find_next_clean_delim_avx2(bytes, start, e1, e2) };
        }
        if rem >= 16 && std::arch::is_x86_feature_detected!("sse2") {
            // SAFETY: Guarded by runtime `sse2` detection and `start < len`.
            return unsafe { find_next_clean_delim_sse2(bytes, start, e1, e2) };
        }
    }
    find_next_clean_delim_scalar(bytes, start, e1, e2)
}

#[inline]
fn find_next_clean_delim_scalar(bytes: &[u8], mut i: usize, e1: u8, e2: u8) -> usize {
    let len = bytes.len();
    while i < len {
        let b = bytes[i];
        if b == b'\n' || b == b'\r' || b == b'"' || b == b'\'' || b == e1 || b == e2 { return i; }
        i += 1;
    }
    len
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn find_next_clean_delim_avx2(bytes: &[u8], mut i: usize, e1: u8, e2: u8) -> usize {
    let len = bytes.len();
    if i >= len { return len; }
    let ptr = bytes.as_ptr();
    let (v_nl, v_cr) = (_mm256_set1_epi8(b'\n' as i8), _mm256_set1_epi8(b'\r' as i8));
    let (v_dq, v_sq) = (_mm256_set1_epi8(b'"' as i8), _mm256_set1_epi8(b'\'' as i8));
    let (v_e1, v_e2) = (_mm256_set1_epi8(e1 as i8), _mm256_set1_epi8(e2 as i8));
    while len - i >= 32 {
        let c = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        let m0 = _mm256_or_si256(_mm256_cmpeq_epi8(c, v_nl), _mm256_cmpeq_epi8(c, v_cr));
        let m1 = _mm256_or_si256(_mm256_cmpeq_epi8(c, v_dq), _mm256_cmpeq_epi8(c, v_sq));
        let m2 = _mm256_or_si256(_mm256_cmpeq_epi8(c, v_e1), _mm256_cmpeq_epi8(c, v_e2));
        let mask = _mm256_movemask_epi8(_mm256_or_si256(_mm256_or_si256(m0, m1), m2)) as u32;
        if mask != 0 { return i + mask.trailing_zeros() as usize; }
        i += 32;
    }
    find_next_clean_delim_scalar(bytes, i, e1, e2)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn find_next_clean_delim_sse2(bytes: &[u8], mut i: usize, e1: u8, e2: u8) -> usize {
    let len = bytes.len();
    if i >= len { return len; }
    let ptr = bytes.as_ptr();
    let (v_nl, v_cr) = (_mm_set1_epi8(b'\n' as i8), _mm_set1_epi8(b'\r' as i8));
    let (v_dq, v_sq) = (_mm_set1_epi8(b'"' as i8), _mm_set1_epi8(b'\'' as i8));
    let (v_e1, v_e2) = (_mm_set1_epi8(e1 as i8), _mm_set1_epi8(e2 as i8));
    while len - i >= 16 {
        let c = _mm_loadu_si128(ptr.add(i) as *const __m128i);
        let m0 = _mm_or_si128(_mm_cmpeq_epi8(c, v_nl), _mm_cmpeq_epi8(c, v_cr));
        let m1 = _mm_or_si128(_mm_cmpeq_epi8(c, v_dq), _mm_cmpeq_epi8(c, v_sq));
        let m2 = _mm_or_si128(_mm_cmpeq_epi8(c, v_e1), _mm_cmpeq_epi8(c, v_e2));
        let mask = _mm_movemask_epi8(_mm_or_si128(_mm_or_si128(m0, m1), m2)) as u32;
        if mask != 0 { return i + mask.trailing_zeros() as usize; }
        i += 16;
    }
    find_next_clean_delim_scalar(bytes, i, e1, e2)
}

/// Finds the first byte index `>= start` equal to `0x1b` (`ESC`) or `0x0d` (`\r`),
/// or `bytes.len()` when neither byte is present.
#[inline]
pub fn find_ansi_or_cr(bytes: &[u8], start: usize) -> usize {
    let len = bytes.len();
    if start >= len { return len; }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let rem = len - start;
        if rem >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: Guarded by runtime `avx2` detection and `start < len`.
            return unsafe { find_ansi_or_cr_avx2(bytes, start) };
        }
        if rem >= 16 && std::arch::is_x86_feature_detected!("sse2") {
            // SAFETY: Guarded by runtime `sse2` detection and `start < len`.
            return unsafe { find_ansi_or_cr_sse2(bytes, start) };
        }
    }
    find_ansi_or_cr_scalar(bytes, start)
}

#[inline]
fn find_ansi_or_cr_scalar(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len {
        let b = bytes[i];
        if b == 0x1b || b == b'\r' { return i; }
        i += 1;
    }
    len
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn find_ansi_or_cr_avx2(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    if i >= len { return len; }
    let ptr = bytes.as_ptr();
    let (v_esc, v_cr) = (_mm256_set1_epi8(0x1b_u8 as i8), _mm256_set1_epi8(b'\r' as i8));
    while len - i >= 32 {
        let c = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
        let mask = _mm256_movemask_epi8(_mm256_or_si256(
            _mm256_cmpeq_epi8(c, v_esc),
            _mm256_cmpeq_epi8(c, v_cr),
        )) as u32;
        if mask != 0 { return i + mask.trailing_zeros() as usize; }
        i += 32;
    }
    find_ansi_or_cr_scalar(bytes, i)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn find_ansi_or_cr_sse2(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    if i >= len { return len; }
    let ptr = bytes.as_ptr();
    let (v_esc, v_cr) = (_mm_set1_epi8(0x1b_u8 as i8), _mm_set1_epi8(b'\r' as i8));
    while len - i >= 16 {
        let c = _mm_loadu_si128(ptr.add(i) as *const __m128i);
        let mask = _mm_movemask_epi8(_mm_or_si128(
            _mm_cmpeq_epi8(c, v_esc),
            _mm_cmpeq_epi8(c, v_cr),
        )) as u32;
        if mask != 0 { return i + mask.trailing_zeros() as usize; }
        i += 16;
    }
    find_ansi_or_cr_scalar(bytes, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_clean_parity(buf: &[u8], start: usize, lang: u8) {
        let (e1, e2) = lang_extra_delims(lang);
        let exp = find_next_clean_delim_scalar(buf, start, e1, e2);
        assert_eq!(find_next_clean_delim(buf, start, lang), exp);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                assert_eq!(unsafe { find_next_clean_delim_avx2(buf, start, e1, e2) }, exp);
            }
            if std::arch::is_x86_feature_detected!("sse2") {
                assert_eq!(unsafe { find_next_clean_delim_sse2(buf, start, e1, e2) }, exp);
            }
        }
    }

    fn check_ansi_parity(buf: &[u8], start: usize) {
        let exp = find_ansi_or_cr_scalar(buf, start);
        assert_eq!(find_ansi_or_cr(buf, start), exp);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                assert_eq!(unsafe { find_ansi_or_cr_avx2(buf, start) }, exp);
            }
            if std::arch::is_x86_feature_detected!("sse2") {
                assert_eq!(unsafe { find_ansi_or_cr_sse2(buf, start) }, exp);
            }
        }
    }

    #[test]
    fn clean_delim_simd_matches_scalar_across_alignments_and_langs() {
        let langs: [(u8, &[u8], u8); 4] = [
            (CLEAN_LANG_CLIKE, b"\n\r\"'/R", b'r'),
            (CLEAN_LANG_RUST, b"\n\r\"'/r", b'R'),
            (CLEAN_LANG_BACKTICK, b"\n\r\"'/`", b'#'),
            (CLEAN_LANG_PYTHON, b"\n\r\"'#", b'/'),
        ];
        let clean_only = vec![b'a'; 128];
        for (lang, triggers, non_trig) in langs {
            for start in 0..65 { check_clean_parity(&clean_only, start, lang); }
            for &trig in triggers {
                for pos in 0..65 {
                    let mut buf = vec![b'x'; 130];
                    buf[pos] = trig;
                    for start in [0usize, 1, 15, 16, 17, 31, 32, 33, pos.min(64), pos + 1] {
                        check_clean_parity(&buf, start, lang);
                    }
                }
            }
            let mut decoy = vec![non_trig; 96];
            decoy[73] = b'"';
            assert_eq!(find_next_clean_delim(&decoy, 0, lang), 73);
            assert_eq!(find_next_clean_delim(&decoy, 96, lang), 96);
            assert_eq!(find_next_clean_delim(&decoy, 200, lang), 96);
        }
    }

    #[test]
    fn ansi_or_cr_simd_matches_scalar_across_alignments() {
        check_ansi_parity(b"", 0);
        let clean = vec![b'z'; 128];
        for start in 0..65 { check_ansi_parity(&clean, start); }
        for target in [0x1bu8, b'\r'] {
            for pos in 0..65 {
                let mut buf = vec![b'a'; 130];
                buf[pos] = target;
                for start in [0usize, 1, 15, 16, 17, 31, 32, 33, pos, pos + 1] {
                    check_ansi_parity(&buf, start);
                }
            }
        }
    }
}
