//! Stack-based integer formatting (2-digit LUT, uninitialized stack buffer)
//! and branchless base-10 digit counting.

use std::mem::MaybeUninit;

const DIGIT_PAIRS: &[u8; 200] = b"\
0001020304050607080910111213141516171819\
2021222324252627282930313233343536373839\
4041424344454647484950515253545556575859\
6061626364656667686970717273747576777879\
8081828384858687888990919293949596979899";

const POW10: [u64; 20] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
    100_000_000_000,
    1_000_000_000_000,
    10_000_000_000_000,
    100_000_000_000_000,
    1_000_000_000_000_000,
    10_000_000_000_000_000,
    100_000_000_000_000_000,
    1_000_000_000_000_000_000,
    10_000_000_000_000_000_000,
];

/// Lower-bound base-10 digit count indexed by `u64::leading_zeros()` (0..=64).
/// For `lz < 64`, equals the decimal digit count of `1u64 << (63 - lz)`.
const LOG10_BY_LZ: [u8; 65] = [
    19, 19, 19, 19, // lz 0..=3   (2^63..2^60)
    18, 18, 18, // lz 4..=6   (2^59..2^57)
    17, 17, 17, // lz 7..=9   (2^56..2^54)
    16, 16, 16, 16, // lz 10..=13 (2^53..2^50)
    15, 15, 15, // lz 14..=16 (2^49..2^47)
    14, 14, 14, // lz 17..=19 (2^46..2^44)
    13, 13, 13, 13, // lz 20..=23 (2^43..2^40)
    12, 12, 12, // lz 24..=26 (2^39..2^37)
    11, 11, 11, // lz 27..=29 (2^36..2^34)
    10, 10, 10, 10, // lz 30..=33 (2^33..2^30)
    9, 9, 9, // lz 34..=36 (2^29..2^27)
    8, 8, 8, // lz 37..=39 (2^26..2^24)
    7, 7, 7, 7, // lz 40..=43 (2^23..2^20)
    6, 6, 6, // lz 44..=46 (2^19..2^17)
    5, 5, 5, // lz 47..=49 (2^16..2^14)
    4, 4, 4, 4, // lz 50..=53 (2^13..2^10)
    3, 3, 3, // lz 54..=56 (2^9..2^7)
    2, 2, 2, // lz 57..=59 (2^6..2^4)
    1, 1, 1, 1, // lz 60..=63 (2^3..2^0)
    1, // lz 64
];

#[inline]
pub fn push_u64(out: &mut String, mut val: u64) {
    if val < 10 {
        out.push((b'0' + val as u8) as char);
        return;
    }
    let mut buf = MaybeUninit::<[u8; 20]>::uninit();
    let base = buf.as_mut_ptr() as *mut u8;
    let mut pos = 20usize;

    while val >= 100 {
        let rem = ((val % 100) as usize) << 1;
        val /= 100;
        pos -= 2;
        // SAFETY: `u64::MAX` is 20 digits; `pos` stays within `0..=20` and `rem + 1 < 200`.
        unsafe {
            std::ptr::copy_nonoverlapping(DIGIT_PAIRS.as_ptr().add(rem), base.add(pos), 2);
        }
    }

    if val >= 10 {
        let rem = (val as usize) << 1;
        pos -= 2;
        // SAFETY: `pos` stays within `0..=20` and `rem + 1 < 200`.
        unsafe {
            std::ptr::copy_nonoverlapping(DIGIT_PAIRS.as_ptr().add(rem), base.add(pos), 2);
        }
    } else {
        pos -= 1;
        // SAFETY: `pos` stays within `0..=19`.
        unsafe {
            base.add(pos).write(b'0' + val as u8);
        }
    }

    // SAFETY: `base[pos..20]` was fully initialized with ASCII digits '0'..='9'.
    let slice = unsafe { std::slice::from_raw_parts(base.add(pos), 20 - pos) };
    let s = unsafe { std::str::from_utf8_unchecked(slice) };
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

/// Branchless decimal digit count for `n` (returns `1` for `0`; portable on 32-bit and 64-bit).
#[inline]
pub fn decimal_digits(n: usize) -> usize {
    let v = (n as u64) | 1;
    let guess = LOG10_BY_LZ[v.leading_zeros() as usize] as usize;
    guess + usize::from(v >= POW10[guess])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt_u64(v: u64) -> String {
        let mut s = String::new();
        push_u64(&mut s, v);
        s
    }

    fn fmt_i64(v: i64) -> String {
        let mut s = String::new();
        push_i64(&mut s, v);
        s
    }

    #[test]
    fn push_integers_edge_cases() {
        for &v in &[
            0u64,
            1,
            9,
            10,
            11,
            99,
            100,
            101,
            999,
            1_000,
            9_999,
            10_000,
            u32::MAX as u64,
            i64::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert_eq!(fmt_u64(v), v.to_string());
        }

        for &v in &[
            i64::MIN,
            i64::MIN + 1,
            -100,
            -99,
            -10,
            -9,
            -1,
            0,
            1,
            9,
            10,
            99,
            100,
            i64::MAX,
        ] {
            assert_eq!(fmt_i64(v), v.to_string());
        }

        let mut s = String::new();
        push_u32(&mut s, 42);
        s.push(',');
        push_usize(&mut s, 123456);
        assert_eq!(s, "42,123456");
    }

    #[test]
    fn decimal_digits_all_power_boundaries() {
        assert_eq!(decimal_digits(0), 1);
        assert_eq!(decimal_digits(1), 1);
        assert_eq!(decimal_digits(usize::MAX), usize::MAX.to_string().len());

        for (exp, &p10) in POW10.iter().enumerate().skip(1) {
            if p10 <= usize::MAX as u64 {
                let p = p10 as usize;
                assert_eq!(decimal_digits(p - 1), exp, "boundary 10^{} - 1", exp);
                assert_eq!(decimal_digits(p), exp + 1, "boundary 10^{}", exp);
                if p < usize::MAX {
                    assert_eq!(decimal_digits(p + 1), exp + 1, "boundary 10^{} + 1", exp);
                }
            }
        }

        // Verify the full 64-bit table against every `1u64 << k` and `(1u64 << k) - 1`.
        for lz in 0u32..64 {
            let v = 1u64 << (63 - lz);
            let guess = LOG10_BY_LZ[lz as usize] as usize;
            let got = guess + usize::from(v >= POW10[guess]);
            assert_eq!(got, v.to_string().len(), "lz={lz}, v={v}");
        }
    }
}
