//! Word-wise 64-bit hashing, LUT-accelerated ASCII path lowercasing,
//! 64-bit trigram Bloom filter, and zero-overhead `HashMap` hashers.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};

const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const K1: u64 = 0x517c_c1b7_2722_0a95;
const K2: u64 = 0x9e37_79b1_85eb_ca87;

/// 256-byte LUT mapping `'A'..='Z' -> 'a'..='z'`, `'\\' -> '/'`, and identity elsewhere.
const ASCII_PATH_LOWER: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = if b >= b'A' && b <= b'Z' {
            b | 0x20
        } else if b == b'\\' {
            b'/'
        } else {
            b
        };
        i += 1;
    }
    table
};

#[inline(always)]
fn finalize64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[inline(always)]
fn fold_word(acc: u64, w: u64, k: u64) -> u64 {
    (acc ^ w).wrapping_mul(k).rotate_left(27)
}

#[inline]
fn fold_bytes(seed: u64, bytes: &[u8]) -> u64 {
    let len = bytes.len();
    let mut acc1 = seed ^ (len as u64).wrapping_mul(K1);
    let mut ptr = bytes.as_ptr();
    let mut rem = len;

    if rem >= 32 {
        let mut acc2 = seed.wrapping_add(K2) ^ (len as u64).wrapping_mul(K2);
        while rem >= 32 {
            // SAFETY: `rem >= 32`; unaligned 64-bit loads are valid within `bytes`.
            unsafe {
                let w0 = (ptr as *const u64).read_unaligned().to_le();
                let w1 = (ptr.add(8) as *const u64).read_unaligned().to_le();
                let w2 = (ptr.add(16) as *const u64).read_unaligned().to_le();
                let w3 = (ptr.add(24) as *const u64).read_unaligned().to_le();
                acc1 = fold_word(acc1, w0, K1);
                acc2 = fold_word(acc2, w1, K2);
                acc1 = fold_word(acc1, w2, K1);
                acc2 = fold_word(acc2, w3, K2);
                ptr = ptr.add(32);
            }
            rem -= 32;
        }
        acc1 = fold_word(acc1, acc2.rotate_left(13), K1);
    }

    while rem >= 8 {
        // SAFETY: `rem >= 8`.
        let w = unsafe { (ptr as *const u64).read_unaligned().to_le() };
        acc1 = fold_word(acc1, w, K1);
        // SAFETY: advancing by 8 stays within `bytes`.
        ptr = unsafe { ptr.add(8) };
        rem -= 8;
    }

    if rem > 0 {
        let mut tail = 0u64;
        // SAFETY: `rem < 8`; each read is strictly within `bytes`.
        unsafe {
            let mut shift = 0u32;
            if rem >= 4 {
                tail = (ptr as *const u32).read_unaligned().to_le() as u64;
                ptr = ptr.add(4);
                rem -= 4;
                shift = 32;
            }
            if rem >= 2 {
                tail |= ((ptr as *const u16).read_unaligned().to_le() as u64) << shift;
                ptr = ptr.add(2);
                rem -= 2;
                shift += 16;
            }
            if rem == 1 {
                tail |= (*ptr as u64) << shift;
            }
        }
        acc1 = fold_word(acc1, tail, K1);
    }

    acc1
}

#[inline]
pub fn fast_hash64(bytes: &[u8]) -> u64 {
    finalize64(fold_bytes(SEED, bytes))
}

#[inline]
pub fn fast_hash64_ascii_lower(bytes: &[u8]) -> u64 {
    let mut acc = SEED ^ (bytes.len() as u64).wrapping_mul(K1);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes([
            ASCII_PATH_LOWER[chunk[0] as usize],
            ASCII_PATH_LOWER[chunk[1] as usize],
            ASCII_PATH_LOWER[chunk[2] as usize],
            ASCII_PATH_LOWER[chunk[3] as usize],
            ASCII_PATH_LOWER[chunk[4] as usize],
            ASCII_PATH_LOWER[chunk[5] as usize],
            ASCII_PATH_LOWER[chunk[6] as usize],
            ASCII_PATH_LOWER[chunk[7] as usize],
        ]);
        acc = fold_word(acc, word, K1);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail = 0u64;
        for (i, &b) in rem.iter().enumerate() {
            tail |= (ASCII_PATH_LOWER[b as usize] as u64) << (i << 3);
        }
        acc = fold_word(acc, tail, K1);
    }
    finalize64(acc)
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
    let mut c0 = ASCII_PATH_LOWER[bytes[0] as usize] as u32;
    let mut c1 = ASCII_PATH_LOWER[bytes[1] as usize] as u32;
    for &raw in &bytes[2..] {
        let c2 = ASCII_PATH_LOWER[raw as usize] as u32;
        let tri = c0 | (c1 << 8) | (c2 << 16);
        let h = tri.wrapping_mul(0x9e37_79b1);
        mask |= (1u64 << (h >> 26)) | (1u64 << ((h >> 20) & 63));
        c0 = c1;
        c1 = c2;
    }
    mask
}

/// Legacy FNV-1a 64-bit hash retained for `.ctx.sha256` upgrade verification.
#[cold]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Clone, Debug)]
pub struct FastHasher {
    state: u64,
}

impl Default for FastHasher {
    #[inline]
    fn default() -> Self {
        Self { state: SEED }
    }
}

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        finalize64(self.state)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.state = fold_bytes(self.state, bytes);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.state = fold_word(self.state, i as u64, K1);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.state = fold_word(self.state, i as u64, K1);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.state = fold_word(self.state, i as u64, K1);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.state = fold_word(self.state, i, K1);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.state = fold_word(self.state, i as u64, K1);
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct BuildFastHasher;

impl BuildHasher for BuildFastHasher {
    type Hasher = FastHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FastHasher::default()
    }
}

pub type FastHashMap<K, V> = HashMap<K, V, BuildFastHasher>;

#[derive(Clone, Copy, Default, Debug)]
pub struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0 = fold_bytes(self.0, bytes);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct BuildIdentityHasher;

impl BuildHasher for BuildIdentityHasher {
    type Hasher = IdentityHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher::default()
    }
}

pub type IdentityHashMap<K, V> = HashMap<K, V, BuildIdentityHasher>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    #[test]
    fn hash_ascii_lower_normalizes_case_and_slash() {
        assert_eq!(
            fast_hash64_ascii_lower(b"Src\\Core/OrderTable.hpp"),
            fast_hash64_ascii_lower(b"src/core/ordertable.hpp")
        );
        assert_ne!(
            fast_hash64(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            fast_hash64(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
        );
    }

    #[test]
    fn trigram_bloom_zero_false_negatives() {
        let path = b"src\\src\\Exchanges/Binance/Manifest.hpp";
        let needle = b"exchanges/binance";
        let bp = trigram_bloom64_ascii_lower(path);
        let bn = trigram_bloom64_ascii_lower(needle);
        assert_eq!(bp & bn, bn);
        assert_eq!(trigram_bloom64_ascii_lower(b"ab"), 0);
    }

    #[test]
    fn fast_hasher_folds_multiple_writes() {
        let mut h1 = FastHasher::default();
        "foo".hash(&mut h1);
        let mut h2 = FastHasher::default();
        "bar".hash(&mut h2);
        assert_ne!(h1.finish(), h2.finish());

        let mut h3 = FastHasher::default();
        h3.write(b"a");
        h3.write(b"bc");
        let mut h4 = FastHasher::default();
        h4.write(b"ab");
        h4.write(b"c");
        assert_ne!(h3.finish(), h4.finish());

        let mut id = IdentityHasher::default();
        id.write_u64(0x1234_5678_9abc_def0);
        assert_eq!(id.finish(), 0x1234_5678_9abc_def0);
    }

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
