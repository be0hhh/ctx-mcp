//! Zero-dependency SIMD (`AVX2` + `BMI1` with runtime detection + portable scalar fallback),
//! 64-byte cache-line padding, fast 64-bit hashing, 64-bit trigram Bloom filtering,
//! single-pass source scanning, literal line search, and zero-allocation integer formatting.

pub mod fmt;
pub mod hash;
pub mod scan;
pub mod search;

use std::fmt as stdfmt;
use std::ops::{Deref, DerefMut};

pub use fmt::{decimal_digits, push_i64, push_u32, push_usize};
pub use hash::{
    fast_hash64, fast_hash64_ascii_lower, fnv1a_64, trigram_bloom64_ascii_lower, FastHashMap,
    IdentityHashMap,
};
pub use scan::{
    escape_json_str, line_slice_at, next_json_escape_pos, scan_source_bytes, ScanError,
};
pub use search::search_lines_literals;

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

impl<T: stdfmt::Debug> stdfmt::Debug for CachePadded<T> {
    fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
        self.0.fmt(f)
    }
}
