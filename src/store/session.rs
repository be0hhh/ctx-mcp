//! Sharded per-agent session read-span tracking and bounded hook deduplication ring.

use super::{now_ms, shard_idx_for, PathId, RamStore};
use crate::base::simd::{fast_hash64, FastHashMap};
use std::path::Path;

pub const SESSION_WINDOW_STEPS: u64 = 30;
const MAX_SESSIONS_PER_SHARD: usize = 32; // 2,048 concurrent sessions across 64 shards
const DEDUP_RING_SLOTS: usize = 2048;
const DEDUP_RING_MASK: usize = DEDUP_RING_SLOTS - 1;

/// Exact 32-byte POD read span (`2` per 64B cache line, `Copy`, `0` heap allocations).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadSpan {
    pub content_hash64: u64,
    pub step_seq: u64,
    pub path_id: PathId,
    pub start_line: u32,
    pub end_line: u32,
    pub strikes: u8,
    pub _pad: [u8; 3],
}

const _: [(); 32] = [(); std::mem::size_of::<ReadSpan>()];

#[derive(Clone, Debug, Default)]
pub struct SessionState {
    pub step_seq: u64,
    pub last_step_ms: u64,
    pub reads: Vec<ReadSpan>,
    pub startup_injected: bool,
}

#[derive(Clone, Debug)]
pub struct DuplicateHit {
    pub covered_start: usize,
    pub covered_end: usize,
    pub total_lines: usize,
    pub unread_ranges: Vec<(usize, usize)>,
    pub outline_summary: String,
    pub rel_path: String,
}

pub(super) struct DedupRing {
    slots: Box<[(u64, u64); DEDUP_RING_SLOTS]>,
    cursor: usize,
}

impl Default for DedupRing {
    fn default() -> Self {
        Self {
            slots: Box::new([(0u64, 0u64); DEDUP_RING_SLOTS]),
            cursor: 0,
        }
    }
}

pub(super) type SessionShardMap = FastHashMap<Box<str>, SessionState>;

impl RamStore {
    fn with_session_mut<R>(
        &self,
        session_key: &str,
        f: impl FnOnce(&mut SessionState) -> R,
    ) -> Option<R> {
        let s_idx = shard_idx_for(session_key);
        let mut map = self.sessions[s_idx].lock().ok()?;
        if !map.contains_key(session_key) && map.len() >= MAX_SESSIONS_PER_SHARD {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, v)| v.last_step_ms)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        let now = now_ms();
        if let Some(existing) = map.get_mut(session_key) {
            existing.last_step_ms = now;
            return Some(f(existing));
        }
        let mut fresh = SessionState {
            last_step_ms: now,
            ..SessionState::default()
        };
        let res = f(&mut fresh);
        map.insert(session_key.into(), fresh);
        Some(res)
    }

    pub fn has_startup_settled(&self, session_key: &str) -> bool {
        let s_idx = shard_idx_for(session_key);
        let Ok(map) = self.sessions[s_idx].lock() else {
            return false;
        };
        map.get(session_key)
            .map(|s| s.startup_injected)
            .unwrap_or(false)
    }

    pub fn try_mark_startup_injected(&self, session_key: &str) -> bool {
        self.with_session_mut(session_key, |sess| {
            if sess.startup_injected {
                false
            } else {
                sess.startup_injected = true;
                true
            }
        })
        .unwrap_or(false)
    }

    pub fn record_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        start_line: usize,
        end_line: usize,
    ) {
        let Ok(entry) = self.get_outline_entry(canon_path, ws_root) else {
            return;
        };
        let pid = entry.path_id;
        let content_hash64 = entry.content_hash64;
        let s = start_line.max(1) as u32;
        let e = end_line.max(start_line.max(1)) as u32;

        let _ = self.with_session_mut(session_key, |sess| {
            sess.step_seq = sess.step_seq.saturating_add(1);
            let step = sess.step_seq;
            let mut merged_s = s;
            let mut merged_e = e;
            sess.reads.retain(|r| {
                if r.path_id == pid {
                    if r.content_hash64 != content_hash64 {
                        return false;
                    }
                    if r.end_line.saturating_add(1) >= merged_s
                        && merged_e.saturating_add(1) >= r.start_line
                    {
                        merged_s = merged_s.min(r.start_line);
                        merged_e = merged_e.max(r.end_line);
                        return false;
                    }
                }
                true
            });
            sess.reads.push(ReadSpan {
                content_hash64,
                step_seq: step,
                path_id: pid,
                start_line: merged_s,
                end_line: merged_e,
                strikes: 0,
                _pad: [0; 3],
            });
        });
    }

    pub fn clear_session(&self, session_key: &str) {
        let s_idx = shard_idx_for(session_key);
        if let Ok(mut map) = self.sessions[s_idx].lock() {
            map.remove(session_key);
        }
    }

    pub fn bump_session_step(&self, session_key: &str) -> u64 {
        self.with_session_mut(session_key, |sess| {
            sess.step_seq = sess.step_seq.saturating_add(1);
            sess.step_seq
        })
        .unwrap_or(0)
    }

    pub fn check_duplicate_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        req_start: Option<usize>,
        req_end: Option<usize>,
    ) -> Option<DuplicateHit> {
        let entry = self.get_outline_entry(canon_path, ws_root).ok()?;
        let total_lines = (entry.line_count as usize).max(1);
        let content_hash64 = entry.content_hash64;
        let pid = entry.path_id;

        let s = req_start.unwrap_or(1).max(1) as u32;
        let e = req_end.unwrap_or(total_lines).min(total_lines).max(s as usize) as u32;

        let s_idx = shard_idx_for(session_key);
        let mut map = self.sessions[s_idx].lock().ok()?;
        let sess = map.get_mut(session_key)?;
        let cur_step = sess.step_seq;

        sess.reads
            .retain(|sp| sp.path_id != pid || sp.content_hash64 == content_hash64);

        for span in sess.reads.iter_mut() {
            if span.path_id == pid
                && span.content_hash64 == content_hash64
                && cur_step.saturating_sub(span.step_seq) <= SESSION_WINDOW_STEPS
                && span.start_line <= s
                && span.end_line >= e
            {
                if span.strikes >= 1 {
                    span.strikes = 0;
                    span.step_seq = cur_step;
                    return None;
                }
                span.strikes = span.strikes.saturating_add(1);
                let cov_s = span.start_line as usize;
                let cov_e = span.end_line as usize;
                let mut unread = Vec::with_capacity(2);
                if cov_s > 1 {
                    unread.push((1, cov_s - 1));
                }
                if cov_e < total_lines {
                    unread.push((cov_e + 1, total_lines));
                }
                return Some(DuplicateHit {
                    covered_start: cov_s,
                    covered_end: cov_e,
                    total_lines,
                    unread_ranges: unread,
                    outline_summary: Self::format_outline_compact(&entry, 10),
                    rel_path: entry.rel_path.to_string(),
                });
            }
        }
        None
    }

    pub fn check_and_mark_dedup(&self, dedup_key: &str) -> bool {
        let now = now_ms();
        let key_hash = fast_hash64(dedup_key.as_bytes()).max(1);
        let Ok(mut ring) = self.dedup_ring.lock() else {
            return false;
        };
        for &(h, ts) in ring.slots.iter() {
            if h == key_hash && now.saturating_sub(ts) < 15_000 {
                return true;
            }
        }
        let idx = ring.cursor;
        ring.slots[idx] = (key_hash, now);
        ring.cursor = (idx + 1) & DEDUP_RING_MASK;
        false
    }
}
