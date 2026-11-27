//! Sharded per-agent session read-span tracking, bounded delta-snapshot ring, and hook dedup ring.

use super::{now_ms, shard_idx_for, CachedFile, PathId, RamStore};
use crate::base::simd::{fast_hash64, FastHashMap};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;

pub const SESSION_WINDOW_STEPS: u64 = 30;
pub const MAX_DELTA_ENTRIES: usize = 256;
pub const MAX_DELTA_TOTAL_BYTES: usize = 16 << 20;
const MAX_SESSIONS_PER_SHARD: usize = 32; // 2,048 concurrent sessions across 64 shards
const MAX_READ_SPANS_PER_SESSION: usize = 128; // Hard bound per session (4 KiB max)
const MAX_LARGE_READ_STRIKES: usize = 32;
const MAX_STALE_CANDIDATES: usize = 4;
const DEDUP_RING_SLOTS: usize = 8192;
const DEDUP_RING_MASK: usize = DEDUP_RING_SLOTS - 1;
const DEDUP_PROBE_WAY: usize = 4;

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
    pub is_worker: bool,
    pub large_read_strikes: Vec<(PathId, u64, u64)>,
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

#[derive(Clone, Debug)]
pub struct DeltaHit {
    pub prev_content: Arc<str>,
    pub covered_start: usize,
    pub covered_end: usize,
}

#[derive(Clone, Debug)]
pub enum SessionReadStatus {
    Unchanged(DuplicateHit),
    Changed(DeltaHit),
    Miss,
}

#[derive(Default)]
pub(super) struct DeltaSnapshotRing {
    entries: VecDeque<(PathId, u64, Arc<str>)>,
    total_bytes: usize,
}

impl DeltaSnapshotRing {
    pub(super) fn insert(&mut self, path_id: PathId, content_hash64: u64, content: Arc<str>) {
        let byte_len = content.len();
        if byte_len > MAX_DELTA_TOTAL_BYTES {
            return;
        }
        if let Some(pos) = self
            .entries
            .iter()
            .position(|&(pid, h, _)| pid == path_id && h == content_hash64)
        {
            if let Some(item) = self.entries.remove(pos) {
                self.entries.push_back(item);
            }
            return;
        }
        while self.entries.len() >= MAX_DELTA_ENTRIES
            || self.total_bytes.saturating_add(byte_len) > MAX_DELTA_TOTAL_BYTES
        {
            let Some((_, _, evicted)) = self.entries.pop_front() else {
                break;
            };
            self.total_bytes = self.total_bytes.saturating_sub(evicted.len());
        }
        self.total_bytes = self.total_bytes.saturating_add(byte_len);
        self.entries.push_back((path_id, content_hash64, content));
    }

    pub(super) fn get(&mut self, path_id: PathId, content_hash64: u64) -> Option<Arc<str>> {
        let pos = self
            .entries
            .iter()
            .rposition(|&(pid, h, _)| pid == path_id && h == content_hash64)?;
        let item = self.entries.remove(pos)?;
        let out = Arc::clone(&item.2);
        self.entries.push_back(item);
        Some(out)
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.total_bytes = 0;
    }
}

#[inline]
fn count_text_lines(text: &str) -> usize {
    text.lines().count()
}

pub(super) struct DedupRing {
    slots: Box<[(u64, u64); DEDUP_RING_SLOTS]>,
}

impl Default for DedupRing {
    fn default() -> Self {
        Self {
            slots: Box::new([(0u64, 0u64); DEDUP_RING_SLOTS]),
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

    pub fn mark_worker_session(&self, session: &str) {
        if session.is_empty() {
            return;
        }
        let _ = self.with_session_mut(session, |sess| {
            sess.is_worker = true;
        });
    }

    pub fn is_worker_session(&self, session: &str) -> bool {
        if session.is_empty() {
            return false;
        }
        let s_idx = shard_idx_for(session);
        let Ok(map) = self.sessions[s_idx].lock() else {
            return false;
        };
        map.get(session).is_some_and(|s| s.is_worker)
    }

    /// Returns `true` if `(path_id, content_hash64)` was already struck within
    /// `SESSION_WINDOW_STEPS` for `session`; otherwise records Strike 1 and returns `false`.
    pub fn check_and_mark_large_read_strike(
        &self,
        session: &str,
        path_id: PathId,
        content_hash64: u64,
    ) -> bool {
        if session.is_empty() {
            return false;
        }
        self.with_session_mut(session, |sess| {
            let cur_step = sess.step_seq;
            sess.large_read_strikes
                .retain(|&(_, _, step)| cur_step.saturating_sub(step) <= SESSION_WINDOW_STEPS);
            if sess
                .large_read_strikes
                .iter()
                .any(|&(pid, h, _)| pid == path_id && h == content_hash64)
            {
                return true;
            }
            sess.large_read_strikes.retain(|&(pid, _, _)| pid != path_id);
            if sess.large_read_strikes.len() >= MAX_LARGE_READ_STRIKES {
                if let Some((oldest_idx, _)) = sess
                    .large_read_strikes
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, &(_, _, step))| step)
                {
                    sess.large_read_strikes.swap_remove(oldest_idx);
                }
            }
            sess.large_read_strikes
                .push((path_id, content_hash64, cur_step));
            false
        })
        .unwrap_or(false)
    }

    pub(super) fn snapshot_delta(&self, path_id: PathId, content_hash64: u64, content: &Arc<str>) {
        if let Ok(mut ring) = self.delta_ring.lock() {
            ring.insert(path_id, content_hash64, Arc::clone(content));
        }
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
        if let Some(content) = entry.content_arc() {
            self.snapshot_delta(pid, content_hash64, content);
        }
        let s = start_line.max(1) as u32;
        let e = end_line.max(start_line.max(1)) as u32;

        let _ = self.with_session_mut(session_key, |sess| {
            sess.step_seq = sess.step_seq.saturating_add(1);
            let step = sess.step_seq;
            let mut merged_s = s;
            let mut merged_e = e;
            sess.reads.retain(|r| {
                if step.saturating_sub(r.step_seq) > SESSION_WINDOW_STEPS {
                    return false;
                }
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
            if sess.reads.len() >= MAX_READ_SPANS_PER_SESSION {
                if let Some((oldest_idx, _)) = sess
                    .reads
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| r.step_seq)
                {
                    sess.reads.swap_remove(oldest_idx);
                }
            }
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

    fn match_unchanged_span(
        sess: &mut SessionState,
        entry: &CachedFile,
        total_lines: usize,
        s: u32,
        e: u32,
    ) -> Option<DuplicateHit> {
        let pid = entry.path_id;
        let content_hash64 = entry.content_hash64;
        let cur_step = sess.step_seq;
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
                    outline_summary: Self::format_outline_compact(entry, 10),
                    rel_path: entry.rel_path.to_string(),
                });
            }
        }
        None
    }

    fn collect_stale_candidates(
        sess: &SessionState,
        pid: PathId,
        content_hash64: u64,
    ) -> ([(u64, u32, u32); MAX_STALE_CANDIDATES], usize) {
        let cur_step = sess.step_seq;
        let mut cands = [(0u64, 0u32, 0u32); MAX_STALE_CANDIDATES];
        let mut len = 0usize;
        for span in sess.reads.iter().rev() {
            if span.path_id == pid
                && span.content_hash64 != content_hash64
                && cur_step.saturating_sub(span.step_seq) <= SESSION_WINDOW_STEPS
            {
                cands[len] = (span.content_hash64, span.start_line, span.end_line);
                len += 1;
                if len == MAX_STALE_CANDIDATES {
                    break;
                }
            }
        }
        (cands, len)
    }

    fn resolve_delta_candidates(
        &self,
        pid: PathId,
        cands: &[(u64, u32, u32)],
        s: u32,
        e: u32,
        total_lines: usize,
        req_start: Option<usize>,
        req_end: Option<usize>,
    ) -> Option<DeltaHit> {
        if cands.is_empty() {
            return None;
        }
        let full_req = req_start.is_none() && req_end.is_none();
        let covers_to_eof =
            req_start.unwrap_or(1) <= 1 && req_end.is_some_and(|re| re >= total_lines);
        let mut ring = self.delta_ring.lock().ok()?;
        for &(prev_hash, cov_s, cov_e) in cands {
            let Some(prev_content) = ring.get(pid, prev_hash) else {
                continue;
            };
            let prev_total = count_text_lines(&prev_content).max(1);
            let explicit_cover = cov_s <= s && cov_e >= e;
            let whole_prev_cover =
                (full_req || covers_to_eof) && cov_s <= 1 && (cov_e as usize) >= prev_total;
            if explicit_cover || whole_prev_cover {
                return Some(DeltaHit {
                    prev_content,
                    covered_start: cov_s as usize,
                    covered_end: cov_e as usize,
                });
            }
        }
        None
    }

    pub fn check_session_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        req_start: Option<usize>,
        req_end: Option<usize>,
    ) -> SessionReadStatus {
        let Ok(entry) = self.get_outline_entry(canon_path, ws_root) else {
            return SessionReadStatus::Miss;
        };
        let total_lines = (entry.line_count as usize).max(1);
        let s = req_start.unwrap_or(1).max(1) as u32;
        let e = req_end.unwrap_or(total_lines).min(total_lines).max(s as usize) as u32;

        let s_idx = shard_idx_for(session_key);
        let (cands, cand_len) = {
            let Ok(mut map) = self.sessions[s_idx].lock() else {
                return SessionReadStatus::Miss;
            };
            let Some(sess) = map.get_mut(session_key) else {
                return SessionReadStatus::Miss;
            };
            if let Some(dup) = Self::match_unchanged_span(sess, &entry, total_lines, s, e) {
                return SessionReadStatus::Unchanged(dup);
            }
            Self::collect_stale_candidates(sess, entry.path_id, entry.content_hash64)
        };
        match self.resolve_delta_candidates(
            entry.path_id,
            &cands[..cand_len],
            s,
            e,
            total_lines,
            req_start,
            req_end,
        ) {
            Some(delta) => SessionReadStatus::Changed(delta),
            None => SessionReadStatus::Miss,
        }
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
        let s = req_start.unwrap_or(1).max(1) as u32;
        let e = req_end.unwrap_or(total_lines).min(total_lines).max(s as usize) as u32;

        let s_idx = shard_idx_for(session_key);
        let mut map = self.sessions[s_idx].lock().ok()?;
        let sess = map.get_mut(session_key)?;
        Self::match_unchanged_span(sess, &entry, total_lines, s, e)
    }

    #[allow(dead_code)]
    pub fn check_delta_read(
        &self,
        session_key: &str,
        canon_path: &Path,
        ws_root: Option<&Path>,
        req_start: Option<usize>,
        req_end: Option<usize>,
    ) -> Option<DeltaHit> {
        let entry = self.get_outline_entry(canon_path, ws_root).ok()?;
        let total_lines = (entry.line_count as usize).max(1);
        let s = req_start.unwrap_or(1).max(1) as u32;
        let e = req_end.unwrap_or(total_lines).min(total_lines).max(s as usize) as u32;

        let s_idx = shard_idx_for(session_key);
        let (cands, cand_len) = {
            let map = self.sessions[s_idx].lock().ok()?;
            let sess = map.get(session_key)?;
            Self::collect_stale_candidates(sess, entry.path_id, entry.content_hash64)
        };
        self.resolve_delta_candidates(
            entry.path_id,
            &cands[..cand_len],
            s,
            e,
            total_lines,
            req_start,
            req_end,
        )
    }

    pub fn check_and_mark_dedup(&self, dedup_key: &str) -> bool {
        let now = now_ms();
        let key_hash = fast_hash64(dedup_key.as_bytes()).max(1);
        let Ok(mut ring) = self.dedup_ring.lock() else {
            return false;
        };
        let base = (key_hash as usize) & DEDUP_RING_MASK;
        let mut replace_idx = base;
        let mut oldest_ts = u64::MAX;
        for way in 0..DEDUP_PROBE_WAY {
            let idx = (base + way) & DEDUP_RING_MASK;
            let (h, ts) = ring.slots[idx];
            let fresh = ts != 0 && now.saturating_sub(ts) < 15_000;
            if fresh && h == key_hash {
                return true;
            }
            if !fresh {
                if oldest_ts != 0 {
                    replace_idx = idx;
                    oldest_ts = 0;
                }
            } else if ts < oldest_ts {
                replace_idx = idx;
                oldest_ts = ts;
            }
        }
        ring.slots[replace_idx] = (key_hash, now);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn delta_snapshot_ring_evicts_by_count_and_byte_cap() {
        let mut ring = DeltaSnapshotRing::default();
        for i in 0..(MAX_DELTA_ENTRIES + 8) {
            let s: Arc<str> = Arc::from(format!("body-{i}\n"));
            ring.insert(PathId(i as u32), i as u64 + 1, s);
        }
        assert_eq!(ring.entries.len(), MAX_DELTA_ENTRIES);
        assert!(ring.get(PathId(0), 1).is_none());
        assert!(ring.get(PathId((MAX_DELTA_ENTRIES + 7) as u32), (MAX_DELTA_ENTRIES + 8) as u64).is_some());

        // LRU touch keeps entry 8 alive when pushing 1 more entry
        assert!(ring.get(PathId(8), 9).is_some());
        ring.insert(PathId(999), 999, Arc::from("extra\n"));
        assert!(ring.get(PathId(8), 9).is_some());
        assert!(ring.get(PathId(9), 10).is_none());

        // Byte cap eviction (17 x 1 MiB > 16 MiB)
        ring.clear();
        let one_mb: Arc<str> = Arc::from("x".repeat(1 << 20));
        for i in 0..17u32 {
            ring.insert(PathId(i), i as u64 + 100, Arc::clone(&one_mb));
        }
        assert!(ring.total_bytes <= MAX_DELTA_TOTAL_BYTES);
        assert_eq!(ring.entries.len(), 16);
        assert!(ring.get(PathId(0), 100).is_none());
        assert!(ring.get(PathId(16), 116).is_some());
    }

    #[test]
    fn worker_session_and_large_read_strike_window_behave_deterministically() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-sess-worker-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&dir).unwrap();
        let store = RamStore::new(dir.join("snap"));

        assert!(!store.is_worker_session("w1"));
        store.mark_worker_session("w1");
        assert!(store.is_worker_session("w1"));

        // Strike 1 records and returns false; Strike 2 returns true.
        assert!(!store.check_and_mark_large_read_strike("w1", PathId(7), 0x1111));
        assert!(store.check_and_mark_large_read_strike("w1", PathId(7), 0x1111));
        // Content hash change resets to Strike 1.
        assert!(!store.check_and_mark_large_read_strike("w1", PathId(7), 0x2222));
        assert!(store.check_and_mark_large_read_strike("w1", PathId(7), 0x2222));
        // Advancing past SESSION_WINDOW_STEPS expires old strike.
        for _ in 0..=SESSION_WINDOW_STEPS {
            store.bump_session_step("w1");
        }
        assert!(!store.check_and_mark_large_read_strike("w1", PathId(7), 0x2222));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_duplicate_read_preserves_stale_span_for_check_delta_read() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-sess-delta-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("demo.rs");
        fs::write(&file, "let a = 1;\nlet b = 2;\n").unwrap();
        let canon = fs::canonicalize(&file).unwrap();
        let store = RamStore::new(dir.join("snap"));

        let _ = store.get_full_entry(&canon, Some(&dir)).unwrap();
        store.record_read("sess-delta", &canon, Some(&dir), 1, 2);

        // Unchanged -> duplicate hit, no delta
        assert!(store.check_duplicate_read("sess-delta", &canon, Some(&dir), None, None).is_some());
        assert!(store.check_delta_read("sess-delta", &canon, Some(&dir), None, None).is_none());

        // Edit file (+1 line added) -> check_duplicate_read returns None WITHOUT evicting stale span
        fs::write(&file, "let a = 1;\nlet b = 22;\nlet c = 3;\n").unwrap();
        let _ = store.refresh_file_content(&canon, Some(&dir)).unwrap();
        assert!(store.check_duplicate_read("sess-delta", &canon, Some(&dir), None, None).is_none());
        let delta = store
            .check_delta_read("sess-delta", &canon, Some(&dir), None, None)
            .expect("stale span must still yield DeltaHit after check_duplicate_read");
        assert_eq!(delta.prev_content.as_ref(), "let a = 1;\nlet b = 2;\n");
        assert_eq!((delta.covered_start, delta.covered_end), (1, 2));

        // Recording new version clears stale span
        store.record_read("sess-delta", &canon, Some(&dir), 1, 3);
        assert!(matches!(
            store.check_session_read("sess-delta", &canon, Some(&dir), None, None),
            SessionReadStatus::Unchanged(_)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
