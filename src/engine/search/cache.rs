//! Bounded in-RAM search micro-cache (`128` entries, `<= 1 MiB`, `2,000 ms` TTL, instant
//! `mutation_epoch` invalidation) with panic-safe in-flight request coalescing.
//!
//! Security boundary: callers MUST run allowlist admission and sensitive-path filtering
//! strictly BEFORE invoking `SearchCache::get_or_compute`. Errors (`Busy`/`Timeout`/`Failed`)
//! are NEVER cached.

use super::rank::SearchHitSet;
use super::{search_time_left, SearchError};
use crate::base::simd::FastHashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_CACHE_ENTRIES: usize = 128;
const MAX_CACHE_BYTES: usize = 1 << 20; // 1 MiB total estimate
const CACHE_TTL: Duration = Duration::from_millis(2_000);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct SearchCacheKey {
    pub ws_root: PathBuf,
    pub canon_cwd: Option<PathBuf>,
    pub admitted_roots: Vec<(PathBuf, bool)>,
    pub query: String,
    pub cap: usize,
    pub code_only: bool,
    pub mutation_epoch: u64,
}

struct CacheEntry {
    value: Arc<SearchHitSet>,
    expires: Instant,
    last_tick: u64,
    est_bytes: usize,
}

enum InflightOutcome {
    Pending,
    Ready(Arc<SearchHitSet>),
    TimedOut,
    Busy,
    Failed(String),
    Panicked,
}

struct InflightSlot {
    outcome: Mutex<InflightOutcome>,
    cv: Condvar,
}

#[derive(Default)]
struct CacheState {
    entries: FastHashMap<SearchCacheKey, CacheEntry>,
    inflight: FastHashMap<SearchCacheKey, Arc<InflightSlot>>,
    est_bytes: usize,
    tick: u64,
}

impl CacheState {
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn prune_expired(&mut self, now: Instant) {
        let mut freed = 0usize;
        self.entries.retain(|_, e| {
            if now < e.expires {
                true
            } else {
                freed = freed.saturating_add(e.est_bytes);
                false
            }
        });
        self.est_bytes = self.est_bytes.saturating_sub(freed);
    }

    fn insert_entry(&mut self, key: SearchCacheKey, value: Arc<SearchHitSet>, now: Instant) {
        let est = estimate_hit_set_bytes(&value);
        if est > MAX_CACHE_BYTES {
            return;
        }
        self.prune_expired(now);
        if let Some(old) = self.entries.remove(&key) {
            self.est_bytes = self.est_bytes.saturating_sub(old.est_bytes);
        }
        while self.entries.len() >= MAX_CACHE_ENTRIES
            || self.est_bytes.saturating_add(est) > MAX_CACHE_BYTES
        {
            let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_tick)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&oldest_key) {
                self.est_bytes = self.est_bytes.saturating_sub(evicted.est_bytes);
            }
        }
        let tick = self.next_tick();
        self.est_bytes = self.est_bytes.saturating_add(est);
        self.entries.insert(
            key,
            CacheEntry {
                value,
                expires: now + CACHE_TTL,
                last_tick: tick,
                est_bytes: est,
            },
        );
    }
}

struct InflightGuard<'a> {
    cache: &'a SearchCache,
    key: SearchCacheKey,
    slot: Arc<InflightSlot>,
    completed: bool,
}

impl<'a> InflightGuard<'a> {
    fn finish(mut self, outcome: InflightOutcome, store_entry: Option<(Instant, Arc<SearchHitSet>)>) {
        if let Ok(mut st) = self.cache.state.lock() {
            if let Some((now, val)) = store_entry {
                st.insert_entry(self.key.clone(), val, now);
            }
            if st
                .inflight
                .get(&self.key)
                .is_some_and(|s| Arc::ptr_eq(s, &self.slot))
            {
                st.inflight.remove(&self.key);
            }
        }
        if let Ok(mut out) = self.slot.outcome.lock() {
            *out = outcome;
        }
        self.slot.cv.notify_all();
        self.completed = true;
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Ok(mut st) = self.cache.state.lock() {
            if st
                .inflight
                .get(&self.key)
                .is_some_and(|s| Arc::ptr_eq(s, &self.slot))
            {
                st.inflight.remove(&self.key);
            }
        }
        if let Ok(mut out) = self.slot.outcome.lock() {
            *out = InflightOutcome::Panicked;
        }
        self.slot.cv.notify_all();
    }
}

pub struct SearchCache {
    state: Mutex<CacheState>,
}

impl Default for SearchCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchCache {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
        }
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.entries.clear();
            st.est_bytes = 0;
        }
    }

    pub(super) fn get_or_compute<F, M>(
        &self,
        key: SearchCacheKey,
        deadline: Instant,
        is_still_fresh: M,
        compute: F,
    ) -> Result<Arc<SearchHitSet>, SearchError>
    where
        F: FnOnce(Instant) -> Result<SearchHitSet, SearchError>,
        M: Fn() -> bool,
    {
        search_time_left(deadline)?;

        enum Action {
            Hit(Arc<SearchHitSet>),
            Wait(Arc<InflightSlot>),
            Lead(Arc<InflightSlot>),
        }

        let action = {
            let mut st = self
                .state
                .lock()
                .map_err(|_| SearchError::Failed("search cache lock poisoned".into()))?;
            let now = Instant::now();
            let tick = st.next_tick();
            if let Some(entry) = st.entries.get_mut(&key) {
                if now < entry.expires {
                    entry.last_tick = tick;
                    Action::Hit(Arc::clone(&entry.value))
                } else {
                    if let Some(expired) = st.entries.remove(&key) {
                        st.est_bytes = st.est_bytes.saturating_sub(expired.est_bytes);
                    }
                    if let Some(slot) = st.inflight.get(&key).cloned() {
                        Action::Wait(slot)
                    } else {
                        let slot = Arc::new(InflightSlot {
                            outcome: Mutex::new(InflightOutcome::Pending),
                            cv: Condvar::new(),
                        });
                        st.inflight.insert(key.clone(), Arc::clone(&slot));
                        Action::Lead(slot)
                    }
                }
            } else if let Some(slot) = st.inflight.get(&key).cloned() {
                Action::Wait(slot)
            } else {
                let slot = Arc::new(InflightSlot {
                    outcome: Mutex::new(InflightOutcome::Pending),
                    cv: Condvar::new(),
                });
                st.inflight.insert(key.clone(), Arc::clone(&slot));
                Action::Lead(slot)
            }
        };

        match action {
            Action::Hit(hit_set) => Ok(hit_set),
            Action::Wait(slot) => {
                let wait_res = {
                    let guard = slot
                        .outcome
                        .lock()
                        .map_err(|_| SearchError::Failed("search inflight lock poisoned".into()))?;
                    let wait_for = deadline.saturating_duration_since(Instant::now());
                    let (guard, _) = slot
                        .cv
                        .wait_timeout_while(guard, wait_for, |o| {
                            matches!(*o, InflightOutcome::Pending)
                        })
                        .map_err(|_| SearchError::Failed("search inflight lock poisoned".into()))?;
                    match &*guard {
                        InflightOutcome::Ready(hit_set) => Ok(Some(Arc::clone(hit_set))),
                        InflightOutcome::Busy => Err(SearchError::Busy),
                        InflightOutcome::Failed(msg) => Err(SearchError::Failed(msg.clone())),
                        InflightOutcome::Pending
                        | InflightOutcome::TimedOut
                        | InflightOutcome::Panicked => Ok(None),
                    }
                }?;

                if let Some(hit_set) = wait_res {
                    return Ok(hit_set);
                }

                // Leader timed out (or panicked) while waiter still has deadline budget:
                // recompute locally instead of inheriting the leader's short timeout.
                search_time_left(deadline)?;
                let computed = Arc::new(compute(deadline)?);
                if is_still_fresh() {
                    if let Ok(mut st) = self.state.lock() {
                        st.insert_entry(key, Arc::clone(&computed), Instant::now());
                    }
                }
                Ok(computed)
            }
            Action::Lead(slot) => {
                let guard = InflightGuard {
                    cache: self,
                    key,
                    slot,
                    completed: false,
                };
                match compute(deadline) {
                    Ok(hit_set) => {
                        let arc = Arc::new(hit_set);
                        let store_entry = is_still_fresh().then(|| (Instant::now(), Arc::clone(&arc)));
                        guard.finish(InflightOutcome::Ready(Arc::clone(&arc)), store_entry);
                        Ok(arc)
                    }
                    Err(SearchError::Timeout) => {
                        guard.finish(InflightOutcome::TimedOut, None);
                        Err(SearchError::Timeout)
                    }
                    Err(SearchError::Busy) => {
                        guard.finish(InflightOutcome::Busy, None);
                        Err(SearchError::Busy)
                    }
                    Err(SearchError::Failed(msg)) => {
                        guard.finish(InflightOutcome::Failed(msg.clone()), None);
                        Err(SearchError::Failed(msg))
                    }
                }
            }
        }
    }
}

fn estimate_hit_set_bytes(set: &SearchHitSet) -> usize {
    let mut bytes = 128usize;
    for h in &set.hits {
        bytes = bytes
            .saturating_add(96)
            .saturating_add(h.path.as_os_str().len())
            .saturating_add(h.workspace.as_os_str().len())
            .saturating_add(h.snippet.len());
    }
    for s in &set.omitted_scopes {
        bytes = bytes.saturating_add(48).saturating_add(s.label.len());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::search::SearchHit;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    fn sample_key(query: &str, epoch: u64) -> SearchCacheKey {
        SearchCacheKey {
            ws_root: PathBuf::from("/tmp/ws"),
            canon_cwd: Some(PathBuf::from("/tmp/ws")),
            admitted_roots: vec![(PathBuf::from("/tmp/ws"), true)],
            query: query.into(),
            cap: 20,
            code_only: false,
            mutation_epoch: epoch,
        }
    }

    fn sample_hit_set(line: usize) -> SearchHitSet {
        SearchHitSet {
            hits: vec![SearchHit {
                path: PathBuf::from("/tmp/ws/a.rs"),
                workspace: PathBuf::from("/tmp/ws"),
                line,
                snippet: format!("fn hit_{line}() {{}}"),
            }],
            total_found: 1,
            scan_truncated: false,
            incomplete_note: None,
            omitted_scopes: Vec::new(),
        }
    }

    #[test]
    fn cache_hits_invalidates_on_epoch_and_never_caches_errors() {
        let cache = SearchCache::new();
        let runs = AtomicUsize::new(0);
        let dl = Instant::now() + Duration::from_secs(2);

        // First call computes; second with same epoch hits cache.
        let r1 = cache
            .get_or_compute(sample_key("alpha", 1), dl, || true, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(sample_hit_set(10))
            })
            .unwrap();
        let r2 = cache
            .get_or_compute(sample_key("alpha", 1), dl, || true, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(sample_hit_set(99))
            })
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&r1, &r2));

        // Bumped mutation_epoch misses instantly and recomputes.
        let r3 = cache
            .get_or_compute(sample_key("alpha", 2), dl, || true, |_| {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(sample_hit_set(20))
            })
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(r3.hits[0].line, 20);

        // Errors are never cached.
        let err_runs = AtomicUsize::new(0);
        for _ in 0..2 {
            let res = cache.get_or_compute(sample_key("bad", 1), dl, || true, |_| {
                err_runs.fetch_add(1, Ordering::SeqCst);
                Err(SearchError::Failed("boom".into()))
            });
            assert!(matches!(res, Err(SearchError::Failed(_))));
        }
        assert_eq!(err_runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn inflight_coalesces_concurrent_callers_and_recomputes_on_leader_timeout() {
        let cache = Arc::new(SearchCache::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));

        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..8 {
                let c = Arc::clone(&cache);
                let r = Arc::clone(&runs);
                let b = Arc::clone(&barrier);
                handles.push(scope.spawn(move || {
                    b.wait();
                    c.get_or_compute(
                        sample_key("coalesce", 5),
                        Instant::now() + Duration::from_secs(2),
                        || true,
                        |_| {
                            r.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(40));
                            Ok(sample_hit_set(42))
                        },
                    )
                    .unwrap()
                }));
            }
            let first = handles.remove(0).join().unwrap();
            for h in handles {
                let got = h.join().unwrap();
                assert!(Arc::ptr_eq(&first, &got));
            }
        });
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // Leader times out quickly -> waiter with remaining budget recomputes locally.
        let entered = Arc::new(Barrier::new(2));
        let c1 = Arc::clone(&cache);
        let c2 = Arc::clone(&cache);
        let b1 = Arc::clone(&entered);
        let b2 = Arc::clone(&entered);
        std::thread::scope(|scope| {
            let leader = scope.spawn(move || {
                c1.get_or_compute(
                    sample_key("short_leader", 6),
                    Instant::now() + Duration::from_secs(2),
                    || true,
                    |_| {
                        b1.wait();
                        std::thread::sleep(Duration::from_millis(30));
                        Err(SearchError::Timeout)
                    },
                )
            });
            let waiter = scope.spawn(move || {
                b2.wait();
                std::thread::sleep(Duration::from_millis(5));
                c2.get_or_compute(
                    sample_key("short_leader", 6),
                    Instant::now() + Duration::from_secs(2),
                    || true,
                    |_| Ok(sample_hit_set(77)),
                )
            });
            assert!(matches!(leader.join().unwrap(), Err(SearchError::Timeout)));
            let recovered = waiter.join().unwrap().unwrap();
            assert_eq!(recovered.hits[0].line, 77);
        });
    }
}
