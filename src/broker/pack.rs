//! Shared in-RAM Context Packs (`PackStore`) with strict bounds, secret filtering,
//! and O(1) per-session delivery deduplication. Stores ONLY selector strings + optional summary
//! (never caches `Arc<CachedFile>`). Zero external crates, zero `div`/`idiv`.

use crate::base::simd::FastHashMap;
use crate::store::now_ms;
use std::sync::{Mutex, RwLock};

pub const MAX_PACK_WORKSPACES: usize = 64;
pub const MAX_PACKS_PER_WORKSPACE: usize = 64;
pub const MAX_PACK_SELECTORS: usize = 32;
pub const MAX_PACK_DEDUP_ENTRIES: usize = 2048;
pub const MAX_PACK_NAME_BYTES: usize = 96;
pub const MAX_PACK_SUMMARY_BYTES: usize = 4096;

const MAX_PACK_SELECTOR_BYTES: usize = 256;
const MAX_PACK_AUTHOR_BYTES: usize = 256;
const PACK_AUTHOR_UNKNOWN: &str = "unknown";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackSpec {
    pub name: String,
    pub selectors: Vec<String>,
    pub summary: Option<String>,
    pub author: String,
    pub updated_ms: u64,
}

#[derive(Default)]
struct PackState {
    workspaces: FastHashMap<String, Vec<PackSpec>>,
    ws_ticks: FastHashMap<String, u64>,
    tick: u64,
}

type DedupKey = (Box<str>, Box<str>, Box<str>);

#[derive(Default)]
struct PackDedupCache {
    entries: FastHashMap<DedupKey, (u64, u64)>,
    tick: u64,
}

#[derive(Default)]
pub struct PackStore {
    state: RwLock<PackState>,
    dedup: Mutex<PackDedupCache>,
}

impl PackStore {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_pack(
        &self,
        ws_norm: &str,
        name: &str,
        selectors: Vec<String>,
        summary: Option<&str>,
        author: &str,
    ) -> Result<String, String> {
        let name = name.trim();
        if name.is_empty()
            || name.len() > MAX_PACK_NAME_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(format!(
                "pack name must be a single line of 1-{MAX_PACK_NAME_BYTES} bytes"
            ));
        }
        if super::contains_known_secret(name) {
            return Err("REFUSED: pack name contains known secret material".to_string());
        }
        if selectors.is_empty() || selectors.len() > MAX_PACK_SELECTORS {
            return Err(format!(
                "pack must declare 1-{MAX_PACK_SELECTORS} selectors"
            ));
        }
        let mut clean_selectors = Vec::with_capacity(selectors.len());
        for raw in selectors {
            let sel = raw.trim();
            if sel.is_empty()
                || sel.len() > MAX_PACK_SELECTOR_BYTES
                || sel.chars().any(char::is_control)
            {
                return Err(format!(
                    "each pack selector must be a single line of 1-{MAX_PACK_SELECTOR_BYTES} bytes"
                ));
            }
            if super::contains_known_secret(sel) {
                return Err("REFUSED: pack selector contains known secret material".to_string());
            }
            clean_selectors.push(sel.to_string());
        }

        let clean_summary = match summary {
            Some(raw) => {
                let s = raw.trim();
                if s.is_empty() {
                    None
                } else if s.len() > MAX_PACK_SUMMARY_BYTES {
                    return Err(format!(
                        "pack summary must be <= {MAX_PACK_SUMMARY_BYTES} bytes"
                    ));
                } else if super::contains_known_secret(s) {
                    return Err("REFUSED: pack summary contains known secret material".to_string());
                } else {
                    Some(s.to_string())
                }
            }
            None => None,
        };

        let author_trim = author.trim();
        let clean_author = if !author_trim.is_empty()
            && author_trim.len() <= MAX_PACK_AUTHOR_BYTES
            && !author_trim.chars().any(char::is_control)
            && !super::contains_known_secret(author_trim)
        {
            author_trim.to_string()
        } else {
            PACK_AUTHOR_UNKNOWN.to_string()
        };

        let sel_count = clean_selectors.len();
        let spec = PackSpec {
            name: name.to_string(),
            selectors: clean_selectors,
            summary: clean_summary,
            author: clean_author,
            updated_ms: now_ms(),
        };

        let mut st = self
            .state
            .write()
            .map_err(|_| "pack store lock poisoned".to_string())?;
        if !st.workspaces.contains_key(ws_norm) && st.workspaces.len() >= MAX_PACK_WORKSPACES {
            if let Some(oldest_ws) = st
                .ws_ticks
                .iter()
                .min_by_key(|&(_, &t)| t)
                .map(|(k, _)| k.clone())
            {
                st.workspaces.remove(&oldest_ws);
                st.ws_ticks.remove(&oldest_ws);
            }
        }
        st.tick = st.tick.wrapping_add(1);
        let tick = st.tick;
        st.ws_ticks.insert(ws_norm.to_string(), tick);

        let list = st.workspaces.entry(ws_norm.to_string()).or_default();
        list.retain(|p| p.name != name);
        if list.len() >= MAX_PACKS_PER_WORKSPACE {
            list.remove(0);
        }
        list.push(spec);
        Ok(format!(
            "Saved pack `{name}` with {sel_count} selector(s)."
        ))
    }

    pub fn get_pack(&self, ws_norm: &str, name: &str) -> Option<PackSpec> {
        let name = name.trim();
        let st = self.state.read().ok()?;
        st.workspaces
            .get(ws_norm)?
            .iter()
            .find(|p| p.name == name)
            .cloned()
    }

    pub fn list_packs(&self, ws_norm: &str) -> Vec<PackSpec> {
        let Ok(st) = self.state.read() else {
            return Vec::new();
        };
        st.workspaces
            .get(ws_norm)
            .map(|list| list.iter().rev().cloned().collect())
            .unwrap_or_default()
    }

    pub fn list_active_pack_slugs(&self, shared_key: &str, max_items: usize) -> Vec<String> {
        if max_items == 0 {
            return Vec::new();
        }
        let Ok(st) = self.state.read() else {
            return Vec::new();
        };
        st.workspaces
            .get(shared_key)
            .map(|list| {
                list.iter()
                    .rev()
                    .take(max_items)
                    .map(|p| p.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn remove_pack(&self, ws_norm: &str, name: Option<&str>) -> usize {
        let removed = {
            let Ok(mut st) = self.state.write() else {
                return 0;
            };
            if let Some(target) = name.map(str::trim).filter(|s| !s.is_empty()) {
                let mut count = 0usize;
                let mut empty_ws = false;
                if let Some(list) = st.workspaces.get_mut(ws_norm) {
                    let before = list.len();
                    list.retain(|p| p.name != target);
                    count = before - list.len();
                    empty_ws = list.is_empty();
                }
                if empty_ws {
                    st.workspaces.remove(ws_norm);
                    st.ws_ticks.remove(ws_norm);
                }
                count
            } else {
                st.ws_ticks.remove(ws_norm);
                st.workspaces.remove(ws_norm).map_or(0, |v| v.len())
            }
        };
        if removed > 0 {
            if let Ok(mut dedup) = self.dedup.lock() {
                if let Some(target) = name.map(str::trim).filter(|s| !s.is_empty()) {
                    dedup
                        .entries
                        .retain(|k, _| !(k.1.as_ref() == ws_norm && k.2.as_ref() == target));
                } else {
                    dedup.entries.retain(|k, _| k.1.as_ref() != ws_norm);
                }
            }
        }
        removed
    }

    pub fn check_and_mark_delivered(
        &self,
        session: &str,
        ws_norm: &str,
        name: &str,
        digest: u64,
        force: bool,
    ) -> bool {
        let Ok(mut cache) = self.dedup.lock() else {
            return false;
        };
        cache.tick = cache.tick.wrapping_add(1);
        let now_tick = cache.tick;
        let key: DedupKey = (session.into(), ws_norm.into(), name.into());

        if let Some(entry) = cache.entries.get_mut(&key) {
            if !force && entry.0 == digest {
                entry.1 = now_tick;
                return true;
            }
            entry.0 = digest;
            entry.1 = now_tick;
            return false;
        }

        if cache.entries.len() >= MAX_PACK_DEDUP_ENTRIES {
            if let Some(oldest_key) = cache
                .entries
                .iter()
                .min_by_key(|&(_, &(_, t))| t)
                .map(|(k, _)| k.clone())
            {
                cache.entries.remove(&oldest_key);
            }
        }
        cache.entries.insert(key, (digest, now_tick));
        false
    }

    pub fn clear_all(&self) {
        if let Ok(mut st) = self.state.write() {
            st.workspaces.clear();
            st.ws_ticks.clear();
            st.tick = 0;
        }
        if let Ok(mut cache) = self.dedup.lock() {
            cache.entries.clear();
            cache.tick = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_workspace_and_pack_bounds_eviction() {
        let store = PackStore::new();
        for i in 0..=MAX_PACKS_PER_WORKSPACE {
            store
                .put_pack("ws-a", &format!("p{i}"), vec!["a.md#Top".into()], None, "w1")
                .unwrap();
        }
        assert_eq!(store.list_packs("ws-a").len(), MAX_PACKS_PER_WORKSPACE);
        assert!(store.get_pack("ws-a", "p0").is_none());
        assert!(store.get_pack("ws-a", &format!("p{MAX_PACKS_PER_WORKSPACE}")).is_some());

        for w in 0..=MAX_PACK_WORKSPACES {
            store
                .put_pack(&format!("ws-evict-{w}"), "core", vec!["a.md#Top".into()], None, "w1")
                .unwrap();
        }
        assert!(store.get_pack("ws-a", "p1").is_none());
        assert!(store.get_pack(&format!("ws-evict-{MAX_PACK_WORKSPACES}"), "core").is_some());

        assert_eq!(store.remove_pack(&format!("ws-evict-{MAX_PACK_WORKSPACES}"), Some("core")), 1);
        assert!(store.get_pack(&format!("ws-evict-{MAX_PACK_WORKSPACES}"), "core").is_none());
        store.clear_all();
        assert!(store.list_packs("ws-evict-1").is_empty());
    }

    #[test]
    fn rejects_secrets_and_invalid_inputs() {
        let store = PackStore::new();
        let fake_tok = "ghp_1234567890abcdefghij1234";
        assert!(store.put_pack("ws", fake_tok, vec!["a.md#H".into()], None, "w").is_err());
        assert!(store.put_pack("ws", "ok", vec![fake_tok.into()], None, "w").is_err());
        assert!(store.put_pack("ws", "ok", vec!["a.md#H".into()], Some(fake_tok), "w").is_err());
        assert!(store.put_pack("ws", "bad\nname", vec!["a.md#H".into()], None, "w").is_err());
        assert!(store.put_pack("ws", "ok", vec![], None, "w").is_err());
        let max_ok: Vec<String> = (0..MAX_PACK_SELECTORS).map(|i| format!("f{i}.md#H")).collect();
        assert!(store.put_pack("ws", "ok_max", max_ok, None, "w").is_ok());
        let too_many: Vec<String> = (0..=MAX_PACK_SELECTORS).map(|i| format!("f{i}.md#H")).collect();
        assert!(store.put_pack("ws", "ok", too_many, None, "w").is_err());
        let too_big = "x".repeat(MAX_PACK_SUMMARY_BYTES + 1);
        assert!(store.put_pack("ws", "ok", vec!["a.md#H".into()], Some(&too_big), "w").is_err());
    }

    #[test]
    fn session_dedup_handles_hit_miss_force_digest_change_and_cap() {
        let store = PackStore::new();
        assert!(!store.check_and_mark_delivered("s1", "ws", "core", 0xAA, false));
        assert!(store.check_and_mark_delivered("s1", "ws", "core", 0xAA, false));
        assert!(!store.check_and_mark_delivered("s1", "ws", "core", 0xAA, true));
        assert!(!store.check_and_mark_delivered("s1", "ws", "core", 0xBB, false));
        assert!(store.check_and_mark_delivered("s1", "ws", "core", 0xBB, false));
        assert!(!store.check_and_mark_delivered("s2", "ws", "core", 0xBB, false));

        for i in 0..=MAX_PACK_DEDUP_ENTRIES {
            assert!(!store.check_and_mark_delivered(&format!("cap-{i}"), "ws", "p", i as u64, false));
        }
        // Earliest entry ("s1", "ws", "core") was evicted once capacity exceeded 256.
        assert!(!store.check_and_mark_delivered("s1", "ws", "core", 0xBB, false));
    }
}
