//! Bounded 1024-slot per-workspace in-RAM change feed (capped at 64 workspaces) for
//! multi-agent edit awareness (0 external crates, 0 `div`/`idiv`, power-of-2 bitmask ring indexing).

use crate::base::json::Json;
use std::collections::HashMap;
use std::sync::Mutex;

const RING_CAP: usize = 1024;
const RING_MASK: usize = 1023;
const MAX_WORKSPACES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeEvent {
    pub seq: u64,
    pub rel_path: String,
    pub changed_symbols: Vec<String>,
    pub actor: String,
    pub ts_ms: u64,
}

struct WorkspaceFeed {
    head_seq: u64,
    last_ts_ms: u64,
    slots: Vec<Option<ChangeEvent>>,
}

impl WorkspaceFeed {
    fn new() -> Self {
        Self {
            head_seq: 0,
            last_ts_ms: 0,
            slots: vec![None; RING_CAP],
        }
    }
    #[inline]
    fn min_retained_seq(&self) -> u64 {
        self.head_seq.saturating_sub((RING_CAP as u64) - 1).max(1)
    }
}

#[derive(Default)]
pub struct ChangeFeed {
    feeds: Mutex<HashMap<String, WorkspaceFeed>>,
}

impl ChangeFeed {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn record_change(
        &self, ws_norm: &str, rel_path: &str, changed_symbols: Vec<String>, actor: &str, ts_ms: u64,
    ) -> u64 {
        let Ok(mut map) = self.feeds.lock() else { return 0 };
        if !map.contains_key(ws_norm) && map.len() >= MAX_WORKSPACES {
            if let Some(oldest_ws) = map
                .iter()
                .min_by_key(|(_, feed)| feed.last_ts_ms)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_ws);
            }
        }
        let feed = map.entry(ws_norm.to_string()).or_insert_with(WorkspaceFeed::new);
        feed.head_seq = feed.head_seq.saturating_add(1);
        feed.last_ts_ms = ts_ms;
        let seq = feed.head_seq;
        feed.slots[(seq as usize) & RING_MASK] = Some(ChangeEvent {
            seq,
            rel_path: rel_path.to_string(),
            changed_symbols,
            actor: actor.to_string(),
            ts_ms,
        });
        seq
    }

    pub fn recent_changes_summary(&self, shared_key: &str, max_items: usize) -> Vec<String> {
        if max_items == 0 {
            return Vec::new();
        }
        let Ok(map) = self.feeds.lock() else {
            return Vec::new();
        };
        let Some(feed) = map.get(shared_key) else {
            return Vec::new();
        };
        if feed.head_seq == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(max_items.min(16));
        for seq in (feed.min_retained_seq()..=feed.head_seq).rev() {
            if let Some(ev) = &feed.slots[(seq as usize) & RING_MASK] {
                if ev.seq == seq {
                    let mut line = format!("#{} {}", ev.seq, ev.rel_path);
                    if !ev.changed_symbols.is_empty() {
                        line.push_str(" (");
                        let show = ev.changed_symbols.len().min(3);
                        line.push_str(&ev.changed_symbols[..show].join(", "));
                        if ev.changed_symbols.len() > show {
                            line.push_str(", ...");
                        }
                        line.push(')');
                    }
                    if !ev.actor.is_empty() {
                        line.push_str(" by ");
                        line.push_str(&ev.actor);
                    }
                    out.push(line);
                    if out.len() >= max_items {
                        break;
                    }
                }
            }
        }
        out
    }

    #[allow(dead_code)]
    pub fn changes_since(&self, ws_norm: &str, since_seq: u64, max_items: usize) -> (u64, Vec<ChangeEvent>) {
        let Ok(map) = self.feeds.lock() else { return (0, Vec::new()) };
        let Some(feed) = map.get(ws_norm) else { return (0, Vec::new()) };
        let head = feed.head_seq;
        if head == 0 || since_seq >= head || max_items == 0 {
            return (head, Vec::new());
        }
        let start = since_seq.saturating_add(1).max(feed.min_retained_seq());
        let mut out = Vec::with_capacity(((head - start + 1) as usize).min(max_items));
        for seq in start..=head {
            if let Some(ev) = &feed.slots[(seq as usize) & RING_MASK] {
                if ev.seq == seq {
                    out.push(ev.clone());
                    if out.len() >= max_items { break; }
                }
            }
        }
        (head, out)
    }

    #[allow(dead_code)]
    pub fn latest_other_actor_change(
        &self, ws_norm: &str, rel_path: &str, current_actor: &str,
    ) -> Option<ChangeEvent> {
        if current_actor.is_empty() || rel_path.is_empty() { return None; }
        let map = self.feeds.lock().ok()?;
        let feed = map.get(ws_norm)?;
        if feed.head_seq == 0 { return None; }
        for seq in (feed.min_retained_seq()..=feed.head_seq).rev() {
            if let Some(ev) = &feed.slots[(seq as usize) & RING_MASK] {
                if ev.seq == seq && ev.rel_path == rel_path
                    && !ev.actor.is_empty() && ev.actor != current_actor
                {
                    return Some(ev.clone());
                }
            }
        }
        None
    }

    pub fn clear_all(&self) {
        if let Ok(mut map) = self.feeds.lock() {
            map.clear();
        }
    }

    #[allow(dead_code)]
    pub fn to_json(head_seq: u64, events: &[ChangeEvent]) -> Json {
        let rows = events.iter().map(|ev| {
            let syms = ev.changed_symbols.iter().map(|s| Json::Str(s.clone())).collect();
            Json::obj(vec![
                ("seq", Json::Int(ev.seq as i64)),
                ("rel_path", Json::Str(ev.rel_path.clone())),
                ("changed_symbols", Json::Arr(syms)),
                ("actor", Json::Str(ev.actor.clone())),
                ("ts_ms", Json::Int(ev.ts_ms as i64)),
            ])
        }).collect();
        Json::obj(vec![("head_seq", Json::Int(head_seq as i64)), ("events", Json::Arr(rows))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_wraparound_and_changes_since_ordering() {
        let feed = ChangeFeed::new();
        for i in 1..=1100u64 {
            assert_eq!(feed.record_change("ws-a", &format!("src/f{i}.rs"), vec![format!("@f{i}")], "w1", 1000 + i), i);
        }
        let (head, all) = feed.changes_since("ws-a", 0, 2048);
        assert_eq!((head, all.len(), all[0].seq, all[RING_CAP - 1].seq), (1100, RING_CAP, 77, 1100));
        assert!(all.windows(2).all(|w| w[0].seq + 1 == w[1].seq));

        let (head2, slice) = feed.changes_since("ws-a", 1096, 2);
        assert_eq!(head2, 1100);
        assert_eq!(slice.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1097, 1098]);
        assert_eq!(feed.changes_since("ws-a", 1100, 10), (1100, Vec::new()));

        let doc = ChangeFeed::to_json(head2, &slice);
        let arr = doc.get("events").and_then(Json::as_arr).unwrap();
        assert_eq!((doc.get_i64("head_seq"), arr.len(), arr[0].get_str("rel_path"), arr[1].get_i64("ts_ms")),
            (Some(1100), 2, Some("src/f1097.rs"), Some(2098)));

        let summary = feed.recent_changes_summary("ws-a", 3);
        assert_eq!(summary.len(), 3);
        assert!(summary[0].starts_with("#1100 src/f1100.rs (@f1100) by w1"));
        assert!(summary[2].starts_with("#1098 src/f1098.rs"));

        // Workspace cap evicts oldest latest ts_ms cleanly.
        let bounded = ChangeFeed::new();
        for w in 0..=(MAX_WORKSPACES as u64) {
            bounded.record_change(&format!("ws-{w}"), "a.rs", vec![], "a", 100 + w);
        }
        assert_eq!(bounded.changes_since("ws-0", 0, 4).1.len(), 0);
        assert_eq!(bounded.changes_since(&format!("ws-{MAX_WORKSPACES}"), 0, 4).1.len(), 1);
    }

    #[test]
    fn latest_other_actor_change_isolates_actors_files_and_workspaces() {
        let feed = ChangeFeed::default();
        feed.record_change("ws-a", "src/a.rs", vec!["@one".into()], "agent-1", 10);
        feed.record_change("ws-a", "src/a.rs", vec!["@anon".into()], "", 20);
        feed.record_change("ws-a", "src/b.rs", vec!["@other".into()], "agent-2", 30);
        feed.record_change("ws-a", "src/a.rs", vec!["@two".into()], "agent-2", 40);
        feed.record_change("ws-a", "src/a.rs", vec!["@three".into()], "agent-1", 50);
        feed.record_change("ws-b", "src/a.rs", vec!["@wsb".into()], "agent-3", 60);

        let s1 = feed.latest_other_actor_change("ws-a", "src/a.rs", "agent-1").unwrap();
        let s2 = feed.latest_other_actor_change("ws-a", "src/a.rs", "agent-2").unwrap();
        assert_eq!((s1.seq, s1.actor.as_str(), s2.seq, s2.actor.as_str()), (4, "agent-2", 5, "agent-1"));
        assert!(feed.latest_other_actor_change("ws-a", "src/a.rs", "").is_none());
        assert!(feed.latest_other_actor_change("ws-a", "src/b.rs", "agent-2").is_none());
        assert_eq!(feed.latest_other_actor_change("ws-b", "src/a.rs", "agent-1").map(|e| e.actor), Some("agent-3".into()));

        feed.clear_all();
        assert_eq!(feed.changes_since("ws-a", 0, 10), (0, Vec::new()));
    }
}
