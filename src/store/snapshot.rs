//! Metadata-only `0600` reboot snapshot (`ACTXSNP2`, format_tag=5, zero raw source).

use super::{
    now_ms, shard_idx_for, CachedFile, RamStore, CLEANED_EVICTED_BIT, MAX_SINGLE_FILE_CACHE_BYTES,
    SNAPSHOT_DISK_CAP_BYTES,
};
use crate::base::security::{ensure_private_dir, write_private_0600};
use crate::base::simd::fast_hash64;
use crate::parser::{SymbolKind, SymbolSpan};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

pub const SNAPSHOT_MAGIC: &[u8; 8] = b"ACTXSNP2";
pub const SNAPSHOT_FORMAT_TAG: u32 = 5;

impl RamStore {
    pub fn save_snapshot_if_dirty(&self, force: bool) -> Result<(), String> {
        if !self.dirty_since_save.load(Ordering::Relaxed) && !force {
            return Ok(());
        }
        let now = now_ms();
        let last = self.last_save_ms.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < 45_000 {
            return Ok(());
        }
        self.save_snapshot()
    }

    pub fn save_snapshot(&self) -> Result<(), String> {
        if let Some(parent) = self.snapshot_path.parent() {
            ensure_private_dir(parent)?;
        }

        let mut entries: Vec<Arc<CachedFile>> = Vec::new();
        for sh in self.shards.iter() {
            if let Ok(guard) = sh.read() {
                entries.extend(guard.values().cloned());
            }
        }
        entries.sort_unstable_by(|a, b| {
            b.last_access
                .load(Ordering::Relaxed)
                .cmp(&a.last_access.load(Ordering::Relaxed))
        });

        let mut payload = Vec::with_capacity(64 * 1024);
        let mut count: u32 = 0;
        for entry in entries {
            let approx = 64 + entry.norm_path.len() + entry.rel_path.len() + entry.symbols.len() * 36;
            if payload.len() + approx > SNAPSHOT_DISK_CAP_BYTES {
                break;
            }
            write_str(&mut payload, &entry.norm_path);
            write_str(&mut payload, &entry.rel_path);
            payload.extend_from_slice(&entry.mtime_ns.to_le_bytes());
            payload.extend_from_slice(&entry.ctime_ns.to_le_bytes());
            payload.extend_from_slice(&entry.ino.to_le_bytes());
            payload.extend_from_slice(&entry.content_hash64.to_le_bytes());
            payload.extend_from_slice(&entry.size_bytes.to_le_bytes());
            payload.extend_from_slice(&entry.line_count.to_le_bytes());
            payload.extend_from_slice(&(entry.symbols.len() as u32).to_le_bytes());
            for sym in entry.symbols.iter() {
                payload.push(sym.kind as u8);
                write_str(&mut payload, &sym.name);
                payload.extend_from_slice(&sym.start_line.to_le_bytes());
                payload.extend_from_slice(&sym.end_line.to_le_bytes());
            }
            count += 1;
        }

        let checksum = fast_hash64(&payload);
        let mut full = Vec::with_capacity(24 + payload.len());
        full.extend_from_slice(SNAPSHOT_MAGIC);
        full.extend_from_slice(&SNAPSHOT_FORMAT_TAG.to_le_bytes());
        full.extend_from_slice(&count.to_le_bytes());
        full.extend_from_slice(&checksum.to_le_bytes());
        full.extend_from_slice(&payload);

        write_private_0600(&self.snapshot_path, &full)?;
        self.dirty_since_save.store(false, Ordering::Relaxed);
        self.last_save_ms.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    pub fn load_snapshot(&self) -> Result<usize, String> {
        if !self.snapshot_path.is_file() {
            return Ok(0);
        }
        let mut f = File::open(&self.snapshot_path).map_err(|e| e.to_string())?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < 24 || len as usize > SNAPSHOT_DISK_CAP_BYTES + 1024 {
            return Err("snapshot size out of bounds".to_string());
        }
        let mut raw = Vec::with_capacity(len as usize);
        f.read_to_end(&mut raw).map_err(|e| e.to_string())?;

        if &raw[0..8] != SNAPSHOT_MAGIC {
            return Err("snapshot magic mismatch (expected ACTXSNP2)".to_string());
        }
        let tag = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        if tag != SNAPSHOT_FORMAT_TAG {
            return Err("snapshot format mismatch".to_string());
        }
        let count = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
        let expected_sum = u64::from_le_bytes([
            raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
        ]);
        let body = &raw[24..];
        if fast_hash64(body) != expected_sum {
            return Err("snapshot checksum mismatch".to_string());
        }

        let mut cur = 0usize;
        let mut loaded = 0usize;
        for _ in 0..count {
            let norm = read_str_slice(body, &mut cur)?;
            let rel = read_str_slice(body, &mut cur)?;
            let mtime_ns = read_u64(body, &mut cur)?;
            let ctime_ns = read_u64(body, &mut cur)?;
            let ino = read_u64(body, &mut cur)?;
            let content_hash64 = read_u64(body, &mut cur)?;
            let size_bytes = read_u32(body, &mut cur)?;
            let line_count = read_u32(body, &mut cur)?;
            let sym_count = read_u32(body, &mut cur)? as usize;
            if sym_count > 100_000 {
                return Err("corrupt symbol count".to_string());
            }
            let mut symbols = Vec::with_capacity(sym_count.min(1024));
            for _ in 0..sym_count {
                let kind_tag = read_u8(body, &mut cur)?;
                let kind = SymbolKind::from_tag(kind_tag)
                    .ok_or_else(|| "invalid symbol kind tag in snapshot".to_string())?;
                let name = read_str_slice(body, &mut cur)?;
                let start_line = read_u32(body, &mut cur)?;
                let end_line = read_u32(body, &mut cur)?;
                symbols.push(SymbolSpan {
                    kind,
                    name: name.into(),
                    signature: "".into(),
                    start_line,
                    end_line,
                });
            }
            let (path_id, key_arc) = self.intern_path(norm);
            let s_idx = shard_idx_for(norm);
            let tick = self.next_tick();
            if let Ok(mut guard) = self.shards[s_idx].write() {
                guard.insert(
                    Arc::clone(&key_arc),
                    Arc::new(CachedFile {
                        norm_path: key_arc,
                        rel_path: rel.into(),
                        mtime_ns,
                        ctime_ns,
                        ino,
                        content_hash64,
                        content_bloom: [0, 0],
                        path_id,
                        size_bytes,
                        line_count,
                        ram_charge: 0,
                        line_offsets: Box::new([]),
                        symbols: Arc::from(symbols),
                        content: None,
                        cleaned_code: OnceLock::new(),
                        cleaned_charge: AtomicU32::new(CLEANED_EVICTED_BIT),
                        last_access: AtomicU64::new(tick),
                    }),
                );
                loaded += 1;
            }
        }
        Ok(loaded)
    }
}

pub fn verify_snapshot_metadata_only(path: &Path) -> Result<(u32, u64), String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!("snapshot permissions {:o} are wider than 0600", mode));
        }
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    if raw.len() < 24 {
        return Err("snapshot header truncated".to_string());
    }
    if &raw[0..8] != SNAPSHOT_MAGIC {
        return Err("snapshot magic is not ACTXSNP2".to_string());
    }
    let tag = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    if tag != SNAPSHOT_FORMAT_TAG {
        return Err(format!("unexpected snapshot format tag {}", tag));
    }
    let count = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let expected_sum = u64::from_le_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ]);
    if fast_hash64(&raw[24..]) != expected_sum {
        return Err("snapshot checksum mismatch".to_string());
    }
    Ok((count, meta.len()))
}

#[inline]
fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

#[inline]
fn read_u8(buf: &[u8], cur: &mut usize) -> Result<u8, String> {
    if *cur + 1 > buf.len() {
        return Err("truncated u8".to_string());
    }
    let v = buf[*cur];
    *cur += 1;
    Ok(v)
}

#[inline]
fn read_u32(buf: &[u8], cur: &mut usize) -> Result<u32, String> {
    let i = *cur;
    if i + 4 > buf.len() {
        return Err("truncated u32".to_string());
    }
    let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
    *cur = i + 4;
    Ok(v)
}

#[inline]
fn read_u64(buf: &[u8], cur: &mut usize) -> Result<u64, String> {
    let i = *cur;
    if i + 8 > buf.len() {
        return Err("truncated u64".to_string());
    }
    let v = u64::from_le_bytes([
        buf[i],
        buf[i + 1],
        buf[i + 2],
        buf[i + 3],
        buf[i + 4],
        buf[i + 5],
        buf[i + 6],
        buf[i + 7],
    ]);
    *cur = i + 8;
    Ok(v)
}

#[inline]
fn read_str_slice<'a>(buf: &'a [u8], cur: &mut usize) -> Result<&'a str, String> {
    let len = read_u32(buf, cur)? as usize;
    if len > (MAX_SINGLE_FILE_CACHE_BYTES << 1) || *cur + len > buf.len() {
        return Err("truncated string".to_string());
    }
    let s = std::str::from_utf8(&buf[*cur..*cur + len])
        .map_err(|_| "invalid UTF-8 in snapshot".to_string())?;
    *cur += len;
    Ok(s)
}
