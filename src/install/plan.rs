//! Transactional install planner: snapshots existing files, validates edits before
//! touching disk, writes unique `.bak` backups, and atomically replaces targets.

use crate::base::json::{self, format_pretty_json, Json};
use crate::base::simd::{fast_hash64, fnv1a_64};
use crate::rpc::stop_daemon_for_install;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(PartialEq)]
struct Snapshot {
    data: Option<Vec<u8>>,
    mode: u32,
}

fn snapshot(path: &Path) -> Result<Snapshot, String> {
    for parent in path.ancestors().skip(1).filter(|p| !p.as_os_str().is_empty()) {
        match fs::symlink_metadata(parent) {
            Ok(m) if !m.is_dir() => return Err(format!("invalid destination parent {}", parent.display())),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => return Err(format!("refusing non-regular destination {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Snapshot { data: None, mode: 0o600 });
        }
        Err(e) => return Err(format!("{}: {}", path.display(), e)),
    };
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = {
        let _ = meta;
        0o600
    };
    Ok(Snapshot {
        data: Some(fs::read(path).map_err(|e| format!("{}: {}", path.display(), e))?),
        mode,
    })
}

pub(super) struct Target {
    pub(super) path: PathBuf,
    before: Snapshot,
    after: Option<Vec<u8>>,
    mode: u32,
}

impl Target {
    pub(super) fn content(&self) -> Option<&[u8]> {
        self.after.as_deref().or(self.before.data.as_deref())
    }

    pub(super) fn changed(&self) -> bool {
        self.after.is_some()
            && (self.content() != self.before.data.as_deref()
                || (cfg!(unix) && self.mode != self.before.mode))
    }

    fn recheck(&self) -> Result<(), String> {
        if snapshot(&self.path)? != self.before {
            return Err(format!("{} changed since preview", self.path.display()));
        }
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct InstallPlan(pub(super) Vec<Target>);

impl InstallPlan {
    pub(super) fn target(&mut self, path: &Path) -> Result<&mut Target, String> {
        let index = match self.0.iter().position(|t| t.path == path) {
            Some(i) => i,
            None => {
                let before = snapshot(path)?;
                self.0.push(Target {
                    path: path.to_owned(),
                    mode: before.mode,
                    before,
                    after: None,
                });
                self.0.len() - 1
            }
        };
        Ok(&mut self.0[index])
    }

    pub(super) fn text(&mut self, path: &Path) -> Result<Option<String>, String> {
        self.target(path)?
            .content()
            .map(|b| {
                std::str::from_utf8(b)
                    .map(str::to_owned)
                    .map_err(|_| format!("{}: invalid UTF-8", path.display()))
            })
            .transpose()
    }

    pub(super) fn set(&mut self, path: &Path, data: Vec<u8>, mode: Option<u32>) -> Result<(), String> {
        let target = self.target(path)?;
        target.after = Some(data);
        if let Some(m) = mode {
            target.mode = m;
        }
        Ok(())
    }

    pub(super) fn json(&mut self, path: &Path) -> Result<Json, String> {
        let Some(raw) = self.text(path)? else {
            return Ok(Json::Obj(vec![]));
        };
        if raw.trim().is_empty() {
            return Ok(Json::Obj(vec![]));
        }
        let val = json::parse_config(&raw)
            .map_err(|e| format!("{}: invalid JSON: {}", path.display(), e))?;
        if val.as_obj().is_none() {
            return Err(format!("{}: expected JSON object", path.display()));
        }
        Ok(val)
    }

    pub(super) fn set_json(&mut self, path: &Path, old: &Json, new: Json) -> Result<(), String> {
        if &new != old {
            self.set(
                path,
                format!("{}\n", format_pretty_json(&new, 0)).into_bytes(),
                None,
            )?;
        }
        Ok(())
    }

    pub(super) fn apply(&self, binary: &Path) -> Result<(), String> {
        for file in &self.0 {
            file.recheck()?;
        }
        for file in self.0.iter().filter(|f| f.changed()) {
            file.recheck()?;
            let parent = file.path.parent().ok_or("missing destination directory")?;
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            if let Some(bytes) = &file.before.data {
                write_unique_sibling(&file.path, "bak", bytes, 0o600)?;
            }
            let staged = write_unique_sibling(
                &file.path,
                &format!("tmp.{}", std::process::id()),
                file.content().ok_or("missing replacement")?,
                file.mode,
            )?;
            let replaced = (|| {
                file.recheck()?;
                if file.path == binary {
                    stop_daemon_for_install()?;
                }
                fs::rename(&staged, &file.path)
                    .map_err(|e| format!("replace {}: {}", file.path.display(), e))
            })();
            if replaced.is_err() {
                let _ = fs::remove_file(staged);
            }
            replaced?;
        }
        Ok(())
    }
}

fn write_unique_sibling(
    path: &Path,
    suffix: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<PathBuf, String> {
    let name = path.file_name().ok_or("invalid filename")?;
    for i in 0u64.. {
        let mut filename = name.to_os_string();
        filename.push(format!(".{suffix}"));
        if i > 0 {
            filename.push(format!(".{i}"));
        }
        let sibling = path.with_file_name(filename);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut out = match options.open(&sibling) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {}", sibling.display(), e)),
        };
        let result = (|| -> std::io::Result<()> {
            out.write_all(bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                out.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            #[cfg(not(unix))]
            let _ = mode;
            out.sync_all()
        })();
        if let Err(e) = result {
            drop(out);
            let _ = fs::remove_file(&sibling);
            return Err(e.to_string());
        }
        return Ok(sibling);
    }
    Err("no free sibling filename".into())
}

pub(super) fn plan_binary(plan: &mut InstallPlan, dest: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let source = fs::read(exe).map_err(|e| e.to_string())?;
    plan_binary_bytes(plan, dest, source)
}

fn plan_binary_bytes(
    plan: &mut InstallPlan,
    dest: &Path,
    source: Vec<u8>,
) -> Result<(), String> {
    let stamp_path = dest.with_file_name(".ctx.sha256");
    let stamp = plan.text(&stamp_path)?;
    let old = plan.target(dest)?.content();
    let fast_stamp = |bytes: &[u8]| format!("{:016x}\n", fast_hash64(bytes));
    let legacy_stamp = |bytes: &[u8]| format!("{:016x}\n", fnv1a_64(bytes));
    let stamp_matches = |s: &str, bytes: &[u8]| s == fast_stamp(bytes) || s == legacy_stamp(bytes);
    let new_stamp = fast_stamp(&source);
    if let Some(old) = old {
        let stamp_ok = stamp.as_deref().is_some_and(|s| stamp_matches(s, old));
        if !stamp_ok && old != source.as_slice() {
            return Err(format!("unmanaged executable {}", dest.display()));
        }
    }
    if let Some(s) = &stamp {
        let old_ok = old.is_some_and(|b| stamp_matches(s, b));
        if !old_ok && s != &new_stamp {
            return Err(format!("unmanaged stamp {}", stamp_path.display()));
        }
    }
    plan.set(dest, source, Some(0o755))?;
    plan.set(&stamp_path, new_stamp.into_bytes(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_temp_dir(tag: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ctx-plan-test-{}-{}-{}",
            tag,
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        fs::canonicalize(&dir).unwrap_or(dir)
    }

    #[test]
    fn legacy_fnv1a_stamp_upgrades_smoothly_to_fast_hash64() {
        let dir = make_temp_dir("legacy-upgrade");
        let dest = dir.join("ctx");
        let stamp_path = dir.join(".ctx.sha256");
        let old_bin = b"legacy-ctx-binary-payload-v1";
        let new_bin = b"upgraded-ctx-binary-payload-v2";

        fs::write(&dest, old_bin).expect("write old binary");
        let legacy = format!("{:016x}\n", fnv1a_64(old_bin));
        fs::write(&stamp_path, &legacy).expect("write legacy stamp");

        // Upgrade must succeed without "unmanaged executable" or "unmanaged stamp".
        let mut plan = InstallPlan::default();
        plan_binary_bytes(&mut plan, &dest, new_bin.to_vec()).expect("legacy stamp upgrade");
        // Pass a sentinel path so test never touches any host daemon.
        plan.apply(&dir.join("__skip_daemon_stop__")).expect("apply upgrade");

        assert_eq!(fs::read(&dest).expect("read upgraded binary"), new_bin);
        let expected_fast = format!("{:016x}\n", fast_hash64(new_bin));
        assert_eq!(
            fs::read_to_string(&stamp_path).expect("read new stamp"),
            expected_fast
        );

        // Re-running with identical binary + fast_hash64 stamp is a no-op.
        let mut plan2 = InstallPlan::default();
        plan_binary_bytes(&mut plan2, &dest, new_bin.to_vec()).expect("idempotent re-plan");
        assert!(plan2.0.iter().all(|t| !t.changed()));

        // Foreign executable with non-matching stamp is still refused.
        let foreign_dest = dir.join("ctx-foreign");
        let foreign_stamp = dir.join(".ctx.sha256");
        fs::write(&foreign_dest, b"some-unrelated-tool").expect("write foreign binary");
        fs::write(&foreign_stamp, "0000000000000000\n").expect("write wrong stamp");
        let mut plan3 = InstallPlan::default();
        let err = plan_binary_bytes(&mut plan3, &foreign_dest, new_bin.to_vec())
            .expect_err("must reject unmanaged executable");
        assert!(err.contains("unmanaged executable"), "unexpected error: {err}");

        let _ = fs::remove_dir_all(&dir);
    }
}
