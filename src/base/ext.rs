//! Zero-overhead compile-time project policy hook.
//!
//! Public `ctx` (`be0hhh/ctx-mcp`) uses `DefaultPolicy` (empty `const` tables and no-ops
//! eliminated under Fat LTO). External downstream overlay binaries depend on
//! `ctx` as a library crate and register a compile-time `ProjectPolicy` once at startup
//! before dispatching CLI/MCP/daemon commands — zero runtime config files.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub trait ProjectPolicy: Send + Sync {
    /// Build identity reported in `ctx status` and `ctx doctor` (`"upstream"` for public `ctx`).
    fn build_flavor(&self) -> &'static str {
        "upstream"
    }

    /// Optional custom rebuild hint shown by `ctx update` when `build_flavor() != "upstream"`.
    fn update_hint(&self) -> Option<&'static str> {
        None
    }

    /// Optional shell-free rebuild argv `(program, args)` executed by `ctx update --rebuild`
    /// for custom local builds.
    fn rebuild_command(&self) -> Option<(&'static str, &'static [&'static str])> {
        None
    }

    /// Returns true if project-specific rules apply to `ws_root`.
    #[allow(dead_code)]
    fn is_workspace_active(&self, _ws_root: &Path) -> bool {
        false
    }

    /// Compile-time project-specific sensitive path guard (read and/or write).
    fn is_extra_sensitive_path(
        &self,
        _path: &Path,
        _ws_root: Option<&Path>,
        _for_write: bool,
    ) -> bool {
        false
    }

    /// Optional compile-time domain shorthand resolution for `ctx_search` (e.g. `Capital` -> dir).
    fn resolve_domain_root(&self, _token: &str, _ws_root: &Path) -> Option<Vec<PathBuf>> {
        None
    }

    /// Small compile-time ranking adjustment in `ctx_search` (`> 0` boosts, `< 0` demotes).
    fn path_rank_bonus(&self, _rel_path: &str, _ws_root: &Path) -> i8 {
        0
    }

    /// Additional related paths surfaced by `ctx_impact` for `target_rel`.
    fn extra_impact_paths(&self, _target_rel: &str, _ws_root: &Path) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Non-blocking in-RAM static warnings emitted after `ctx_edit` and in `ctx_git diff`.
    fn post_edit_lint(
        &self,
        _rel_path: &str,
        _ws_root: &Path,
        _content: &str,
        _dir_file_count: usize,
    ) -> Vec<String> {
        Vec::new()
    }

    /// Extra compile-time suspect symbols checked by `ctx_elf_audit`.
    fn extra_elf_suspect_symbols(&self) -> &'static [&'static str] {
        &[]
    }

    /// Optional compile-time virtual Shared Context Packs (e.g. `project:core`).
    /// Virtual packs take strict precedence over agent-registered packs of the same name.
    fn list_virtual_packs(&self, _ws_root: &Path) -> &'static [&'static str] {
        &[]
    }

    /// Resolves a named virtual pack into `(label_summary, selector_list)` for `ws_root`.
    fn resolve_virtual_pack(&self, _ws_root: &Path, _name: &str) -> Option<(String, Vec<String>)> {
        None
    }
}

pub struct DefaultPolicy;

impl ProjectPolicy for DefaultPolicy {}

static DEFAULT_POLICY: DefaultPolicy = DefaultPolicy;
static ACTIVE_POLICY: OnceLock<&'static dyn ProjectPolicy> = OnceLock::new();

/// Registers the compile-time project policy once at process startup.
#[allow(dead_code)]
pub fn install_policy(policy: &'static dyn ProjectPolicy) {
    let _ = ACTIVE_POLICY.set(policy);
}

#[inline]
pub fn policy() -> &'static dyn ProjectPolicy {
    *ACTIVE_POLICY.get().unwrap_or(&(&DEFAULT_POLICY as &'static dyn ProjectPolicy))
}
