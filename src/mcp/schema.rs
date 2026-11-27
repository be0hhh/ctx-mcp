//! MCP tool and resource JSON schemas advertised by `tools/list` and `resources/list`.

use super::{is_write_tool, MEMO_ACTIONS};
use crate::base::json::Json;
use crate::engine::SEARCH_RESPONSE_BYTES;
use std::borrow::Cow;

pub(super) fn tool_schemas(write_enabled: bool) -> Json {
    let str_array = Json::obj(vec![
        ("type", Json::Str("array".to_string())),
        (
            "items",
            Json::obj(vec![("type", Json::Str("string".to_string()))]),
        ),
    ]);
    let string = || Json::obj(vec![("type", Json::Str("string".into()))]);
    let int_t = || Json::obj(vec![("type", Json::Str("integer".into()))]);
    let bool_t = || Json::obj(vec![("type", Json::Str("boolean".into()))]);

    let mut tools = vec![
        Json::obj(vec![
            ("name", Json::Str("ctx_capsule".into())),
            (
                "description",
                Json::Str("Prepare or claim a host-addressed subagent launch capsule.".into()),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("action", string()),
                            ("assignment", string()),
                            ("workspace", string()),
                            ("key", string()),
                            ("pack_refs", str_array.clone()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("action".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_read".into())),
            (
                "description",
                Json::Str(
                    "Read files/slices (`path:s-e`) from RAM (auto-delta on small session edits). `hashes=true` adds `ln:h3|` anchors."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_bytes", int_t()),
                            ("force", bool_t()),
                            ("hashes", bool_t()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_inspect".into())),
            (
                "description",
                Json::Str("Triage dirs/files (<=80): lines, flags, includes, symbols.".into()),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_files", int_t()),
                            ("max_bytes", int_t()),
                            ("warn_lines", int_t()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_outline".into())),
            (
                "description",
                Json::Str(
                    "Return structural [L_start-L_end] symbol outlines from RAM (single file uncapped by count; optional max_symbols/max_bytes)."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            ("max_files", int_t()),
                            ("max_bytes", int_t()),
                            ("max_symbols", int_t()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_symbols".into())),
            (
                "description",
                Json::Str(
                    "Symbol/section bodies (`Mod#Sym`, `Mod#Type::method`, `Mod#impl:Type`, `doc.md#Heading`, `cfg.json#a.b`). Full body by default; `compact=true` <=48L preview, `hashes=true` for anchors, `raw=true` disables doc compaction."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("requests", str_array.clone()),
                            ("compact", bool_t()),
                            ("hashes", bool_t()),
                            ("raw", bool_t()),
                            ("max_bytes", int_t()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("requests".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_search".into())),
            (
                "description",
                Json::Str(
                    "Ranked search: 1-6 `Mod:pat` in `q` (smart-case, auto +-1 context on <=6 hits, `code_only=true` skips comments/strings)."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("q", str_array.clone()),
                            ("query", string()),
                            ("roots", str_array.clone()),
                            ("max_results", int_t()),
                            ("context_lines", int_t()),
                            ("code_only", bool_t()),
                            (
                                "max_bytes",
                                Json::obj(vec![
                                    ("type", Json::Str("integer".into())),
                                    ("minimum", Json::Int(1)),
                                    ("maximum", Json::Int(SEARCH_RESPONSE_BYTES as i64)),
                                ]),
                            ),
                            (
                                "detail",
                                Json::obj(vec![
                                    ("type", Json::Str("string".into())),
                                    (
                                        "enum",
                                        Json::Arr(vec![
                                            Json::Str("compact".into()),
                                            Json::Str("scopes".into()),
                                        ]),
                                    ),
                                ]),
                            ),
                        ]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_impact".into())),
            (
                "description",
                Json::Str(
                    "First call before editing: 1-6 `Mod#Sym`, `path:line`, or small `path` targets -> hash-anchored bodies, git status, callers & tests in 1 call."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("targets", str_array.clone()),
                            ("target", string()),
                            ("max_callers", int_t()),
                            ("include_tests", bool_t()),
                            ("include_git_status", bool_t()),
                            ("max_bytes", int_t()),
                        ]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_edit".into())),
            (
                "description",
                Json::Str(
                    "Atomic multi-file `edits`, `creates` (new files/scripts with `executable`), and/or scoped `renames` + optional `verify_absent`. Returns diff & fresh hashes."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            (
                                "edits",
                                Json::obj(vec![
                                    ("type", Json::Str("array".into())),
                                    (
                                        "items",
                                        Json::obj(vec![
                                            ("type", Json::Str("object".into())),
                                            (
                                                "properties",
                                                Json::obj(vec![
                                                    ("path", string()),
                                                    (
                                                        "ops",
                                                        Json::obj(vec![
                                                            ("type", Json::Str("array".into())),
                                                            (
                                                                "items",
                                                                Json::obj(vec![
                                                                    ("type", Json::Str("object".into())),
                                                                    (
                                                                        "properties",
                                                                        Json::obj(vec![
                                                                            (
                                                                                "op",
                                                                                Json::obj(vec![
                                                                                    ("type", Json::Str("string".into())),
                                                                                    (
                                                                                        "enum",
                                                                                        Json::Arr(vec![
                                                                                            Json::Str("replace_lines".into()),
                                                                                            Json::Str("insert_after".into()),
                                                                                        ]),
                                                                                    ),
                                                                                ]),
                                                                            ),
                                                                            ("start", string()),
                                                                            ("end", string()),
                                                                            ("anchor", string()),
                                                                            ("content", string()),
                                                                        ]),
                                                                    ),
                                                                    (
                                                                        "required",
                                                                        Json::Arr(vec![Json::Str("op".into())]),
                                                                    ),
                                                                ]),
                                                            ),
                                                        ]),
                                                    ),
                                                ]),
                                            ),
                                            (
                                                "required",
                                                Json::Arr(vec![
                                                    Json::Str("path".into()),
                                                    Json::Str("ops".into()),
                                                ]),
                                            ),
                                        ]),
                                    ),
                                ]),
                            ),
                            (
                                "renames",
                                Json::obj(vec![
                                    ("type", Json::Str("array".into())),
                                    (
                                        "items",
                                        Json::obj(vec![
                                            ("type", Json::Str("object".into())),
                                            (
                                                "properties",
                                                Json::obj(vec![
                                                    ("old_name", string()),
                                                    ("new_name", string()),
                                                    ("paths", str_array.clone()),
                                                    ("roots", str_array.clone()),
                                                ]),
                                            ),
                                            (
                                                "required",
                                                Json::Arr(vec![
                                                    Json::Str("old_name".into()),
                                                    Json::Str("new_name".into()),
                                                ]),
                                            ),
                                        ]),
                                    ),
                                ]),
                            ),
                            (
                                "creates",
                                Json::obj(vec![
                                    ("type", Json::Str("array".into())),
                                    (
                                        "items",
                                        Json::obj(vec![
                                            ("type", Json::Str("object".into())),
                                            (
                                                "properties",
                                                Json::obj(vec![
                                                    ("path", string()),
                                                    ("content", string()),
                                                    ("executable", bool_t()),
                                                    ("overwrite", bool_t()),
                                                ]),
                                            ),
                                            (
                                                "required",
                                                Json::Arr(vec![
                                                    Json::Str("path".into()),
                                                    Json::Str("content".into()),
                                                ]),
                                            ),
                                        ]),
                                    ),
                                ]),
                            ),
                            ("verify_absent", str_array.clone()),
                            ("dry_run", bool_t()),
                        ]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_git".into())),
            (
                "description",
                Json::Str(
                    "Read-only compact Git inspector (`diff` symbol-aware with hash anchors, `status`, `log`, `show`). Never mutates Git state."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            (
                                "action",
                                Json::obj(vec![
                                    ("type", Json::Str("string".into())),
                                    (
                                        "enum",
                                        Json::Arr(vec![
                                            Json::Str("diff".into()),
                                            Json::Str("status".into()),
                                            Json::Str("log".into()),
                                            Json::Str("show".into()),
                                        ]),
                                    ),
                                ]),
                            ),
                            ("rev", string()),
                            ("staged", bool_t()),
                            ("stat", bool_t()),
                            ("paths", str_array.clone()),
                            ("symbol", string()),
                            ("limit", int_t()),
                            ("hashes", bool_t()),
                            ("max_bytes", int_t()),
                        ]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_memo".into())),
            (
                "description",
                Json::Str(
                    "Shared in-RAM memo, change-feed & Shared Context Packs (`put`|`get`|`list`|`changes`|`pack`|`pack_get`|`packs`), auto-deduped per session."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            (
                                "action",
                                Json::obj(vec![
                                    ("type", Json::Str("string".into())),
                                    (
                                        "enum",
                                        Json::Arr(
                                            MEMO_ACTIONS
                                                .iter()
                                                .map(|&action| Json::Str(action.into()))
                                                .collect(),
                                        ),
                                    ),
                                ]),
                            ),
                            ("topic", string()),
                            ("summary", string()),
                            ("kind", string()),
                            ("since_seq", int_t()),
                            ("force", bool_t()),
                            ("raw", bool_t()),
                            ("max_bytes", int_t()),
                            ("paths", str_array),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("action".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_elf_audit".into())),
            (
                "description",
                Json::Str(
                    "Read-only static ELF64 section/symbol, optional ASM audit, and optional baseline before/after diff."
                        .into(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".into())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("elf_path", string()),
                            ("asm_path", string()),
                            ("baseline_elf_path", string()),
                            ("baseline_asm_path", string()),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("elf_path".into())])),
                ]),
            ),
        ]),
    ];

    if !write_enabled {
        tools.retain(|tool| {
            tool.get_str("name")
                .map_or(true, |name| !is_write_tool(name))
        });
    }

    for tool in &mut tools {
        if let Json::Obj(fields) = tool {
            let name = fields
                .iter()
                .find(|(k, _)| k.as_ref() == "name")
                .and_then(|(_, v)| v.as_str())
                .unwrap_or("");
            if matches!(
                name,
                "ctx_inspect"
                    | "ctx_read"
                    | "ctx_outline"
                    | "ctx_symbols"
                    | "ctx_search"
                    | "ctx_impact"
                    | "ctx_git"
                    | "ctx_elf_audit"
            ) {
                fields.push((
                    Cow::Borrowed("annotations"),
                    Json::obj(vec![
                        ("readOnlyHint", Json::Bool(true)),
                        ("destructiveHint", Json::Bool(false)),
                        ("openWorldHint", Json::Bool(false)),
                    ]),
                ));
            } else if is_write_tool(name) {
                fields.push((
                    Cow::Borrowed("annotations"),
                    Json::obj(vec![
                        ("readOnlyHint", Json::Bool(false)),
                        ("destructiveHint", Json::Bool(true)),
                        ("openWorldHint", Json::Bool(false)),
                    ]),
                ));
            }
            if let Some((_, Json::Obj(schema))) = fields
                .iter_mut()
                .find(|(key, _)| key.as_ref() == "inputSchema")
            {
                if let Some((_, Json::Obj(properties))) = schema
                    .iter_mut()
                    .find(|(key, _)| key.as_ref() == "properties")
                {
                    properties.push((Cow::Borrowed("ctx_context"), string()));
                }
            }
        }
    }
    Json::Arr(tools)
}

pub(super) fn resource_schemas() -> Json {
    Json::Arr(vec![
        Json::obj(vec![
            ("uri", Json::Str("ctx://status".into())),
            ("name", Json::Str("RAM Context Broker Status".into())),
            (
                "description",
                Json::Str(
                    "Live in-RAM cache, write mode, build flavor, and update status for agent_ctx."
                        .into(),
                ),
            ),
            ("mimeType", Json::Str("application/json".into())),
        ]),
        Json::obj(vec![
            ("uri", Json::Str("ctx://memos".into())),
            ("name", Json::Str("Workspace Findings Board".into())),
            (
                "description",
                Json::Str(
                    "Shared workspace invariants and findings with automatic [STALE] content-hash tracking."
                        .into(),
                ),
            ),
            ("mimeType", Json::Str("text/markdown".into())),
        ]),
    ])
}
