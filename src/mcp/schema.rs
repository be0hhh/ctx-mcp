//! MCP tool and resource JSON schemas advertised by `tools/list` and `resources/list`.

use super::MEMO_ACTIONS;
use crate::base::json::Json;
use crate::engine::SEARCH_RESPONSE_BYTES;
use std::borrow::Cow;

pub(super) fn tool_schemas() -> Json {
    let str_array = Json::obj(vec![
        ("type", Json::Str("array".to_string())),
        (
            "items",
            Json::obj(vec![("type", Json::Str("string".to_string()))]),
        ),
    ]);

    let string = || Json::obj(vec![("type", Json::Str("string".into()))]);
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
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("action".into())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_read".to_string())),
            (
                "description",
                Json::Str(
                    "Batch-read full files (<=1 MiB, no 800L cap) or `path:start-end` slices from RAM."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            (
                                "max_bytes",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                            (
                                "force",
                                Json::obj(vec![("type", Json::Str("boolean".to_string()))]),
                            ),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_inspect".to_string())),
            (
                "description",
                Json::Str(
                    "Batch-inspect directories/files (<=80 default): lines, >=600L/>800L flags, ns, #include, [L_start-L_end] symbols."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            (
                                "max_files",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                            (
                                "max_bytes",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                            (
                                "warn_lines",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_outline".to_string())),
            (
                "description",
                Json::Str("Return structural [L_start-L_end] symbol outlines from RAM.".to_string()),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("paths", str_array.clone()),
                            (
                                "max_files",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                            (
                                "max_bytes",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("paths".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_symbols".to_string())),
            (
                "description",
                Json::Str(
                    "Batch symbol bodies (`path#Symbol`; shorthand filenames supported). Set compact=true for <=24L + continuation."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("requests", str_array.clone()),
                            (
                                "compact",
                                Json::obj(vec![("type", Json::Str("boolean".to_string()))]),
                            ),
                            (
                                "max_bytes",
                                Json::obj(vec![("type", Json::Str("integer".to_string()))]),
                            ),
                        ]),
                    ),
                    (
                        "required",
                        Json::Arr(vec![Json::Str("requests".to_string())]),
                    ),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_search".to_string())),
            (
                "description",
                Json::Str(
                    "Search source. Batch 1-4 `root:pattern` strings in q, e.g. `graph:scan_manifests`. \
                     Use a known file, directory, or module stem as each root. Use lowercase patterns for smart-case. \
                     Use `query` for an unscoped lookup. Answer from sufficient hits."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            ("q", str_array.clone()),
                            (
                                "query",
                                Json::obj(vec![("type", Json::Str("string".to_string()))]),
                            ),
                            ("roots", str_array.clone()),
                            (
                                "max_results",
                                Json::obj(vec![
                                    ("type", Json::Str("integer".to_string())),
                                    ("description", Json::Str("Per-query hit limit.".to_string())),
                                ]),
                            ),
                            (
                                "context_lines",
                                Json::obj(vec![
                                    ("type", Json::Str("integer".to_string())),
                                    (
                                        "description",
                                        Json::Str("Adjacent lines when needed. Default 0.".to_string()),
                                    ),
                                ]),
                            ),
                            (
                                "max_bytes",
                                Json::obj(vec![
                                    ("type", Json::Str("integer".to_string())),
                                    ("minimum", Json::Int(1)),
                                    ("maximum", Json::Int(SEARCH_RESPONSE_BYTES as i64)),
                                    (
                                        "description",
                                        Json::Str("Total UTF-8 text budget. Default 8192.".to_string()),
                                    ),
                                ]),
                            ),
                            (
                                "detail",
                                Json::obj(vec![
                                    ("type", Json::Str("string".to_string())),
                                    (
                                        "enum",
                                        Json::Arr(vec![
                                            Json::Str("compact".to_string()),
                                            Json::Str("scopes".to_string()),
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
            ("name", Json::Str("ctx_memo".to_string())),
            (
                "description",
                Json::Str(
                    "Shared in-RAM workspace memo board (`put` | `get` | `list`) for frozen path maps, invariant notes, and cross-agent findings, automatically tagged `[STALE]` if linked files change."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
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
                            (
                                "topic",
                                Json::obj(vec![("type", Json::Str("string".to_string()))]),
                            ),
                            (
                                "summary",
                                Json::obj(vec![("type", Json::Str("string".to_string()))]),
                            ),
                            ("kind", string()),
                            ("paths", str_array),
                        ]),
                    ),
                    ("required", Json::Arr(vec![Json::Str("action".to_string())])),
                ]),
            ),
        ]),
        Json::obj(vec![
            ("name", Json::Str("ctx_elf_audit".to_string())),
            (
                "description",
                Json::Str(
                    "Read-only static ELF64 section/symbol and optional ASM audit for a compiled binary artifact."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Json::obj(vec![
                    ("type", Json::Str("object".to_string())),
                    (
                        "properties",
                        Json::obj(vec![
                            (
                                "elf_path",
                                Json::obj(vec![("type", Json::Str("string".to_string()))]),
                            ),
                            (
                                "asm_path",
                                Json::obj(vec![("type", Json::Str("string".to_string()))]),
                            ),
                        ]),
                    ),
                    (
                        "required",
                        Json::Arr(vec![Json::Str("elf_path".to_string())]),
                    ),
                ]),
            ),
        ]),
    ];
    for tool in &mut tools {
        if let Json::Obj(fields) = tool {
            let read_only = fields.iter().any(|(key, value)| {
                key.as_ref() == "name"
                    && matches!(
                        value.as_str(),
                        Some(
                            "ctx_inspect"
                                | "ctx_read"
                                | "ctx_outline"
                                | "ctx_symbols"
                                | "ctx_search"
                        )
                    )
            });
            if read_only {
                fields.push((
                    Cow::Borrowed("annotations"),
                    Json::obj(vec![
                        ("readOnlyHint", Json::Bool(true)),
                        ("destructiveHint", Json::Bool(false)),
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
            ("uri", Json::Str("ctx://status".to_string())),
            ("name", Json::Str("RAM Context Broker Status".to_string())),
            (
                "description",
                Json::Str(
                    "Live in-RAM cache, shard, session, and snapshot telemetry for agent_ctx."
                        .to_string(),
                ),
            ),
            ("mimeType", Json::Str("application/json".to_string())),
        ]),
        Json::obj(vec![
            ("uri", Json::Str("ctx://memos".to_string())),
            ("name", Json::Str("Workspace Findings Board".to_string())),
            (
                "description",
                Json::Str(
                    "Shared workspace invariants and findings with automatic [STALE] content-hash tracking."
                        .to_string(),
                ),
            ),
            ("mimeType", Json::Str("text/markdown".to_string())),
        ]),
    ])
}
