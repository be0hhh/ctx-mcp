//! MCP resource readers (`ctx://status`, `ctx://memos`).

use crate::base::json::Json;
use crate::rpc::{call_daemon_or_inproc, workspace_cwd_str};
use std::path::Path;

pub(super) fn read_mcp_resource(uri: &str, repo_root: Option<&Path>) -> Result<Json, String> {
    match uri {
        "ctx://status" => {
            let reply =
                call_daemon_or_inproc(Json::obj(vec![("op", Json::Str("status".to_string()))]));
            let payload = reply.get("status").unwrap_or(&reply).to_json_string();
            Ok(Json::obj(vec![(
                "contents",
                Json::Arr(vec![Json::obj(vec![
                    ("uri", Json::Str("ctx://status".to_string())),
                    ("mimeType", Json::Str("application/json".to_string())),
                    ("text", Json::Str(payload)),
                ])]),
            )]))
        }
        "ctx://memos" => {
            let reply = call_daemon_or_inproc(Json::obj(vec![
                ("op", Json::Str("memo".to_string())),
                ("action", Json::Str("list".to_string())),
                ("cwd", Json::Str(workspace_cwd_str(repo_root))),
                ("explicit_root", Json::Bool(repo_root.is_some())),
            ]));
            let mut md = String::from("# Workspace Findings Board (`ctx://memos`)\n\n");
            if let Some(items) = reply.get("memos").and_then(Json::as_arr) {
                if items.is_empty() {
                    md.push_str("_No workspace memos recorded yet._\n");
                } else {
                    for item in items {
                        let topic = item.get_str("topic").unwrap_or("untitled");
                        let status = item.get_str("status").unwrap_or("fresh");
                        let kind = item.get_str("kind").unwrap_or("finding");
                        md.push_str(&format!(
                            "- **`{}`** (`{}`, status: `{}`)\n",
                            topic, kind, status
                        ));
                    }
                }
            } else {
                md.push_str("_No workspace memos recorded yet._\n");
            }
            Ok(Json::obj(vec![(
                "contents",
                Json::Arr(vec![Json::obj(vec![
                    ("uri", Json::Str("ctx://memos".to_string())),
                    ("mimeType", Json::Str("text/markdown".to_string())),
                    ("text", Json::Str(md)),
                ])]),
            )]))
        }
        other => Err(format!("unknown resource uri: {other}")),
    }
}
