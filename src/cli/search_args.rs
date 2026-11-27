//! Argument parser for `ctx search` (positional, `-q` shorthand, and `--batch-json`).

use super::cli_session_fields;
use crate::base::json::{self, Json, JsonKey};
use crate::rpc::workspace_cwd_str;
use std::borrow::Cow;

pub fn parse_search_cli(args: &[String]) -> Result<Json, String> {
    let mut fields: Vec<(JsonKey, Json)> = vec![
        (Cow::Borrowed("op"), Json::Str("search".into())),
        (Cow::Borrowed("cwd"), Json::Str(workspace_cwd_str(None))),
    ];
    let mut args = args.iter();
    let mut shorthand = Vec::new();
    let mut batch = None;
    let mut positional = Vec::new();
    let mut has_detail = false;
    let mut wants_context = false;
    let mut session: Option<String> = None;
    while let Some(arg) = args.next() {
        let option = arg.as_str();
        let value = |args: &mut std::slice::Iter<'_, String>| {
            args.next()
                .cloned()
                .ok_or_else(|| format!("missing value for {option}"))
        };
        match option {
            "-q" | "--q" => shorthand.push(Json::Str(value(&mut args)?)),
            "--batch-json" => {
                if batch.is_some() {
                    return Err("provide --batch-json once".into());
                }
                batch = match json::parse(&value(&mut args)?) {
                    Ok(array @ Json::Arr(_)) => Some(array),
                    _ => return Err("--batch-json expects a JSON array".into()),
                };
            }
            "--max-results" | "--context-lines" | "--max-bytes" => {
                let number = value(&mut args)?
                    .parse::<i64>()
                    .map_err(|_| format!("{option} expects an integer"))?;
                let key: &'static str = match option {
                    "--max-results" => "max_results",
                    "--context-lines" => {
                        wants_context = number > 0;
                        "context_lines"
                    }
                    _ => "max_bytes",
                };
                fields.retain(|(name, _)| name.as_ref() != key);
                fields.push((Cow::Borrowed(key), Json::Int(number)));
            }
            "--detail" => {
                has_detail = true;
                fields.retain(|(name, _)| name.as_ref() != "detail");
                fields.push((Cow::Borrowed("detail"), Json::Str(value(&mut args)?)));
            }
            "--code-only" => {
                fields.retain(|(name, _)| name.as_ref() != "code_only");
                fields.push((Cow::Borrowed("code_only"), Json::Bool(true)));
            }
            "--session" => {
                session = Some(value(&mut args)?);
            }
            "--" => {
                positional.extend(args.map(|value| Json::Str(value.clone())));
                break;
            }
            _ => positional.push(Json::Str(arg.clone())),
        }
    }
    let positionals = !positional.is_empty();
    let has_shorthand = !shorthand.is_empty();
    if u8::from(positionals) + u8::from(has_shorthand) + u8::from(batch.is_some()) != 1 {
        return Err(
            "provide one search form: <query> [roots...], -q <root:query> [-q ...], or --batch-json '<array>'"
                .into(),
        );
    }
    if let Some(batch) = batch {
        fields.push((Cow::Borrowed("queries"), batch));
    } else if has_shorthand {
        fields.push((Cow::Borrowed("q"), Json::Arr(shorthand)));
    } else {
        if !has_detail && !wants_context {
            fields.push((Cow::Borrowed("detail"), Json::Str("scopes".into())));
        }
        let mut items = positional.into_iter();
        if let Some(query) = items.next() {
            fields.push((Cow::Borrowed("query"), query));
        }
        fields.push((Cow::Borrowed("roots"), Json::Arr(items.collect())));
    }
    for (k, v) in cli_session_fields(session.as_deref()) {
        fields.push((Cow::Borrowed(k), v));
    }
    Ok(Json::Obj(fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_search_cli_handles_all_three_forms_and_rejects_mixing() {
        let q = parse_search_cli(&svec(&[
            "-q",
            "Mod:needle",
            "--max-bytes",
            "4096",
            "--session",
            "agy:s1",
        ]))
        .expect("shorthand");
        assert_eq!(q.get_str("op"), Some("search"));
        assert_eq!(q.get_i64("max_bytes"), Some(4096));
        assert_eq!(q.get_str("session"), Some("agy:s1"));
        assert_eq!(
            q.get("q").and_then(Json::as_arr).map(|a| a.len()),
            Some(1)
        );

        let pos = parse_search_cli(&svec(&["needle", "src"])).expect("positional");
        assert_eq!(pos.get_str("query"), Some("needle"));
        assert_eq!(pos.get_str("detail"), Some("scopes"));

        let batch = parse_search_cli(&svec(&["--batch-json", r#"[{"query":"foo"}]"#]))
            .expect("batch");
        assert!(batch.get("queries").and_then(Json::as_arr).is_some());

        assert!(parse_search_cli(&svec(&["-q", "a:b", "positional"])).is_err());
        assert!(parse_search_cli(&svec(&[])).is_err());
    }
}
