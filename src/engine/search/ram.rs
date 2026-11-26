use super::{
    prioritize_and_balance_file_hits, search_snippet, search_time_left, SearchError, SearchHit,
};
use crate::base::simd::search_lines_literals;
use crate::engine::walk_source_dir;
use crate::rpc::BrokerService;
use std::path::PathBuf;
use std::time::Instant;

const IN_RAM_SEARCH_MAX_FILES: usize = 256;
const PER_FILE_SCAN_CANDIDATES: usize = 64;

pub(super) fn try_in_ram_simd_search(
    svc: &BrokerService,
    needles: &[&str],
    search_roots: &[(PathBuf, PathBuf, bool)],
    cap: usize,
    deadline: Instant,
) -> Result<Option<Vec<SearchHit>>, SearchError> {
    let mut targets: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(32);
    for (canon, ws_root, is_dir) in search_roots {
        search_time_left(deadline)?;
        if *is_dir {
            let mut sub = Vec::new();
            walk_source_dir(
                canon,
                &mut sub,
                (IN_RAM_SEARCH_MAX_FILES + 1).saturating_sub(targets.len()),
            );
            for f in sub {
                if !targets.iter().any(|(existing, _)| existing == &f) {
                    targets.push((f, ws_root.clone()));
                }
                if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                    return Ok(None);
                }
            }
        } else {
            if !targets.iter().any(|(existing, _)| existing == canon) {
                targets.push((canon.clone(), ws_root.clone()));
            }
            if targets.len() > IN_RAM_SEARCH_MAX_FILES {
                return Ok(None);
            }
        }
    }

    let case_sensitive = needles.iter().any(|n| n.chars().any(char::is_uppercase));
    let single_file = targets.len() == 1;
    let per_file_scan_cap = if single_file {
        cap.max(PER_FILE_SCAN_CANDIDATES)
    } else {
        PER_FILE_SCAN_CANDIDATES
    };
    let mut per_file: Vec<Vec<SearchHit>> = Vec::with_capacity(targets.len().min(16));

    for (file, ws_root) in targets {
        search_time_left(deadline)?;
        let Ok(entry) = svc.store.get_full_entry(&file, Some(&ws_root)) else {
            continue;
        };
        let Some(text) = entry.content.as_deref() else {
            continue;
        };
        let line_nums = search_lines_literals(
            text,
            &entry.line_offsets,
            needles,
            case_sensitive,
            per_file_scan_cap,
        );
        if line_nums.is_empty() {
            continue;
        }
        let mut file_hits = Vec::with_capacity(line_nums.len());
        for ln in line_nums {
            file_hits.push(SearchHit {
                path: file.clone(),
                workspace: ws_root.clone(),
                line: ln as usize,
                snippet: search_snippet(entry.line_slice(ln)),
            });
        }
        per_file.push(file_hits);
        // When many files match in a broad directory scan, stop once enough distinct files have hits.
        if per_file.len() >= cap {
            break;
        }
    }
    Ok(Some(prioritize_and_balance_file_hits(per_file, cap)))
}
