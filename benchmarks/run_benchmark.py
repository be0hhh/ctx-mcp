#!/usr/bin/env python3
"""Reproducible `ctx-mcp` benchmark runner (synthetic 1-200 agent waves + optional live A/B).

Zero external Python dependencies. Supports:
  - `--synthetic-only`: runs `ctx bench --agents 1,10,50,100,200 --ops 25 --json`
  - `--tasks-json <path>`: runs parallel `direct` (rg) vs `ctx` (MCP) waves on Antigravity (`agy`)
    and/or Codex (`codex`) and emits a complete summary with absolute and percentage deltas.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_RS = REPO_ROOT / "src" / "main.rs"


def ensure_ctx_binary(explicit_bin: str | None, tmp_dir: Path) -> Path:
    if explicit_bin:
        p = Path(explicit_bin).expanduser().resolve()
        if p.is_file():
            return p
    installed = Path.home() / ".local" / "bin" / ("ctx.exe" if os.name == "nt" else "ctx")
    if installed.is_file():
        return installed
    found_path = shutil.which("ctx")
    if found_path:
        return Path(found_path)
    rustc = shutil.which("rustc") or str(Path.home() / ".cargo" / "bin" / ("rustc.exe" if os.name == "nt" else "rustc"))
    if not Path(rustc).is_file() and not shutil.which(rustc):
        raise RuntimeError("Neither `ctx` nor `rustc` found in PATH")
    out = tmp_dir / ("ctx.exe" if os.name == "nt" else "ctx")
    subprocess.run([rustc, "--edition", "2021", "-C", "opt-level=3", str(MAIN_RS), "-o", str(out)], check=True)
    return out


def extract_citations(text: str, workspace: Path) -> set[tuple[str, int]]:
    refs: set[tuple[str, int]] = set()
    prefixes = (f"file://{workspace.as_posix()}/", f"{workspace.as_posix()}/", "./")
    for pat in (
        r"((?:file://)?[\w./-]+\.(?:hpp|cpp|py|rs|ts|tsx|js|go|h|cc)):(\d+)",
        r"((?:file://)?[\w./-]+\.(?:hpp|cpp|py|rs|ts|tsx|js|go|h|cc))#L(\d+)",
    ):
        for m in re.finditer(pat, text):
            raw_p = m.group(1)
            for pref in prefixes:
                if raw_p.startswith(pref):
                    raw_p = raw_p[len(pref) :]
                    break
            refs.add((raw_p, int(m.group(2))))
    return refs


def resolve_ground_truth(workspace: Path, tasks: list[dict[str, Any]]) -> dict[str, list[set[tuple[str, int]]]]:
    gt: dict[str, list[set[tuple[str, int]]]] = {}
    for item in tasks:
        tid = item["id"]
        sets: list[set[tuple[str, int]]] = []
        for suffix, needles in item["anchors"]:
            matched = {
                (p.relative_to(workspace).as_posix(), ln)
                for p in workspace.rglob(Path(suffix).name)
                if p.is_file() and p.relative_to(workspace).as_posix().endswith(suffix)
                for ln, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
                if any(n in line for n in needles)
            }
            if not matched:
                raise RuntimeError(f"Anchor not found in {workspace} for {tid}: {suffix} {needles}")
            sets.append(matched)
        gt[tid] = sets
    return gt


def check_anchors(refs: set[tuple[str, int]], expected_sets: list[set[tuple[str, int]]]) -> tuple[int, int, bool]:
    matched = 0
    for s in expected_sets:
        if any(rl == gl and (rp == gp or gp.endswith("/" + rp)) for gp, gl in s for rp, rl in refs):
            matched += 1
    return matched, len(expected_sets), matched == len(expected_sets)


def run_agy_task(
    agy_bin: str,
    model: str,
    workspace: Path,
    task: dict[str, Any],
    expected: list[set[tuple[str, int]]],
    route: str,
    workers: int,
) -> dict[str, Any]:
    if route == "direct":
        r_prompt = (
            "Use ONLY direct local rg/grep via run_command (or built-in grep_search / view_file). "
            "Batch searches where useful. Do NOT call call_mcp_tool or agent_ctx MCP."
        )
    elif route.startswith("ctx:"):
        r_prompt = (
            "Use agent_ctx (`mcp_agent_ctx_ctx_search` directly when declared, or `call_mcp_tool` when lazy) "
            'with `{"q": ["ModOrDir:pattern", ...]}` (1-4 parallel searches; bare module stem matches '
            "all extensions; lowercase = smart-case). Finish directly from search matches when sufficient."
        )
    else:
        r_prompt = (
            'Use ONLY agent_ctx MCP via `mcp_agent_ctx_ctx_search` (or `call_mcp_tool` if lazy) with '
            '`{"q": ["ModOrDir:pattern", ...]}` (1-4 parallel searches; bare module stem matches '
            "all extensions; lowercase = smart-case). Finish directly from search matches when sufficient."
        )
    prompt = (
        f"Read-only source navigation. {r_prompt} No writes, builds, web, or subagents. "
        f"Return {len(expected)} repository-relative file:line citations and one concise sentence. "
        f"Task: {task['question']}"
    )
    cmd = [
        agy_bin,
        "-p",
        prompt,
        "--model",
        model,
        "--output-format",
        "stream-json",
        "--dangerously-skip-permissions",
        "--disable-slash-commands",
    ]
    t0 = time.monotonic()
    res = subprocess.run(cmd, cwd=workspace, capture_output=True, text=True, timeout=180)
    wall_s = round(time.monotonic() - t0, 3)
    events = [json.loads(ln) for ln in res.stdout.splitlines() if ln.startswith("{")]
    result_obj: dict[str, Any] = {}
    tool_calls = 0
    mcp_calls = 0
    direct_eager_mcp_calls = 0
    lazy_wrapper_mcp_calls = 0
    result_bytes = 0
    tool_ms = 0.0
    for ev in events:
        if ev.get("event") == "step_update":
            su = ev.get("step_update") or {}
            if su.get("step_type") == "tool" and su.get("state") == "DONE":
                tool_calls += 1
                tool_ms += float(su.get("duration_seconds") or 0.0) * 1000.0
                ti = su.get("tool_info") or {}
                result_bytes += len(str(ti.get("output") or "").encode("utf-8"))
                tname = su.get("tool_name") or ti.get("name") or ""
                if tname.startswith("mcp_agent_ctx_"):
                    mcp_calls += 1
                    direct_eager_mcp_calls += 1
                elif tname == "call_mcp_tool" and (ti.get("parameters") or {}).get("ServerName") == "agent_ctx":
                    mcp_calls += 1
                    lazy_wrapper_mcp_calls += 1
        elif ev.get("event") == "result":
            result_obj = ev.get("result") or {}
    usage = result_obj.get("usage") or {}
    in_uncached = int(usage.get("input_tokens") or 0)
    in_cached = int(usage.get("cache_read_tokens") or 0)
    out_tok = int(usage.get("output_tokens") or 0)
    think_tok = int(usage.get("thinking_tokens") or 0)
    refs = extract_citations(str(result_obj.get("response") or ""), workspace)
    m_cnt, tot_cnt, ok = check_anchors(refs, expected)
    return {
        "harness": "antigravity",
        "model": model,
        "route": route,
        "task": task["id"],
        "anchors_matched": m_cnt,
        "anchors_total": tot_cnt,
        "anchors_ok": ok,
        "seconds": round(float(result_obj.get("duration_seconds") or wall_s), 3),
        "tool_calls": tool_calls,
        "mcp_calls": mcp_calls,
        "direct_eager_mcp_calls": direct_eager_mcp_calls,
        "lazy_wrapper_mcp_calls": lazy_wrapper_mcp_calls,
        "tool_exec_total_ms": round(tool_ms, 3),
        "tool_result_bytes": result_bytes,
        "total_input_tokens": in_uncached + in_cached,
        "cached_input_tokens": in_cached,
        "uncached_input_tokens": in_uncached,
        "output_tokens": out_tok,
        "reasoning_tokens": think_tok,
        "total_tokens": in_uncached + in_cached + out_tok + think_tok,
    }


def summarize_pair(direct_rows: list[dict[str, Any]], ctx_rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = (
        "seconds",
        "tool_calls",
        "tool_exec_total_ms",
        "tool_result_bytes",
        "uncached_input_tokens",
        "cached_input_tokens",
        "total_input_tokens",
        "output_tokens",
        "total_tokens",
    )
    table: dict[str, Any] = {}
    for m in metrics:
        d_sum = round(sum(float(r[m]) for r in direct_rows), 2)
        c_sum = round(sum(float(r[m]) for r in ctx_rows), 2)
        d_mean = round(statistics.mean(float(r[m]) for r in direct_rows), 2)
        c_mean = round(statistics.mean(float(r[m]) for r in ctx_rows), 2)
        diff = round(c_sum - d_sum, 2)
        pct = round(((c_sum - d_sum) / d_sum) * 100.0, 1) if d_sum else None
        table[m] = {
            "direct_mean": d_mean,
            "ctx_mean": c_mean,
            "direct_sum": d_sum,
            "ctx_sum": c_sum,
            "delta_sum_abs": diff,
            "delta_pct": pct,
        }
    return table


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ctx-bin", default=None, help="Path to ctx binary")
    ap.add_argument("--synthetic-only", action="store_true", help="Run only built-in synthetic multi-agent waves")
    ap.add_argument("--workspace", type=Path, default=Path.cwd(), help="Target repository for live tasks")
    ap.add_argument("--tasks-json", type=Path, default=None, help="JSON file defining benchmark tasks")
    ap.add_argument("--harnesses", default="agy", help="Comma-separated harnesses: agy")
    ap.add_argument("--agy-model", default="gemini-4-carbon-low", help="Antigravity model name")
    ap.add_argument(
        "--eager-profiles",
        default=None,
        help="Optional comma-separated Antigravity eager modes to compare (e.g. none,search,core)",
    )
    ap.add_argument("--parallel", type=int, default=5, help="Parallel task workers per wave")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="ctx-mcp-bench-") as tmp:
        ctx_bin = ensure_ctx_binary(args.ctx_bin, Path(tmp))
        micro_raw = subprocess.run(
            [str(ctx_bin), "bench", "--agents", "1,10,50,100,200", "--ops", "25", "--json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        ).stdout
        report: dict[str, Any] = {"synthetic_waves": json.loads(micro_raw).get("waves", [])}
        if args.synthetic_only or not args.tasks_json:
            print(json.dumps(report, indent=2))
            return 0

        ws = args.workspace.resolve()
        tasks = json.loads(args.tasks_json.read_text(encoding="utf-8"))
        gt = resolve_ground_truth(ws, tasks)
        harnesses = {h.strip() for h in args.harnesses.split(",") if h.strip()}

        if "agy" in harnesses or "antigravity" in harnesses:
            agy_bin = shutil.which("agy") or str(Path.home() / ".gemini/antigravity-cli/bin/agy")
            runs: dict[str, list[dict[str, Any]]] = {}
            if args.eager_profiles:
                profiles = [p.strip() for p in args.eager_profiles.split(",") if p.strip()]
                routes = ["direct"] + [f"ctx:{p}" for p in profiles]
            else:
                profiles = []
                routes = ["direct", "ctx"]
            for route in routes:
                if route.startswith("ctx:"):
                    prof = route.split(":", 1)[1]
                    subprocess.run(
                        [str(ctx_bin), "install", "--targets", "agy", f"--eager={prof}"],
                        check=True,
                        timeout=30,
                    )
                with ThreadPoolExecutor(max_workers=args.parallel) as pool:
                    futs = [pool.submit(run_agy_task, agy_bin, args.agy_model, ws, t, gt[t["id"]], route, args.parallel) for t in tasks]
                    rows = [f.result() for f in as_completed(futs)]
                rows.sort(key=lambda r: r["task"])
                runs[route] = rows
            if profiles:
                subprocess.run(
                    [str(ctx_bin), "install", "--targets", "agy", "--eager=core"],
                    check=True,
                    timeout=30,
                )
                report["antigravity"] = {
                    "summaries_vs_direct": {
                        f"ctx:{p}": summarize_pair(runs["direct"], runs[f"ctx:{p}"]) for p in profiles
                    },
                    "runs": runs,
                }
            else:
                report["antigravity"] = {
                    "summary": summarize_pair(runs["direct"], runs["ctx"]),
                    "runs": runs,
                }

        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
