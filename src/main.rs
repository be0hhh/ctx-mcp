//! `ctx` — Single zero-dependency Rust Context Broker serving:
//!   1. `ctx daemon`                — Concurrent 32-thread / 64-shard <=4 GiB RAM broker + `0600` metadata-only snapshot
//!   2. `ctx inspect | read | outline | sym | search | impact | edit | git | memo | capsule | elf | status | clear` — Sub-ms CLI
//!   3. `ctx mcp [--repo-root DIR] [--read-only | --write]` — Native Stdio MCP server (`agent_ctx`)
//!   4. `ctx hook <agy|codex|claude> [--global]` — Sub-ms per-agent lifecycle hook router
//!   5. `ctx setup | install | uninstall | doctor | mode | update` — Built-in installer, mode toggle, and updater
//!
//! Declares modules directly so bare `rustc --edition 2021 -D warnings -O src/main.rs`
//! builds identically to Cargo with zero external crates.

mod base;
mod broker;
mod cli;
mod edit;
mod engine;
mod hooks;
mod install;
mod mcp;
mod parser;
mod rpc;
mod store;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cli::dispatch(&args));
}
