//! Zero-dependency Rust Context Broker library root (`ctx`).
//! Exposes the modular hierarchy for integration tests, `ctx-bench`, and compile-time
//! downstream extensions (such as a project-specific overlay binary).

pub mod base;
pub mod broker;
pub mod cli;
pub mod edit;
pub mod engine;
pub mod hooks;
pub mod install;
pub mod mcp;
pub mod parser;
pub mod rpc;
pub mod store;

/// Entry point for compile-time downstream binaries that register a custom `ProjectPolicy`
/// before dispatching CLI/MCP/daemon commands under unified Fat LTO.
pub fn run_cli_with_policy(
    args: &[String],
    policy: &'static dyn crate::base::ext::ProjectPolicy,
) -> i32 {
    crate::base::ext::install_policy(policy);
    crate::cli::dispatch(args)
}
