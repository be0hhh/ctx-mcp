//! Zero-dependency Rust Context Broker library root (`ctx`).
//! Exposes the modular hierarchy for integration tests and `ctx-bench`.

pub mod base;
pub mod broker;
pub mod cli;
pub mod engine;
pub mod hooks;
pub mod install;
pub mod mcp;
pub mod parser;
pub mod rpc;
pub mod store;
