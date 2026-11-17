//! Library half of the `kpa` crate.
//!
//! Split out from `main.rs` purely so integration tests under `tests/` can
//! `use kpa::...` — a binary-only crate has nothing for them to link
//! against. `main.rs` uses these same modules for the actual CLI.

pub mod authn;
pub mod authz;
pub mod clip;
pub mod config;
mod io;
pub mod log;
pub mod output;
pub mod paths;
pub mod policy;
mod prompt;
pub mod proto;
pub mod request_policy;
pub mod server;
pub mod socket;
pub mod ssh_agent;
pub mod tray;
pub mod vault;
mod wayland;

/// The crate version alone (e.g. `0.1.0`) when built from an exact release
/// tag, `{crate_version}+{short hash}` otherwise. Set by `build.rs`.
pub const VERSION: &str = env!("KPA_VERSION");
