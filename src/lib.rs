//! Library half of the `kpa` crate.
//!
//! Split out from `main.rs` purely so integration tests under `tests/` can
//! `use kpa::...` — a binary-only crate has nothing for them to link
//! against. `main.rs` uses these same modules for the actual CLI.

pub mod clip;
pub mod config;
pub mod output;
pub mod policy;
pub mod proto;
pub mod server;
pub mod socket;
pub mod tray;
pub mod vault;

/// `v{tag}` when built from an exact release tag, `dev-{short hash}`
/// otherwise. Set by `build.rs`.
pub const VERSION: &str = env!("KPA_VERSION");
