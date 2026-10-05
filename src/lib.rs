//! Library half of the `kpa` crate.
//!
//! Split out from `main.rs` purely so integration tests under `tests/` can
//! `use kpa::...` — a binary-only crate has nothing for them to link
//! against. `main.rs` uses these same modules for the actual CLI.

pub mod config;
pub mod proto;
pub mod server;
pub mod socket;
pub mod vault;
