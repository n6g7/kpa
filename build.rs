//! Embeds the version `kpa version` reports: the crate version alone
//! (`Cargo.toml`'s, e.g. `0.1.0`) when `HEAD` is exactly a release tag,
//! `{crate_version}+{commit}` otherwise (with a `-dirty` suffix if the
//! working tree has uncommitted changes). Resolved at build time (not
//! runtime) since the built binary may run on a machine, or in a
//! container, with no `.git` directory at all.
//!
//! The Nix package build has no `.git` in its sandbox, so it can't ask git
//! anything — including whether the commit it's building is a release
//! tag. It instead sets `KPA_BUILD_REV` (to the flake's
//! `self.dirtyShortRev`, which already carries a `-dirty` suffix of its
//! own when applicable), and that takes priority over any git lookup,
//! reporting `{crate_version}+{rev}` (e.g. `0.1.0+abc1234`) rather than
//! guessing whether the commit it's building happens to be a release.
//!
//! The actual decision is a pure function in `build_support/version.rs`,
//! unit-tested from `tests/version.rs`; everything here is just gathering
//! its inputs from git and the environment.

#[path = "build_support/version.rs"]
mod version;

use std::process::Command;
use version::{VersionInputs, compute_version};

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=KPA_BUILD_REV");

    let build_rev_override = std::env::var("KPA_BUILD_REV").ok();
    // Cargo sets this for every build script, from the `[package]
    // version` in Cargo.toml.
    let crate_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let exact_tag = exact_tag();
    let short_hash = short_hash();
    let dirty = is_dirty();

    let version = compute_version(VersionInputs {
        build_rev_override: build_rev_override.as_deref(),
        crate_version: &crate_version,
        exact_tag: exact_tag.as_deref(),
        short_hash: short_hash.as_deref(),
        dirty,
    });

    println!("cargo:rustc-env=KPA_VERSION={version}");
}

fn exact_tag() -> Option<String> {
    run_git(&["describe", "--tags", "--exact-match", "HEAD"])
}

fn short_hash() -> Option<String> {
    run_git(&["rev-parse", "--short", "HEAD"])
}

fn is_dirty() -> bool {
    let Some(output) = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
    else {
        return false;
    };
    output.status.success() && !output.stdout.is_empty()
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
