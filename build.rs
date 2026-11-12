//! Embeds the version `kpa version` reports: `{crate_version}+{commit}`
//! (`Cargo.toml`'s version, e.g. `0.1.0+abc1234`), with a `-dirty` suffix
//! if the working tree has uncommitted changes. Resolved at build time
//! (not runtime) since the built binary may run on a machine, or in a
//! container, with no `.git` directory at all.
//!
//! The Nix package build has no `.git` in its sandbox, so it can't ask git
//! anything. It instead sets `KPA_BUILD_REV` (to the flake's
//! `self.dirtyShortRev`, which already carries a `-dirty` suffix of its
//! own when applicable), and that takes priority over any git lookup.
//!
//! The actual decision is a pure function in `build_support/version.rs`,
//! unit-tested from `tests/version.rs`; everything here is just gathering
//! its inputs from git and the environment.

#[path = "build_support/version.rs"]
mod version;

use std::process::Command;
use version::{VersionInputs, compute_version};

fn main() {
    watch_git_head();
    // `dirty` depends on the working tree, which cargo can't see through git.
    for path in ["src", "build_support", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=KPA_BUILD_REV");

    let build_rev_override = std::env::var("KPA_BUILD_REV").ok();
    // Cargo sets this for every build script, from the `[package]
    // version` in Cargo.toml.
    let crate_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let short_hash = short_hash();
    let dirty = is_dirty();

    let version = compute_version(VersionInputs {
        build_rev_override: build_rev_override.as_deref(),
        crate_version: &crate_version,
        short_hash: short_hash.as_deref(),
        dirty,
    });

    println!("cargo:rustc-env=KPA_VERSION={version}");
}

/// Reruns when the checked-out commit changes. Paths come from git rather
/// than a hardcoded `.git/`, which doesn't exist in a worktree (`.git` is a
/// file there); a watched path that's missing makes cargo rerun every build.
fn watch_git_head() {
    let Some(head) = run_git(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={head}");
    // HEAD only names the branch; the branch's ref moves on each commit.
    // Packed refs have no loose file, and a missing path would force a rerun.
    if let Some(branch) = run_git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = run_git(&["rev-parse", "--git-path", &branch])
        && std::path::Path::new(&path).exists()
    {
        println!("cargo:rerun-if-changed={path}");
    }
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
