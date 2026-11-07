//! Embeds the version `kpa version` reports: `v{tag}` when `HEAD` is
//! exactly a release tag, `dev-{commit}` otherwise (with a `-dirty` suffix
//! if the working tree has uncommitted changes). Resolved at build time
//! (not runtime) since the built binary may run on a machine, or in a
//! container, with no `.git` directory at all.
//!
//! The Nix package build has no `.git` in its sandbox, so it can't ask git
//! anything. It instead sets `KPA_BUILD_REV` (to the flake's
//! `self.dirtyShortRev`, which already carries a `-dirty` suffix of its
//! own when applicable) and that takes priority over any git lookup.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=KPA_BUILD_REV");

    let version = std::env::var("KPA_BUILD_REV")
        .ok()
        .filter(|rev| !rev.is_empty())
        .map(|rev| format!("dev-{rev}"))
        .or_else(git_version)
        .unwrap_or_else(|| "dev-unknown".to_string());

    println!("cargo:rustc-env=KPA_VERSION={version}");
}

fn git_version() -> Option<String> {
    let dirty_suffix = if is_dirty() { "-dirty" } else { "" };

    exact_tag()
        .map(|tag| format!("v{}{dirty_suffix}", tag.strip_prefix('v').unwrap_or(&tag)))
        .or_else(|| short_hash().map(|hash| format!("dev-{hash}{dirty_suffix}")))
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
