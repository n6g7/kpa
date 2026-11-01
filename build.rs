//! Embeds the version `kpa version` reports: `v{tag}` when `HEAD` is
//! exactly a release tag, `dev-{short hash}` otherwise. Resolved at build
//! time (not runtime) since the built binary may run on a machine, or in a
//! container, with no `.git` directory at all.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    let version = exact_tag()
        .map(|tag| format!("v{}", tag.strip_prefix('v').unwrap_or(&tag)))
        .or_else(|| short_hash().map(|hash| format!("dev-{hash}")))
        .unwrap_or_else(|| "dev-unknown".to_string());

    println!("cargo:rustc-env=KPA_VERSION={version}");
}

fn exact_tag() -> Option<String> {
    run_git(&["describe", "--tags", "--exact-match", "HEAD"])
}

fn short_hash() -> Option<String> {
    run_git(&["rev-parse", "--short", "HEAD"])
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
