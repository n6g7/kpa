//! Unit tests for the pure version decision in `build_support/version.rs`
//! (included here the same way `build.rs` includes it, via `#[path]`, so
//! `cargo test` can exercise it directly — `build.rs` itself isn't part of
//! `cargo test`'s targets).

#[path = "../build_support/version.rs"]
mod version;

use version::{VersionInputs, compute_version};

const CRATE_VERSION: &str = "0.1.0";

fn inputs<'a>(
    build_rev_override: Option<&'a str>,
    exact_tag: Option<&'a str>,
    short_hash: Option<&'a str>,
    dirty: bool,
) -> VersionInputs<'a> {
    VersionInputs {
        build_rev_override,
        crate_version: CRATE_VERSION,
        exact_tag,
        short_hash,
        dirty,
    }
}

#[test]
fn exact_tag_clean() {
    let version = compute_version(inputs(None, Some("v1.2.3"), Some("abc1234"), false));
    assert_eq!(version, "v1.2.3");
}

#[test]
fn exact_tag_dirty() {
    let version = compute_version(inputs(None, Some("v1.2.3"), Some("abc1234"), true));
    assert_eq!(version, "v1.2.3-dirty");
}

#[test]
fn exact_tag_without_v_prefix_still_gets_one() {
    // `git describe --tags` returns tags verbatim; a tag named without a
    // leading `v` shouldn't produce `vv1.2.3` or lose the `v` prefix kpa's
    // version string always has.
    let version = compute_version(inputs(None, Some("1.2.3"), Some("abc1234"), false));
    assert_eq!(version, "v1.2.3");
}

#[test]
fn untagged_clean() {
    let version = compute_version(inputs(None, None, Some("abc1234"), false));
    assert_eq!(version, "dev-abc1234");
}

#[test]
fn untagged_dirty() {
    let version = compute_version(inputs(None, None, Some("abc1234"), true));
    assert_eq!(version, "dev-abc1234-dirty");
}

#[test]
fn build_rev_override_takes_priority_over_everything() {
    // KPA_BUILD_REV (the Nix package build's path) wins even if git
    // somehow had a tag/hash to offer, and ignores the dirty flag (it
    // isn't consulted for this branch; the override carries its own
    // `-dirty` suffix already, from the flake's `self.dirtyShortRev`).
    let version = compute_version(inputs(
        Some("abc1234"),
        Some("v9.9.9"),
        Some("def5678"),
        true,
    ));
    assert_eq!(version, "0.1.0+abc1234");
}

#[test]
fn build_rev_override_clean() {
    // Nix has no .git, so it can't tell a release tag from any other
    // commit — the override path always reports {crate_version}+{rev}
    // rather than guessing `v`/`dev-`.
    let version = compute_version(inputs(Some("abc1234"), None, None, false));
    assert_eq!(version, "0.1.0+abc1234");
}

#[test]
fn build_rev_override_already_carries_dirty_suffix() {
    // self.dirtyShortRev appends its own "-dirty"; compute_version must
    // not add a second one.
    let version = compute_version(inputs(Some("abc1234-dirty"), None, None, false));
    assert_eq!(version, "0.1.0+abc1234-dirty");
}

#[test]
fn empty_build_rev_override_is_ignored() {
    // std::env::var("KPA_BUILD_REV") can come back as Some("") if the
    // variable is set but empty; that should fall through to git, not
    // produce "0.1.0+".
    let version = compute_version(inputs(Some(""), None, Some("abc1234"), false));
    assert_eq!(version, "dev-abc1234");
}

#[test]
fn nothing_available_falls_back_to_dev_unknown() {
    let version = compute_version(inputs(None, None, None, false));
    assert_eq!(version, "dev-unknown");
}

#[test]
fn nothing_available_dirty_flag_has_no_effect() {
    // No commit to describe means no `-dirty` suffix either; "dirty
    // dev-unknown" wouldn't mean anything.
    let version = compute_version(inputs(None, None, None, true));
    assert_eq!(version, "dev-unknown");
}
