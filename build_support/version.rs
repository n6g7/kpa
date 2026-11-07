//! The pure decision behind `KPA_VERSION` (what `kpa version` reports),
//! split out from `build.rs`'s git/env I/O so it can be unit-tested with
//! `cargo test`. `build.rs` includes this file as a module via `#[path]`,
//! and `tests/version.rs` includes the same file the same way to exercise
//! it directly — see both for how.

/// Everything the decision needs, already resolved to plain values so this
/// function has no I/O of its own.
pub struct VersionInputs<'a> {
    /// `KPA_BUILD_REV`, set by the Nix package build (there's no `.git` in
    /// its sandbox for build.rs to ask itself). Takes priority over the git
    /// lookup when present and non-empty. The flake sets this from
    /// `self.dirtyShortRev`, which already carries its own `-dirty` suffix
    /// when applicable, so this is used as-is.
    pub build_rev_override: Option<&'a str>,
    /// `CARGO_PKG_VERSION` (the crate version from `Cargo.toml`), the base
    /// every `+{commit}` is appended to.
    pub crate_version: &'a str,
    /// `git rev-parse --short HEAD`'s output.
    pub short_hash: Option<&'a str>,
    /// Whether the working tree has uncommitted changes (only consulted
    /// for the git-derived case, not `build_rev_override`).
    pub dirty: bool,
}

/// Decides the `KPA_VERSION` string: `{crate_version}+{commit}` always, so
/// a cargo build and a Nix build of the same commit print the same string,
/// release tag or not (a Nix build can't tell, and a version that depends
/// on how it was built can't be compared). Build metadata doesn't affect
/// semver precedence, so `0.1.0+abc1234` is still version 0.1.0.
/// - `{crate_version}+{rev}` when `build_rev_override` is set (the Nix
///   package build path);
/// - otherwise, with a `.git` to ask, `{crate_version}+{hash}`, with a
///   `-dirty` suffix if the working tree has uncommitted changes;
/// - `{crate_version}+unknown` when there's no `.git` to ask and no
///   override either.
pub fn compute_version(inputs: VersionInputs) -> String {
    if let Some(rev) = inputs.build_rev_override
        && !rev.is_empty()
    {
        return format!("{}+{rev}", inputs.crate_version);
    }

    if let Some(hash) = inputs.short_hash {
        let dirty_suffix = if inputs.dirty { "-dirty" } else { "" };
        return format!("{}+{hash}{dirty_suffix}", inputs.crate_version);
    }

    format!("{}+unknown", inputs.crate_version)
}
