//! The pure decision behind `KPA_VERSION` (what `kpa version` reports),
//! split out from `build.rs`'s git/env I/O so it can be unit-tested with
//! `cargo test`. `build.rs` includes this file as a module via `#[path]`,
//! and `tests/version.rs` includes the same file the same way to exercise
//! it directly — see both for how.

/// Everything the decision needs, already resolved to plain values so this
/// function has no I/O of its own.
pub struct VersionInputs<'a> {
    /// `KPA_BUILD_REV`, set by the Nix package build (there's no `.git` in
    /// its sandbox for build.rs to ask itself, and no tag info either —
    /// the flake's `self` only has a commit). Takes priority over
    /// everything else when present and non-empty. The flake sets this
    /// from `self.dirtyShortRev`, which already carries its own `-dirty`
    /// suffix when applicable, so this is used as-is.
    pub build_rev_override: Option<&'a str>,
    /// `CARGO_PKG_VERSION` (the crate version from `Cargo.toml`). Used in
    /// every case: as the base every `+{something}` is appended to, and
    /// alone for an exact release tag. Also what `build_rev_override`
    /// falls back on, since that path can't tell a release commit from
    /// any other — it reports `{crate_version}+{rev}` unconditionally
    /// rather than guessing.
    pub crate_version: &'a str,
    /// `git describe --tags --exact-match HEAD`'s output, if `HEAD` is
    /// exactly a release tag.
    pub exact_tag: Option<&'a str>,
    /// `git rev-parse --short HEAD`'s output.
    pub short_hash: Option<&'a str>,
    /// Whether the working tree has uncommitted changes (only consulted
    /// for the git-derived cases, not `build_rev_override`).
    pub dirty: bool,
}

/// Decides the `KPA_VERSION` string. One shape throughout —
/// `{crate_version}` alone only for an exact release tag, `+{something}`
/// appended for every other case — so a cargo build and a Nix build of the
/// same commit print the same string, and nothing printed needs its own
/// parsing rule:
/// - `{crate_version}+{rev}` when `build_rev_override` is set (the Nix
///   package build path, which has no way to tell a release commit from
///   any other);
/// - otherwise, with a `.git` to ask: `{crate_version}` when `HEAD` is
///   exactly a release tag (the tag's own `v` prefix is for git, not for
///   this string), `{crate_version}+{hash}` otherwise — each with a
///   `-dirty` suffix if the working tree has uncommitted changes;
/// - `{crate_version}+unknown` when there's no `.git` to ask and no
///   override either.
pub fn compute_version(inputs: VersionInputs) -> String {
    if let Some(rev) = inputs.build_rev_override
        && !rev.is_empty()
    {
        return format!("{}+{rev}", inputs.crate_version);
    }

    let dirty_suffix = if inputs.dirty { "-dirty" } else { "" };

    if let Some(tag) = inputs.exact_tag {
        let tag = tag.strip_prefix('v').unwrap_or(tag);
        return format!("{tag}{dirty_suffix}");
    }

    if let Some(hash) = inputs.short_hash {
        return format!("{}+{hash}{dirty_suffix}", inputs.crate_version);
    }

    format!("{}+unknown", inputs.crate_version)
}
