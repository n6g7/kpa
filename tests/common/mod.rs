//! Shared test fixture setup.
//!
//! `mod.rs` under `tests/common/` (rather than `tests/common.rs`) so cargo
//! doesn't treat this as its own standalone test binary — it's a helper
//! module, imported by the actual test files.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

static FIXTURES_INIT: Once = Once::new();

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Build the fixtures (via `tests/fixture.sh`) on first use, once per test
/// binary process. `fixture.sh` itself is idempotent (skips work if the
/// files already exist), but `Once` also protects against two test
/// binaries racing to create the same directory concurrently.
fn ensure_fixtures() -> PathBuf {
    let dir = fixtures_dir();
    FIXTURES_INIT.call_once(|| {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture.sh");
        let status = Command::new("sh")
            .arg(&script)
            .arg(&dir)
            .status()
            .expect("failed to spawn tests/fixture.sh — is `sh` on PATH?");
        assert!(
            status.success(),
            "tests/fixture.sh exited with {status}; is keepassxc-cli on PATH?"
        );
    });
    dir
}

/// The password every fixture in the password-only database was created
/// with (`tests/fixture.sh`).
pub const PASSWORD: &str = "testpass123";

pub fn password_db() -> PathBuf {
    ensure_fixtures().join("fixture.kdbx")
}

pub fn keyfile_db() -> PathBuf {
    ensure_fixtures().join("fixture-kf.kdbx")
}

pub fn keyfile() -> PathBuf {
    ensure_fixtures().join("fixture-kf.keyx")
}

/// A genuine KDBX4 database (built with pykeepass — keepassxc-cli's
/// `db-create` has no way to request KDBX4, see `tests/fixture.sh`).
pub fn kdbx4_db() -> PathBuf {
    ensure_fixtures().join("fixture-kdbx4.kdbx")
}
