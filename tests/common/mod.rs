//! Shared test fixture setup.
//!
//! `mod.rs` under `tests/common/` (rather than `tests/common.rs`) so cargo
//! doesn't treat this as its own standalone test binary — it's a helper
//! module, imported by the actual test files.
//!
//! Cargo compiles this module once per integration-test binary, so a
//! helper only some binaries call (e.g. `tests/server.rs` doesn't need
//! `keyfile_db`) shows up as dead code in the others. The allow is for that
//! structural fact, not for genuinely unused fixtures.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Once};

static FIXTURES_INIT: Once = Once::new();

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Build the fixtures (via `tests/fixture.sh`) on first use, once per test
/// binary process. `fixture.sh` itself is idempotent (skips work if the
/// files already exist). `Once` only dedupes calls within this one process
/// — cargo runs test binaries as separate parallel processes, so it does
/// not protect against two of them racing to create the same directory.
/// Latent today because only one binary uses these fixtures.
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

/// A database whose entry text is full of characters a terminal acts on
/// (`tests/fixture.sh`).
pub fn hostile_db() -> PathBuf {
    ensure_fixtures().join("fixture-hostile.kdbx")
}

/// A database for `copy`'s custom-field, collision, and `totp` cases
/// (`tests/fixture.sh`): entry `"Example"` has a custom `api-key` field, a
/// custom `PASSWORD` field colliding with the built-in, and a valid `otp`
/// field; `"NoOtp"` has none; `"BadOtp"`'s `otp` field doesn't parse.
pub fn fields_db() -> PathBuf {
    ensure_fixtures().join("fixture-fields.kdbx")
}

/// A config whose one database is `db_path` under the name `"personal"`,
/// and whose `prompt` runs `prompt_script` under `sh -c`, standing in for a
/// real dmenu-style prompt.
pub fn config_toml(prompt_script: &str, db_path: &str) -> String {
    format!(
        "prompt = [\"/bin/sh\", \"-c\", \"{prompt_script}\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{db_path}\"\n",
    )
}

/// Runs `kpa --socket <socket> <args>` with the real binary and parses its
/// printed response line. Read as plain JSON on purpose: these tests check
/// what goes over the wire, literally, rather than what a typed client
/// makes of it.
pub fn run_cli(socket: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_kpa"))
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("failed to spawn kpa client");
    let text = String::from_utf8(output.stdout).expect("client stdout is not valid UTF-8");
    serde_json::from_str(text.trim())
        .unwrap_or_else(|err| panic!("could not decode response {text:?}: {err}"))
}

/// The daemon, run on threads of the test process rather than as a
/// spawned `kpa serve`, and driven with the real `kpa` CLI over its socket.
///
/// Every connection counts as coming from the desktop by default
/// (`Server::assume_origin`; `with_origin` overrides it), so `unlock`
/// raises the configured prompt wherever the tests run: a test runner is
/// rarely in the display session. No logind watch runs, so nothing
/// publishes the desk's state on its own — `with_config` and `with_origin`
/// seed it as an active, unlocked session (`policy::Locks::set_desk`),
/// standing in for logind the same way `assume_origin` stands in for the
/// peer's cgroup, so `copy` passes its gate the way it always did before
/// that gate existed. A test about the gate itself (an `Outside` origin, or
/// a locked/inactive/absent desk) overrides either through `self.server`.
/// No tray is started either. The daemon's threads run until the test
/// binary exits.
///
/// What this doesn't cover, and the tests on the spawned binary do:
/// `kpa serve`'s argument and config-file handling, its startup
/// (`PR_SET_DUMPABLE`, the logind watch, the tray), and logging to a
/// stderr of its own.
pub struct InProcessDaemon {
    pub socket: PathBuf,
    pub server: Arc<kpa::server::Server>,
    _dir: tempfile::TempDir,
}

impl InProcessDaemon {
    /// Starts a daemon on `config`, TOML as in a config file.
    pub fn start(config: &str) -> InProcessDaemon {
        InProcessDaemon::with_config(kpa::config::Config::parse(config).expect("valid config"))
    }

    pub fn with_config(config: kpa::config::Config) -> InProcessDaemon {
        InProcessDaemon::with_origin(config, kpa::origin::Origin::Desktop)
    }

    /// Like `with_config`, but classifies every connection as `origin`
    /// instead of the default `Desktop` — for copy-gating tests that need
    /// an `Outside` requester.
    pub fn with_origin(
        config: kpa::config::Config,
        origin: kpa::origin::Origin,
    ) -> InProcessDaemon {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let socket = dir.path().join("sock");
        let server = Arc::new(kpa::server::Server::new(config));
        server.assume_origin(origin);
        kpa::policy::Locks::set_desk(
            &server,
            kpa::policy::Desk::Unlocked {
                session: "test".to_string(),
                active: true,
            },
        );
        // Not `socket::bind_socket`: it sets the process-wide umask for the
        // bind, and a directory another test thread created meanwhile
        // would come out without its search bit.
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("failed to bind socket");
        let serving = server.clone();
        std::thread::spawn(move || kpa::server::serve(serving, listener));
        InProcessDaemon {
            socket,
            server,
            _dir: dir,
        }
    }

    pub fn run(&self, args: &[&str]) -> serde_json::Value {
        run_cli(&self.socket, args)
    }
}
