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

use std::os::unix::process::CommandExt as _;
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

/// A database for `ssh_agent::keys` (`tests/fixture.sh`): entries `"Ed25519"`,
/// `"Ecdsa"` and `"Rsa"` each hold one OpenSSH private-key attachment;
/// `"Pem"` holds a PEM-format key that must be skipped; `"Historical"`'s
/// key is reachable only through its history, and `"Recycled"`'s only
/// through the recycle bin — both must be invisible to a scan. `"Encrypted"`
/// holds a passphrase-protected key, which a scan skips.
pub fn ssh_db() -> PathBuf {
    ensure_fixtures().join("fixture-ssh.kdbx")
}

/// The fingerprint of `ssh_db()`'s entry named `title` (`"Ed25519"`,
/// `"Ecdsa"` or `"Rsa"`) — for building a `[[database.ssh_key]]` override
/// before a daemon that serves it has even started, since a fresh fixture
/// has a different fingerprint every run.
pub fn ssh_fixture_fingerprint(title: &str) -> String {
    let password = zeroize::Zeroizing::new(PASSWORD.to_string());
    let (db, _) =
        kpa::vault::open(&ssh_db(), Some(&password), None).expect("ssh fixture should open");
    let attachments = kpa::vault::list_attachments(&db);
    kpa::ssh_agent::keys::scan(&attachments)
        .found
        .into_iter()
        .find(|key| key.entry_title.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("no {title:?} key found in the ssh fixture"))
        .fingerprint
        .to_string()
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

/// A pseudo-terminal, for driving `kpa unlock`'s terminal read
/// (`docs/headless.md` § 4) the way a real shell would: a spawned process
/// attaches the slave as its controlling terminal (`attach`), and the test
/// types into and reads from the master (`type_text`, `read_until`),
/// including checking that echo is actually off (`echoing`).
pub struct Pty {
    pub master: std::fs::File,
    slave_path: std::ffi::CString,
}

impl Pty {
    pub fn open() -> Pty {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        // `NOCTTY`: opening the master must not make it *this* process's
        // controlling terminal — only the spawned child's, via `attach`.
        // `CLOEXEC`: otherwise every other test's spawned `kpa` inherits
        // this master too, across `fork` — tests run as threads of one
        // process, and `exec` is the only place a leftover fd like that
        // gets closed.
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let slave_path = ptsname(&master, Vec::new()).expect("ptsname");
        Pty {
            master: std::fs::File::from(master),
            slave_path,
        }
    }

    /// Makes the slave `cmd`'s controlling terminal and its stdin, stdout
    /// and stderr, so `/dev/tty` inside it resolves to this pty.
    ///
    /// The closure runs in the forked child, between `fork` and `exec`
    /// (`CommandExt::pre_exec`), where only async-signal-safe calls are
    /// safe to make — `setsid`, `open`, `ioctl` and `dup2`/`close` all
    /// qualify. `setsid` first detaches the child from any controlling
    /// terminal the test binary itself has, so opening the slave right
    /// after, without `O_NOCTTY`, acquires it as this child's own;
    /// `TIOCSCTTY` is belt and suspenders for a kernel that didn't do that
    /// implicitly.
    pub fn attach(&self, cmd: &mut Command) {
        let slave_path = self.slave_path.clone();
        // SAFETY: see the doc comment above — every call the closure makes
        // is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let fd = libc::open(slave_path.as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let _ = libc::ioctl(fd, libc::TIOCSCTTY as _, 0);
                libc::dup2(fd, 0);
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                if fd > 2 {
                    libc::close(fd);
                }
                Ok(())
            });
        }
    }

    /// Whether the pty's termios currently has `ECHO` set. Queryable from
    /// either end of the pair, which is what lets a test check it without
    /// opening the slave itself.
    pub fn echoing(&self) -> bool {
        rustix::termios::tcgetattr(&self.master)
            .expect("tcgetattr on the pty master")
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO)
    }

    /// Types `text` into whatever's attached to the slave.
    pub fn type_text(&self, text: &str) {
        use std::io::Write as _;
        (&self.master)
            .write_all(text.as_bytes())
            .expect("writing to pty master");
    }

    /// Reads from the master until `needle` appears in what's been read so
    /// far, or `timeout` passes (panicking then — a test hang is a bug,
    /// not a slow pass). Polls with a deadline rather than blocking, so a
    /// child that never answers shows up as a timeout instead of a hang.
    pub fn read_until(&self, needle: &str, timeout: std::time::Duration) -> String {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        let deadline = std::time::Instant::now() + timeout;
        let mut out = String::new();
        let mut buf = [0u8; 4096];
        loop {
            if out.contains(needle) {
                return out;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !left.is_zero(),
                "timed out waiting for {needle:?}; read so far: {out:?}"
            );
            let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
            let ts = Timespec {
                tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: left.subsec_nanos().into(),
            };
            match poll(&mut fds, Some(&ts)) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) => panic!("poll on pty master: {err}"),
            }
            if fds[0].revents().is_empty() {
                continue; // The poll above timed out this round.
            }
            match rustix::io::read(&self.master, &mut buf[..]) {
                Ok(0) => continue,
                Ok(n) => out.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
                Err(err) => panic!("reading pty master: {err}"),
            }
        }
    }
}
