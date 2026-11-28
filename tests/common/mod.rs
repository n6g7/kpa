//! Shared test fixture setup.
//!
//! `mod.rs` under `tests/common/` (rather than `tests/common.rs`) so cargo
//! doesn't treat this as its own standalone test binary — it's a helper
//! module, imported by the actual test files.
//!
//! Cargo compiles this module once per integration-test binary, so a
//! helper only some binaries call (e.g. `tests/control.rs` doesn't need
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

/// A database for `ssh::keys` (`tests/fixture.sh`): entries `"Ed25519"`,
/// `"Ecdsa"` and `"Rsa"` each hold one OpenSSH private-key attachment;
/// `"Pem"` holds a PEM-format key that must be skipped; `"Historical"`'s
/// key is reachable only through its history, and `"Recycled"`'s only
/// through the recycle bin — both must be invisible to a scan. `"Encrypted"`
/// holds a passphrase-protected key, which a scan skips.
pub fn ssh_db() -> PathBuf {
    ensure_fixtures().join("fixture-ssh.kdbx")
}

/// A `Databases` holding the one fixture at `path`, named `"fixture"`,
/// unlocked with the fixtures' password.
pub fn unlocked_fixture(path: &Path) -> kpa::databases::Databases {
    let databases = kpa::databases::Databases::new(
        vec![kpa::config::DatabaseConfig {
            name: "fixture".to_string(),
            path: path.to_path_buf(),
            keyfile: None,
            serve_ssh_keys: true,
            ssh_keys: Vec::new(),
        }],
        std::time::Duration::from_secs(3600),
    );
    let password = zeroize::Zeroizing::new(PASSWORD.to_string());
    match databases.begin_unlock("fixture") {
        Ok(kpa::databases::Begin::Started(unlocking)) => {
            unlocking.finish(Some(&password)).expect("fixture unlocks");
        }
        _ => panic!("expected to start an unlock of the fixture"),
    }
    databases
}

/// The fingerprint of `ssh_db()`'s entry named `title` (`"Ed25519"`,
/// `"Ecdsa"` or `"Rsa"`), for building a `[[database.ssh_key]]` override
/// before a daemon that serves it has started: a fresh fixture has
/// different keys every run.
pub fn ssh_fixture_fingerprint(title: &str) -> String {
    let db = unlocked_fixture(&ssh_db());
    kpa::ssh::keys::scan(&db.open("fixture").expect("unlocked"))
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

/// A cgroup on the desktop of the display session `session`, or in a
/// system service when not `on_desktop`.
pub fn cgroup_on(on_desktop: bool, session: &str) -> String {
    let uid = kpa::authn::process_uid();
    if on_desktop {
        format!("0::/user.slice/user-{uid}.slice/session-{session}.scope\n")
    } else {
        "0::/system.slice/cron.service\n".to_string()
    }
}

/// The daemon, run on threads of the test process rather than as a
/// spawned `kpa serve`, built by `kpa::daemon` and driven with the real
/// `kpa` CLI over its socket.
///
/// Every connection counts as coming from the desktop by default
/// (`authn::assume_cgroup`; `with_requester_on` overrides it), so `unlock`
/// raises the configured prompt wherever the tests run: a test runner is
/// rarely in the display session. No logind watch runs unless a test asks
/// for one (`on_bus`), so nothing publishes the display session's state on
/// its own: the other constructors seed it as an active, unlocked session,
/// standing in for logind the same way `authn::assume_cgroup` stands in
/// for the peer's cgroup, so `copy` passes its gate. A test about the gate
/// itself (a requester outside the desktop, or a locked, inactive or absent
/// display session) sets it through `display`. The daemon's threads run
/// until the test binary exits.
///
/// What this doesn't cover, and the tests on the spawned binary do:
/// `kpa serve`'s argument and config-file handling and its startup
/// (`PR_SET_DUMPABLE`), and logging to a stderr of its own.
pub struct InProcessDaemon {
    pub socket: PathBuf,
    /// The cgroup its connections are taken to have, on this socket and on
    /// an agent socket a test starts (`kpa::authn::assume_cgroup`).
    pub cgroup: String,
    /// What serves the sockets: a test that wants the SSH agent's starts it
    /// with `serve_agent`.
    pub daemon: Arc<kpa::daemon::Daemon>,
    pub databases: Arc<kpa::databases::Databases>,
    /// The display session as the daemon's front ends read it. Written by
    /// the test, or by the logind watch of `on_bus` (then `None`).
    pub display: Option<Arc<kpa::display_session::DisplayWriter>>,
    /// The daemon's file locations: its SSH key cache lives under its own
    /// tempdir, so a test never touches the real one.
    pub paths: kpa::paths::Paths,
    /// The one `known_hosts` file the daemon reads, in its own tempdir
    /// rather than the user's and the system's.
    pub known_hosts: PathBuf,
    _dir: tempfile::TempDir,
}

/// The sleep hold's place in a daemon with no logind watch.
struct NoSleepHold;

impl kpa::databases::Observer for NoSleepHold {}

impl InProcessDaemon {
    /// Starts a daemon on `config`, TOML as in a config file.
    pub fn start(config: &str) -> InProcessDaemon {
        InProcessDaemon::with_config(kpa::config::Config::parse(config).expect("valid config"))
    }

    pub fn with_config(config: kpa::config::Config) -> InProcessDaemon {
        InProcessDaemon::with_requester_on(config, true)
    }

    /// Like `with_config`, but every connection runs on the desktop only if
    /// `on_desktop`: for copy-gating tests that need a requester outside it.
    pub fn with_requester_on(config: kpa::config::Config, on_desktop: bool) -> InProcessDaemon {
        let (writer, display) = kpa::display_session::channel();
        writer.set(kpa::display_session::DisplaySession::Unlocked {
            id: "test".to_string(),
            active: true,
        });
        InProcessDaemon::build(
            config,
            cgroup_on(on_desktop, "test"),
            Some(writer),
            display,
            Arc::new(NoSleepHold),
            None,
        )
    }

    /// A daemon whose lock triggers come from a message bus at `address`
    /// (a private bus a test runs a mock logind on), and whose display
    /// session is whatever that bus reports; its connections run on the
    /// desktop of the display session `session`.
    pub fn on_bus(config: kpa::config::Config, address: &str, session: &str) -> InProcessDaemon {
        let (writer, display) = kpa::display_session::channel();
        let (sleep_hold, auto_lock) = kpa::frontends::auto_lock::start(
            kpa::frontends::auto_lock::Source::at(address),
            writer,
        );
        InProcessDaemon::build(
            config,
            cgroup_on(true, session),
            None,
            display,
            Arc::new(sleep_hold),
            Some(auto_lock),
        )
    }

    fn build(
        mut config: kpa::config::Config,
        cgroup: String,
        writer: Option<kpa::display_session::DisplayWriter>,
        display: kpa::display_session::DisplayHandle,
        sleep_hold: Arc<dyn kpa::databases::Observer>,
        auto_lock: Option<kpa::frontends::auto_lock::AutoLock>,
    ) -> InProcessDaemon {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let socket = dir.path().join("sock");
        let paths = kpa::paths::Paths {
            cache_dir: Some(dir.path().join("cache")),
            ..kpa::paths::Paths::default()
        };
        let known_hosts = dir.path().join("known_hosts");
        config.ssh_agent.known_hosts = vec![known_hosts.clone()];
        let idle_timeout = config.idle_timeout;
        let backends = kpa::daemon::Backends::real(&config);
        // No tray: there is no session bus to show one on.
        let (daemon, _tray) =
            kpa::daemon::build(config, paths.clone(), backends, display, sleep_hold);
        let daemon = Arc::new(daemon);
        let databases = Arc::clone(&daemon.databases);
        match auto_lock {
            Some(auto_lock) => {
                let databases = Arc::clone(&databases);
                std::thread::spawn(move || auto_lock.run(databases, idle_timeout));
            }
            // No logind watch, so no idle tick either: this one stands in for
            // `auto_lock`'s, at the same rate.
            None => {
                let databases = Arc::clone(&databases);
                let tick = (idle_timeout / 10).clamp(
                    std::time::Duration::from_millis(10),
                    std::time::Duration::from_secs(1),
                );
                std::thread::spawn(move || {
                    loop {
                        std::thread::sleep(tick);
                        databases.expire_idle(std::time::Instant::now());
                    }
                });
            }
        }
        kpa::authn::assume_cgroup(&socket, &cgroup);
        // Not `socket::bind_socket`: it sets the process-wide umask for the
        // bind, and a directory another test thread created meanwhile
        // would come out without its search bit.
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).expect("failed to bind socket");
        let serving = Arc::clone(&daemon);
        std::thread::spawn(move || serving.serve_control(listener));
        InProcessDaemon {
            socket,
            cgroup,
            daemon,
            databases,
            display: writer.map(Arc::new),
            paths,
            known_hosts,
            _dir: dir,
        }
    }

    /// Unlocks `name` with the fixtures' password, as an unlock at the desk
    /// would.
    pub fn unlock(&self, name: &str) {
        let password = zeroize::Zeroizing::new(PASSWORD.to_string());
        match self.databases.begin_unlock(name) {
            Ok(kpa::databases::Begin::Started(unlocking)) => {
                unlocking.finish(Some(&password)).expect("unlock");
            }
            _ => panic!("expected to start an unlock of {name}"),
        }
    }

    /// Sets the display session the daemon's front ends read.
    pub fn set_display(&self, session: kpa::display_session::DisplaySession) {
        self.display
            .as_ref()
            .expect("the logind watch writes this daemon's display session")
            .set(session);
    }

    pub fn run(&self, args: &[&str]) -> serde_json::Value {
        run_cli(&self.socket, args)
    }
}

/// The running SSH agent socket for a `daemon`, in its own
/// tempdir. The key cache is the daemon's own, under its tempdir
/// (`InProcessDaemon::paths`), never this process's real
/// `$XDG_CACHE_HOME`.
pub struct SshAgent {
    pub socket: PathBuf,
    _socket_dir: tempfile::TempDir,
}

pub fn start_ssh_agent(daemon: &InProcessDaemon) -> SshAgent {
    let socket_dir = tempfile::tempdir().expect("tempdir");
    let socket = socket_dir.path().join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind ssh agent socket");
    kpa::authn::assume_cgroup(&socket, &daemon.cgroup);
    let serving = std::sync::Arc::clone(&daemon.daemon);
    std::thread::spawn(move || serving.serve_agent(listener));
    SshAgent {
        socket,
        _socket_dir: socket_dir,
    }
}

/// A pseudo-terminal, for driving `kpa unlock`'s terminal prompt
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

    /// The slave end, opened as a client's `/dev/tty` would be, for passing
    /// to the daemon on a socket.
    pub fn open_slave(&self) -> std::os::fd::OwnedFd {
        use rustix::fs::{Mode, OFlags, open};

        open(
            self.slave_path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open the pty's slave")
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

    /// Whether the screen has anything on it to read now.
    pub fn shows_anything(&self) -> bool {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        let mut fds = [PollFd::new(&self.master, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut fds, Some(&now)).expect("poll on pty master");
        // Not just any event: the master hangs up once every slave is closed.
        fds[0].revents().contains(PollFlags::IN)
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
                "timed out waiting for {needle:?}; read so far: {out:?}\n{}",
                dump_processes()
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

/// Where every thread of this process and every child of it is, for a test
/// that timed out.
pub fn dump_processes() -> String {
    use std::fmt::Write as _;
    use std::fs;

    fn read(path: &str) -> String {
        fs::read_to_string(path)
            .map(|text| text.trim().replace('\0', " "))
            .unwrap_or_else(|err| format!("<{err}>"))
    }

    fn describe(out: &mut String, pid: u32) {
        let _ = writeln!(
            out,
            "pid {pid}: cmd={:?}",
            read(&format!("/proc/{pid}/cmdline"))
        );
        let _ = writeln!(
            out,
            "  stat={}",
            read(&format!("/proc/{pid}/stat"))
                .chars()
                .take(120)
                .collect::<String>()
        );
        if let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) {
            for task in tasks.flatten() {
                let tid = task.file_name().to_string_lossy().to_string();
                let base = format!("/proc/{pid}/task/{tid}");
                let state = read(&format!("{base}/stat"));
                let state = state
                    .rsplit_once(") ")
                    .map(|(_, rest)| rest.chars().take(1).collect::<String>())
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  task {tid} comm={} state={state} syscall={} wchan={}",
                    read(&format!("{base}/comm")),
                    read(&format!("{base}/syscall")),
                    read(&format!("{base}/wchan")),
                );
            }
        }
        if let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) {
            let mut links: Vec<String> = fds
                .flatten()
                .map(|fd| {
                    format!(
                        "{}->{}",
                        fd.file_name().to_string_lossy(),
                        fs::read_link(fd.path())
                            .map(|l| l.display().to_string())
                            .unwrap_or_default()
                    )
                })
                .collect();
            links.sort();
            let _ = writeln!(out, "  fds={}", links.join(" "));
        }
    }

    let mut out = String::new();
    let me = std::process::id();
    let _ = writeln!(out, "--- processes at {:?}", std::time::SystemTime::now());
    describe(&mut out, me);
    let mut ppids = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let stat = read(&format!("/proc/{pid}/stat"));
            if let Some((_, rest)) = stat.rsplit_once(") ")
                && let Some(ppid) = rest
                    .split_whitespace()
                    .nth(1)
                    .and_then(|p| p.parse::<u32>().ok())
            {
                ppids.push((pid, ppid));
            }
        }
    }
    let mut children = Vec::new();
    let mut frontier = vec![me];
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in &ppids {
            if ppid == parent && !children.contains(&pid) {
                children.push(pid);
                frontier.push(pid);
            }
        }
    }
    children.sort();
    for pid in children {
        describe(&mut out, pid);
    }
    let _ = writeln!(out, "--- load: {}", read("/proc/loadavg"));
    if let Ok(ps) = Command::new("ps")
        .args(["-eo", "pid,ppid,stat,pcpu,etime,args", "--sort=-pcpu"])
        .output()
    {
        let _ = writeln!(
            out,
            "--- ps\n{}",
            String::from_utf8_lossy(&ps.stdout)
                .lines()
                .take(40)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    out
}
