//! What the daemon writes to its log, for the cases that need an unlock:
//! the daemon runs in-process (`common::InProcessDaemon`, see
//! `tests/control.rs`), with this process's stderr pointed at a file while
//! it serves.
//!
//! Its own test binary because stderr and the log level are process-wide.
//! The tests here take turns through `STDERR_LOCK`.

mod common;

use std::io::{Read, Seek};
use std::os::fd::AsFd;
use std::sync::Mutex;

use common::{InProcessDaemon, config_toml};
use kpa::log::Level;

static STDERR_LOCK: Mutex<()> = Mutex::new(());

/// Runs `body` with fd 2 pointed at a temp file, puts the original back,
/// and returns what was written. `crate::log` writes to fd 2 directly, so
/// the test harness's output capture doesn't see it.
fn capture_stderr(body: impl FnOnce()) -> String {
    let _turn = STDERR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = rustix::io::dup(std::io::stderr().as_fd()).expect("dup stderr");
    let mut file = tempfile::tempfile().expect("tempfile");
    rustix::stdio::dup2_stderr(&file).expect("point stderr at the file");
    body();
    rustix::stdio::dup2_stderr(&original).expect("restore stderr");
    let mut log = String::new();
    file.rewind().expect("rewind");
    file.read_to_string(&mut log).expect("read log");
    log
}

/// What the daemon logs names operations and databases, never what a
/// database holds — at the most verbose level too (`docs/design.md`
/// § Secrets).
#[test]
fn the_log_never_carries_vault_contents_or_the_password() {
    let daemon = InProcessDaemon::start(&config_toml(
        &format!("printf %s '{}'", common::PASSWORD),
        &common::password_db().display().to_string(),
    ));
    let mut listed = serde_json::Value::Null;
    let log = capture_stderr(|| {
        kpa::log::set_level(Level::Debug);
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
        listed = daemon.run(&["list"]);
        assert_eq!(listed["ok"], true);
        assert_eq!(daemon.run(&["unlock", "nope"])["ok"], false);
        assert_eq!(daemon.run(&["lock"])["ok"], true);
        kpa::log::set_level(Level::Info);
    });

    assert!(log.contains(" INFO  unlocked \"personal\""), "{log}");
    assert!(log.contains(" DEBUG prompting for \"personal\""), "{log}");
    assert!(log.contains(" DEBUG connection from the desktop"), "{log}");
    assert!(log.contains(" WARN  unlock failed"), "{log}");
    assert!(log.contains(" INFO  locked every database"), "{log}");

    let mut secrets = vec![common::PASSWORD.to_string()];
    for entry in listed["entries"].as_array().expect("entries") {
        for field in ["title", "username", "url"] {
            if let Some(text) = entry[field].as_str().filter(|t| t.len() > 2) {
                secrets.push(text.to_string());
            }
        }
    }
    assert!(
        secrets.len() > 1,
        "the fixture listed no entry text: {listed}"
    );
    for secret in &secrets {
        assert!(
            !log.contains(secret.as_str()),
            "{secret:?} reached the log:\n{log}"
        );
    }
}

/// A lock the freshness guard makes is logged with its reason, as every lock
/// is (`docs/design.md` § Logging).
#[test]
fn a_changed_file_is_logged_as_the_reason_for_a_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = dir.path().join("personal.kdbx");
    std::fs::copy(common::password_db(), &copy).expect("copy the fixture");
    let daemon = InProcessDaemon::start(&config_toml(
        &format!("printf %s '{}'", common::PASSWORD),
        &copy.display().to_string(),
    ));
    // The whole run is under the capture: stderr is process-wide, and the
    // other tests read it.
    let log = capture_stderr(|| {
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&copy)
            .and_then(|mut file| std::io::Write::write_all(&mut file, b"x"))
            .expect("append to the copy");
        assert_eq!(daemon.run(&["list"])["ok"], false);
    });

    assert!(
        log.contains(" INFO  locked \"personal\" (file changed)"),
        "{log}"
    );
}

/// `docs/threat-model.md` T-4: "the prompt gets its own stderr, never the
/// daemon's." A prompt script writing to its own stderr must not have that
/// output land in the daemon's log, unescaped and without a level or
/// timestamp. The prompt is spawned while fd 2 is the capture file, so a
/// prompt that inherited the daemon's stderr would write there.
#[test]
fn the_prompts_stderr_never_reaches_the_daemons() {
    let daemon = InProcessDaemon::start(&config_toml(
        &format!(
            "echo MARKER:{} >&2; printf %s '{}'",
            common::PASSWORD,
            common::PASSWORD
        ),
        &common::password_db().display().to_string(),
    ));
    let log = capture_stderr(|| {
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    });

    assert!(log.contains(" INFO  unlocked \"personal\""), "{log}");
    assert!(
        !log.contains("MARKER:"),
        "the prompt's stderr reached the daemon's log:\n{log}"
    );
}

/// Unlocking an already-unlocked database succeeds without opening
/// anything, so it logs nothing.
#[test]
fn unlocking_twice_logs_one_unlocked_line() {
    let daemon = InProcessDaemon::start(&config_toml(
        &format!("printf %s '{}'", common::PASSWORD),
        &common::password_db().display().to_string(),
    ));
    let log = capture_stderr(|| {
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    });

    assert_eq!(log.matches(" INFO  unlocked").count(), 1, "{log}");
}

/// `kpa ssh keys` hands entry titles and attachment names to its caller.
/// The daemon's log, at the most verbose level, names neither.
#[test]
fn the_log_never_carries_what_ssh_keys_returns() {
    let daemon = InProcessDaemon::start(&config_toml(
        &format!("printf %s '{}'", common::PASSWORD),
        &common::ssh_db().display().to_string(),
    ));
    let mut printed = String::new();
    let log = capture_stderr(|| {
        kpa::log::set_level(Level::Debug);
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_kpa"))
            .arg("--socket")
            .arg(&daemon.socket)
            .args(["ssh", "keys"])
            .output()
            .expect("failed to spawn kpa");
        assert!(output.status.success());
        printed = String::from_utf8(output.stdout).expect("UTF-8");
        kpa::log::set_level(Level::Info);
    });

    for secret in ["Ed25519", "Ecdsa", "Rsa", "id_ed25519", "id_rsa_pem"] {
        assert!(printed.contains(secret), "sanity: {secret:?} not printed");
        assert!(!log.contains(secret), "{secret:?} reached the log:\n{log}");
    }
}
