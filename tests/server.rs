//! Integration test for `docs/plan.md` step 2: spawns the real `kpa serve`
//! binary against a temp socket and config, then drives it through the
//! actual `kpa` client subcommands — not a hand-rolled socket client — so
//! this exercises the real protocol round-trip an operator would see. One
//! raw-socket test (`version_mismatch_is_rejected`) is the exception: there
//! is no client subcommand that sends a wrong `v` on purpose.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Daemon {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    /// Starts `kpa serve` with a config that unlocks `common::password_db()`
    /// under the name `"personal"`, whose configured prompt just echoes
    /// `password`. Waits for the socket to appear before returning.
    fn start(password: &str) -> Daemon {
        Daemon::spawn(&format!("printf %s '{password}'"), Stdio::null())
    }

    /// Like `start`, but the prompt takes a second to answer — long enough
    /// to land another request while an unlock is still in flight.
    fn start_slow(password: &str) -> Daemon {
        Daemon::spawn(&format!("sleep 1; printf %s '{password}'"), Stdio::null())
    }

    fn spawn(prompt_script: &str, stdout: Stdio) -> Daemon {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let socket = dir.path().join("sock");
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_toml(prompt_script)).expect("failed to write config");

        let child = Command::new(env!("CARGO_BIN_EXE_kpa"))
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--config")
            .arg(&config_path)
            .stdout(stdout)
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn kpa serve");

        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "kpa serve did not create its socket in time"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        Daemon {
            child,
            socket,
            _dir: dir,
        }
    }

    /// Runs `kpa <args> --socket <socket>` and parses its printed response
    /// line. Read as plain JSON on purpose: these tests check what goes over
    /// the wire, literally, rather than what a typed client makes of it.
    fn run(&self, args: &[&str]) -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_kpa"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .expect("failed to spawn kpa client");
        let text = String::from_utf8(output.stdout).expect("client stdout is not valid UTF-8");
        serde_json::from_str(text.trim())
            .unwrap_or_else(|err| panic!("could not decode response {text:?}: {err}"))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A config whose one database is `common::password_db()` under the name
/// `"personal"`, and whose `prompt` runs `prompt_script` under `sh -c` —
/// standing in for a real dmenu-style prompt.
fn config_toml(prompt_script: &str) -> String {
    format!(
        "prompt = [\"/bin/sh\", \"-c\", \"{prompt_script}\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{}\"\n",
        common::password_db().display(),
    )
}

#[test]
fn full_lifecycle() {
    let daemon = Daemon::start(common::PASSWORD);

    // Starts locked.
    let status = daemon.run(&["status"]);
    assert_eq!(status["ok"], true);
    assert_eq!(status["databases"].as_array().map(Vec::len), Some(1));
    assert_eq!(status["databases"][0]["locked"], true);
    assert!(status["databases"][0].get("entries").is_none());

    // list on a locked db, named explicitly, is an error.
    let listed = daemon.run(&["list", "personal"]);
    assert_eq!(listed["ok"], false);
    assert_eq!(listed["error"], "locked");

    // list with no db named is not an error — just nothing yet, since
    // nothing is unlocked.
    let listed_all = daemon.run(&["list"]);
    assert_eq!(listed_all["ok"], true);
    assert_eq!(listed_all["entries"], serde_json::json!([]));

    // An unconfigured database name is its own error, distinct from Locked.
    let unknown = daemon.run(&["list", "does-not-exist"]);
    assert_eq!(unknown["ok"], false);
    assert_eq!(unknown["error"], "unknown_db");

    // Unlock.
    let unlocked = daemon.run(&["unlock", "personal"]);
    assert_eq!(unlocked["ok"], true, "unlock failed: {unlocked}");
    assert_eq!(unlocked["db"], "personal");

    // Unlocking again while already unlocked is a no-op success, not a
    // second prompt.
    let unlocked_again = daemon.run(&["unlock", "personal"]);
    assert_eq!(unlocked_again["ok"], true);

    let status = daemon.run(&["status"]);
    assert_eq!(status["databases"][0]["locked"], false);
    assert_eq!(status["databases"][0]["entries"], 1);

    // list now returns the fixture's one entry.
    let listed = daemon.run(&["list"]);
    let entries = &listed["entries"];
    assert_eq!(entries.as_array().map(Vec::len), Some(1));
    assert_eq!(entries[0]["db"], "personal");
    assert_eq!(entries[0]["title"], "Example");
    assert_eq!(entries[0]["username"], "alice");
    assert_eq!(entries[0]["group"], "Web");

    // Naming the db explicitly gives the same one entry.
    let listed_named = daemon.run(&["list", "personal"]);
    assert_eq!(listed_named["entries"].as_array().map(Vec::len), Some(1));

    // Lock, then confirm list on it errors again.
    let locked = daemon.run(&["lock", "personal"]);
    assert_eq!(locked["ok"], true);
    let listed = daemon.run(&["list", "personal"]);
    assert_eq!(listed["ok"], false);
    assert_eq!(listed["error"], "locked");
}

#[test]
fn wrong_password_is_reported_and_leaves_the_database_locked() {
    let daemon = Daemon::start("not-the-real-password");

    let unlocked = daemon.run(&["unlock", "personal"]);
    assert_eq!(unlocked["ok"], false);
    assert_eq!(unlocked["error"], "wrong_credentials");

    let status = daemon.run(&["status"]);
    assert_eq!(
        status["databases"][0]["locked"], true,
        "a failed unlock must not leave it unlocked"
    );
}

#[test]
fn lock_all_locks_every_database() {
    let daemon = Daemon::start(common::PASSWORD);
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);

    let locked = daemon.run(&["lock"]); // no db named = lock all
    assert_eq!(locked["ok"], true);

    let status = daemon.run(&["status"]);
    assert_eq!(status["databases"][0]["locked"], true);
}

/// The one test that talks to the socket directly rather than through a
/// `kpa` client subcommand — there's no legitimate way to make the real
/// client send a mismatched `v`.
#[test]
fn version_mismatch_is_rejected() {
    let daemon = Daemon::start(common::PASSWORD);

    let mut stream =
        UnixStream::connect(&daemon.socket).expect("failed to connect to daemon socket");
    writeln!(stream, r#"{{"v":99,"op":"status"}}"#).expect("failed to write request");

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("failed to read response");

    let response: Value = serde_json::from_str(line.trim()).expect("failed to decode response");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"], "version_mismatch");
    // The response always carries the daemon's own version, not the
    // client's claimed one — that's the whole point (docs/design.md).
    assert_eq!(response["v"], kpa::proto::VERSION);
    // `docs/plan.md` step 2 asks for "a clear error naming both versions".
    let detail = response["detail"]
        .as_str()
        .expect("version mismatch should explain itself");
    assert!(
        detail.contains('1'),
        "should name the daemon's version: {detail}"
    );
    assert!(
        detail.contains("99"),
        "should name the client's claimed version: {detail}"
    );
}

/// Malformed JSON must get a clean error, never take the daemon down —
/// the socket is the untrusted-input boundary `docs/plan.md` step 6's
/// fuzzing will exercise harder later, but even a single malformed line
/// must not be special.
#[test]
fn malformed_request_is_rejected_without_crashing_the_daemon() {
    let daemon = Daemon::start(common::PASSWORD);

    let mut stream =
        UnixStream::connect(&daemon.socket).expect("failed to connect to daemon socket");
    writeln!(stream, "not json at all").expect("failed to write request");

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("failed to read response");

    let response: Value = serde_json::from_str(line.trim()).expect("failed to decode response");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"], "malformed_request");

    // The daemon is still alive and serving normally.
    assert_eq!(daemon.run(&["status"])["ok"], true);
}

/// A `lock` issued while an `unlock` is still prompting wins: the unlock
/// finishes, discards what it opened, and reports `locked`
/// (docs/review-2026-09-robustness.md finding 3). Before the lock epoch,
/// the unlock re-opened the database after the lock was acknowledged.
#[test]
fn a_lock_during_an_unlock_is_not_undone() {
    let daemon = Daemon::start_slow(common::PASSWORD);

    std::thread::scope(|scope| {
        let unlocking = scope.spawn(|| daemon.run(&["unlock", "personal"]));
        std::thread::sleep(Duration::from_millis(300));

        assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);

        let unlocked = unlocking.join().expect("unlock thread panicked");
        assert_eq!(
            unlocked["ok"], false,
            "the unlock should report the lock: {unlocked}"
        );
        assert_eq!(unlocked["error"], "locked");
    });

    let status = daemon.run(&["status"]);
    assert_eq!(status["databases"][0]["locked"], true);
}

/// A second `unlock` while the first is prompting is refused rather than
/// opening a second prompt; the first still succeeds.
#[test]
fn a_second_unlock_does_not_open_a_second_prompt() {
    let daemon = Daemon::start_slow(common::PASSWORD);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| daemon.run(&["unlock", "personal"]));
        std::thread::sleep(Duration::from_millis(300));

        let second = daemon.run(&["unlock", "personal"]);
        assert_eq!(second["error"], "unlock_in_progress");

        assert_eq!(first.join().expect("unlock thread panicked")["ok"], true);
    });

    assert_eq!(
        daemon.run(&["unlock", "personal"])["ok"],
        true,
        "unlocked, so this is a no-op"
    );
}

/// Nobody reading the daemon's stdout must not kill it or cost a client
/// its reply (docs/review-2026-09-robustness.md finding 4).
#[test]
fn a_closed_stdout_does_not_take_the_daemon_down() {
    let mut daemon = Daemon::spawn(&format!("printf %s '{}'", common::PASSWORD), Stdio::piped());
    drop(daemon.child.stdout.take());

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    assert_eq!(daemon.run(&["lock"])["ok"], true);
    assert!(
        daemon.child.try_wait().expect("try_wait").is_none(),
        "the daemon exited"
    );
}
