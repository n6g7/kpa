//! Integration tests for `docs/plan.md` step 3's `copy` op.
//!
//! `copy_fails_cleanly_without_a_wayland_compositor` runs unconditionally —
//! it's exactly what this sandbox's own environment exercises, and it's a
//! real property worth pinning: a daemon that can't reach a compositor
//! must still answer instead of hanging or crashing.
//!
//! The rest of `docs/plan.md` step 3's test plan — `wl-paste` actually
//! seeing the secret, `wl-paste --list-types` showing the password-manager
//! hint, the timeout expiring it, and the ownership test (copy, then
//! `wl-copy hello`, confirm `hello` survives past the timeout) — needs a
//! real, reachable Wayland compositor. `wayland_available` checks for one;
//! where it's missing (as in this sandbox: no `$WAYLAND_DISPLAY`, nothing
//! listening), the tests that need it print why and skip rather than fail,
//! per `docs/plan.md` step 3's instruction to adapt to what's actually
//! available. The state machine those tests would exercise — supersession
//! making a timeout a no-op, a second `copy` replacing the first — is
//! covered without any compositor at all by `src/clip.rs`'s own unit tests.

mod common;

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
    fn start(password: &str) -> Daemon {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let socket = dir.path().join("sock");
        let config_path = dir.path().join("config.toml");
        let config = format!(
            "prompt = [\"/bin/sh\", \"-c\", \"printf %s {password}\"]\n\n\
             [[database]]\n\
             name = \"personal\"\n\
             path = \"{}\"\n",
            common::password_db().display()
        );
        std::fs::write(&config_path, config).expect("failed to write config");

        let child = Command::new(env!("CARGO_BIN_EXE_kpa"))
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::null())
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

/// Whether a Wayland compositor is actually reachable — not just whether
/// `$WAYLAND_DISPLAY` is set, since a stale value with nothing listening
/// behind it should skip exactly the same as it being unset.
fn wayland_available() -> bool {
    let Some(display) = std::env::var_os("WAYLAND_DISPLAY") else {
        return false;
    };
    let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return false;
    };
    let socket_path = PathBuf::from(runtime_dir).join(&display);
    UnixStream::connect(&socket_path).is_ok()
}

/// The uuid `tests/fixture.sh`'s password-only database's one entry was
/// given, read back through `list` rather than hardcoded — this test
/// shouldn't also be the one place that knows the fixture's internal
/// uuid.
fn fixture_entry_uuid(daemon: &Daemon) -> String {
    let listed = daemon.run(&["list"]);
    listed["entries"][0]["uuid"]
        .as_str()
        .expect("fixture has one entry with a uuid")
        .to_string()
}

/// `docs/design.md` § Clipboard explicitly plans for a daemon run without
/// Wayland reachable — logind-less hosts get the analogous treatment in
/// `policy.rs`. `copy` must answer with a clean error, not hang the
/// connection or take the daemon down, so every other request still gets
/// answered afterward.
#[test]
fn copy_fails_cleanly_without_a_wayland_compositor() {
    if wayland_available() {
        eprintln!(
            "skipping: this test is specifically about an unreachable compositor, \
             but one is reachable in this environment"
        );
        return;
    }

    let daemon = Daemon::start(common::PASSWORD);
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let uuid = fixture_entry_uuid(&daemon);

    let copied = daemon.run(&["copy", "personal", &uuid, "password"]);
    assert_eq!(copied["ok"], false, "got {copied}");
    assert_eq!(copied["error"], "io");
    assert_eq!(copied["db"], "personal");
    // No secret value anywhere in the response — just which field was
    // asked for lives in the request, never in this error.
    assert!(copied.get("password").is_none());

    // The daemon is still alive and answering other requests — a failed
    // clipboard handoff must not have taken it down or left the
    // connection-handling thread stuck.
    let status = daemon.run(&["status"]);
    assert_eq!(status["ok"], true);
}

/// `docs/plan.md` step 3's own test plan, run against a real compositor
/// when one is reachable: `copy`, then a real `wl-paste` sees the secret
/// and `wl-paste --list-types` shows the password-manager hint.
#[test]
fn copy_reaches_a_reachable_compositor() {
    if !wayland_available() {
        eprintln!(
            "skipping: no reachable Wayland compositor in this environment \
             ($WAYLAND_DISPLAY/$XDG_RUNTIME_DIR did not resolve to a live socket); \
             docs/plan.md step 3's full clipboard test plan needs one"
        );
        return;
    }

    let daemon = Daemon::start(common::PASSWORD);
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let uuid = fixture_entry_uuid(&daemon);

    let copied = daemon.run(&["copy", "personal", &uuid, "password"]);
    assert_eq!(copied["ok"], true, "got {copied}");
    assert_eq!(copied["copied"], "password");

    let pasted = Command::new("wl-paste")
        .arg("--no-newline")
        .output()
        .expect("failed to spawn wl-paste");
    assert_eq!(
        String::from_utf8_lossy(&pasted.stdout),
        "entrypass1",
        "wl-paste did not see the copied secret"
    );

    let types = Command::new("wl-paste")
        .arg("--list-types")
        .output()
        .expect("failed to spawn wl-paste --list-types");
    let types = String::from_utf8_lossy(&types.stdout);
    assert!(
        types.contains("x-kde-passwordManagerHint"),
        "missing password-manager hint, got {types:?}"
    );
}

/// The ownership test from `docs/plan.md` step 3: copy, then something
/// else (`wl-copy hello`) takes the clipboard immediately, then wait past
/// `clipboard_timeout` — `hello` must survive, proving the timeout-driven
/// drop was a no-op once superseded rather than a blind clear.
#[test]
fn surviving_a_takeover_past_the_timeout() {
    if !wayland_available() {
        eprintln!(
            "skipping: no reachable Wayland compositor in this environment; \
             this is docs/plan.md step 3's ownership test"
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("sock");
    let config_path = dir.path().join("config.toml");
    let config = format!(
        "clipboard_timeout = \"1s\"\n\
         prompt = [\"/bin/sh\", \"-c\", \"printf %s {}\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{}\"\n",
        common::PASSWORD,
        common::password_db().display()
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_kpa"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kpa serve");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(20));
    }

    let run = |args: &[&str]| -> Value {
        let output = Command::new(env!("CARGO_BIN_EXE_kpa"))
            .arg("--socket")
            .arg(&socket)
            .args(args)
            .output()
            .expect("spawn kpa client");
        let text = String::from_utf8(output.stdout).expect("utf8 stdout");
        serde_json::from_str(text.trim()).expect("valid JSON response")
    };

    assert_eq!(run(&["unlock", "personal"])["ok"], true);
    let listed = run(&["list"]);
    let uuid = listed["entries"][0]["uuid"].as_str().expect("has a uuid");

    assert_eq!(run(&["copy", "personal", uuid, "password"])["ok"], true);

    // Immediately take the clipboard with something else.
    let status = Command::new("wl-copy")
        .arg("hello")
        .status()
        .expect("spawn wl-copy");
    assert!(status.success());

    // Wait past clipboard_timeout.
    std::thread::sleep(Duration::from_millis(1500));

    let pasted = Command::new("wl-paste")
        .arg("--no-newline")
        .output()
        .expect("spawn wl-paste");
    assert_eq!(
        String::from_utf8_lossy(&pasted.stdout),
        "hello",
        "kpa's belated drop clobbered a later, unrelated clipboard write"
    );

    let _ = child.kill();
    let _ = child.wait();
}
