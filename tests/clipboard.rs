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
//! real, reachable Wayland compositor, and drives that session's actual
//! clipboard: anything else on it (a clipboard manager, an X11 bridge) can
//! take the selection mid-test and fail the run. They share that one
//! clipboard, so they take turns on [`LIVE_CLIPBOARD`]. And they're
//! `#[ignore]`d, run only on request when the clipboard logic changes:
//!
//! ```sh
//! nix develop -c cargo test --test clipboard -- --ignored
//! ```
//!
//! The daemon finds the compositor through the service manager's
//! environment, not its own (`src/clipboard/wayland/compositor.rs`), so
//! `compositor` looks it up the same way, and the `wl-paste`/`wl-copy` the
//! tests run are pointed at it. Where none is reachable, an opted-in test
//! prints why and skips rather than fails. The state machine those tests
//! exercise — a timeout or a lock ending the current offer, a second
//! `copy` replacing the first — is covered without any compositor at all
//! by `src/clipboard/mod.rs`'s own unit tests.

mod common;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use common::InProcessDaemon;
use kpa::display_session::DisplaySession;

/// Held by each test that drives the live clipboard, for its whole run.
static LIVE_CLIPBOARD: Mutex<()> = Mutex::new(());

/// An in-process daemon (`common::InProcessDaemon`) for
/// `common::password_db()`, whose prompt echoes `password`. In-process
/// because these tests unlock through that prompt, and a spawned
/// `kpa serve` asks for an `unlock` from outside the desktop on a terminal.
fn start(password: &str) -> InProcessDaemon {
    InProcessDaemon::start(&common::config_toml(
        &format!("printf %s {password}"),
        &common::password_db().display().to_string(),
    ))
}

/// The compositor the daemon would copy to: `WAYLAND_DISPLAY` from the
/// service manager's environment, if a socket by that name in
/// `$XDG_RUNTIME_DIR` accepts a connection. A stale value with nothing
/// listening behind it counts as none.
fn compositor() -> Option<String> {
    let shown = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .ok()?;
    let environment = String::from_utf8(shown.stdout).ok()?;
    let display = environment
        .lines()
        .find_map(|line| line.strip_prefix("WAYLAND_DISPLAY="))?
        .to_string();
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
    UnixStream::connect(PathBuf::from(runtime_dir).join(&display)).ok()?;
    Some(display)
}

/// The user's logind display session, which the daemon's must name
/// for the compositor to pass as being on the desktop when it runs in
/// that session's scope.
fn display_session() -> Option<String> {
    let uid = kpa::authn::process_uid().to_string();
    let shown = Command::new("loginctl")
        .args(["show-user", &uid, "--property=Display", "--value"])
        .output()
        .ok()?;
    let session = String::from_utf8(shown.stdout).ok()?.trim().to_string();
    (!session.is_empty()).then_some(session)
}

/// A daemon like `start`'s, whose state names the real display session.
fn start_on_the_display_session(config: &str, session: String) -> InProcessDaemon {
    let daemon = InProcessDaemon::start(config);
    daemon.set_display(DisplaySession::Unlocked {
        id: session,
        active: true,
    });
    daemon
}

/// The uuid `tests/fixture.sh`'s password-only database's one entry was
/// given, read back through `list` rather than hardcoded — this test
/// shouldn't also be the one place that knows the fixture's internal
/// uuid.
fn fixture_entry_uuid(daemon: &InProcessDaemon) -> String {
    let listed = daemon.run(&["list"]);
    listed["entries"][0]["uuid"]
        .as_str()
        .expect("fixture has one entry with a uuid")
        .to_string()
}

/// `docs/design.md` § Clipboard explicitly plans for a daemon run without
/// Wayland reachable — logind-less hosts get the analogous treatment in
/// `frontends/auto_lock/logind.rs`. `copy` must answer with a clean error, not hang the
/// connection or take the daemon down, so every other request still gets
/// answered afterward.
#[test]
fn copy_fails_cleanly_without_a_wayland_compositor() {
    if compositor().is_some() {
        eprintln!(
            "skipping: this test is specifically about an unreachable compositor, \
             but one is reachable in this environment"
        );
        return;
    }

    let daemon = start(common::PASSWORD);
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

/// `docs/headless.md` § 5: a requester outside the desktop never reaches
/// the clipboard — `copy` answers `no_display` before touching it, so
/// unlike the tests above, this needs no reachable compositor, and the
/// database stays locked throughout (the gate is checked before `Locked`,
/// so it fires even here).
#[test]
fn copy_from_outside_the_desktop_is_refused() {
    let config = common::config_toml(
        "printf %s unused",
        &common::password_db().display().to_string(),
    );
    let daemon = InProcessDaemon::with_requester_on(
        kpa::config::Config::parse(&config).expect("valid config"),
        false,
    );

    let copied = daemon.run(&[
        "copy",
        "personal",
        &uuid::Uuid::nil().to_string(),
        "password",
    ]);
    assert_eq!(copied["ok"], false, "got {copied}");
    assert_eq!(copied["error"], "no_display");
    // `no_display` names no database — it's about where the request came
    // from, not about any database (same shape as `unlock`'s).
    assert!(copied.get("db").is_none(), "got {copied}");

    // Still alive and answering other requests.
    assert_eq!(daemon.run(&["status"])["ok"], true);
}

/// Same gate, from the desktop: a locked, inactive, or absent display
/// session all refuse `copy` with `no_display` too — only an active,
/// unlocked session passes (`copy_fails_cleanly_without_a_wayland_compositor`
/// above is that passing case).
#[test]
fn copy_from_the_desktop_is_refused_without_an_active_unlocked_display_session() {
    let daemon = start(common::PASSWORD);
    let cases = [
        DisplaySession::Locked {
            id: "test".to_string(),
            active: true,
        },
        DisplaySession::Unlocked {
            id: "test".to_string(),
            active: false,
        },
        DisplaySession::None,
    ];
    for display_session in cases {
        daemon.set_display(display_session.clone());
        let copied = daemon.run(&[
            "copy",
            "personal",
            &uuid::Uuid::nil().to_string(),
            "password",
        ]);
        assert_eq!(
            copied["error"], "no_display",
            "display session {display_session:?}, got {copied}"
        );
    }
}

/// `docs/plan.md` step 3's own test plan, run against a real compositor
/// when one is reachable: `copy`, then a real `wl-paste` sees the secret
/// and `wl-paste --list-types` shows the password-manager hint.
#[test]
#[ignore = "drives the live Wayland clipboard; run with --ignored when changing clipboard logic"]
fn copy_reaches_a_reachable_compositor() {
    let _turn = LIVE_CLIPBOARD.lock().unwrap_or_else(|e| e.into_inner());
    let (Some(display), Some(session)) = (compositor(), display_session()) else {
        eprintln!(
            "skipping: no reachable Wayland compositor in the service manager's \
             environment, or no display session; docs/plan.md step 3's full \
             clipboard test plan needs both"
        );
        return;
    };

    let daemon = start_on_the_display_session(
        &common::config_toml(
            &format!("printf %s {}", common::PASSWORD),
            &common::password_db().display().to_string(),
        ),
        session,
    );
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let uuid = fixture_entry_uuid(&daemon);

    let copied = daemon.run(&["copy", "personal", &uuid, "password"]);
    assert_eq!(copied["ok"], true, "got {copied}");
    assert_eq!(copied["copied"], "password");

    let pasted = Command::new("wl-paste")
        .arg("--no-newline")
        .env("WAYLAND_DISPLAY", &display)
        .output()
        .expect("failed to spawn wl-paste");
    assert_eq!(
        String::from_utf8_lossy(&pasted.stdout),
        "entrypass1",
        "wl-paste did not see the copied secret"
    );

    let types = Command::new("wl-paste")
        .arg("--list-types")
        .env("WAYLAND_DISPLAY", &display)
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
#[ignore = "drives the live Wayland clipboard; run with --ignored when changing clipboard logic"]
fn surviving_a_takeover_past_the_timeout() {
    let _turn = LIVE_CLIPBOARD.lock().unwrap_or_else(|e| e.into_inner());
    let (Some(display), Some(session)) = (compositor(), display_session()) else {
        eprintln!(
            "skipping: no reachable Wayland compositor or display session; \
             this is docs/plan.md step 3's ownership test"
        );
        return;
    };

    let daemon = start_on_the_display_session(
        &format!(
            "clipboard_timeout = \"1s\"\n{}",
            common::config_toml(
                &format!("printf %s {}", common::PASSWORD),
                &common::password_db().display().to_string(),
            )
        ),
        session,
    );
    let run = |args: &[&str]| daemon.run(args);

    assert_eq!(run(&["unlock", "personal"])["ok"], true);
    let listed = run(&["list"]);
    let uuid = listed["entries"][0]["uuid"].as_str().expect("has a uuid");

    assert_eq!(run(&["copy", "personal", uuid, "password"])["ok"], true);

    // Immediately take the clipboard with something else.
    let status = Command::new("wl-copy")
        .arg("hello")
        .env("WAYLAND_DISPLAY", &display)
        .status()
        .expect("spawn wl-copy");
    assert!(status.success());

    // Wait past clipboard_timeout.
    std::thread::sleep(Duration::from_millis(1500));

    let pasted = Command::new("wl-paste")
        .arg("--no-newline")
        .env("WAYLAND_DISPLAY", &display)
        .output()
        .expect("spawn wl-paste");
    assert_eq!(
        String::from_utf8_lossy(&pasted.stdout),
        "hello",
        "kpa's belated drop clobbered a later, unrelated clipboard write"
    );
}

/// A lock ends the offer its database's `copy` started (G-6): the
/// clipboard no longer serves the secret once `lock` answers.
#[test]
#[ignore = "drives the live Wayland clipboard; run with --ignored when changing clipboard logic"]
fn a_lock_ends_the_offer() {
    let _turn = LIVE_CLIPBOARD.lock().unwrap_or_else(|e| e.into_inner());
    let (Some(display), Some(session)) = (compositor(), display_session()) else {
        eprintln!("skipping: no reachable Wayland compositor or display session");
        return;
    };

    let daemon = start_on_the_display_session(
        &common::config_toml(
            &format!("printf %s {}", common::PASSWORD),
            &common::password_db().display().to_string(),
        ),
        session,
    );
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let uuid = fixture_entry_uuid(&daemon);
    assert_eq!(
        daemon.run(&["copy", "personal", &uuid, "password"])["ok"],
        true
    );

    assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);

    let pasted = Command::new("wl-paste")
        .arg("--no-newline")
        .env("WAYLAND_DISPLAY", &display)
        .output()
        .expect("spawn wl-paste");
    assert_ne!(
        String::from_utf8_lossy(&pasted.stdout),
        "entrypass1",
        "the secret was still served after its database locked"
    );
}
