//! The lock triggers over a real D-Bus, against a private `dbus-daemon` and
//! a mock logind served from this test. Nothing touches the system bus or
//! the user's session bus.
//!
//! Needs `dbus-daemon` on `PATH` (the flake's devShell provides it).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod common;

use kpa::authn::Requester;
use kpa::config::Config;
use kpa::paths::Paths;
use kpa::proto::{Unlock, UnlockError, UnlockRequest};
use kpa::server::Server;
use kpa::session_watch::{self, Bus, DisplaySession, SessionEvent};
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;
use zbus::zvariant::{self, OwnedObjectPath, Value};

const MANAGER: &str = "/org/freedesktop/login1";
const USER: &str = "/org/freedesktop/login1/user/_1000";
const SESSION_1: &str = "/org/freedesktop/login1/session/_31";
const SESSION_2: &str = "/org/freedesktop/login1/session/_32";
const TIMEOUT: Duration = Duration::from_secs(10);

/// The logind session id behind each mock session's object path, as
/// `User.Display` reports it. logind's "no display session" is `("", "/")`.
fn session_id(path: &str) -> &'static str {
    match path {
        SESSION_1 => "31",
        SESSION_2 => "32",
        _ => "",
    }
}

/// An unlocked display session, active unless the test says otherwise (the mock's
/// `Active` property defaults to `true` — a session is active until a
/// test says it isn't).
fn unlocked(session: &str) -> DisplaySession {
    DisplaySession::Unlocked {
        id: session.to_string(),
        active: true,
    }
}

fn locked(session: &str) -> DisplaySession {
    DisplaySession::Locked {
        id: session.to_string(),
        active: true,
    }
}

fn unlocked_inactive(session: &str) -> DisplaySession {
    DisplaySession::Unlocked {
        id: session.to_string(),
        active: false,
    }
}

/// A `dbus-daemon` on a socket inside a temp directory, killed on drop.
struct PrivateBus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl PrivateBus {
    fn start() -> PrivateBus {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("bus");
        let stderr_path = dir.path().join("dbus-daemon.stderr");
        // A self-contained bus config, so the daemon does not pick up the
        // host's session.conf or user config (the CI runner's dbus setup
        // differs from a developer's machine).
        let config_path = dir.path().join("bus.conf");
        std::fs::write(
            &config_path,
            format!(
                "<busconfig>\
                 <type>session</type>\
                 <listen>unix:path={}</listen>\
                 <policy context=\"default\">\
                 <allow send_destination=\"*\" eavesdrop=\"true\"/>\
                 <allow eavesdrop=\"true\"/>\
                 <allow own=\"*\"/>\
                 </policy>\
                 </busconfig>",
                socket.display()
            ),
        )
        .unwrap();
        let mut child = Command::new("dbus-daemon")
            .args(["--nofork", "--print-address=1"])
            .arg(format!("--config-file={}", config_path.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .expect("dbus-daemon not found on PATH; run inside `nix develop`");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line
            .trim()
            .split(',')
            .next()
            .unwrap_or_default()
            .to_string();
        if !address.starts_with("unix:") {
            // The daemon never announced a bus. Reap it and show why.
            let _ = child.kill();
            let status = child.wait().ok();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("dbus-daemon printed no bus address (status {status:?}); stderr:\n{stderr}");
        }
        PrivateBus {
            child,
            address,
            _dir: dir,
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        self.kill();
    }
}

/// What the mock logind is holding: the display session, each session's
/// `LockedHint` and `Active`, and the sleep inhibitors handed out.
#[derive(Default)]
struct MockState {
    display: String,
    hints: HashMap<String, bool>,
    /// Absent means active — a session is active until a test says
    /// otherwise, same as real logind for the one session on a seat.
    actives: HashMap<String, bool>,
    /// The read end of each inhibitor's pipe. Once kpa drops the write end,
    /// a read here returns EOF, which is how the test sees a release.
    inhibitors: Vec<UnixStream>,
}

type Shared = Arc<Mutex<MockState>>;

struct Manager(Shared);

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn get_user(&self, _uid: u32) -> OwnedObjectPath {
        OwnedObjectPath::try_from(USER).unwrap()
    }

    fn inhibit(
        &self,
        _what: &str,
        _who: &str,
        _why: &str,
        _mode: &str,
    ) -> zbus::fdo::Result<zvariant::OwnedFd> {
        let (reader, writer) =
            UnixStream::pair().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        reader
            .set_nonblocking(true)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        self.0.lock().unwrap().inhibitors.push(reader);
        Ok(OwnedFd::from(writer).into())
    }
}

struct User(Shared);

#[zbus::interface(name = "org.freedesktop.login1.User")]
impl User {
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        let display = self.0.lock().unwrap().display.clone();
        (
            session_id(&display).to_string(),
            OwnedObjectPath::try_from(display).unwrap(),
        )
    }
}

struct Session {
    state: Shared,
    path: &'static str,
}

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .hints
            .get(self.path)
            .copied()
            .unwrap_or(false)
    }

    #[zbus(property)]
    fn active(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .actives
            .get(self.path)
            .copied()
            .unwrap_or(true)
    }
}

/// The mock logind: owns `org.freedesktop.login1` on the private bus.
struct MockLogind {
    conn: Connection,
    state: Shared,
}

impl MockLogind {
    fn start(address: &str) -> MockLogind {
        let state: Shared = Arc::new(Mutex::new(MockState {
            display: SESSION_1.to_string(),
            ..MockState::default()
        }));
        let conn = Builder::address(address)
            .unwrap()
            .name("org.freedesktop.login1")
            .unwrap()
            .serve_at(MANAGER, Manager(state.clone()))
            .unwrap()
            .serve_at(USER, User(state.clone()))
            .unwrap()
            .serve_at(
                SESSION_1,
                Session {
                    state: state.clone(),
                    path: SESSION_1,
                },
            )
            .unwrap()
            .serve_at(
                SESSION_2,
                Session {
                    state: state.clone(),
                    path: SESSION_2,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        MockLogind { conn, state }
    }

    fn set_hint(&self, session: &'static str, value: bool) {
        self.state
            .lock()
            .unwrap()
            .hints
            .insert(session.to_string(), value);
        self.properties_changed(
            session,
            "org.freedesktop.login1.Session",
            "LockedHint",
            Value::from(value),
        );
    }

    fn set_active(&self, session: &'static str, value: bool) {
        self.state
            .lock()
            .unwrap()
            .actives
            .insert(session.to_string(), value);
        self.properties_changed(
            session,
            "org.freedesktop.login1.Session",
            "Active",
            Value::from(value),
        );
    }

    fn set_display(&self, session: &'static str) {
        self.state.lock().unwrap().display = session.to_string();
        let value = Value::from((
            session_id(session),
            OwnedObjectPath::try_from(session).unwrap(),
        ));
        self.properties_changed(USER, "org.freedesktop.login1.User", "Display", value);
    }

    fn lock_signal(&self, session: &'static str) {
        self.conn
            .emit_signal(
                None::<&str>,
                session,
                "org.freedesktop.login1.Session",
                "Lock",
                &(),
            )
            .unwrap();
    }

    fn prepare_for_sleep(&self, starting: bool) {
        self.conn
            .emit_signal(
                None::<&str>,
                MANAGER,
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &starting,
            )
            .unwrap();
    }

    fn properties_changed(&self, path: &str, iface: &str, name: &str, value: Value<'_>) {
        let mut changed: HashMap<&str, Value<'_>> = HashMap::new();
        changed.insert(name, value);
        self.conn
            .emit_signal(
                None::<&str>,
                path,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(iface, changed, Vec::<&str>::new()),
            )
            .unwrap();
    }

    fn inhibitor_count(&self) -> usize {
        self.state.lock().unwrap().inhibitors.len()
    }

    /// True once the most recent inhibitor's write end is closed.
    fn last_inhibitor_released(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some(reader) = state.inhibitors.last_mut() else {
            return false;
        };
        let mut buf = [0u8; 1];
        match reader.read(&mut buf) {
            Ok(0) => true,
            Err(e) if e.kind() == ErrorKind::WouldBlock => false,
            _ => false,
        }
    }
}

/// What the watcher reported, as a test sees it: events collected by a
/// thread of their own.
#[derive(Default)]
struct Observed {
    events: Mutex<Vec<SessionEvent>>,
}

/// Collects `events` until the watcher is gone.
fn observe(events: Receiver<SessionEvent>) -> Arc<Observed> {
    let observed = Arc::new(Observed::default());
    let collecting = observed.clone();
    thread::spawn(move || {
        for event in events {
            collecting.events.lock().unwrap().push(event);
        }
    });
    observed
}

impl Observed {
    /// The display session as the last report left it: no session after a
    /// lost watch.
    fn display_session(&self) -> DisplaySession {
        let events = self.events.lock().unwrap();
        events
            .iter()
            .rev()
            .find_map(|event| match event {
                SessionEvent::Changed(display_session) => Some(display_session.clone()),
                SessionEvent::WatchLost => Some(DisplaySession::None),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// How many reports the server answers with a lock of everything.
    fn locks(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| match event {
                SessionEvent::Changed(display_session) => display_session.is_locked(),
                _ => true,
            })
            .count()
    }

    fn sleeps(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == SessionEvent::Sleeping)
            .count()
    }

    fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

/// Poll `check` until it holds or the timeout passes.
fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Settle time for "nothing should happen" assertions.
fn quiet() {
    thread::sleep(Duration::from_millis(300));
}

#[test]
fn logind_reports_lock_triggers_and_holds_the_sleep_inhibitor_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let (events, delay) = session_watch::start(Bus::Address(bus.address.clone()));
    let observed = observe(events);

    // Wait for the watcher to subscribe: a lock signal sent before that is
    // simply lost, so keep sending until one gets through.
    eventually("the first lock signal to be reported", || {
        mock.lock_signal(SESSION_1);
        thread::sleep(Duration::from_millis(50));
        observed.locks() > 0
    });
    quiet();
    observed.clear();

    // 1. A Lock signal on the display session is reported once.
    mock.lock_signal(SESSION_1);
    eventually("a Lock signal to be reported", || observed.locks() == 1);
    quiet();
    assert_eq!(observed.locks(), 1, "one Lock signal, one report");
    observed.clear();

    assert!(
        !observed.display_session().is_locked(),
        "a Lock signal alone doesn't mark the display session locked"
    );

    // 2. LockedHint turning true is reported as a locked display session;
    //    turning false as an unlocked one, which asks for no lock.
    mock.set_hint(SESSION_1, true);
    eventually("LockedHint=true to be reported", || observed.locks() == 1);
    assert!(observed.display_session().is_locked());
    mock.set_hint(SESSION_1, false);
    eventually("LockedHint=false to be reported", || {
        !observed.display_session().is_locked()
    });
    quiet();
    assert_eq!(observed.locks(), 1, "LockedHint=false is not a lock");
    observed.clear();

    // 3. Telling the delay that something is unlocked takes the inhibitor.
    delay.hold_while(true);
    eventually("the sleep inhibitor to be taken", || {
        mock.inhibitor_count() == 1
    });
    assert!(!mock.last_inhibitor_released(), "held while unlocked");

    // 4. PrepareForSleep(true) is reported, and releases nothing by
    //    itself: the server locks first, then says nothing is unlocked.
    mock.prepare_for_sleep(true);
    eventually("the suspend to be reported", || observed.sleeps() == 1);
    quiet();
    assert!(
        !mock.last_inhibitor_released(),
        "held until the server has locked"
    );
    delay.hold_while(false);
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });

    // 5. While the machine sleeps nothing is held, but an unlock that came
    //    in the meantime holds at resume.
    delay.hold_while(true);
    quiet();
    assert_eq!(mock.inhibitor_count(), 1, "no inhibitor while sleeping");
    mock.prepare_for_sleep(false);
    eventually("the inhibitor to be taken at resume", || {
        mock.inhibitor_count() == 2
    });
    assert!(!mock.last_inhibitor_released());

    // 6. Resume with nothing unlocked does not take the inhibitor again.
    delay.hold_while(false);
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });
    mock.prepare_for_sleep(true);
    eventually("the second suspend to be reported", || {
        observed.sleeps() == 2
    });
    mock.prepare_for_sleep(false);
    quiet();
    assert_eq!(mock.inhibitor_count(), 2, "no inhibitor without an unlock");
    observed.clear();

    // 7. A display change moves the watch: the old session is ignored,
    //    the new one is reported.
    mock.set_display(SESSION_2);
    quiet();
    observed.clear();
    mock.lock_signal(SESSION_1);
    quiet();
    assert_eq!(observed.locks(), 0, "the old session's Lock is ignored");
    mock.lock_signal(SESSION_2);
    eventually("the new display session's Lock to be reported", || {
        observed.locks() == 1
    });
    observed.clear();

    // 8. Losing the bus is reported, since the watch can no longer say
    //    what the screen state is.
    bus.kill();
    eventually("a lost bus to be reported", || observed.locks() == 1);
}

/// The display session's state as published to the server: its id
/// and `LockedHint`, following display changes, with no session when
/// logind reports none or the watch is lost.
#[test]
fn the_display_session_state_follows_logind_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let (events, _delay) = session_watch::start(Bus::Address(bus.address.clone()));
    let recorder = observe(events);

    // 1. Subscribing reads the display session and its hint.
    eventually("the first display session state", || {
        recorder.display_session() == unlocked("31")
    });

    // 2. LockedHint changes on the display session move it between locked
    //    and unlocked.
    mock.set_hint(SESSION_1, true);
    eventually("LockedHint=true", || {
        recorder.display_session() == locked("31")
    });
    mock.set_hint(SESSION_1, false);
    eventually("LockedHint=false", || {
        recorder.display_session() == unlocked("31")
    });

    // 3. Neither a Lock signal nor another session's hint changes it.
    mock.lock_signal(SESSION_1);
    mock.set_hint(SESSION_2, true);
    eventually("the Lock signal to lock", || recorder.locks() > 0);
    quiet();
    assert_eq!(recorder.display_session(), unlocked("31"));

    // 4. A display change reads the new session's hint.
    mock.set_display(SESSION_2);
    eventually("the new display session", || {
        recorder.display_session() == locked("32")
    });

    // 5. No display session.
    mock.set_display("/");
    eventually("no display session", || {
        recorder.display_session() == DisplaySession::None
    });
    mock.set_display(SESSION_1);
    eventually("the display session back", || {
        recorder.display_session() == unlocked("31")
    });

    // 6. A lost watch can't say, so there is no session until it's back.
    bus.kill();
    eventually("a lost bus to forget the display session", || {
        recorder.display_session() == DisplaySession::None
    });
}

/// `Active` is watched the same way as `LockedHint`, but turning it off
/// (a VT switch away from the display session, say) must not lock
/// anything — only `LockedHint` does that (`docs/headless.md` § 5:
/// counting an inactive session as locked would make kpa lock the vault
/// on a VT switch).
#[test]
fn the_active_state_follows_logind_and_never_locks() {
    let bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let (events, _delay) = session_watch::start(Bus::Address(bus.address.clone()));
    let recorder = observe(events);

    // 1. Subscribing reads the session as active.
    eventually("the first display session state", || {
        recorder.display_session() == unlocked("31")
    });

    // 2. Turning `Active` off is published, but locks nothing.
    mock.set_active(SESSION_1, false);
    eventually("Active=false", || {
        recorder.display_session() == unlocked_inactive("31")
    });
    quiet();
    assert_eq!(recorder.locks(), 0, "an inactive session is not a lock");
    assert!(
        !recorder.display_session().is_locked(),
        "Active alone never marks the display session locked"
    );

    // 3. Turning it back on is published too.
    mock.set_active(SESSION_1, true);
    eventually("Active=true", || {
        recorder.display_session() == unlocked("31")
    });

    // 4. `LockedHint` and `Active` are tracked independently: locking
    //    while inactive keeps `active` on the published state, and it
    //    still locks everything, same as while active.
    mock.set_active(SESSION_1, false);
    eventually("Active=false again", || {
        recorder.display_session() == unlocked_inactive("31")
    });
    mock.set_hint(SESSION_1, true);
    eventually("LockedHint=true while inactive", || {
        recorder.display_session()
            == DisplaySession::Locked {
                id: "31".to_string(),
                active: false,
            }
    });
    assert_eq!(recorder.locks(), 1, "LockedHint still locks while inactive");
}

/// The real server reacting to what the watcher reports: while the display session's
/// `LockedHint` is true, an unlock raises no prompt; once it clears, the
/// prompt runs and the fixture unlocks; and a `Lock` signal ends a prompt
/// still open.
#[test]
fn the_display_session_state_gates_prompts_and_a_lock_ends_them_over_a_bus() {
    let bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    // Locked before kpa subscribes, so it reads the hint on subscribing.
    mock.set_hint(SESSION_1, true);

    let dir = tempfile::tempdir().unwrap();
    // The prompt records that it ran, waits while `hang` exists, then
    // answers with the fixture's password.
    let prompted = dir.path().join("prompted");
    let hang = dir.path().join("hang");
    let script = format!(
        "touch '{}'; while [ -e '{}' ]; do sleep 0.1; done; printf %s '{}'",
        prompted.display(),
        hang.display(),
        common::PASSWORD
    );
    let config = Config::parse(&format!(
        "prompt = [\"/bin/sh\", \"-c\", {script:?}]\n\
         [[database]]\nname = \"personal\"\npath = {:?}\n",
        common::password_db().display().to_string()
    ))
    .unwrap();
    let (events, delay) = session_watch::start(Bus::Address(bus.address.clone()));
    let server = Arc::new(Server::new(config, Paths::default(), delay));
    let reacting = server.clone();
    thread::spawn(move || {
        for event in events {
            reacting.on_session_event(event);
        }
    });
    let unlock = || {
        server.unlock(
            &UnlockRequest {
                db: "personal".to_string(),
                password: None,
            },
            &Requester {
                uid: kpa::authn::process_uid(),
                // On the desktop of the mock's display session.
                cgroup: Some(common::cgroup_on(true, "31")),
                command: None,
            },
        )
    };
    let refused = Err(UnlockError::NoDisplay);

    // 1. While the display session is known locked, no prompt runs. Until kpa has
    //    subscribed it doesn't know, so the marker is cleared before each
    //    try: only the last, refused, one counts.
    eventually("a locked display session to refuse the unlock", || {
        let _ = std::fs::remove_file(&prompted);
        unlock() == refused
    });
    assert!(!prompted.exists(), "a prompt ran behind the locker");

    // 2. Once the hint clears, the prompt runs and the fixture unlocks.
    mock.set_hint(SESSION_1, false);
    eventually("an unlocked display session to allow the prompt", || {
        unlock().is_ok()
    });
    assert!(prompted.exists());
    assert_eq!(server.display_session(), unlocked("31"));

    // 3. A Lock signal ends a prompt still open.
    mock.lock_signal(SESSION_1);
    eventually("the Lock signal to lock", || !server.any_unlocked());
    std::fs::write(&hang, b"").unwrap();
    std::fs::remove_file(&prompted).unwrap();
    thread::scope(|scope| {
        let unlocking = scope.spawn(unlock);
        eventually("the prompt to start", || prompted.exists());
        mock.lock_signal(SESSION_1);
        let locked_at = Instant::now();
        assert_eq!(
            unlocking.join().unwrap(),
            Err(UnlockError::LockedDuringUnlock {
                db: "personal".to_string()
            })
        );
        assert!(locked_at.elapsed() < Duration::from_secs(5));
    });
    assert!(!server.any_unlocked());
}
