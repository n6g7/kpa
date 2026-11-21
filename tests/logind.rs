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

use kpa::config::Config;
use kpa::databases::{Begin, Databases};
use kpa::display_session::{self, DisplaySession};
use kpa::frontends::auto_lock::logind::{self, Bus, Inhibitor};
use kpa::frontends::auto_lock::{self, Event, Source};
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
    events: Mutex<Vec<Event>>,
}

/// Starts the watcher on the private bus at `address`, with its events on a
/// channel of its own.
fn watch(address: &str) -> (Receiver<Event>, Inhibitor) {
    let (events, incoming) = std::sync::mpsc::channel();
    let inhibitor = logind::start(Bus::Address(address.to_string()), events);
    (incoming, inhibitor)
}

/// Collects `events` until the watcher is gone.
fn observe(events: Receiver<Event>) -> Arc<Observed> {
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
                Event::DisplayChanged(display_session) => Some(display_session.clone()),
                Event::WatchLost => Some(DisplaySession::None),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// How many reports the daemon answers with a lock of everything.
    fn locks(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| match event {
                Event::DisplayChanged(display_session) => display_session.is_locked(),
                Event::Resumed | Event::Unlocked(_) => false,
                _ => true,
            })
            .count()
    }

    fn sleeps(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == Event::Sleeping)
            .count()
    }

    fn resumes(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == Event::Resumed)
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
    let (events, inhibitor) = watch(&bus.address);
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

    // 3. Asking to hold takes the inhibitor, once however often it is asked.
    inhibitor.hold(true);
    inhibitor.hold(true);
    eventually("the sleep inhibitor to be taken", || {
        mock.inhibitor_count() == 1
    });
    quiet();
    assert_eq!(mock.inhibitor_count(), 1, "holding twice takes one");
    assert!(
        !mock.last_inhibitor_released(),
        "held until asked to let go"
    );

    // 4. PrepareForSleep is reported both ways, and releases nothing by
    //    itself.
    mock.prepare_for_sleep(true);
    eventually("the suspend to be reported", || observed.sleeps() == 1);
    mock.prepare_for_sleep(false);
    eventually("the resume to be reported", || observed.resumes() == 1);
    assert!(!mock.last_inhibitor_released());

    // 5. Asking to let go releases it, and letting go again does nothing.
    inhibitor.hold(false);
    inhibitor.hold(false);
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });
    quiet();
    assert_eq!(mock.inhibitor_count(), 1);
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

/// The display session's state as published to the daemon: its id
/// and `LockedHint`, following display changes, with no session when
/// logind reports none or the watch is lost.
#[test]
fn the_display_session_state_follows_logind_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let (events, _inhibitor) = watch(&bus.address);
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
    let (events, _inhibitor) = watch(&bus.address);
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

/// The real daemon reacting to what the watcher reports: while the display
/// session's `LockedHint` is true, an unlock raises no prompt; once it
/// clears, the prompt runs and the fixture unlocks; and a `Lock` signal ends
/// a prompt still open.
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
    let daemon = common::InProcessDaemon::on_bus(config, &bus.address, "31");
    let unlock = || daemon.run(&["unlock", "personal"]);
    let refused = |reply: &serde_json::Value| reply["error"] == "no_prompt";

    // 1. While the display session is known locked, no prompt runs. Until kpa has
    //    subscribed it doesn't know, so the marker is cleared before each
    //    try: only the last, refused, one counts.
    eventually("a locked display session to refuse the unlock", || {
        let _ = std::fs::remove_file(&prompted);
        refused(&unlock())
    });
    assert!(!prompted.exists(), "a prompt ran behind the locker");

    // 2. Once the hint clears, the prompt runs and the fixture unlocks.
    mock.set_hint(SESSION_1, false);
    eventually("an unlocked display session to allow the prompt", || {
        unlock()["ok"] == true
    });
    assert!(prompted.exists());

    // 3. A Lock signal ends a prompt still open.
    mock.lock_signal(SESSION_1);
    eventually("the Lock signal to lock", || {
        !daemon.databases.any_unlocked()
    });
    std::fs::write(&hang, b"").unwrap();
    std::fs::remove_file(&prompted).unwrap();
    thread::scope(|scope| {
        let unlocking = scope.spawn(unlock);
        eventually("the prompt to start", || prompted.exists());
        mock.lock_signal(SESSION_1);
        let locked_at = Instant::now();
        let reply = unlocking.join().unwrap();
        assert_eq!(reply["error"], "locked", "{reply}");
        assert!(locked_at.elapsed() < Duration::from_secs(5));
    });
    assert!(!daemon.databases.any_unlocked());
}

/// Unlocks every database in `databases` with the fixture's password.
fn unlock_all(databases: &Databases) {
    let password = zeroize::Zeroizing::new(common::PASSWORD.to_string());
    for config in databases.configs() {
        match databases.begin_unlock(&config.name) {
            Ok(Begin::Started(unlocking)) => unlocking.finish(Some(&password)).expect("unlock"),
            _ => panic!("expected to start an unlock of {}", config.name),
        }
    }
    assert!(databases.any_unlocked());
}

#[test]
fn auto_lock_locks_everything_and_follows_the_display_session_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let config = Config::parse(&format!(
        "[[database]]\nname = \"personal\"\npath = {:?}\n",
        common::password_db().display().to_string()
    ))
    .unwrap();

    let (writer, display) = display_session::channel();
    let (hold, auto_lock) = auto_lock::start(Source::at(bus.address.clone()), writer);
    let mut databases = Databases::new(config.databases.clone(), Duration::from_secs(3600));
    databases.observe(Arc::new(hold));
    let databases = Arc::new(databases);
    let running = databases.clone();
    thread::spawn(move || auto_lock.run(running, Duration::from_secs(3600)));

    // A Lock signal sent before the watcher subscribes is lost, so keep
    // sending until one locks.
    unlock_all(&databases);
    eventually("a Lock signal to lock everything", || {
        mock.lock_signal(SESSION_1);
        thread::sleep(Duration::from_millis(50));
        !databases.any_unlocked()
    });
    assert!(
        !display.get().is_locked(),
        "a Lock signal alone doesn't mark the display session"
    );

    // A locked display session is marked, and locks everything.
    unlock_all(&databases);
    mock.set_hint(SESSION_1, true);
    eventually("LockedHint=true to lock everything", || {
        !databases.any_unlocked()
    });
    assert!(display.get().is_locked());
    mock.set_hint(SESSION_1, false);
    eventually("LockedHint=false to be recorded", || {
        !display.get().is_locked()
    });

    // The inhibitor is taken by an unlock, and released by the lock on
    // suspend.
    unlock_all(&databases);
    eventually("the sleep inhibitor to be taken", || {
        mock.inhibitor_count() >= 1 && !mock.last_inhibitor_released()
    });
    mock.prepare_for_sleep(true);
    eventually("the suspend to lock everything", || {
        !databases.any_unlocked()
    });
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });

    // While the machine sleeps nothing is held, even by an unlock; resuming
    // holds again because something is unlocked, and locking releases it.
    let taken = mock.inhibitor_count();
    unlock_all(&databases);
    quiet();
    assert_eq!(mock.inhibitor_count(), taken, "no inhibitor while sleeping");
    mock.prepare_for_sleep(false);
    eventually("the inhibitor to be taken at resume", || {
        mock.inhibitor_count() == taken + 1 && !mock.last_inhibitor_released()
    });
    databases.lock_all();
    eventually("the inhibitor to be released once locked", || {
        mock.last_inhibitor_released()
    });

    // A lost watch forgets the display session and locks everything.
    unlock_all(&databases);
    bus.kill();
    eventually("a lost bus to lock everything", || {
        !databases.any_unlocked()
    });
    assert_eq!(display.get(), DisplaySession::None);
}
