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
use std::sync::{Arc, Condvar, Mutex};
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

/// Any peer may send anything to anyone, and call anyone.
const OPEN_POLICY: &str = "<allow send_destination=\"*\" eavesdrop=\"true\"/>\
                           <allow eavesdrop=\"true\"/>\
                           <allow own=\"*\"/>";

/// The system bus's stock default policy: every user may connect, send
/// signals (to anyone, whatever they subscribed to) and receive them, and
/// call the bus itself and logind, but not other peers.
const STOCK_POLICY: &str = "<allow user=\"*\"/>\
                            <allow own=\"*\"/>\
                            <deny send_type=\"method_call\"/>\
                            <allow send_type=\"signal\"/>\
                            <allow send_requested_reply=\"true\" send_type=\"method_return\"/>\
                            <allow send_requested_reply=\"true\" send_type=\"error\"/>\
                            <allow receive_type=\"method_call\"/>\
                            <allow receive_type=\"method_return\"/>\
                            <allow receive_type=\"error\"/>\
                            <allow receive_type=\"signal\"/>\
                            <allow send_destination=\"org.freedesktop.DBus\" \
                                   send_interface=\"org.freedesktop.DBus\"/>\
                            <allow send_destination=\"org.freedesktop.login1\"/>";

/// A `dbus-daemon` on a socket inside a temp directory, killed on drop.
struct PrivateBus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl PrivateBus {
    fn start() -> PrivateBus {
        PrivateBus::with_policy(OPEN_POLICY)
    }

    fn with_policy(policy: &str) -> PrivateBus {
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
                 <policy context=\"default\">{policy}</policy>\
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

/// Holds back the mock's answers while closed, so a test knows kpa is in the
/// middle of a call and can have a flood in kpa's queue before the answer.
/// Open unless a test closes it.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    closed: bool,
    /// How many answers are held back right now.
    waiting: usize,
}

impl Gate {
    /// Called by the mock before it answers. A test that never opens the
    /// gate gets the answer after `TIMEOUT`, not a hang.
    fn pass(&self) {
        let mut state = self.state.lock().unwrap();
        state.waiting += 1;
        self.changed.notify_all();
        let deadline = Instant::now() + TIMEOUT;
        while state.closed {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
        state.waiting -= 1;
    }

    fn set_closed(&self, closed: bool) {
        self.state.lock().unwrap().closed = closed;
        self.changed.notify_all();
    }

    fn waiting(&self) -> usize {
        self.state.lock().unwrap().waiting
    }
}

struct Manager(Shared, Arc<Gate>);

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn get_user(&self, _uid: u32) -> OwnedObjectPath {
        self.1.pass();
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

struct User(Shared, Arc<Gate>);

#[zbus::interface(name = "org.freedesktop.login1.User")]
impl User {
    #[zbus(property)]
    fn display(&self) -> (String, OwnedObjectPath) {
        self.1.pass();
        let display = self.0.lock().unwrap().display.clone();
        (
            session_id(&display).to_string(),
            OwnedObjectPath::try_from(display).unwrap(),
        )
    }
}

struct Session {
    state: Shared,
    gate: Arc<Gate>,
    path: &'static str,
}

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.gate.pass();
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
        self.gate.pass();
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
    gate: Arc<Gate>,
}

impl MockLogind {
    fn start(address: &str) -> MockLogind {
        MockLogind::start_with_gate(address, Arc::new(Gate::default()))
    }

    /// Starts with `gate` in front of every answer, so a test can close it
    /// before kpa's first call.
    fn start_with_gate(address: &str, gate: Arc<Gate>) -> MockLogind {
        let state: Shared = Arc::new(Mutex::new(MockState {
            display: SESSION_1.to_string(),
            ..MockState::default()
        }));
        let conn = Builder::address(address)
            .unwrap()
            .name("org.freedesktop.login1")
            .unwrap()
            .serve_at(MANAGER, Manager(state.clone(), gate.clone()))
            .unwrap()
            .serve_at(USER, User(state.clone(), gate.clone()))
            .unwrap()
            .serve_at(
                SESSION_1,
                Session {
                    state: state.clone(),
                    gate: gate.clone(),
                    path: SESSION_1,
                },
            )
            .unwrap()
            .serve_at(
                SESSION_2,
                Session {
                    state: state.clone(),
                    gate: gate.clone(),
                    path: SESSION_2,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        MockLogind { conn, state, gate }
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

    /// Every event the watcher has sent, in order.
    fn reported(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
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

/// One database, locked by the real `auto_lock` front end watching the bus at
/// `address`. Returns the databases and the display session `auto_lock`
/// writes.
fn auto_locked(address: &str) -> (Arc<Databases>, display_session::DisplayHandle) {
    let config = Config::parse(&format!(
        "[[database]]\nname = \"personal\"\npath = {:?}\n",
        common::password_db().display().to_string()
    ))
    .unwrap();

    let (writer, display) = display_session::channel();
    let (hold, auto_lock) = auto_lock::start(Source::at(address), writer);
    let mut databases = Databases::new(config.databases.clone(), Duration::from_secs(3600));
    databases.observe(Arc::new(hold));
    let databases = Arc::new(databases);
    let running = databases.clone();
    thread::spawn(move || auto_lock.run(running, Duration::from_secs(3600)));
    (databases, display)
}

#[test]
fn auto_lock_locks_everything_and_follows_the_display_session_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let (databases, display) = auto_locked(&bus.address);

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

/// A second client of the bus. Under the stock policy it can't call anyone
/// but the bus and logind, but it can send a signal to any connection, and
/// the receiver's match rules don't apply to a signal sent to it.
struct Attacker {
    conn: Connection,
}

impl Attacker {
    fn start(address: &str) -> Attacker {
        Attacker {
            conn: Builder::address(address).unwrap().build().unwrap(),
        }
    }

    /// Sends every other connection but `mock`'s the three signals that
    /// would change what the watcher reports if they came from logind (the
    /// display session's `LockedHint` clearing, the user's `Display` moving
    /// to another session, `PrepareForSleep(true)`) and a report from the bus
    /// that logind's name lost its owner. Returns once the bus has passed
    /// them on, so anything sent after it arrives after them.
    fn spoof_logind(&self, mock: &MockLogind) {
        let mine = self.conn.unique_name().unwrap().to_string();
        let logind = mock.conn.unique_name().unwrap().to_string();
        let names: Vec<String> = self.bus_call("ListNames").body().deserialize().unwrap();
        for victim in names
            .iter()
            .filter(|name| name.starts_with(':') && **name != mine && **name != logind)
        {
            let to = Some(victim.as_str());
            self.properties_changed(
                to,
                SESSION_1,
                "org.freedesktop.login1.Session",
                "LockedHint",
                Value::from(false),
            );
            self.properties_changed(
                to,
                USER,
                "org.freedesktop.login1.User",
                "Display",
                Value::from((
                    session_id(SESSION_2),
                    OwnedObjectPath::try_from(SESSION_2).unwrap(),
                )),
            );
            self.conn
                .emit_signal(
                    to,
                    MANAGER,
                    "org.freedesktop.login1.Manager",
                    "PrepareForSleep",
                    &true,
                )
                .unwrap();
            self.conn
                .emit_signal(
                    to,
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "NameOwnerChanged",
                    &("org.freedesktop.login1", logind.as_str(), ""),
                )
                .unwrap();
        }
        self.bus_call("GetId");
    }

    /// Sends `count` signals of no meaning to every other connection but
    /// `mock`'s, one after the other. Returns once the bus has queued them
    /// all for their receivers, so whatever the bus sends after it arrives
    /// behind them.
    fn flood(&self, mock: &MockLogind, count: usize) {
        let mine = self.conn.unique_name().unwrap().to_string();
        let logind = mock.conn.unique_name().unwrap().to_string();
        let names: Vec<String> = self.bus_call("ListNames").body().deserialize().unwrap();
        for victim in names
            .iter()
            .filter(|name| name.starts_with(':') && **name != mine && **name != logind)
        {
            for _ in 0..count {
                self.conn
                    .emit_signal(
                        Some(victim.as_str()),
                        "/org/example/Junk",
                        "org.example.Junk",
                        "Junk",
                        &(),
                    )
                    .unwrap();
            }
        }
        self.bus_call("GetId");
    }

    fn bus_call(&self, method: &str) -> zbus::Message {
        self.conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                method,
                &(),
            )
            .unwrap()
    }

    fn properties_changed(
        &self,
        to: Option<&str>,
        path: &str,
        iface: &str,
        name: &str,
        value: Value<'_>,
    ) {
        let mut changed: HashMap<&str, Value<'_>> = HashMap::new();
        changed.insert(name, value);
        self.conn
            .emit_signal(
                to,
                path,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(iface, changed, Vec::<&str>::new()),
            )
            .unwrap();
    }
}

/// A peer that sends signals straight to kpa's connection can't pass for
/// logind: they're delivered whatever kpa subscribed to, and only their
/// sender tells them from logind's. Under the stock policy a second client
/// sends the display session's `LockedHint` clearing, the user's `Display`
/// moving to another session and `PrepareForSleep(true)` to every other
/// connection on the bus. The watcher reports nothing of it, the display
/// session stays locked, a `Lock` from logind still locks, and an unlock
/// still takes the sleep inhibitor.
#[test]
fn signals_from_a_peer_other_than_logind_are_ignored_over_a_bus() {
    let bus = PrivateBus::with_policy(STOCK_POLICY);
    let mock = MockLogind::start(&bus.address);
    // Locked before kpa subscribes, so it reads the hint on subscribing.
    mock.set_hint(SESSION_1, true);

    // The watcher on its own, for what it reports...
    let (events, _inhibitor) = watch(&bus.address);
    let observed = observe(events);
    // ...and the front end around one, for what that does with it.
    let (databases, display) = auto_locked(&bus.address);
    eventually("a locked display session", || {
        observed.display_session() == locked("31") && display.get() == locked("31")
    });
    unlock_all(&databases);
    eventually("the sleep inhibitor to be taken", || {
        mock.inhibitor_count() == 1 && !mock.last_inhibitor_released()
    });

    Attacker::start(&bus.address).spoof_logind(&mock);

    // logind's own `Lock` came after the spoofs, so once it is reported they
    // have been dealt with.
    mock.lock_signal(SESSION_1);
    eventually("the Lock from logind to be reported", || {
        observed.reported().len() > 1
    });
    assert_eq!(
        observed.reported(),
        [Event::DisplayChanged(locked("31")), Event::LockRequested]
    );
    assert_eq!(display.get(), locked("31"));
    eventually("the Lock from logind to lock everything", || {
        !databases.any_unlocked()
    });
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });

    unlock_all(&databases);
    eventually("an unlock to take the sleep inhibitor", || {
        mock.inhibitor_count() == 2 && !mock.last_inhibitor_released()
    });
}

/// A new logind is a new connection with the same name. The watch resolved
/// the old one, so it ends (everything locks) and the next one follows the
/// new logind, whose messages the old one would have refused.
#[test]
fn a_restarted_logind_is_a_lost_watch_and_the_next_one_follows_it_over_a_bus() {
    let bus = PrivateBus::with_policy(STOCK_POLICY);
    let mock = MockLogind::start(&bus.address);
    let (events, _inhibitor) = watch(&bus.address);
    let observed = observe(events);
    eventually("the first display session state", || {
        observed.display_session() == unlocked("31")
    });

    drop(mock);
    eventually("a lost watch", || {
        observed.display_session() == DisplaySession::None
    });
    assert_eq!(observed.locks(), 1, "the lost watch locks everything");

    let restarted = MockLogind::start(&bus.address);
    restarted.set_hint(SESSION_1, true);
    eventually("the restarted logind's display session state", || {
        observed.display_session() == locked("31")
    });
    restarted.set_hint(SESSION_1, false);
    eventually("the restarted logind's changes", || {
        observed.display_session() == unlocked("31")
    });
}

/// What a lock must beat once a peer floods kpa's connection: more signals
/// than its queue holds (64), whatever the match rules say.
const FLOOD: usize = 1000;

/// A lock arrives within this long of the flood being let through.
const PROMPTLY: Duration = Duration::from_secs(1);

/// Polls `check` for up to `PROMPTLY`.
fn promptly(mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + PROMPTLY;
    while !check() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    true
}

/// A peer that floods kpa's connection while the watcher reads the new
/// display session must not stop a lock: the answer logind gives is queued
/// behind the flood, and the watcher still reads it.
#[test]
fn a_flood_while_the_display_session_changes_doesnt_stop_a_lock_over_a_bus() {
    let bus = PrivateBus::with_policy(STOCK_POLICY);
    let mock = MockLogind::start(&bus.address);
    let (databases, display) = auto_locked(&bus.address);
    eventually("the watcher to subscribe", || {
        display.get() == unlocked("31")
    });
    unlock_all(&databases);

    // The display moves to another session. The watcher asks logind about it,
    // and logind holds the answer until the flood has been queued behind it.
    mock.gate.set_closed(true);
    mock.set_display(SESSION_2);
    eventually("the watcher to ask about the new session", || {
        mock.gate.waiting() > 0
    });
    Attacker::start(&bus.address).flood(&mock, FLOOD);
    mock.gate.set_closed(false);

    mock.lock_signal(SESSION_2);
    assert!(
        promptly(|| !databases.any_unlocked()),
        "a flood on kpa's connection suppressed the lock"
    );
    assert_eq!(display.get(), unlocked("32"));

    // The connection that holds the sleep inhibitor was flooded too.
    let taken = mock.inhibitor_count();
    unlock_all(&databases);
    eventually("an unlock to take the sleep inhibitor", || {
        mock.inhibitor_count() == taken + 1 && !mock.last_inhibitor_released()
    });
}

/// The same flood while the watcher subscribes: it has asked logind for the
/// user and waits for the answer, which comes behind the flood.
#[test]
fn a_flood_while_the_watch_subscribes_doesnt_stop_a_lock_over_a_bus() {
    let bus = PrivateBus::with_policy(STOCK_POLICY);
    let gate = Arc::new(Gate::default());
    gate.set_closed(true);
    let mock = MockLogind::start_with_gate(&bus.address, gate);
    let (databases, display) = auto_locked(&bus.address);
    eventually("the watcher to ask logind for the user", || {
        mock.gate.waiting() > 0
    });
    Attacker::start(&bus.address).flood(&mock, FLOOD);
    mock.gate.set_closed(false);

    eventually("the watcher to subscribe", || {
        display.get() == unlocked("31")
    });
    unlock_all(&databases);
    mock.lock_signal(SESSION_1);
    assert!(
        promptly(|| !databases.any_unlocked()),
        "a flood on kpa's connection suppressed the lock"
    );
}
