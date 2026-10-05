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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kpa::policy::{self, Bus, Locks};
use zbus::blocking::Connection;
use zbus::blocking::connection::Builder;
use zbus::zvariant::{self, OwnedObjectPath, Value};

const MANAGER: &str = "/org/freedesktop/login1";
const USER: &str = "/org/freedesktop/login1/user/_1000";
const SESSION_1: &str = "/org/freedesktop/login1/session/_31";
const SESSION_2: &str = "/org/freedesktop/login1/session/_32";
const TIMEOUT: Duration = Duration::from_secs(10);

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
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .arg(format!("--address=unix:path={}", socket.display()))
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
/// `LockedHint`, and the sleep inhibitors handed out.
#[derive(Default)]
struct MockState {
    display: String,
    hints: HashMap<String, bool>,
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
        let id = if display == SESSION_1 { "31" } else { "32" };
        (id.to_string(), OwnedObjectPath::try_from(display).unwrap())
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

    fn set_display(&self, session: &'static str) {
        self.state.lock().unwrap().display = session.to_string();
        let value = Value::from((
            if session == SESSION_1 { "31" } else { "32" },
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

/// Records what the policy does to the databases.
#[derive(Default)]
struct Recorder {
    unlocked: AtomicBool,
    log: Mutex<Vec<&'static str>>,
}

impl Locks for Recorder {
    fn lock_all(&self) {
        self.unlocked.store(false, Ordering::SeqCst);
        self.log.lock().unwrap().push("lock");
    }
    fn any_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }
}

impl Recorder {
    fn locks(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == "lock")
            .count()
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
fn logind_triggers_lock_and_hold_the_sleep_inhibitor_over_a_bus() {
    let mut bus = PrivateBus::start();
    let mock = MockLogind::start(&bus.address);
    let recorder = Arc::new(Recorder::default());
    let events = policy::start(recorder.clone(), Bus::Address(bus.address.clone()));

    // Wait for the watcher to subscribe: a lock signal sent before that is
    // simply lost, so keep sending until one gets through.
    eventually("the first lock signal to be acted on", || {
        mock.lock_signal(SESSION_1);
        thread::sleep(Duration::from_millis(50));
        recorder.locks() > 0
    });
    quiet();
    recorder.log.lock().unwrap().clear();

    // 1. A Lock signal on the display session locks.
    mock.lock_signal(SESSION_1);
    eventually("a Lock signal to lock", || recorder.locks() == 1);
    quiet();
    assert_eq!(recorder.locks(), 1, "one Lock signal, one lock");
    recorder.log.lock().unwrap().clear();

    // 2. LockedHint turning true locks; turning false does not.
    mock.set_hint(SESSION_1, true);
    eventually("LockedHint=true to lock", || recorder.locks() == 1);
    mock.set_hint(SESSION_1, false);
    quiet();
    assert_eq!(recorder.locks(), 1, "LockedHint=false is not a lock");
    recorder.log.lock().unwrap().clear();

    // 3. An unlock takes the inhibitor, once the server has reported it.
    recorder.unlocked.store(true, Ordering::SeqCst);
    events.send(policy::Event::Unlocked).unwrap();
    eventually("the sleep inhibitor to be taken", || {
        mock.inhibitor_count() == 1
    });
    assert!(!mock.last_inhibitor_released(), "held while unlocked");

    // 4. PrepareForSleep(true) locks first, then releases the inhibitor.
    mock.prepare_for_sleep(true);
    eventually("the inhibitor to be released", || {
        mock.last_inhibitor_released()
    });
    assert_eq!(recorder.locks(), 1, "locked before the release");
    assert!(!recorder.any_unlocked());

    // 5. Resume with nothing unlocked does not take the inhibitor again.
    mock.prepare_for_sleep(false);
    quiet();
    assert_eq!(mock.inhibitor_count(), 1, "no inhibitor without an unlock");

    // 6. A display change moves the watch: the old session is ignored,
    //    the new one locks.
    mock.set_display(SESSION_2);
    quiet();
    recorder.log.lock().unwrap().clear();
    mock.lock_signal(SESSION_1);
    quiet();
    assert_eq!(recorder.locks(), 0, "the old session's Lock is ignored");
    mock.lock_signal(SESSION_2);
    eventually("the new display session's Lock to lock", || {
        recorder.locks() == 1
    });
    recorder.log.lock().unwrap().clear();

    // 7. Losing the bus locks everything, since the watch can no longer
    //    report the screen state.
    recorder.unlocked.store(true, Ordering::SeqCst);
    bus.kill();
    eventually("a lost bus to lock", || recorder.locks() == 1);
}
