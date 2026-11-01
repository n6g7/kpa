//! Lock triggers from logind: screen lock and suspend (`docs/threat-model.md`
//! T-8 and ASM-7, `docs/design.md` § Lock policy).
//!
//! Two halves, joined by one channel of [`Event`]s:
//!
//! - [`watch_forever`] owns a D-Bus connection to logind. It turns signals
//!   and property changes into events: a `Lock` signal or `LockedHint`
//!   turning true on the user's display session, `PrepareForSleep`, and a
//!   lost subscription.
//! - [`Policy`] decides what to do with an event: lock, and hold or release
//!   a `delay` sleep inhibitor. It sees only the [`Locks`] and
//!   [`SleepInhibitor`] traits, so it can be tested with injected events and
//!   no bus at all.
//!
//! The server reports successful unlocks on the same channel, so the
//! inhibitor is taken as soon as something is unlocked.
//!
//! This module needs systemd-logind reachable on the bus it's given
//! (`Bus::System` in production), which means a systemd Linux host. It
//! works unmodified on any such host. On a Linux host without systemd, or
//! on a non-Linux platform such as macOS, there's no logind to connect
//! to: [`watch_forever`] retries forever and [`LogindInhibitor::hold`]
//! always fails, so screen-lock and suspend never produce an event and no
//! inhibitor is ever held. None of that panics or stops the server —
//! databases still lock on their own idle timer, the only trigger left.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Message;
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue};

const LOGIND: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const USER_IFACE: &str = "org.freedesktop.login1.User";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const DBUS: &str = "org.freedesktop.DBus";

/// The signals and properties kpa subscribes to. `sender` is pinned to
/// logind's well-known name, so a same-bus peer can't inject them.
const MATCH_RULES: [&str; 3] = [
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Lock'",
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
];

const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Something the lock policy reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The user's screen is locked: the display session's `Lock` signal, or
    /// its `LockedHint` turned true.
    ScreenLocked,
    /// logind's `PrepareForSleep`: `true` just before sleep, `false` on resume.
    Sleeping(bool),
    /// A database was unlocked; the inhibitor may need to be taken.
    Unlocked,
    /// A database was locked (explicitly, via the `lock` op); the
    /// inhibitor may need to be released, if that was the last one.
    Locked,
    /// A subscription that had been working has dropped.
    WatchLost,
}

/// What the policy can do to the databases.
pub trait Locks: Send + Sync {
    /// Lock every database. Must return before the inhibitor is released.
    fn lock_all(&self);
    /// Whether any database is currently unlocked.
    fn any_unlocked(&self) -> bool;
}

impl<T: Locks + ?Sized> Locks for Arc<T> {
    fn lock_all(&self) {
        (**self).lock_all();
    }
    fn any_unlocked(&self) -> bool {
        (**self).any_unlocked()
    }
}

/// A `delay` sleep inhibitor: while held, logind waits (up to
/// `InhibitDelayMaxUSec`) before suspending.
pub trait SleepInhibitor: Send {
    fn hold(&mut self) -> Result<(), String>;
    fn release(&mut self);
    fn is_held(&self) -> bool;
}

/// The policy state. Holds the inhibitor exactly when something is unlocked
/// and the machine is not in the middle of sleeping.
pub struct Policy<L, I> {
    locks: L,
    inhibitor: I,
    sleeping: bool,
}

impl<L: Locks, I: SleepInhibitor> Policy<L, I> {
    pub fn new(locks: L, inhibitor: I) -> Self {
        Policy {
            locks,
            inhibitor,
            sleeping: false,
        }
    }

    pub fn handle(&mut self, event: Event) {
        match event {
            Event::ScreenLocked => {
                self.locks.lock_all();
                crate::server::log(format_args!("locked all databases (screen lock)"));
            }
            Event::WatchLost => {
                self.locks.lock_all();
                crate::server::log(format_args!(
                    "locked all databases (logind subscription lost)"
                ));
            }
            Event::Sleeping(true) => {
                // Lock first, release second: releasing is what lets the
                // machine sleep, so the lock must be complete by then.
                self.sleeping = true;
                self.locks.lock_all();
                self.inhibitor.release();
                crate::server::log(format_args!("locked all databases (suspending)"));
            }
            Event::Sleeping(false) => self.sleeping = false,
            // Both just change what's unlocked; `reconcile` below, run
            // unconditionally, is what reads that and takes or releases
            // the inhibitor.
            Event::Unlocked | Event::Locked => {}
        }
        self.reconcile();
    }

    /// Take or release the inhibitor so that it is held exactly while
    /// something is unlocked (and not sleeping). Reads the current state
    /// rather than trusting the event, so an event that raced an unlock
    /// still ends in the right state.
    fn reconcile(&mut self) {
        let want = !self.sleeping && self.locks.any_unlocked();
        if want && !self.inhibitor.is_held() {
            if let Err(err) = self.inhibitor.hold() {
                eprintln!("kpa: could not hold a sleep inhibitor: {err}");
            }
        } else if !want && self.inhibitor.is_held() {
            self.inhibitor.release();
        }
    }
}

/// Handle events until every sender is gone.
pub fn run<L: Locks, I: SleepInhibitor>(events: Receiver<Event>, mut policy: Policy<L, I>) {
    for event in events {
        policy.handle(event);
    }
}

/// Where logind is: the system bus in production, a private bus in tests.
#[derive(Debug, Clone)]
pub enum Bus {
    System,
    Address(String),
}

impl Bus {
    fn connect(&self) -> zbus::Result<Connection> {
        match self {
            Bus::System => Connection::system(),
            Bus::Address(address) => {
                zbus::blocking::connection::Builder::address(address.as_str())?.build()
            }
        }
    }
}

/// Start the policy thread and the logind watcher. Returns the sender the
/// server uses to report unlocks.
pub fn start<L: Locks + 'static>(locks: L, bus: Bus) -> Sender<Event> {
    let (tx, rx) = mpsc::channel();
    let inhibitor = LogindInhibitor::new(bus.clone());
    let policy = Policy::new(locks, inhibitor);
    thread::spawn(move || run(rx, policy));

    let watch_tx = tx.clone();
    let uid = rustix::process::getuid().as_raw();
    thread::spawn(move || watch_forever(&bus, uid, &watch_tx));
    tx
}

/// Keep a watch on logind for the life of the process. A subscription that
/// drops after working locks everything (the lock can't be confirmed to
/// have been sent) and is re-established with backoff. A first failure is
/// only logged: nothing can be unlocked before the first subscription.
fn watch_forever(bus: &Bus, uid: u32, events: &Sender<Event>) {
    let mut last_error: Option<String> = None;
    loop {
        let mut subscribed = false;
        let error = match bus.connect() {
            Ok(conn) => watch(&conn, uid, events, &mut subscribed),
            Err(err) => err.to_string(),
        };
        if subscribed {
            let _ = events.send(Event::WatchLost);
        }
        if last_error.as_deref() != Some(error.as_str()) {
            eprintln!("kpa: logind watch: {error}; retrying");
            last_error = Some(error);
        }
        thread::sleep(RETRY_DELAY);
    }
}

/// Subscribe and forward events until the connection fails. Always returns
/// an error: a watch doesn't end on purpose.
fn watch(conn: &Connection, uid: u32, events: &Sender<Event>, subscribed: &mut bool) -> String {
    // Created before the match rules are added, so nothing sent after the
    // subscription is missed.
    let messages = MessageIterator::from(conn);
    for rule in MATCH_RULES {
        if let Err(err) = conn.call_method(
            Some(DBUS),
            "/org/freedesktop/DBus",
            Some(DBUS),
            "AddMatch",
            &rule,
        ) {
            return err.to_string();
        }
    }

    let user = match get_user(conn, uid) {
        Ok(user) => user,
        Err(err) => return err,
    };
    let mut session = match display_session(conn, user.as_str()) {
        Ok(session) => session,
        Err(err) => return err,
    };
    *subscribed = true;
    if let Some(path) = &session {
        match locked_hint(conn, path.as_str()) {
            Ok(true) => {
                let _ = events.send(Event::ScreenLocked);
            }
            Ok(false) => {}
            Err(err) => return err,
        }
    }

    for message in messages {
        let message = match message {
            Ok(message) => message,
            Err(err) => return err.to_string(),
        };
        let current = session.as_ref().map(|path| path.as_str());
        match interpret(&message, user.as_str(), current) {
            Step::Event(event) => {
                let _ = events.send(event);
            }
            Step::DisplayChanged(path) => {
                session = path;
                if let Some(path) = &session {
                    match locked_hint(conn, path.as_str()) {
                        Ok(true) => {
                            let _ = events.send(Event::ScreenLocked);
                        }
                        Ok(false) => {}
                        Err(err) => return err,
                    }
                }
            }
            Step::Ignore => {}
        }
    }
    "the system bus connection closed".to_string()
}

/// What one incoming message means to the watcher.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Event(Event),
    /// The user's display session changed to this one (`None`: no display
    /// session any more).
    DisplayChanged(Option<OwnedObjectPath>),
    Ignore,
}

/// Classify a message. Pure, so the matching can be tested without a bus.
/// `user` is the user object kpa watches; `session` is the display session
/// it currently follows.
fn interpret(message: &Message, user: &str, session: Option<&str>) -> Step {
    let header = message.header();
    let (Some(path), Some(interface), Some(member)) =
        (header.path(), header.interface(), header.member())
    else {
        return Step::Ignore;
    };
    let on_session = session == Some(path.as_str());

    match (interface.as_str(), member.as_str()) {
        (MANAGER_IFACE, "PrepareForSleep") => match message.body().deserialize::<bool>() {
            Ok(starting) => Step::Event(Event::Sleeping(starting)),
            Err(_) => Step::Ignore,
        },
        (SESSION_IFACE, "Lock") if on_session => Step::Event(Event::ScreenLocked),
        (PROPERTIES_IFACE, "PropertiesChanged") => {
            let Ok((changed_iface, changed, _)) =
                message
                    .body()
                    .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
            else {
                return Step::Ignore;
            };
            if path.as_str() == user && changed_iface == USER_IFACE {
                match changed.get("Display").map(parse_display) {
                    Some(Some(display)) => return Step::DisplayChanged(display),
                    _ => return Step::Ignore,
                }
            }
            if on_session && changed_iface == SESSION_IFACE {
                let hint = changed
                    .get("LockedHint")
                    .and_then(|v| bool::try_from(v).ok());
                if hint == Some(true) {
                    return Step::Event(Event::ScreenLocked);
                }
            }
            Step::Ignore
        }
        _ => Step::Ignore,
    }
}

/// Parse a `User.Display` value, `(so)`. Returns `Some(None)` for logind's
/// "no display session" (`"/"`), `None` if the value doesn't have that shape.
fn parse_display(value: &OwnedValue) -> Option<Option<OwnedObjectPath>> {
    let (_id, path) = <(String, OwnedObjectPath)>::try_from(value.clone()).ok()?;
    if path.as_str() == "/" {
        Some(None)
    } else {
        Some(Some(path))
    }
}

fn get_user(conn: &Connection, uid: u32) -> Result<OwnedObjectPath, String> {
    let reply = conn
        .call_method(
            Some(LOGIND),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "GetUser",
            &uid,
        )
        .map_err(|err| format!("GetUser({uid}): {err}"))?;
    reply
        .body()
        .deserialize::<OwnedObjectPath>()
        .map_err(|err| err.to_string())
}

fn display_session(conn: &Connection, user: &str) -> Result<Option<OwnedObjectPath>, String> {
    let value = get_property(conn, user, USER_IFACE, "Display")?;
    parse_display(&value).ok_or_else(|| "unexpected User.Display value".to_string())
}

fn locked_hint(conn: &Connection, session: &str) -> Result<bool, String> {
    let value = get_property(conn, session, SESSION_IFACE, "LockedHint")?;
    bool::try_from(&value).map_err(|err| err.to_string())
}

fn get_property(
    conn: &Connection,
    path: &str,
    interface: &str,
    name: &str,
) -> Result<OwnedValue, String> {
    let reply = conn
        .call_method(
            Some(LOGIND),
            path,
            Some(PROPERTIES_IFACE),
            "Get",
            &(interface, name),
        )
        .map_err(|err| format!("{name} on {path}: {err}"))?;
    reply
        .body()
        .deserialize::<OwnedValue>()
        .map_err(|err| err.to_string())
}

/// Holds a `delay` inhibitor through logind's `Manager.Inhibit`. Dropping
/// the returned fd releases it.
pub struct LogindInhibitor {
    bus: Bus,
    conn: Option<Connection>,
    fd: Option<OwnedFd>,
}

impl LogindInhibitor {
    pub fn new(bus: Bus) -> Self {
        LogindInhibitor {
            bus,
            conn: None,
            fd: None,
        }
    }
}

impl SleepInhibitor for LogindInhibitor {
    fn hold(&mut self) -> Result<(), String> {
        if self.fd.is_some() {
            return Ok(());
        }
        if self.conn.as_ref().is_none_or(|conn| conn.is_closed()) {
            self.conn = Some(self.bus.connect().map_err(|err| err.to_string())?);
        }
        let conn = self.conn.as_ref().expect("connected above");
        let reply = conn
            .call_method(
                Some(LOGIND),
                MANAGER_PATH,
                Some(MANAGER_IFACE),
                "Inhibit",
                &("sleep", "kpa", "Lock databases before suspend", "delay"),
            )
            .map_err(|err| format!("Inhibit: {err}"))?;
        let fd = reply
            .body()
            .deserialize::<zvariant::OwnedFd>()
            .map_err(|err| err.to_string())?;
        self.fd = Some(fd.into());
        Ok(())
    }

    fn release(&mut self) {
        self.fd = None;
    }

    fn is_held(&self) -> bool {
        self.fd.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// Records calls into a shared log so tests can check ordering.
    struct FakeLocks {
        unlocked: AtomicBool,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Locks for FakeLocks {
        fn lock_all(&self) {
            self.unlocked.store(false, Ordering::SeqCst);
            self.log.lock().unwrap().push("lock");
        }
        fn any_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
    }

    struct FakeInhibitor {
        held: bool,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl SleepInhibitor for FakeInhibitor {
        fn hold(&mut self) -> Result<(), String> {
            self.held = true;
            self.log.lock().unwrap().push("hold");
            Ok(())
        }
        fn release(&mut self) {
            if self.held {
                self.held = false;
                self.log.lock().unwrap().push("release");
            }
        }
        fn is_held(&self) -> bool {
            self.held
        }
    }

    struct Harness {
        policy: Policy<Arc<FakeLocks>, FakeInhibitor>,
        locks: Arc<FakeLocks>,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Harness {
        fn new() -> Self {
            let log = Arc::new(Mutex::new(Vec::new()));
            let locks = Arc::new(FakeLocks {
                unlocked: AtomicBool::new(false),
                log: log.clone(),
            });
            let inhibitor = FakeInhibitor {
                held: false,
                log: log.clone(),
            };
            Harness {
                policy: Policy::new(locks.clone(), inhibitor),
                locks,
                log,
            }
        }

        /// Simulate a successful unlock, then the server's notification.
        fn unlock(&mut self) {
            self.locks.unlocked.store(true, Ordering::SeqCst);
            self.policy.handle(Event::Unlocked);
        }

        /// Simulate an explicit `lock` (of the last unlocked database),
        /// then the server's notification. Unlike `ScreenLocked` or
        /// `WatchLost`, this doesn't go through `Locks::lock_all` — the
        /// server already locked the one database itself.
        fn lock(&mut self) {
            self.locks.unlocked.store(false, Ordering::SeqCst);
            self.policy.handle(Event::Locked);
        }

        fn log(&self) -> Vec<&'static str> {
            self.log.lock().unwrap().clone()
        }

        fn held(&self) -> bool {
            self.policy.inhibitor.is_held()
        }
    }

    #[test]
    fn a_screen_lock_locks_everything() {
        let mut h = Harness::new();
        h.unlock();
        h.policy.handle(Event::ScreenLocked);
        assert!(!h.locks.any_unlocked());
        assert!(!h.held());
    }

    #[test]
    fn the_inhibitor_is_held_while_anything_is_unlocked() {
        let mut h = Harness::new();
        assert!(!h.held());
        h.unlock();
        assert!(h.held());
        h.unlock(); // a second unlock doesn't take it twice
        assert_eq!(h.log(), vec!["hold"]);
    }

    #[test]
    fn suspend_locks_before_the_inhibitor_is_released() {
        let mut h = Harness::new();
        h.unlock();
        h.policy.handle(Event::Sleeping(true));
        assert!(!h.locks.any_unlocked());
        assert!(!h.held());
        assert_eq!(h.log(), vec!["hold", "lock", "release"]);
    }

    #[test]
    fn nothing_unlocked_means_no_inhibitor_at_suspend() {
        let mut h = Harness::new();
        h.policy.handle(Event::Sleeping(true));
        assert_eq!(h.log(), vec!["lock"]);
        assert!(!h.held());
    }

    #[test]
    fn an_unlock_during_sleep_is_not_inhibited_until_resume() {
        let mut h = Harness::new();
        h.policy.handle(Event::Sleeping(true));
        h.unlock();
        assert!(
            !h.held(),
            "no inhibitor while the machine is going to sleep"
        );
        h.policy.handle(Event::Sleeping(false));
        assert!(h.held(), "re-taken on resume while still unlocked");
    }

    #[test]
    fn resume_does_not_hold_when_everything_is_locked() {
        let mut h = Harness::new();
        h.unlock();
        h.policy.handle(Event::Sleeping(true));
        h.policy.handle(Event::Sleeping(false));
        assert!(!h.held());
    }

    #[test]
    fn locking_the_last_database_directly_releases_the_inhibitor() {
        // Regression test: an explicit `lock` of the last unlocked
        // database (not a screen lock or a sleep) must still run
        // `reconcile`, or the inhibitor stays held until some unrelated
        // event happens to trigger it.
        let mut h = Harness::new();
        h.unlock();
        assert!(h.held());
        h.lock();
        assert!(!h.held());
        assert_eq!(h.log(), vec!["hold", "release"]);
    }

    #[test]
    fn a_lost_subscription_locks_everything() {
        let mut h = Harness::new();
        h.unlock();
        h.policy.handle(Event::WatchLost);
        assert!(!h.locks.any_unlocked());
        assert!(!h.held());
    }

    #[test]
    fn run_drains_events_until_the_senders_are_gone() {
        let (tx, rx) = mpsc::channel();
        let h = Harness::new();
        let Harness {
            policy, locks, log, ..
        } = h;
        locks.unlocked.store(true, Ordering::SeqCst);
        tx.send(Event::ScreenLocked).unwrap();
        drop(tx);
        run(rx, policy);
        assert_eq!(*log.lock().unwrap(), vec!["lock"]);
    }

    fn signal<B>(path: &str, interface: &str, member: &str, body: &B) -> Message
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        Message::signal(path, interface, member)
            .unwrap()
            .build(body)
            .unwrap()
    }

    fn properties_changed(path: &str, iface: &str, key: &str, value: OwnedValue) -> Message {
        let mut changed = HashMap::new();
        changed.insert(key.to_string(), value);
        signal(
            path,
            PROPERTIES_IFACE,
            "PropertiesChanged",
            &(iface, changed, Vec::<String>::new()),
        )
    }

    const USER: &str = "/org/freedesktop/login1/user/_1000";
    const SESSION: &str = "/org/freedesktop/login1/session/_31";
    const OTHER: &str = "/org/freedesktop/login1/session/_32";

    #[test]
    fn a_lock_signal_on_the_display_session_is_a_screen_lock() {
        let msg = signal(SESSION, SESSION_IFACE, "Lock", &());
        assert_eq!(
            interpret(&msg, USER, Some(SESSION)),
            Step::Event(Event::ScreenLocked)
        );
    }

    #[test]
    fn a_lock_signal_on_another_session_is_ignored() {
        let msg = signal(OTHER, SESSION_IFACE, "Lock", &());
        assert_eq!(interpret(&msg, USER, Some(SESSION)), Step::Ignore);
    }

    #[test]
    fn locked_hint_turning_true_is_a_screen_lock_and_false_is_not() {
        let on = properties_changed(SESSION, SESSION_IFACE, "LockedHint", OwnedValue::from(true));
        let off = properties_changed(
            SESSION,
            SESSION_IFACE,
            "LockedHint",
            OwnedValue::from(false),
        );
        assert_eq!(
            interpret(&on, USER, Some(SESSION)),
            Step::Event(Event::ScreenLocked)
        );
        assert_eq!(interpret(&off, USER, Some(SESSION)), Step::Ignore);
    }

    #[test]
    fn locked_hint_on_another_session_is_ignored() {
        let other = properties_changed(OTHER, SESSION_IFACE, "LockedHint", OwnedValue::from(true));
        assert_eq!(interpret(&other, USER, Some(SESSION)), Step::Ignore);
    }

    #[test]
    fn prepare_for_sleep_maps_to_sleeping() {
        let start = signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep", &true);
        let end = signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep", &false);
        assert_eq!(
            interpret(&start, USER, None),
            Step::Event(Event::Sleeping(true))
        );
        assert_eq!(
            interpret(&end, USER, None),
            Step::Event(Event::Sleeping(false))
        );
    }

    #[test]
    fn a_display_change_on_the_user_object_moves_the_session() {
        let display = OwnedValue::try_from(zvariant::Value::from((
            "32",
            OwnedObjectPath::try_from(OTHER).unwrap(),
        )))
        .unwrap();
        let msg = properties_changed(USER, USER_IFACE, "Display", display);
        assert_eq!(
            interpret(&msg, USER, None),
            Step::DisplayChanged(Some(OwnedObjectPath::try_from(OTHER).unwrap()))
        );
    }

    #[test]
    fn a_display_change_to_no_session_clears_it() {
        let display = OwnedValue::try_from(zvariant::Value::from((
            "",
            OwnedObjectPath::try_from("/").unwrap(),
        )))
        .unwrap();
        let msg = properties_changed(USER, USER_IFACE, "Display", display);
        assert_eq!(interpret(&msg, USER, None), Step::DisplayChanged(None));
    }

    #[test]
    fn a_user_property_change_for_another_user_is_ignored() {
        let display = OwnedValue::try_from(zvariant::Value::from((
            "32",
            OwnedObjectPath::try_from(OTHER).unwrap(),
        )))
        .unwrap();
        let msg = properties_changed(
            "/org/freedesktop/login1/user/_1001",
            USER_IFACE,
            "Display",
            display,
        );
        assert_eq!(interpret(&msg, USER, None), Step::Ignore);
    }
}
