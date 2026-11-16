//! Lock triggers from logind: screen lock and suspend (`docs/threat-model.md`
//! T-8 and ASM-7, `docs/design.md` § Lock policy).
//!
//! Two halves, joined by one channel of [`Event`]s:
//!
//! - [`watch_forever`] owns a D-Bus connection to logind. It turns signals
//!   and property changes into events: a `Lock` signal on the user's
//!   display session, that session's `LockedHint` and `Active`,
//!   `PrepareForSleep`, and a lost subscription.
//! - [`Policy`] decides what to do with an event: lock, tell the server
//!   the display session's state ([`DisplaySession`]), and hold or release a `delay` sleep
//!   inhibitor. It sees only the [`Locks`] and
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

use crate::origin::Origin;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The display session's `Lock` signal. A locker that only sends this
    /// never reports the unlock (ASM-7), so it locks without marking the
    /// display session locked.
    ScreenLocked,
    /// The display session's state: read on subscribing, whenever the display session
    /// changes, and on each change of its `LockedHint` or `Active`.
    /// [`DisplaySession::Locked`] locks; `Active` never does (`DisplaySession`'s own doc
    /// comment).
    DisplaySession(DisplaySession),
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

/// The user's display session, as the logind watch last saw it
/// (`docs/headless.md` § 3 and § 5).
///
/// Only `LockedHint` makes the display session locked. A locker that only sends the
/// `Lock` signal never reports the unlock (ASM-7), so its display session stays
/// [`DisplaySession::Unlocked`]. `active` is a separate fact, carried alongside
/// `LockedHint` for [`may_copy`](DisplaySession::may_copy) alone: counting an
/// inactive session (one a VT switch moved away from) as locked would make
/// kpa lock the vault just for that, so `active` never touches
/// [`is_locked`](DisplaySession::is_locked) or [`may_prompt`](DisplaySession::may_prompt).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DisplaySession {
    /// No display session (`User.Display` is `/`), or no working logind
    /// watch to say otherwise.
    #[default]
    None,
    /// The display session `session` (its logind id), with `LockedHint`
    /// true. `active` is the session's `Active` property.
    Locked { id: String, active: bool },
    /// The display session `session`, with `LockedHint` false. `active` is
    /// the session's `Active` property.
    Unlocked { id: String, active: bool },
}

impl DisplaySession {
    fn from_state(id: &str, locked: bool, active: bool) -> DisplaySession {
        let id = id.to_string();
        if locked {
            DisplaySession::Locked { id, active }
        } else {
            DisplaySession::Unlocked { id, active }
        }
    }

    /// Same session and `LockedHint`, with `locked` in place of the
    /// current one. A no-op on [`DisplaySession::None`]: there is no session to
    /// carry a hint for.
    fn with_locked(&self, locked: bool) -> DisplaySession {
        match self {
            DisplaySession::None => DisplaySession::None,
            DisplaySession::Locked { id, active } | DisplaySession::Unlocked { id, active } => {
                DisplaySession::from_state(id, locked, *active)
            }
        }
    }

    /// Same session and `LockedHint`, with `active` in place of the
    /// current one. A no-op on [`DisplaySession::None`].
    fn with_active(&self, active: bool) -> DisplaySession {
        match self {
            DisplaySession::None => DisplaySession::None,
            DisplaySession::Locked { id, .. } => DisplaySession::Locked {
                id: id.clone(),
                active,
            },
            DisplaySession::Unlocked { id, .. } => DisplaySession::Unlocked {
                id: id.clone(),
                active,
            },
        }
    }

    pub fn is_locked(&self) -> bool {
        matches!(self, DisplaySession::Locked { .. })
    }

    /// The display session's logind id, if there is one. Its scope is
    /// `session-<id>.scope`.
    pub fn id(&self) -> Option<&str> {
        match self {
            DisplaySession::None => None,
            DisplaySession::Locked { id, .. } | DisplaySession::Unlocked { id, .. } => Some(id),
        }
    }

    /// Whether an unlock from `origin` may raise the graphical prompt: only
    /// for a requester on the desktop, and not while the display session is known to
    /// be locked (`docs/headless.md` § 2). Anything else gets `no_display`.
    /// Never reads `active` — see this type's own doc comment.
    pub fn may_prompt(&self, origin: Origin) -> bool {
        origin == Origin::Desktop && !self.is_locked()
    }

    /// Whether a `copy` from `origin` may reach the clipboard: only for a
    /// requester on the desktop, with the display session active and
    /// `LockedHint` false (`docs/headless.md` § 5). Anything else —
    /// outside the desktop, no session, inactive, or locked — gets
    /// `no_display`, and the clipboard is never touched.
    pub fn may_copy(&self, origin: Origin) -> bool {
        origin == Origin::Desktop && matches!(self, DisplaySession::Unlocked { active: true, .. })
    }
}

/// What the policy can do to the databases.
pub trait Locks: Send + Sync {
    /// Lock every database. Must return before the inhibitor is released.
    fn lock_all(&self);
    /// Whether any database is currently unlocked.
    fn any_unlocked(&self) -> bool;
    /// The display session's latest state. No prompt is raised while it is locked.
    fn set_display_session(&self, display_session: DisplaySession);
}

impl<T: Locks + ?Sized> Locks for Arc<T> {
    fn lock_all(&self) {
        (**self).lock_all();
    }
    fn any_unlocked(&self) -> bool {
        (**self).any_unlocked()
    }
    fn set_display_session(&self, display_session: DisplaySession) {
        (**self).set_display_session(display_session);
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
                crate::log::info(format_args!("locked all databases (screen lock)"));
            }
            Event::DisplaySession(display_session) if display_session.is_locked() => {
                // Marked first, so an unlock that starts after `lock_all`
                // can't raise a prompt behind the locker.
                self.locks.set_display_session(display_session);
                self.locks.lock_all();
                crate::log::info(format_args!("locked all databases (screen lock)"));
            }
            Event::DisplaySession(display_session) => {
                self.locks.set_display_session(display_session)
            }
            Event::WatchLost => {
                // The display session's state is unknown until the watch is back.
                self.locks.set_display_session(DisplaySession::None);
                self.locks.lock_all();
                crate::log::warn(format_args!(
                    "locked all databases (logind subscription lost)"
                ));
            }
            Event::Sleeping(true) => {
                // Lock first, release second: releasing is what lets the
                // machine sleep, so the lock must be complete by then.
                self.sleeping = true;
                self.locks.lock_all();
                self.inhibitor.release();
                crate::log::info(format_args!("locked all databases (suspending)"));
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
            match self.inhibitor.hold() {
                Ok(()) => crate::log::debug(format_args!("holding sleep inhibitor")),
                Err(err) => {
                    crate::log::warn(format_args!("could not hold a sleep inhibitor: {err}"))
                }
            }
        } else if !want && self.inhibitor.is_held() {
            self.inhibitor.release();
            crate::log::debug(format_args!("released sleep inhibitor"));
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
            crate::log::warn(format_args!("logind watch: {error}; retrying"));
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
    let mut session = match logind_session(conn, user.as_str()) {
        Ok(session) => session,
        Err(err) => return err,
    };
    *subscribed = true;
    crate::log::debug(format_args!("subscribed to logind"));
    // The last `DisplaySession` sent, so a single-property change (`Step::Property`)
    // has something to merge into — `interpret` itself is stateless.
    let mut current = match display_session(conn, session.as_ref()) {
        Ok(display_session) => display_session,
        Err(err) => return err,
    };
    let _ = events.send(Event::DisplaySession(current.clone()));

    for message in messages {
        let message = match message {
            Ok(message) => message,
            Err(err) => return err.to_string(),
        };
        match interpret(&message, user.as_str(), session.as_ref()) {
            Step::Event(event) => {
                let _ = events.send(event);
            }
            Step::DisplayChanged(display) => {
                session = display;
                current = match display_session(conn, session.as_ref()) {
                    Ok(display_session) => display_session,
                    Err(err) => return err,
                };
                let _ = events.send(Event::DisplaySession(current.clone()));
            }
            Step::Property(Property::Locked(locked)) => {
                current = current.with_locked(locked);
                let _ = events.send(Event::DisplaySession(current.clone()));
            }
            Step::Property(Property::Active(active)) => {
                current = current.with_active(active);
                let _ = events.send(Event::DisplaySession(current.clone()));
            }
            Step::Ignore => {}
        }
    }
    "the system bus connection closed".to_string()
}

/// The user's display session: its logind id and object path, from
/// `User.Display`.
#[derive(Debug, PartialEq, Eq)]
struct LogindSession {
    id: String,
    path: OwnedObjectPath,
}

/// What one incoming message means to the watcher.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Event(Event),
    /// The user's display session changed to this one (`None`: no display
    /// session any more).
    DisplayChanged(Option<LogindSession>),
    /// `LockedHint` or `Active` changed on the display session, to this new
    /// value. `interpret` has no state to merge it into — `watch` does
    /// that, against the `DisplaySession` it last sent.
    Property(Property),
    Ignore,
}

/// One property change reported for the display session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Property {
    Locked(bool),
    Active(bool),
}

/// Classify a message. Pure, so the matching can be tested without a bus.
/// `user` is the user object kpa watches; `session` is the display session
/// it currently follows.
fn interpret(message: &Message, user: &str, session: Option<&LogindSession>) -> Step {
    let header = message.header();
    let (Some(path), Some(interface), Some(member)) =
        (header.path(), header.interface(), header.member())
    else {
        return Step::Ignore;
    };
    let on_session = session.is_some_and(|session| session.path.as_str() == path.as_str());

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
                if let Some(locked) = changed
                    .get("LockedHint")
                    .and_then(|v| bool::try_from(v).ok())
                {
                    return Step::Property(Property::Locked(locked));
                }
                if let Some(active) = changed.get("Active").and_then(|v| bool::try_from(v).ok()) {
                    return Step::Property(Property::Active(active));
                }
            }
            Step::Ignore
        }
        _ => Step::Ignore,
    }
}

/// Parse a `User.Display` value, `(so)`. Returns `Some(None)` for logind's
/// "no display session" (`"/"`), `None` if the value doesn't have that shape.
fn parse_display(value: &OwnedValue) -> Option<Option<LogindSession>> {
    let (id, path) = <(String, OwnedObjectPath)>::try_from(value.clone()).ok()?;
    if path.as_str() == "/" {
        Some(None)
    } else {
        Some(Some(LogindSession { id, path }))
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

fn logind_session(conn: &Connection, user: &str) -> Result<Option<LogindSession>, String> {
    let value = get_property(conn, user, USER_IFACE, "Display")?;
    parse_display(&value).ok_or_else(|| "unexpected User.Display value".to_string())
}

/// The state of the user's display session: which one it is, its `LockedHint`,
/// and its `Active`.
fn display_session(
    conn: &Connection,
    session: Option<&LogindSession>,
) -> Result<DisplaySession, String> {
    match session {
        Some(session) => {
            let locked = locked_hint(conn, session.path.as_str())?;
            let active = active_hint(conn, session.path.as_str())?;
            Ok(DisplaySession::from_state(&session.id, locked, active))
        }
        None => Ok(DisplaySession::None),
    }
}

fn locked_hint(conn: &Connection, session: &str) -> Result<bool, String> {
    let value = get_property(conn, session, SESSION_IFACE, "LockedHint")?;
    bool::try_from(&value).map_err(|err| err.to_string())
}

/// Whether the display session is the one currently active on its seat
/// (`docs/headless.md` § 5) — separate from `LockedHint`, and read the
/// same way.
fn active_hint(conn: &Connection, session: &str) -> Result<bool, String> {
    let value = get_property(conn, session, SESSION_IFACE, "Active")?;
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
        display_session: Mutex<DisplaySession>,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeLocks {
        fn display_session(&self) -> DisplaySession {
            self.display_session.lock().unwrap().clone()
        }
    }

    impl Locks for FakeLocks {
        fn lock_all(&self) {
            self.unlocked.store(false, Ordering::SeqCst);
            self.log.lock().unwrap().push("lock");
        }
        fn any_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
        fn set_display_session(&self, display_session: DisplaySession) {
            self.log.lock().unwrap().push(match display_session {
                DisplaySession::None => "no display session",
                DisplaySession::Locked { .. } => "display session locked",
                DisplaySession::Unlocked { .. } => "display session unlocked",
            });
            *self.display_session.lock().unwrap() = display_session;
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
                display_session: Mutex::new(DisplaySession::None),
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

    /// A locked display session, active unless `active` says otherwise.
    fn locked_display_session() -> DisplaySession {
        DisplaySession::Locked {
            id: "31".to_string(),
            active: true,
        }
    }

    /// An unlocked display session, active unless `active` says otherwise.
    fn unlocked_display_session() -> DisplaySession {
        DisplaySession::Unlocked {
            id: "31".to_string(),
            active: true,
        }
    }

    /// An unlocked display session that isn't the active one — a VT
    /// switch, say.
    fn inactive_unlocked_display_session() -> DisplaySession {
        DisplaySession::Unlocked {
            id: "31".to_string(),
            active: false,
        }
    }

    /// The display session is marked locked before anything is locked, so an unlock
    /// starting in between can't raise a prompt behind the locker.
    #[test]
    fn a_locked_hint_marks_the_display_session_locked_then_locks_everything() {
        let mut h = Harness::new();
        h.unlock();
        h.policy
            .handle(Event::DisplaySession(locked_display_session()));
        assert!(!h.locks.any_unlocked());
        assert_eq!(h.locks.display_session(), locked_display_session());
        assert_eq!(
            h.log(),
            vec!["hold", "display session locked", "lock", "release"]
        );
    }

    #[test]
    fn a_cleared_locked_hint_unmarks_the_display_session_and_locks_nothing() {
        let mut h = Harness::new();
        h.policy
            .handle(Event::DisplaySession(locked_display_session()));
        h.unlock();
        h.policy
            .handle(Event::DisplaySession(unlocked_display_session()));
        assert_eq!(h.locks.display_session(), unlocked_display_session());
        assert!(h.locks.any_unlocked());
    }

    #[test]
    fn no_display_session_is_published_and_locks_nothing() {
        let mut h = Harness::new();
        h.policy
            .handle(Event::DisplaySession(unlocked_display_session()));
        h.unlock();
        h.policy.handle(Event::DisplaySession(DisplaySession::None));
        assert_eq!(h.locks.display_session(), DisplaySession::None);
        assert!(h.locks.any_unlocked());
    }

    /// A locker that only sends `Lock` never reports the unlock, so the
    /// signal alone must not leave the display session marked locked.
    #[test]
    fn a_lock_signal_does_not_mark_the_display_session_locked() {
        let mut h = Harness::new();
        h.policy
            .handle(Event::DisplaySession(unlocked_display_session()));
        h.policy.handle(Event::ScreenLocked);
        assert_eq!(h.locks.display_session(), unlocked_display_session());
    }

    #[test]
    fn a_lost_subscription_forgets_the_display_session_state() {
        let mut h = Harness::new();
        h.policy
            .handle(Event::DisplaySession(locked_display_session()));
        h.policy.handle(Event::WatchLost);
        assert_eq!(h.locks.display_session(), DisplaySession::None);
    }

    #[test]
    fn only_a_requester_on_the_desktop_may_prompt_and_not_while_locked() {
        assert!(unlocked_display_session().may_prompt(Origin::Desktop));
        assert!(!locked_display_session().may_prompt(Origin::Desktop));
        assert!(!unlocked_display_session().may_prompt(Origin::Outside));
        assert!(!locked_display_session().may_prompt(Origin::Outside));
        assert!(!DisplaySession::None.may_prompt(Origin::Outside));
    }

    /// `may_prompt` never reads `active` — an inactive display session (a VT switch)
    /// is treated exactly like an active one for prompting.
    #[test]
    fn may_prompt_ignores_whether_the_display_session_is_active() {
        assert!(inactive_unlocked_display_session().may_prompt(Origin::Desktop));
    }

    /// `docs/headless.md` § 5: `copy` needs a desktop requester, an active
    /// display session, and `LockedHint` false — every other combination
    /// gets `no_display`.
    #[test]
    fn only_a_desktop_requester_on_an_active_unlocked_display_session_may_copy() {
        assert!(unlocked_display_session().may_copy(Origin::Desktop));
        assert!(!unlocked_display_session().may_copy(Origin::Outside));
        assert!(!locked_display_session().may_copy(Origin::Desktop));
        assert!(!locked_display_session().may_copy(Origin::Outside));
        assert!(!inactive_unlocked_display_session().may_copy(Origin::Desktop));
        assert!(!inactive_unlocked_display_session().may_copy(Origin::Outside));
        assert!(!DisplaySession::None.may_copy(Origin::Desktop));
        assert!(!DisplaySession::None.may_copy(Origin::Outside));
    }

    #[test]
    fn the_display_session_names_its_session_and_whether_it_is_locked() {
        assert_eq!(DisplaySession::None.id(), None);
        assert!(!DisplaySession::None.is_locked());
        assert_eq!(locked_display_session().id(), Some("31"));
        assert!(locked_display_session().is_locked());
        assert_eq!(unlocked_display_session().id(), Some("31"));
        assert!(!unlocked_display_session().is_locked());
    }

    /// `with_locked` and `with_active` carry the session across and only
    /// change the one property asked for; both are a no-op on
    /// `DisplaySession::None` (there is nothing to carry).
    #[test]
    fn with_locked_and_with_active_change_one_property_at_a_time() {
        assert_eq!(
            unlocked_display_session().with_locked(true),
            locked_display_session()
        );
        assert_eq!(
            locked_display_session().with_locked(false),
            unlocked_display_session()
        );
        assert_eq!(
            unlocked_display_session().with_active(false),
            inactive_unlocked_display_session()
        );
        assert_eq!(
            inactive_unlocked_display_session().with_active(true),
            unlocked_display_session()
        );
        assert_eq!(DisplaySession::None.with_locked(true), DisplaySession::None);
        assert_eq!(
            DisplaySession::None.with_active(false),
            DisplaySession::None
        );
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

    fn session_at(id: &str, path: &str) -> LogindSession {
        LogindSession {
            id: id.to_string(),
            path: OwnedObjectPath::try_from(path).unwrap(),
        }
    }

    #[test]
    fn a_lock_signal_on_the_display_session_is_a_screen_lock() {
        let msg = signal(SESSION, SESSION_IFACE, "Lock", &());
        assert_eq!(
            interpret(&msg, USER, Some(&session_at("31", SESSION))),
            Step::Event(Event::ScreenLocked)
        );
    }

    #[test]
    fn a_lock_signal_on_another_session_is_ignored() {
        let msg = signal(OTHER, SESSION_IFACE, "Lock", &());
        assert_eq!(
            interpret(&msg, USER, Some(&session_at("31", SESSION))),
            Step::Ignore
        );
    }

    #[test]
    fn locked_hint_changes_report_the_property() {
        let on = properties_changed(SESSION, SESSION_IFACE, "LockedHint", OwnedValue::from(true));
        let off = properties_changed(
            SESSION,
            SESSION_IFACE,
            "LockedHint",
            OwnedValue::from(false),
        );
        assert_eq!(
            interpret(&on, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Locked(true))
        );
        assert_eq!(
            interpret(&off, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Locked(false))
        );
    }

    #[test]
    fn locked_hint_on_another_session_is_ignored() {
        let other = properties_changed(OTHER, SESSION_IFACE, "LockedHint", OwnedValue::from(true));
        assert_eq!(
            interpret(&other, USER, Some(&session_at("31", SESSION))),
            Step::Ignore
        );
    }

    /// `Active` is watched the same way as `LockedHint`, and reported as
    /// its own `Property` — never folded into an `Event::DisplaySession` by
    /// `interpret` itself, since that needs the other property's current
    /// value, which only `watch`'s own state has.
    #[test]
    fn active_changes_report_the_property() {
        let on = properties_changed(SESSION, SESSION_IFACE, "Active", OwnedValue::from(true));
        let off = properties_changed(SESSION, SESSION_IFACE, "Active", OwnedValue::from(false));
        assert_eq!(
            interpret(&on, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Active(true))
        );
        assert_eq!(
            interpret(&off, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Active(false))
        );
    }

    #[test]
    fn active_on_another_session_is_ignored() {
        let other = properties_changed(OTHER, SESSION_IFACE, "Active", OwnedValue::from(false));
        assert_eq!(
            interpret(&other, USER, Some(&session_at("31", SESSION))),
            Step::Ignore
        );
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
            Step::DisplayChanged(Some(session_at("32", OTHER)))
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
