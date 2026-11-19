//! The OS side of the lock triggers: what logind reports about the user's
//! display session and about suspend, and the inhibitor that delays suspend
//! (`docs/threat-model.md` T-8 and ASM-7, `docs/design.md` § Lock policy).
//!
//! This module only reports; it knows nothing about databases or locking.
//! [`start`] returns the [`SessionEvent`]s the daemon reacts to
//! (`Server::on_session_event`) and a [`SleepDelay`] the daemon tells
//! whether anything is unlocked. A watcher thread owns a D-Bus connection
//! to logind and turns its signals and property changes into events: a
//! `Lock` signal on the user's display session, that session's
//! `LockedHint` and `Active`, `PrepareForSleep`, and a lost subscription.
//! A second thread owns the `Inhibit` call and its file descriptor, so no
//! request ever waits on D-Bus.
//!
//! This module needs systemd-logind reachable on the bus it's given
//! (`Bus::System` in production), which means a systemd Linux host. It
//! works unmodified on any such host. On a Linux host without systemd, or
//! on a non-Linux platform such as macOS, there's no logind to connect
//! to: the watcher retries forever and the inhibitor never holds, so
//! screen-lock and suspend never produce an event and no inhibitor is ever
//! held. None of that panics or stops the server: databases still lock on
//! their own idle timer, the only trigger left.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Message;
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue};

use crate::display_session::DisplaySession;

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

/// What the OS reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The display session is new, or its locked or active state changed.
    /// Read on subscribing, whenever the display session changes, and on
    /// each change of its `LockedHint` or `Active`.
    Changed(DisplaySession),
    /// The display session's `Lock` signal. A locker that only sends this
    /// never reports the unlock (ASM-7), so it doesn't change the display
    /// session's state.
    LockRequested,
    /// The machine is about to suspend.
    Sleeping,
    /// A subscription that had been working has dropped: the display
    /// session's state is unknown until it is back.
    WatchLost,
}

/// Delays suspend while the daemon says something is unlocked, and never
/// while the machine is going to sleep. [`SleepDelay::hold_while`] only
/// sends a message; the thread that owns the `Inhibit` call acts on it.
#[derive(Debug, Clone)]
pub struct SleepDelay {
    requests: Sender<bool>,
    state: Arc<DelayState>,
}

/// What the watcher and the inhibitor thread share with the handles.
#[derive(Debug, Default)]
struct DelayState {
    /// The last request: whether anything is unlocked.
    wanted: AtomicBool,
    /// Between `PrepareForSleep(true)` and `PrepareForSleep(false)`.
    sleeping: AtomicBool,
}

impl SleepDelay {
    /// A delay that sends its requests to the returned receiver, not to
    /// logind: what [`start`] builds on, and what tests read.
    pub fn new() -> (SleepDelay, Receiver<bool>) {
        let (requests, receiver) = mpsc::channel();
        let delay = SleepDelay {
            requests,
            state: Arc::new(DelayState::default()),
        };
        (delay, receiver)
    }

    /// Asks to delay suspend while `anything_unlocked`, and to let it go
    /// when it isn't. The daemon says so after every change to what is
    /// unlocked.
    pub fn hold_while(&self, anything_unlocked: bool) {
        self.state.wanted.store(anything_unlocked, Ordering::SeqCst);
        let _ = self.requests.send(anything_unlocked);
    }

    /// `PrepareForSleep(true)`: requests to hold are ignored from now on.
    /// Nothing is released here: the daemon locks first, then says nothing
    /// is unlocked, and that releases it.
    fn going_to_sleep(&self) {
        self.state.sleeping.store(true, Ordering::SeqCst);
    }

    /// `PrepareForSleep(false)`: holds again if something was unlocked
    /// while the machine slept.
    fn resumed(&self) {
        self.state.sleeping.store(false, Ordering::SeqCst);
        let _ = self.requests.send(self.state.wanted.load(Ordering::SeqCst));
    }

    fn sleeping(&self) -> bool {
        self.state.sleeping.load(Ordering::SeqCst)
    }
}

/// What the inhibitor thread does about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inhibit {
    Hold,
    Release,
    Keep,
}

/// What to do about a request that anything is `unlocked`, given whether
/// the machine is `sleeping` and whether the inhibitor is `held`. Pure, so
/// the gating can be tested without a bus.
fn inhibit(unlocked: bool, sleeping: bool, held: bool) -> Inhibit {
    match (unlocked && !sleeping, held) {
        (true, false) => Inhibit::Hold,
        (false, true) => Inhibit::Release,
        _ => Inhibit::Keep,
    }
}

/// Acts on each request until the [`SleepDelay`] is gone.
fn inhibit_forever(requests: Receiver<bool>, delay: SleepDelay, mut inhibitor: LogindInhibitor) {
    for unlocked in requests {
        match inhibit(unlocked, delay.sleeping(), inhibitor.is_held()) {
            Inhibit::Hold => match inhibitor.hold() {
                Ok(()) => crate::log::debug(format_args!("holding sleep inhibitor")),
                Err(err) => {
                    crate::log::warn(format_args!("could not hold a sleep inhibitor: {err}"))
                }
            },
            Inhibit::Release => {
                inhibitor.release();
                crate::log::debug(format_args!("released sleep inhibitor"));
            }
            Inhibit::Keep => {}
        }
    }
}

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
fn with_locked(session: &DisplaySession, locked: bool) -> DisplaySession {
    match session {
        DisplaySession::None => DisplaySession::None,
        DisplaySession::Locked { id, active } | DisplaySession::Unlocked { id, active } => {
            from_state(id, locked, *active)
        }
    }
}

/// Same session and `LockedHint`, with `active` in place of the
/// current one. A no-op on [`DisplaySession::None`].
fn with_active(session: &DisplaySession, active: bool) -> DisplaySession {
    match session {
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

/// Start the logind watcher and the inhibitor thread. The events are what
/// the watcher reports; the delay is what the daemon tells about unlocks.
pub fn start(bus: Bus) -> (Receiver<SessionEvent>, SleepDelay) {
    let (events, session_events) = mpsc::channel();
    let (delay, requests) = SleepDelay::new();

    let inhibitor = LogindInhibitor::new(bus.clone());
    let inhibiting = delay.clone();
    thread::spawn(move || inhibit_forever(requests, inhibiting, inhibitor));

    let watching = delay.clone();
    let uid = crate::authn::process_uid();
    thread::spawn(move || watch_forever(&bus, uid, &events, &watching));
    (session_events, delay)
}

/// Keep a watch on logind for the life of the process. A subscription that
/// drops after working locks everything (the lock can't be confirmed to
/// have been sent) and is re-established with backoff. A first failure is
/// only logged: nothing can be unlocked before the first subscription.
fn watch_forever(bus: &Bus, uid: u32, events: &Sender<SessionEvent>, delay: &SleepDelay) {
    let mut last_error: Option<String> = None;
    loop {
        let mut subscribed = false;
        let error = match bus.connect() {
            Ok(conn) => watch(&conn, uid, events, delay, &mut subscribed),
            Err(err) => err.to_string(),
        };
        if subscribed {
            let _ = events.send(SessionEvent::WatchLost);
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
fn watch(
    conn: &Connection,
    uid: u32,
    events: &Sender<SessionEvent>,
    delay: &SleepDelay,
    subscribed: &mut bool,
) -> String {
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
    let _ = events.send(SessionEvent::Changed(current.clone()));

    for message in messages {
        let message = match message {
            Ok(message) => message,
            Err(err) => return err.to_string(),
        };
        match interpret(&message, user.as_str(), session.as_ref()) {
            Step::LockRequested => {
                let _ = events.send(SessionEvent::LockRequested);
            }
            Step::Sleeping(true) => {
                // Marked before it is reported, so nothing taken after the
                // report holds the machine awake; the delay itself is
                // released by the server once it has locked.
                delay.going_to_sleep();
                let _ = events.send(SessionEvent::Sleeping);
            }
            Step::Sleeping(false) => delay.resumed(),
            Step::DisplayChanged(display) => {
                session = display;
                current = match display_session(conn, session.as_ref()) {
                    Ok(display_session) => display_session,
                    Err(err) => return err,
                };
                let _ = events.send(SessionEvent::Changed(current.clone()));
            }
            Step::Property(Property::Locked(locked)) => {
                current = with_locked(&current, locked);
                let _ = events.send(SessionEvent::Changed(current.clone()));
            }
            Step::Property(Property::Active(active)) => {
                current = with_active(&current, active);
                let _ = events.send(SessionEvent::Changed(current.clone()));
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
    /// The display session's `Lock` signal.
    LockRequested,
    /// `PrepareForSleep`: `true` just before sleep, `false` on resume.
    Sleeping(bool),
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
            Ok(starting) => Step::Sleeping(starting),
            Err(_) => Step::Ignore,
        },
        (SESSION_IFACE, "Lock") if on_session => Step::LockRequested,
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
            Ok(from_state(&session.id, locked, active))
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
struct LogindInhibitor {
    bus: Bus,
    conn: Option<Connection>,
    fd: Option<OwnedFd>,
}

impl LogindInhibitor {
    fn new(bus: Bus) -> Self {
        LogindInhibitor {
            bus,
            conn: None,
            fd: None,
        }
    }

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
    use super::*;

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

    /// `with_locked` and `with_active` carry the session across and only
    /// change the one property asked for; both are a no-op on
    /// `DisplaySession::None` (there is nothing to carry).
    #[test]
    fn with_locked_and_with_active_change_one_property_at_a_time() {
        assert_eq!(
            with_locked(&unlocked_display_session(), true),
            locked_display_session()
        );
        assert_eq!(
            with_locked(&locked_display_session(), false),
            unlocked_display_session()
        );
        assert_eq!(
            with_active(&unlocked_display_session(), false),
            inactive_unlocked_display_session()
        );
        assert_eq!(
            with_active(&inactive_unlocked_display_session(), true),
            unlocked_display_session()
        );
        assert_eq!(
            with_locked(&DisplaySession::None, true),
            DisplaySession::None
        );
        assert_eq!(
            with_active(&DisplaySession::None, false),
            DisplaySession::None
        );
    }

    #[test]
    fn a_request_to_hold_holds_while_the_machine_is_awake_and_never_while_it_sleeps() {
        // (something unlocked, sleeping, held) and what happens.
        for (unlocked, sleeping, held, expected) in [
            (true, false, false, Inhibit::Hold),
            (true, false, true, Inhibit::Keep),
            (false, false, true, Inhibit::Release),
            (false, false, false, Inhibit::Keep),
            (true, true, false, Inhibit::Keep),
            (true, true, true, Inhibit::Release),
            (false, true, true, Inhibit::Release),
            (false, true, false, Inhibit::Keep),
        ] {
            assert_eq!(
                inhibit(unlocked, sleeping, held),
                expected,
                "unlocked: {unlocked}, sleeping: {sleeping}, held: {held}"
            );
        }
    }

    #[test]
    fn hold_while_sends_what_it_was_asked() {
        let (delay, requests) = SleepDelay::new();

        delay.hold_while(true);
        delay.hold_while(false);

        assert_eq!(requests.try_iter().collect::<Vec<_>>(), [true, false]);
    }

    /// Going to sleep releases nothing (the daemon locks first, then says
    /// nothing is unlocked); resuming asks again with the last answer, so
    /// an unlock that came while the machine slept holds at resume, and
    /// nothing is held at resume when everything is locked.
    #[test]
    fn resuming_asks_again_with_the_last_request() {
        let (delay, requests) = SleepDelay::new();
        delay.hold_while(true);
        let _ = requests.try_iter().count();

        delay.going_to_sleep();
        assert!(delay.sleeping());
        assert!(
            requests.try_recv().is_err(),
            "nothing is released by the report alone"
        );
        delay.hold_while(true);
        delay.resumed();

        assert!(!delay.sleeping());
        assert_eq!(requests.try_iter().collect::<Vec<_>>(), [true, true]);

        delay.hold_while(false);
        delay.going_to_sleep();
        delay.resumed();
        assert_eq!(requests.try_iter().collect::<Vec<_>>(), [false, false]);
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
            Step::LockRequested
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
    /// its own `Property` — never folded into a `SessionEvent::Changed` by
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
        assert_eq!(interpret(&start, USER, None), Step::Sleeping(true));
        assert_eq!(interpret(&end, USER, None), Step::Sleeping(false));
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
