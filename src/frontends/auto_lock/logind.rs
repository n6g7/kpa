//! The OS side of the lock triggers: what logind reports about the user's
//! display session and about suspend, and the inhibitor that delays suspend
//! (`docs/threat-model.md` T-8 and ASM-7, `docs/design.md` § Locking).
//!
//! This module only watches and executes; it knows nothing about databases
//! or locking. [`start`] sends the watcher's [`Event`]s on the channel it is
//! given and returns an [`Inhibitor`] that `auto_lock` tells whether to hold.
//! A watcher thread owns a D-Bus connection to logind and turns its signals
//! and property changes into events: a `Lock` signal on the user's display
//! session, that session's `LockedHint` and `Active`, `PrepareForSleep`, and
//! a lost subscription (the bus connection ends, or logind's name changes
//! owner). A second thread owns the `Inhibit` call and its file descriptor,
//! so no request ever waits on D-Bus. The watcher acts only on messages sent
//! by the connection that owns logind's name.
//!
//! This module needs systemd-logind reachable on the bus it's given
//! (`Bus::System` in production), which means a systemd Linux host. It
//! works unmodified on any such host. On a Linux host without systemd, or
//! on a non-Linux platform such as macOS, there's no logind to connect
//! to: the watcher retries forever and the inhibitor never holds, so
//! screen-lock and suspend never produce an event and no inhibitor is ever
//! held. None of that panics or stops the daemon: databases still lock on
//! their own idle timer, the only trigger left.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Message;
use zbus::zvariant::{self, OwnedObjectPath, OwnedValue};

use super::Event;
use crate::display_session::DisplaySession;

const LOGIND: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const USER_IFACE: &str = "org.freedesktop.login1.User";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const DBUS: &str = "org.freedesktop.DBus";

/// The signals and properties kpa subscribes to, and the bus's report that
/// logind's name changed owner. A match rule only selects which broadcast
/// signals the bus forwards to kpa: a peer can still send a signal straight
/// to kpa's connection, and it arrives whatever the rules say. So the
/// rules don't authenticate anything; [`interpret`] accepts a message only
/// from the connection that owns logind's name.
const MATCH_RULES: [&str; 4] = [
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Lock'",
    "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
    "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.login1'",
];

const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Delays suspend while it is told to hold. [`Inhibitor::hold`] only sends a
/// message; the thread that owns the `Inhibit` call acts on it.
#[derive(Debug, Clone)]
pub struct Inhibitor {
    requests: Sender<bool>,
}

impl Inhibitor {
    /// Asks to hold the delay (`true`) or to let it go. Applying a state
    /// already in effect does nothing, and a hold that failed is tried again
    /// by the next request.
    pub fn hold(&self, held: bool) {
        let _ = self.requests.send(held);
    }
}

/// Applies each request until the [`Inhibitor`] is gone.
fn inhibit_forever(requests: Receiver<bool>, mut inhibitor: LogindInhibitor) {
    for held in requests {
        if held {
            if inhibitor.is_held() {
                continue;
            }
            match inhibitor.hold() {
                Ok(()) => crate::log::debug(format_args!("holding sleep inhibitor")),
                Err(err) => {
                    crate::log::warn(format_args!("could not hold a sleep inhibitor: {err}"))
                }
            }
        } else if inhibitor.is_held() {
            inhibitor.release();
            crate::log::debug(format_args!("released sleep inhibitor"));
        }
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

/// Start the logind watcher and the inhibitor thread. The watcher sends its
/// events on `events`; the returned [`Inhibitor`] is how `auto_lock` says
/// whether to delay suspend.
pub fn start(bus: Bus, events: Sender<Event>) -> Inhibitor {
    let (requests, receiver) = mpsc::channel();
    let inhibitor = LogindInhibitor::new(bus.clone());
    thread::spawn(move || inhibit_forever(receiver, inhibitor));

    let uid = crate::authn::process_uid();
    thread::spawn(move || watch_forever(&bus, uid, &events));
    Inhibitor { requests }
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

/// Subscribe and forward events until the connection fails or logind's name
/// changes owner. Always returns an error: a watch doesn't end on purpose.
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

    // Read once the rules are in, so a later change of owner arrives as a
    // message and ends the watch.
    let owner = match logind_owner(conn) {
        Ok(owner) => owner,
        Err(err) => return err,
    };
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
    let _ = events.send(Event::DisplayChanged(current.clone()));

    for message in messages {
        let message = match message {
            Ok(message) => message,
            Err(err) => return err.to_string(),
        };
        match interpret(&message, &owner, user.as_str(), session.as_ref()) {
            Step::OwnerChanged => return "logind's name changed owner".to_string(),
            Step::LockRequested => {
                let _ = events.send(Event::LockRequested);
            }
            Step::Sleeping(true) => {
                let _ = events.send(Event::Sleeping);
            }
            Step::Sleeping(false) => {
                let _ = events.send(Event::Resumed);
            }
            Step::DisplayChanged(display) => {
                session = display;
                current = match display_session(conn, session.as_ref()) {
                    Ok(display_session) => display_session,
                    Err(err) => return err,
                };
                let _ = events.send(Event::DisplayChanged(current.clone()));
            }
            Step::Property(Property::Locked(locked)) => {
                current = current.with_locked(locked);
                let _ = events.send(Event::DisplayChanged(current.clone()));
            }
            Step::Property(Property::Active(active)) => {
                current = current.with_active(active);
                let _ = events.send(Event::DisplayChanged(current.clone()));
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
    /// The bus reports that logind's name has a new owner (or none). What was
    /// resolved when the watch subscribed no longer says who logind is.
    OwnerChanged,
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
/// `owner` is the unique name of the connection that owns logind's name.
/// Its messages are the only ones that count, besides the bus's own report
/// that logind's name changed owner. `user` is the user object kpa watches;
/// `session` is the display session it currently follows.
fn interpret(message: &Message, owner: &str, user: &str, session: Option<&LogindSession>) -> Step {
    let header = message.header();
    let (Some(sender), Some(path), Some(interface), Some(member)) = (
        header.sender(),
        header.path(),
        header.interface(),
        header.member(),
    ) else {
        return Step::Ignore;
    };
    if sender.as_str() == DBUS {
        return match (interface.as_str(), member.as_str()) {
            (DBUS, "NameOwnerChanged") if names_logind(message) => Step::OwnerChanged,
            _ => Step::Ignore,
        };
    }
    if sender.as_str() != owner {
        return Step::Ignore;
    }
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

/// Whether a `NameOwnerChanged` is about logind's name.
fn names_logind(message: &Message) -> bool {
    message
        .body()
        .deserialize::<(String, String, String)>()
        .is_ok_and(|(name, _old_owner, _new_owner)| name == LOGIND)
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

/// The unique name of the connection that owns logind's name now.
fn logind_owner(conn: &Connection) -> Result<String, String> {
    let reply = conn
        .call_method(
            Some(DBUS),
            "/org/freedesktop/DBus",
            Some(DBUS),
            "GetNameOwner",
            &LOGIND,
        )
        .map_err(|err| format!("GetNameOwner({LOGIND}): {err}"))?;
    reply
        .body()
        .deserialize::<String>()
        .map_err(|err| err.to_string())
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

/// The state of the user's display session (`docs/headless.md` § 3 and § 5):
/// which one it is, its `LockedHint` and its `Active`. The id is logind's
/// session id: its scope is `session-<id>.scope`. `User.Display` being `/` is
/// [`DisplaySession::None`]. Only `LockedHint` makes it locked: a locker that
/// only sends the `Lock` signal never reports the unlock (ASM-7), so its
/// session stays unlocked.
fn display_session(
    conn: &Connection,
    session: Option<&LogindSession>,
) -> Result<DisplaySession, String> {
    match session {
        Some(session) => {
            let locked = locked_hint(conn, session.path.as_str())?;
            let active = active_hint(conn, session.path.as_str())?;
            Ok(DisplaySession::new(&session.id, locked, active))
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

    /// The connection that owns logind's name in these tests.
    const OWNER: &str = ":1.7";
    /// Another connection on the bus.
    const PEER: &str = ":1.99";

    fn signal_from<B>(sender: &str, path: &str, interface: &str, member: &str, body: &B) -> Message
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        Message::signal(path, interface, member)
            .unwrap()
            .sender(sender)
            .unwrap()
            .build(body)
            .unwrap()
    }

    fn signal<B>(path: &str, interface: &str, member: &str, body: &B) -> Message
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        signal_from(OWNER, path, interface, member, body)
    }

    fn properties_changed_from(
        sender: &str,
        path: &str,
        iface: &str,
        key: &str,
        value: OwnedValue,
    ) -> Message {
        let mut changed = HashMap::new();
        changed.insert(key.to_string(), value);
        signal_from(
            sender,
            path,
            PROPERTIES_IFACE,
            "PropertiesChanged",
            &(iface, changed, Vec::<String>::new()),
        )
    }

    fn properties_changed(path: &str, iface: &str, key: &str, value: OwnedValue) -> Message {
        properties_changed_from(OWNER, path, iface, key, value)
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
            interpret(&msg, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::LockRequested
        );
    }

    #[test]
    fn a_lock_signal_on_another_session_is_ignored() {
        let msg = signal(OTHER, SESSION_IFACE, "Lock", &());
        assert_eq!(
            interpret(&msg, OWNER, USER, Some(&session_at("31", SESSION))),
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
            interpret(&on, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Locked(true))
        );
        assert_eq!(
            interpret(&off, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Locked(false))
        );
    }

    #[test]
    fn locked_hint_on_another_session_is_ignored() {
        let other = properties_changed(OTHER, SESSION_IFACE, "LockedHint", OwnedValue::from(true));
        assert_eq!(
            interpret(&other, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Ignore
        );
    }

    /// `Active` is watched the same way as `LockedHint`, and reported as
    /// its own `Property` — never folded into a `Event::DisplayChanged` by
    /// `interpret` itself, since that needs the other property's current
    /// value, which only `watch`'s own state has.
    #[test]
    fn active_changes_report_the_property() {
        let on = properties_changed(SESSION, SESSION_IFACE, "Active", OwnedValue::from(true));
        let off = properties_changed(SESSION, SESSION_IFACE, "Active", OwnedValue::from(false));
        assert_eq!(
            interpret(&on, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Active(true))
        );
        assert_eq!(
            interpret(&off, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Property(Property::Active(false))
        );
    }

    #[test]
    fn active_on_another_session_is_ignored() {
        let other = properties_changed(OTHER, SESSION_IFACE, "Active", OwnedValue::from(false));
        assert_eq!(
            interpret(&other, OWNER, USER, Some(&session_at("31", SESSION))),
            Step::Ignore
        );
    }

    #[test]
    fn prepare_for_sleep_maps_to_sleeping() {
        let start = signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep", &true);
        let end = signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep", &false);
        assert_eq!(interpret(&start, OWNER, USER, None), Step::Sleeping(true));
        assert_eq!(interpret(&end, OWNER, USER, None), Step::Sleeping(false));
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
            interpret(&msg, OWNER, USER, None),
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
        assert_eq!(
            interpret(&msg, OWNER, USER, None),
            Step::DisplayChanged(None)
        );
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
        assert_eq!(interpret(&msg, OWNER, USER, None), Step::Ignore);
    }

    /// A signal a peer sends straight to kpa's connection arrives whatever
    /// the match rules say, so only the sender tells it from logind's. Each of
    /// these changes what the watcher reports when logind is the sender.
    #[test]
    fn a_signal_from_a_peer_that_isnt_logind_is_ignored() {
        let session = session_at("31", SESSION);
        let display = OwnedValue::try_from(zvariant::Value::from((
            "32",
            OwnedObjectPath::try_from(OTHER).unwrap(),
        )))
        .unwrap();
        let spoofs = [
            signal_from(PEER, SESSION, SESSION_IFACE, "Lock", &()),
            signal_from(PEER, MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep", &true),
            properties_changed_from(
                PEER,
                SESSION,
                SESSION_IFACE,
                "LockedHint",
                OwnedValue::from(false),
            ),
            properties_changed_from(
                PEER,
                SESSION,
                SESSION_IFACE,
                "Active",
                OwnedValue::from(false),
            ),
            properties_changed_from(PEER, USER, USER_IFACE, "Display", display),
        ];
        for spoof in &spoofs {
            assert_eq!(
                interpret(spoof, OWNER, USER, Some(&session)),
                Step::Ignore,
                "{spoof:?}"
            );
        }
    }

    #[test]
    fn a_message_without_a_sender_is_ignored() {
        let msg = Message::signal(MANAGER_PATH, MANAGER_IFACE, "PrepareForSleep")
            .unwrap()
            .build(&true)
            .unwrap();
        assert_eq!(interpret(&msg, OWNER, USER, None), Step::Ignore);
    }

    fn name_owner_changed(sender: &str, name: &str, old_owner: &str, new_owner: &str) -> Message {
        signal_from(
            sender,
            "/org/freedesktop/DBus",
            DBUS,
            "NameOwnerChanged",
            &(name, old_owner, new_owner),
        )
    }

    #[test]
    fn the_bus_reporting_a_change_of_logind_s_owner_ends_the_watch() {
        for (old_owner, new_owner) in [(OWNER, ""), ("", ":1.8"), (OWNER, ":1.8")] {
            let msg = name_owner_changed(DBUS, LOGIND, old_owner, new_owner);
            assert_eq!(
                interpret(&msg, OWNER, USER, None),
                Step::OwnerChanged,
                "{old_owner:?} to {new_owner:?}"
            );
        }
    }

    #[test]
    fn the_bus_reporting_another_name_changing_owner_is_ignored() {
        let msg = name_owner_changed(DBUS, "org.example.Other", ":1.8", ":1.9");
        assert_eq!(interpret(&msg, OWNER, USER, None), Step::Ignore);
    }

    #[test]
    fn a_peer_reporting_a_change_of_logind_s_owner_is_ignored() {
        let msg = name_owner_changed(PEER, LOGIND, OWNER, "");
        assert_eq!(interpret(&msg, OWNER, USER, None), Step::Ignore);
    }
}
