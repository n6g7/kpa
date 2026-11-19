//! The front end that locks without a request: when the screen locks, the
//! machine suspends, the watch on the display session is lost, or a
//! database sits idle (`docs/design.md` § Lock policy).
//!
//! This file is OS-neutral and names no D-Bus type: [`logind`] reports the
//! triggers as [`SessionEvent`](logind::SessionEvent)s and holds the sleep
//! inhibitor, and [`AutoLock`] says what each one means for the databases.
//! [`SleepHold`] is the observer that tells the inhibitor whether anything
//! is unlocked.
//!
//! The display session is this front end's to write ([`DisplayWriter`]) and
//! everyone else's to read ([`DisplayHandle`](crate::display_session::DisplayHandle)).
//! A locked display session is written before anything is locked, so no
//! observer or later reader sees a lock without it.

pub mod logind;

use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use self::logind::{Bus, SessionEvent, SleepSignal};
use crate::cancel::CancelToken;
use crate::databases::{Databases, Observer};
use crate::display_session::{DisplaySession, DisplayWriter};
use crate::log;

/// Where the lock triggers come from.
pub struct Source(Bus);

impl Source {
    /// The OS's own source: logind on the system bus.
    pub fn system() -> Source {
        Source(Bus::System)
    }

    /// A private message bus at `address`, for tests.
    pub fn at(address: impl Into<String>) -> Source {
        Source(Bus::Address(address.into()))
    }
}

/// Starts the watcher and the inhibitor thread. Returns the observer that
/// feeds the inhibitor, to register after the observers that hold secrets,
/// and the loop that reacts to the triggers.
pub fn start(source: Source, display: DisplayWriter) -> (SleepHold, AutoLock) {
    let (events, signals) = logind::start(source.0);
    (
        SleepHold {
            signals,
            order: Mutex::new(()),
        },
        AutoLock { events, display },
    )
}

/// The loop that reacts to the lock triggers.
pub struct AutoLock {
    events: Receiver<SessionEvent>,
    display: DisplayWriter,
}

impl AutoLock {
    /// Spawns the idle tick, then blocks reacting to events for as long as
    /// the watcher lives.
    pub fn run(self, databases: Arc<Databases>, idle_timeout: Duration) {
        let ticking = databases.clone();
        thread::spawn(move || watch_idle(&ticking, idle_timeout));
        for event in self.events {
            react(&databases, &self.display, event);
        }
    }
}

/// Tells the sleep inhibitor whether anything is unlocked after every
/// change, in the order the changes happened.
pub struct SleepHold {
    signals: Sender<SleepSignal>,
    /// Held while reading `any_unlocked` and sending it, so the inhibitor
    /// hears the states in the order they were read whichever threads
    /// changed them.
    order: Mutex<()>,
}

impl SleepHold {
    fn sync(&self, databases: &Databases) {
        let _turn = self.order.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .signals
            .send(SleepSignal::Unlocked(databases.any_unlocked()));
    }
}

impl Observer for SleepHold {
    fn unlocked(&self, databases: &Databases, _db: &str, _unlock: &CancelToken) {
        self.sync(databases);
    }

    fn locked(&self, databases: &Databases, _db: &str, _unlock: &CancelToken) {
        self.sync(databases);
    }
}

/// What one trigger means. A locked display session is written before
/// anything is locked; a lock request alone doesn't mark it; a lost watch
/// forgets it, since its state is unknown until the watch is back. On
/// suspend everything is locked, and the inhibitor is released when
/// [`SleepHold`] is told.
fn react(databases: &Databases, display: &DisplayWriter, event: SessionEvent) {
    match event {
        SessionEvent::Changed(session) => {
            let locked = session.is_locked();
            display.set(session);
            if locked {
                databases.lock_all();
                log::info(format_args!("locked all databases (screen lock)"));
            }
        }
        SessionEvent::LockRequested => {
            databases.lock_all();
            log::info(format_args!("locked all databases (screen lock)"));
        }
        SessionEvent::Sleeping => {
            databases.lock_all();
            log::info(format_args!("locked all databases (suspending)"));
        }
        SessionEvent::WatchLost => {
            display.set(DisplaySession::None);
            databases.lock_all();
            log::warn(format_args!(
                "locked all databases (logind subscription lost)"
            ));
        }
    }
}

/// Checks the idle timer on a fixed tick for as long as the daemon runs.
/// The tick is a tenth of `idle_timeout`, clamped to between 10 ms and 1 s.
fn watch_idle(databases: &Databases, idle_timeout: Duration) {
    let tick = (idle_timeout / 10).clamp(Duration::from_millis(10), Duration::from_secs(1));
    loop {
        thread::sleep(tick);
        databases.expire_idle(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::DatabaseConfig;
    use crate::display_session::{DisplayHandle, channel};

    const HOUR: Duration = Duration::from_secs(3600);

    fn config(name: &str) -> DatabaseConfig {
        DatabaseConfig {
            name: name.to_string(),
            path: PathBuf::new(),
            keyfile: None,
            serve_ssh_keys: false,
            ssh_keys: Vec::new(),
        }
    }

    fn databases(idle_timeout: Duration) -> Databases {
        Databases::for_test(vec![config("personal"), config("work")], idle_timeout)
    }

    /// Both databases unlocked.
    fn unlocked(databases: &Databases) {
        databases.install_for_test("personal", Vec::new());
        databases.install_for_test("work", Vec::new());
        assert!(databases.any_unlocked());
    }

    fn session(locked: bool) -> DisplaySession {
        let id = "31".to_string();
        if locked {
            DisplaySession::Locked { id, active: true }
        } else {
            DisplaySession::Unlocked { id, active: true }
        }
    }

    fn reacting(event: SessionEvent) -> (Databases, DisplayHandle) {
        let databases = databases(HOUR);
        unlocked(&databases);
        let (writer, display) = channel();
        react(&databases, &writer, event);
        (databases, display)
    }

    #[test]
    fn a_lock_request_a_locked_screen_a_suspend_and_a_lost_watch_each_lock_everything() {
        for event in [
            SessionEvent::LockRequested,
            SessionEvent::Changed(session(true)),
            SessionEvent::Sleeping,
            SessionEvent::WatchLost,
        ] {
            let (databases, _) = reacting(event.clone());
            assert!(!databases.any_unlocked(), "{event:?} should lock");
        }
    }

    #[test]
    fn a_display_session_that_is_not_locked_is_recorded_and_locks_nothing() {
        let (databases, display) = reacting(SessionEvent::Changed(session(false)));
        assert!(databases.any_unlocked());
        assert_eq!(display.get(), session(false));
    }

    #[test]
    fn a_lock_request_does_not_mark_the_display_session() {
        let databases = databases(HOUR);
        unlocked(&databases);
        let (writer, display) = channel();
        writer.set(session(false));
        react(&databases, &writer, SessionEvent::LockRequested);
        assert_eq!(display.get(), session(false));
    }

    #[test]
    fn a_lost_watch_forgets_the_display_session() {
        let databases = databases(HOUR);
        let (writer, display) = channel();
        writer.set(session(false));
        react(&databases, &writer, SessionEvent::WatchLost);
        assert_eq!(display.get(), DisplaySession::None);
    }

    /// Records what the display session was when each database was locked.
    struct SeesDisplay {
        display: DisplayHandle,
        seen: Mutex<Vec<DisplaySession>>,
    }

    impl Observer for SeesDisplay {
        fn locked(&self, _: &Databases, _: &str, _: &CancelToken) {
            self.seen.lock().unwrap().push(self.display.get());
        }
    }

    #[test]
    fn a_locked_display_session_is_marked_before_anything_is_locked() {
        let (writer, display) = channel();
        let seen = Arc::new(SeesDisplay {
            display,
            seen: Mutex::new(Vec::new()),
        });
        let mut databases = databases(HOUR);
        databases.observe(seen.clone());
        unlocked(&databases);
        react(&databases, &writer, SessionEvent::Changed(session(true)));
        assert_eq!(*seen.seen.lock().unwrap(), [session(true), session(true)]);
    }

    #[test]
    fn the_idle_tick_locks_what_is_idle() {
        let databases = Arc::new(databases(Duration::from_millis(50)));
        unlocked(&databases);
        let ticking = databases.clone();
        thread::spawn(move || watch_idle(&ticking, Duration::from_millis(50)));
        let deadline = Instant::now() + Duration::from_secs(10);
        while databases.any_unlocked() {
            assert!(Instant::now() < deadline, "the idle tick never locked");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A database with a sleep hold registered, and what the hold tells the
    /// inhibitor.
    fn held() -> (Databases, Receiver<SleepSignal>) {
        let (signals, told) = std::sync::mpsc::channel();
        let mut databases = databases(HOUR);
        databases.observe(Arc::new(SleepHold {
            signals,
            order: Mutex::new(()),
        }));
        (databases, told)
    }

    /// The answers to "is anything unlocked" the inhibitor has been sent
    /// since the last call, in order.
    fn answers(told: &Receiver<SleepSignal>) -> Vec<bool> {
        told.try_iter()
            .map(|signal| match signal {
                SleepSignal::Unlocked(unlocked) => unlocked,
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    #[test]
    fn the_inhibitor_hears_every_change_to_something_is_unlocked_in_order() {
        let (databases, told) = held();
        databases.install_for_test("personal", Vec::new());
        databases.install_for_test("work", Vec::new());
        databases.lock("personal").unwrap();
        databases.lock("work").unwrap();
        assert_eq!(answers(&told), [true, true, true, false]);
    }

    #[test]
    fn on_suspend_the_inhibitor_is_released_only_after_everything_is_locked() {
        let (databases, told) = held();
        unlocked(&databases);
        let (writer, _) = channel();
        assert_eq!(answers(&told), [true, true]);
        react(&databases, &writer, SessionEvent::Sleeping);
        assert!(!databases.any_unlocked());
        // Nothing released it while something was still unlocked: every
        // answer it got after the lock says nothing is unlocked.
        let after = answers(&told);
        assert!(!after.is_empty() && after.iter().all(|held| !held));
    }

    #[test]
    fn concurrent_changes_leave_the_inhibitor_with_the_last_state() {
        let (databases, told) = held();
        let databases = Arc::new(databases);
        let threads: Vec<_> = ["personal", "work"]
            .into_iter()
            .map(|name| {
                let databases = databases.clone();
                thread::spawn(move || {
                    for _ in 0..50 {
                        databases.install_for_test(name, Vec::new());
                        databases.lock(name).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            answers(&told).last().copied(),
            Some(databases.any_unlocked())
        );
    }
}
