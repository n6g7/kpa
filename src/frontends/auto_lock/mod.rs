//! The front end that locks without a request: when the screen locks, the
//! machine suspends, the watch on the display session is lost, or a
//! database sits idle (`docs/design.md` § Locking).
//!
//! This file is OS-neutral and names no D-Bus type. [`logind`] watches the OS
//! and sends what it sees as [`Event`]s; [`SleepHold`] sends the other one,
//! whether anything is unlocked; and [`AutoLock`], the one reader of that
//! channel, says what each event means for the databases and whether the
//! sleep inhibitor is held.
//!
//! The display session is this front end's to write ([`DisplayWriter`]) and
//! everyone else's to read ([`DisplayHandle`](crate::display_session::DisplayHandle)).
//! A locked display session is written before anything is locked, so no
//! observer or later reader sees a lock without it.

pub mod logind;

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use self::logind::{Bus, Inhibitor};
use crate::cancel::CancelToken;
use crate::clock::Moment;
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

/// What `auto_lock` reacts to, on one channel with one reader. The OS side
/// sends all but [`Event::Unlocked`], which [`SleepHold`] sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The display session is new, or its locked or active state changed.
    /// Read on subscribing, whenever the display session changes, and on
    /// each change of its locked state or whether it is in front.
    DisplayChanged(DisplaySession),
    /// The display session's lock request. A locker that only sends this
    /// never reports the unlock (ASM-7), so it doesn't change the display
    /// session's state.
    LockRequested,
    /// The machine is about to suspend.
    Sleeping,
    /// The machine has resumed.
    Resumed,
    /// A subscription that had been working has dropped: the display
    /// session's state is unknown until it is back.
    WatchLost,
    /// Whether anything is unlocked now.
    Unlocked(bool),
}

/// Starts the watcher and the inhibitor thread. Returns the observer that
/// reports what is unlocked, to register after the observers that hold
/// secrets, and the loop that reacts to everything.
pub fn start(source: Source, display: DisplayWriter) -> (SleepHold, AutoLock) {
    let (events, incoming) = mpsc::channel();
    let inhibitor = logind::start(source.0, events.clone());
    (
        SleepHold {
            events,
            order: Mutex::new(()),
        },
        AutoLock {
            incoming,
            display,
            inhibitor,
            sleep: SleepState::default(),
        },
    )
}

/// The loop that reacts to the events: the one reader of the channel.
pub struct AutoLock {
    incoming: Receiver<Event>,
    display: DisplayWriter,
    inhibitor: Inhibitor,
    sleep: SleepState,
}

impl AutoLock {
    /// Spawns the idle tick, then blocks reacting to events for as long as
    /// the watcher lives. Each event is reacted to first and the inhibitor
    /// decided second, so a suspend's release comes after everything is
    /// locked.
    pub fn run(mut self, databases: Arc<Databases>, idle_timeout: Duration) {
        let ticking = databases.clone();
        thread::spawn(move || watch_idle(&ticking, idle_timeout));
        for event in self.incoming {
            let hold = self.sleep.hold_after(&event);
            react(&databases, &self.display, event);
            self.inhibitor.hold(hold);
        }
    }
}

/// What the inhibitor decision knows.
#[derive(Debug, Default)]
pub struct SleepState {
    /// The last [`Event::Unlocked`].
    unlocked: bool,
    /// Between [`Event::Sleeping`] and [`Event::Resumed`].
    sleeping: bool,
}

impl SleepState {
    /// Takes `event` in and says whether the inhibitor is held now: exactly
    /// while something is unlocked, and never while the machine sleeps.
    /// Pure.
    pub fn hold_after(&mut self, event: &Event) -> bool {
        match event {
            Event::Unlocked(unlocked) => self.unlocked = *unlocked,
            Event::Sleeping => self.sleeping = true,
            Event::Resumed => self.sleeping = false,
            Event::DisplayChanged(_) | Event::LockRequested | Event::WatchLost => {}
        }
        self.unlocked && !self.sleeping
    }
}

/// Tells the loop whether anything is unlocked after every change, in the
/// order the changes happened.
pub struct SleepHold {
    events: Sender<Event>,
    /// Held while reading `any_unlocked` and sending it, so the loop hears
    /// the states in the order they were read whichever threads changed
    /// them.
    order: Mutex<()>,
}

impl SleepHold {
    fn sync(&self, databases: &Databases) {
        let _turn = self.order.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.events.send(Event::Unlocked(databases.any_unlocked()));
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
/// suspend everything is locked.
fn react(databases: &Databases, display: &DisplayWriter, event: Event) {
    match event {
        Event::DisplayChanged(session) => {
            let locked = session.is_locked();
            display.set(session);
            if locked {
                databases.lock_all();
                log::info(format_args!("locked all databases (screen lock)"));
            }
        }
        Event::LockRequested => {
            databases.lock_all();
            log::info(format_args!("locked all databases (screen lock)"));
        }
        Event::Sleeping => {
            databases.lock_all();
            log::info(format_args!("locked all databases (suspending)"));
        }
        Event::Resumed | Event::Unlocked(_) => {}
        Event::WatchLost => {
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
        databases.expire_idle(Moment::now());
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Instant;

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

    fn reacting(event: Event) -> (Databases, DisplayHandle) {
        let databases = databases(HOUR);
        unlocked(&databases);
        let (writer, display) = channel();
        react(&databases, &writer, event);
        (databases, display)
    }

    #[test]
    fn a_lock_request_a_locked_screen_a_suspend_and_a_lost_watch_each_lock_everything() {
        for event in [
            Event::LockRequested,
            Event::DisplayChanged(session(true)),
            Event::Sleeping,
            Event::WatchLost,
        ] {
            let (databases, _) = reacting(event.clone());
            assert!(!databases.any_unlocked(), "{event:?} should lock");
        }
    }

    #[test]
    fn a_display_session_that_is_not_locked_is_recorded_and_locks_nothing() {
        let (databases, display) = reacting(Event::DisplayChanged(session(false)));
        assert!(databases.any_unlocked());
        assert_eq!(display.get(), session(false));
    }

    #[test]
    fn a_lock_request_does_not_mark_the_display_session() {
        let databases = databases(HOUR);
        unlocked(&databases);
        let (writer, display) = channel();
        writer.set(session(false));
        react(&databases, &writer, Event::LockRequested);
        assert_eq!(display.get(), session(false));
    }

    #[test]
    fn a_lost_watch_forgets_the_display_session() {
        let databases = databases(HOUR);
        let (writer, display) = channel();
        writer.set(session(false));
        react(&databases, &writer, Event::WatchLost);
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
        react(&databases, &writer, Event::DisplayChanged(session(true)));
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
    fn held() -> (Databases, Receiver<Event>) {
        let (events, told) = std::sync::mpsc::channel();
        let mut databases = databases(HOUR);
        databases.observe(Arc::new(SleepHold {
            events,
            order: Mutex::new(()),
        }));
        (databases, told)
    }

    /// The answers to "is anything unlocked" the inhibitor has been sent
    /// since the last call, in order.
    fn answers(told: &Receiver<Event>) -> Vec<bool> {
        told.try_iter()
            .map(|signal| match signal {
                Event::Unlocked(unlocked) => unlocked,
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

    /// What `hold_after` says after each event, from a fresh state.
    fn holds(events: &[Event]) -> Vec<bool> {
        let mut sleep = SleepState::default();
        events.iter().map(|event| sleep.hold_after(event)).collect()
    }

    #[test]
    fn the_inhibitor_is_held_exactly_while_something_is_unlocked() {
        use Event::Unlocked;
        assert_eq!(
            holds(&[Unlocked(true), Unlocked(true), Unlocked(false)]),
            [true, true, false]
        );
    }

    #[test]
    fn nothing_is_held_while_the_machine_sleeps() {
        use Event::*;
        assert_eq!(
            holds(&[Unlocked(true), Sleeping, Unlocked(true), Unlocked(false)]),
            [true, false, false, false]
        );
    }

    #[test]
    fn a_suspend_releases_the_inhibitor_on_its_own_event() {
        use Event::*;
        // The loop reacts to `Sleeping` (locking everything) before it acts
        // on this answer, so the release comes after the lock.
        assert_eq!(holds(&[Unlocked(true), Sleeping]), [true, false]);
    }

    #[test]
    fn resuming_holds_again_only_if_something_is_unlocked() {
        use Event::*;
        assert_eq!(
            holds(&[Unlocked(true), Sleeping, Resumed]),
            [true, false, true]
        );
        assert_eq!(
            holds(&[Unlocked(true), Sleeping, Unlocked(false), Resumed]),
            [true, false, false, false]
        );
        assert_eq!(
            holds(&[Sleeping, Unlocked(true), Resumed]),
            [false, false, true]
        );
    }

    #[test]
    fn other_events_leave_the_decision_as_it_was() {
        use Event::*;
        assert_eq!(
            holds(&[
                Unlocked(true),
                LockRequested,
                WatchLost,
                DisplayChanged(session(true))
            ]),
            [true; 4]
        );
    }

    #[test]
    fn on_suspend_the_inhibitor_is_released_only_after_everything_is_locked() {
        let (databases, told) = held();
        unlocked(&databases);
        let (writer, _) = channel();
        assert_eq!(answers(&told), [true, true]);
        react(&databases, &writer, Event::Sleeping);
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
