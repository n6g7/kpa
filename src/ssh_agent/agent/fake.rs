//! [`FakeHost`]: an in-memory [`SshHost`] for this module's tests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use keepass::Database;

use super::{SlotView, SshHost, SshSlot};
use crate::authn::Requester;
use crate::config::DatabaseConfig;
use crate::prompt::CancelSource;
use crate::session_watch::DisplaySession;

/// The display session the fake host starts with.
const SESSION: &str = "3";

/// A requester on the desktop of the display session the fake host starts
/// with, so prompts may appear for it.
pub(super) fn requester() -> Requester {
    Requester {
        uid: 0,
        cgroup: Some(format!(
            "0::/user.slice/user-0.slice/session-{SESSION}.scope\n"
        )),
        command: None,
    }
}

/// One database's slot, as the daemon keeps it.
struct FakeSlot {
    db: Option<Database>,
    ssh: SshSlot,
    last_activity: Instant,
    lock_signal: CancelSource,
}

impl FakeSlot {
    /// Locks the database, as the daemon's `Slot::lock` does.
    fn lock(&mut self) {
        self.db = None;
        self.ssh = SshSlot::default();
        self.lock_signal = CancelSource::new();
    }
}

/// Configured databases, each with its slot; at most the first one open.
/// Prompts may appear for [`requester`] unless [`FakeHost::without_prompts`]
/// says otherwise.
pub(super) struct FakeHost {
    databases: Vec<DatabaseConfig>,
    slots: Mutex<HashMap<String, FakeSlot>>,
    display_session: DisplaySession,
    /// What `unlocked` opened the first database as, for reopening it.
    opened: Option<Database>,
    /// The first database's file has changed: the next freshness guard
    /// locks it.
    stale: AtomicBool,
}

impl FakeHost {
    /// Every database in `databases`, locked.
    pub(super) fn locked(databases: Vec<DatabaseConfig>) -> FakeHost {
        let slots = databases
            .iter()
            .map(|cfg| {
                let slot = FakeSlot {
                    db: None,
                    ssh: SshSlot::default(),
                    last_activity: Instant::now(),
                    lock_signal: CancelSource::new(),
                };
                (cfg.name.clone(), slot)
            })
            .collect();
        FakeHost {
            databases,
            slots: Mutex::new(slots),
            display_session: DisplaySession::Unlocked {
                id: SESSION.to_string(),
                active: true,
            },
            opened: None,
            stale: AtomicBool::new(false),
        }
    }

    /// Like `locked`, but the first database is open as `db`, scanned as
    /// an unlock would.
    pub(super) fn unlocked(databases: Vec<DatabaseConfig>, db: Database) -> FakeHost {
        let mut host = FakeHost::locked(databases);
        host.opened = Some(db);
        host.reopen();
        host
    }

    /// Opens the first database again as `unlocked` opened it, scanned and
    /// installed as an unlock would.
    pub(super) fn reopen(&self) {
        let cfg = &self.databases[0];
        let db = self.opened.clone().expect("opened by `unlocked`");
        let mut slots = self.slots.lock().expect("slots");
        let slot = slots.get_mut(&cfg.name).expect("configured");
        slot.ssh = SshSlot::scan(&db, cfg);
        slot.db = Some(db);
    }

    /// The first database's file changes on disk.
    pub(super) fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    /// No prompt may appear: there is no display session.
    pub(super) fn without_prompts(mut self) -> FakeHost {
        self.display_session = DisplaySession::None;
        self
    }

    /// Locks `db`, as the daemon does.
    pub(super) fn lock(&self, db: &str) {
        self.slots
            .lock()
            .expect("slots")
            .get_mut(db)
            .expect("configured")
            .lock();
    }

    /// Looks at `db`'s agent state, open or not.
    pub(super) fn peek<R>(&self, db: &str, f: impl FnOnce(bool, &SshSlot) -> R) -> R {
        let slots = self.slots.lock().expect("slots");
        let slot = &slots[db];
        f(slot.db.is_some(), &slot.ssh)
    }

    /// When `db`'s idle timer last reset.
    pub(super) fn last_activity(&self, db: &str) -> Instant {
        self.slots.lock().expect("slots")[db].last_activity
    }
}

impl SshHost for FakeHost {
    fn databases(&self) -> &[DatabaseConfig] {
        &self.databases
    }

    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R> {
        let mut slots = self.slots.lock().expect("slots");
        let slot = slots.get_mut(db)?;
        if db == self.databases[0].name && self.stale.swap(false, Ordering::SeqCst) {
            slot.lock();
        }
        Some(f(SlotView::new(
            slot.db.as_ref(),
            &mut slot.ssh,
            &mut slot.last_activity,
            &slot.lock_signal,
        )))
    }

    fn display_session(&self) -> DisplaySession {
        self.display_session.clone()
    }
}
