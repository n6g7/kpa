//! [`FakeHost`]: an in-memory [`SshHost`] for this module's tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keepass::Database;
use zeroize::Zeroizing;

use super::{SlotView, SshHost, SshSlot};
use crate::authn::Requester;
use crate::authz;
use crate::config::DatabaseConfig;
use crate::prompt::{CancelSource, Prompt, PromptOutcome, PromptQueue, Scripted};
use crate::proto::{Unlock, UnlockError, UnlockRequest};
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
    backoff: Option<Instant>,
}

impl FakeSlot {
    /// Locks the database, as the daemon's `Slot::lock` does: the backoff
    /// stays.
    fn lock(&mut self) {
        self.db = None;
        self.ssh = SshSlot::default();
        self.lock_signal = CancelSource::new();
    }
}

/// A step to run at the start of an unlock.
type Hook = Box<dyn FnOnce() + Send>;

/// Configured databases, each with its slot; at most the first one open.
/// Prompts may appear for [`requester`] unless [`FakeHost::without_prompts`]
/// says otherwise.
/// Its unlock raises a prompt that a test scripts, in the queue the
/// agent's confirm prompt shares, and its clock moves only when a test
/// says.
pub(super) struct FakeHost {
    databases: Vec<DatabaseConfig>,
    slots: Mutex<HashMap<String, FakeSlot>>,
    display_session: DisplaySession,
    /// What `unlocked` opened the first database as, for reopening it.
    opened: Option<Database>,
    /// The first database's file has changed: the next freshness guard
    /// locks it.
    stale: AtomicBool,
    clock: Mutex<Instant>,
    queue: Arc<PromptQueue>,
    prompt_to_unlock: Prompt<Zeroizing<String>>,
    unlocks: Scripted<Zeroizing<String>>,
    before_unlock: Mutex<Option<Hook>>,
    /// How many times `with_slot` has run.
    holds: AtomicUsize,
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
                    backoff: None,
                };
                (cfg.name.clone(), slot)
            })
            .collect();
        let queue = Arc::new(PromptQueue::new());
        let unlocks = Scripted::new();
        FakeHost {
            databases,
            slots: Mutex::new(slots),
            display_session: DisplaySession::Unlocked {
                id: SESSION.to_string(),
                active: true,
            },
            opened: None,
            stale: AtomicBool::new(false),
            clock: Mutex::new(Instant::now()),
            prompt_to_unlock: Prompt::new(
                Arc::clone(&queue),
                unlocks.clone(),
                Duration::from_secs(60),
            ),
            queue,
            unlocks,
            before_unlock: Mutex::new(None),
            holds: AtomicUsize::new(0),
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
    /// installed as an unlock would, which ends its backoff.
    pub(super) fn reopen(&self) {
        let cfg = &self.databases[0];
        let db = self.opened.clone().expect("opened by `unlocked`");
        let mut slots = self.slots.lock().expect("slots");
        let slot = slots.get_mut(&cfg.name).expect("configured");
        slot.ssh = SshSlot::scan(&db, cfg);
        slot.db = Some(db);
        slot.backoff = None;
    }

    /// The queue the host's unlock prompt waits in: the agent's approval
    /// prompt waits in it too.
    pub(super) fn queue(&self) -> Arc<PromptQueue> {
        Arc::clone(&self.queue)
    }

    /// The script the host's unlock prompt follows.
    pub(super) fn unlocks(&self) -> Scripted<Zeroizing<String>> {
        self.unlocks.clone()
    }

    /// Runs `f` at the start of the next unlock, before it looks at the
    /// database: a user's own unlock getting there first, say.
    pub(super) fn before_unlock(&self, f: impl FnOnce() + Send + 'static) {
        *self.before_unlock.lock().expect("hook") = Some(Box::new(f));
    }

    /// Moves the clock on.
    pub(super) fn advance(&self, by: Duration) {
        *self.clock.lock().expect("clock") += by;
    }

    /// How many holds on a slot have run so far.
    pub(super) fn holds(&self) -> usize {
        self.holds.load(Ordering::SeqCst)
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
        self.holds.fetch_add(1, Ordering::SeqCst);
        let mut slots = self.slots.lock().expect("slots");
        let slot = slots.get_mut(db)?;
        if db == self.databases[0].name && self.stale.swap(false, Ordering::SeqCst) {
            slot.lock();
        }
        Some(f(SlotView::new(
            *self.clock.lock().expect("clock"),
            slot.db.as_ref(),
            &mut slot.ssh,
            &mut slot.last_activity,
            &slot.lock_signal,
            &mut slot.backoff,
        )))
    }

    fn display_session(&self) -> DisplaySession {
        self.display_session.clone()
    }
}

/// As the daemon's unlock does, for the first database: its prompt
/// answers as the script says, and an answer opens the database.
impl Unlock for FakeHost {
    fn unlock(
        &self,
        request: &UnlockRequest,
        requester: &Requester,
        message: Option<&str>,
    ) -> Result<String, UnlockError> {
        let db = request.db.as_str();
        let message = message.expect("the agent says why it unlocks");
        let named = || db.to_string();
        let hook = self.before_unlock.lock().expect("hook").take();
        if let Some(hook) = hook {
            hook();
        }
        let token = {
            let slots = self.slots.lock().expect("slots");
            let slot = slots
                .get(db)
                .ok_or(UnlockError::UnknownDb { db: named() })?;
            if slot.db.is_some() {
                return Ok(named());
            }
            if !authz::may_prompt_on_screen(requester, &self.display_session) {
                return Err(UnlockError::NoDisplay);
            }
            slot.lock_signal.token()
        };
        match self.prompt_to_unlock.ask(message, &token) {
            Ok(PromptOutcome::Answer(_)) => {}
            Ok(PromptOutcome::Cancelled | PromptOutcome::TimedOut) => {
                return Err(UnlockError::PromptCancelled { db: named() });
            }
            Ok(PromptOutcome::Interrupted) => {
                return Err(UnlockError::LockedDuringUnlock { db: named() });
            }
            Err(err) => {
                return Err(UnlockError::PromptFailed {
                    db: named(),
                    detail: err.to_string(),
                });
            }
        }
        if token.is_cancelled() {
            return Err(UnlockError::LockedDuringUnlock { db: named() });
        }
        self.reopen();
        Ok(named())
    }
}
