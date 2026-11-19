//! [`SshHost`], what the agent needs from the daemon that hosts it, and
//! [`SlotView`], one database's slot as the agent sees it.

use std::time::{Duration, Instant};

use keepass::Database;

use super::SshSlot;
use crate::config::DatabaseConfig;
use crate::frontends::control::proto::Unlock;
use crate::prompt::{CancelSource, CancelToken};
use crate::session_watch::DisplaySession;

/// What the agent needs from the daemon that hosts it. The daemon
/// implements it as a thin adapter over its database slots; the agent's
/// logic stays in this module. A host also serves `unlock` (`Unlock`), which
/// the agent calls as `kpa unlock` does: the same prompt, in the same queue,
/// and the same key derivation and scan. It is not called inside
/// `with_slot`: it blocks on the user.
pub trait SshHost: Unlock {
    /// Every configured database, in config order.
    fn databases(&self) -> &[DatabaseConfig];

    /// Runs `f` on `db`'s slot under the daemon's lock on its slots, or
    /// returns `None` if there is no such database. The freshness guard
    /// runs first, in the same hold (`docs/ssh-agent.md` § 6.9, G-8): a
    /// database whose file changed on disk is locked before `f` sees it.
    /// `f` must not block.
    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R>;

    /// The display session as it is now. The agent decides against it
    /// (`authz`) whether a prompt may appear on screen for a requester
    /// (`docs/ssh-agent.md` § 6.8), inside `with_slot`, so the answer holds
    /// for the hold it is asked in.
    fn display_session(&self) -> DisplaySession;
}

/// One database's slot as the agent sees it, while the host holds its
/// slots' lock.
pub struct SlotView<'a> {
    /// The time of this hold, which backoff deadlines are measured from.
    now: Instant,
    /// The open database, `None` while locked.
    pub(super) db: Option<&'a Database>,
    pub(super) ssh: &'a mut SshSlot,
    /// The database's idle timer (`docs/ssh-agent.md` § 6.9).
    last_activity: &'a mut Instant,
    /// What the database's next lock cancels.
    lock_signal: &'a CancelSource,
    /// Until when no prompt is raised for this database's signatures
    /// (`docs/ssh-agent.md` § 6.6). A lock doesn't clear it; the host
    /// clears it when it installs an unlocked database.
    backoff: &'a mut Option<Instant>,
}

impl<'a> SlotView<'a> {
    pub fn new(
        now: Instant,
        db: Option<&'a Database>,
        ssh: &'a mut SshSlot,
        last_activity: &'a mut Instant,
        lock_signal: &'a CancelSource,
        backoff: &'a mut Option<Instant>,
    ) -> SlotView<'a> {
        SlotView {
            now,
            db,
            ssh,
            last_activity,
            lock_signal,
            backoff,
        }
    }

    /// Whether the database is unlocked.
    pub(super) fn is_open(&self) -> bool {
        self.db.is_some()
    }

    /// The time of this hold.
    pub(super) fn now(&self) -> Instant {
        self.now
    }

    /// Whether prompts are held back.
    pub(super) fn backing_off(&self) -> bool {
        self.backoff.is_some_and(|until| self.now < until)
    }

    /// Holds prompts back for `duration` from now.
    pub(super) fn back_off(&mut self, duration: Duration) {
        if let Some(until) = self.now.checked_add(duration) {
            *self.backoff = Some(until);
        }
    }

    /// Resets the database's idle timer to now.
    pub(super) fn touch(&mut self) {
        *self.last_activity = Instant::now();
    }

    /// A token the database's next lock cancels: what a confirm prompt
    /// raised now ends on, and how a later hold tells that no lock came in
    /// since this one.
    pub(super) fn cancel_token(&self) -> CancelToken {
        self.lock_signal.token()
    }
}
