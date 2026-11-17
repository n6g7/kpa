//! [`SshHost`], what the agent needs from the daemon that hosts it, and
//! [`SlotView`], one database's slot as the agent sees it.

use std::time::Instant;

use keepass::Database;

use super::SshSlot;
use crate::authn::Requester;
use crate::config::DatabaseConfig;
use crate::prompt::{CancelSource, CancelToken};
use crate::proto::{UnlockError, Unlocked};
use crate::session_watch::DisplaySession;

/// What the agent needs from the daemon that hosts it. The daemon
/// implements it as a thin adapter over its database slots; the agent's
/// logic stays in this module.
pub trait SshHost {
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

    /// The current time, for backoff deadlines.
    fn now(&self) -> Instant;

    /// Unlocks `db` as `kpa unlock` does: the same prompt, in the same
    /// queue, and the same key derivation and scan. The prompt says
    /// `message`. A user's own unlock that is already prompting for `db`
    /// makes this fail as [`UnlockError::InProgress`]. Not called inside
    /// `with_slot`: it blocks on the user.
    fn unlock(
        &self,
        db: &str,
        message: &str,
        requester: &Requester,
    ) -> Result<Unlocked, UnlockError>;
}

/// One database's slot as the agent sees it, while the host holds its
/// slots' lock.
pub struct SlotView<'a> {
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
        db: Option<&'a Database>,
        ssh: &'a mut SshSlot,
        last_activity: &'a mut Instant,
        lock_signal: &'a CancelSource,
        backoff: &'a mut Option<Instant>,
    ) -> SlotView<'a> {
        SlotView {
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

    /// Whether prompts are held back at `now`.
    pub(super) fn backing_off(&self, now: Instant) -> bool {
        self.backoff.is_some_and(|until| now < until)
    }

    /// Holds prompts back until `until`.
    pub(super) fn back_off(&mut self, until: Instant) {
        *self.backoff = Some(until);
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
