//! [`SshHost`], what the agent needs from the daemon that hosts it, and
//! [`SlotView`], one database's slot as the agent sees it.

use std::time::Instant;

use keepass::Database;

use super::SshSlot;
use crate::authn::Requester;
use crate::config::DatabaseConfig;
use crate::prompt::{CancelSource, CancelToken};

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

    /// Whether a prompt may appear on screen for a connection from
    /// `requester` (`docs/ssh-agent.md` § 6.8). Asked inside `with_slot`, so
    /// the answer holds for the hold it is asked in.
    fn may_prompt_on_screen(&self, requester: &Requester) -> bool;
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
}

impl<'a> SlotView<'a> {
    pub fn new(
        db: Option<&'a Database>,
        ssh: &'a mut SshSlot,
        last_activity: &'a mut Instant,
        lock_signal: &'a CancelSource,
    ) -> SlotView<'a> {
        SlotView {
            db,
            ssh,
            last_activity,
            lock_signal,
        }
    }

    /// Resets the database's idle timer to now.
    pub(super) fn touch(&mut self) {
        *self.last_activity = Instant::now();
    }

    /// A token the database's next lock cancels: what an approval prompt
    /// raised now ends on, and how a later hold tells that no lock came in
    /// since this one.
    pub(super) fn cancel_token(&self) -> CancelToken {
        self.lock_signal.token()
    }
}
