//! [`SshHost`], what the agent needs from the daemon that hosts it, and
//! [`SlotView`], one database's slot as the agent sees it.

use keepass::Database;

use super::SshSlot;
use crate::config::DatabaseConfig;
use crate::origin::PeerOrigin;

/// What the agent needs from the daemon that hosts it. The daemon
/// implements it as a thin adapter over its database slots; the agent's
/// logic stays in this module.
pub trait SshHost: PeerOrigin {
    /// Every configured database, in config order.
    fn databases(&self) -> &[DatabaseConfig];

    /// Runs `f` on `db`'s slot under the daemon's lock on its slots, or
    /// returns `None` if there is no such database. The freshness guard
    /// runs first, in the same hold (`docs/ssh-agent.md` § 6.9, G-8): a
    /// database whose file changed on disk is locked before `f` sees it.
    /// `f` must not block.
    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R>;
}

/// One database's slot as the agent sees it, while the host holds its
/// slots' lock.
pub struct SlotView<'a> {
    /// The open database, `None` while locked.
    pub(super) db: Option<&'a Database>,
    pub(super) ssh: &'a mut SshSlot,
}

impl<'a> SlotView<'a> {
    pub fn new(db: Option<&'a Database>, ssh: &'a mut SshSlot) -> SlotView<'a> {
        SlotView { db, ssh }
    }
}
