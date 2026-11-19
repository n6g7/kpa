//! What the front ends register to hear of unlocks and locks, and the order
//! they hear them in.

use super::{Covered, Databases};
use crate::cancel::CancelToken;

/// Told of every unlock and lock, after the core's lock is released, in the
/// thread that caused the change, before the call that caused it returns. An
/// observer may call back into the core, and may block. It doesn't panic: a
/// panic skips the observers after it.
///
/// Each observer tags what it holds with the token of the unlock it belongs
/// to and compares on every use, so a late notification for an old unlock
/// can't touch the state of a new one.
pub trait Observer: Send + Sync {
    /// `db` was unlocked; `unlock` is the unlock's token.
    fn unlocked(&self, _databases: &Databases, _db: &str, _unlock: &CancelToken) {}

    /// A lock covered `db`, unlocked or not; `unlock` is the token of the
    /// unlock it ended, which is cancelled.
    fn locked(&self, _databases: &Databases, _db: &str, _unlock: &CancelToken) {}
}

impl Databases {
    /// In registration order, each observer is told of every database
    /// before the next is told anything.
    pub(super) fn tell_locked(&self, covered: &[Covered]) {
        for observer in &self.observers {
            for lock in covered {
                observer.locked(self, &lock.name, &lock.token);
            }
        }
    }

    pub(super) fn tell_unlocked(&self, name: &str, token: &CancelToken) {
        for observer in &self.observers {
            observer.unlocked(self, name, token);
        }
    }
}
