//! Unlocking: the claim on a database's one unlock, and finishing it.

use zeroize::Zeroizing;

use super::{Databases, vault};
use crate::cancel::CancelToken;
use crate::log;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginError {
    UnknownDb,
    /// Another unlock holds the claim.
    InProgress,
}

pub enum Begin<'a> {
    AlreadyUnlocked,
    Started(Unlocking<'a>),
}

#[derive(Debug)]
pub enum UnlockFailure {
    Vault(vault::VaultError),
    /// A lock came in while the file was being read; nothing was installed.
    LockedMeanwhile,
}

/// The claim on a database's one unlock. Dropping it clears the claim, so
/// every way out of an unlock, a panic included, ends it.
pub struct Unlocking<'a> {
    databases: &'a Databases,
    index: usize,
    token: CancelToken,
    /// The claim is already cleared.
    released: bool,
}

impl Databases {
    /// Freshness guard, then claims the database's one unlock and takes its
    /// token.
    pub fn begin_unlock(&self, name: &str) -> Result<Begin<'_>, BeginError> {
        let index = self.index(name).ok_or(BeginError::UnknownDb)?;
        let (mut slots, stale) = self.checked_slots(index);
        let slot = &mut slots[index];
        let begin = if slot.loaded.is_some() {
            Ok(Begin::AlreadyUnlocked)
        } else if slot.unlocking {
            Err(BeginError::InProgress)
        } else {
            slot.unlocking = true;
            Ok(Begin::Started(Unlocking {
                databases: self,
                index,
                token: slot.source.token(),
                released: false,
            }))
        };
        drop(slots);
        if let Some(ended) = stale {
            self.tell_locked(&[self.logged(index, ended)]);
        }
        begin
    }

    /// Logs and tells observers of an unlock that was installed.
    pub(super) fn installed(&self, index: usize, token: &CancelToken) {
        let name = &self.configs[index].name;
        log::info(format_args!("unlocked {name:?}"));
        self.tell_unlocked(name, token);
    }
}

impl Unlocking<'_> {
    /// Cancelled by the lock that ends this unlock, so a prompt waiting on it
    /// ends.
    pub fn unlock_token(&self) -> &CancelToken {
        &self.token
    }

    /// Reads the file with `password` and the configured keyfile, outside the
    /// core's lock, then installs it unless a lock came in meanwhile. The
    /// password is borrowed for the read; the core keeps no copy.
    pub fn finish(self, password: Option<&Zeroizing<String>>) -> Result<(), UnlockFailure> {
        let config = &self.databases.configs[self.index];
        let (db, stamp) = vault::open(&config.path, password, config.keyfile.as_deref())
            .map_err(UnlockFailure::Vault)?;
        self.install(db, stamp)
    }

    /// Clears the claim and installs in one hold of the core's lock, then
    /// tells observers.
    pub(super) fn install(
        mut self,
        db: keepass::Database,
        stamp: vault::Fingerprint,
    ) -> Result<(), UnlockFailure> {
        let installed = {
            let mut slots = self.databases.slots();
            let slot = &mut slots[self.index];
            slot.unlocking = false;
            self.released = true;
            slot.install(&self.token, db, stamp)
        };
        if !installed {
            return Err(UnlockFailure::LockedMeanwhile);
        }
        self.databases.installed(self.index, &self.token);
        Ok(())
    }
}

impl Drop for Unlocking<'_> {
    fn drop(&mut self) {
        if !self.released {
            self.databases.slots()[self.index].unlocking = false;
        }
    }
}
