//! The databases: which are unlocked, and what locks them. The one stateful
//! part of kpa; front ends call it, and it knows nothing of sockets, prompts,
//! the clipboard or the display session.
//!
//! - An unlocked database is read through an [`Open`] guard, which holds the
//!   core's lock and runs the freshness guard first.
//! - Unlocking is [`Databases::begin_unlock`], whatever the front end does to
//!   get a password, then [`Unlocking::finish`].
//! - Every lock replaces the database's cancel source, which cancels the
//!   [`CancelToken`] of the unlock it ends. An unlock installs only if its
//!   token is still live, so a lock beats an unlock.
//! - What must die with a lock lives in the front ends, which register an
//!   [`Observer`] and are told after the core's lock is released.

mod observer;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
mod unlock;
mod vault;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cancel::{CancelSource, CancelToken};
use crate::config::DatabaseConfig;
use crate::log;
use vault::Fingerprint;

pub use observer::Observer;
pub use unlock::{Begin, BeginError, UnlockFailure, Unlocking};
pub use vault::AttachmentView as Attachment;

/// The names of the fields every entry has, as `Entry::field` takes them.
pub mod fields {
    pub use keepass::db::fields::{NOTES, PASSWORD, URL, USERNAME};
}
pub use vault::{EntrySummary, VaultError};

/// Every configured database and the lifecycle around it. `Send + Sync`,
/// built once, shared as an `Arc`.
pub struct Databases {
    configs: Vec<DatabaseConfig>,
    idle_timeout: Duration,
    /// One slot per config, in config order.
    slots: Mutex<Vec<Slot>>,
    observers: Vec<Arc<dyn Observer>>,
    /// Keeps the placeholder files of [`Databases::for_test`] alive.
    #[cfg(test)]
    scratch: Option<tempfile::TempDir>,
    /// What the next unlock of a database reads instead of its file
    /// ([`Databases::stage_for_test`]).
    #[cfg(test)]
    staged: Mutex<std::collections::HashMap<String, keepass::Database>>,
}

struct Slot {
    loaded: Option<Loaded>,
    /// Replaced by every lock that covers this database, which cancels every
    /// token taken from the one before, so a prompt waiting on one ends. A
    /// token of the current source is the token of the unlock the database
    /// is in, or the one that is starting.
    source: CancelSource,
    /// An unlock holds the claim: it is prompting or deriving the key.
    unlocking: bool,
}

/// What an unlocked database holds.
struct Loaded {
    db: keepass::Database,
    /// The file's fingerprint when `db` was read.
    stamp: Fingerprint,
    /// Where this database's idle timer runs from.
    last_activity: Instant,
}

impl Slot {
    /// Drops the database and replaces the source, even for a database that
    /// is already locked. Returns the token of the unlock this ended, which
    /// is cancelled by the time this returns.
    fn lock(&mut self) -> CancelToken {
        self.loaded = None;
        let ended = self.source.token();
        // Assigning drops the old source, which cancels `ended`.
        self.source = CancelSource::new();
        ended
    }

    /// Installs `db` unless a lock has ended the unlock `token` belongs to.
    fn install(&mut self, token: &CancelToken, db: keepass::Database, stamp: Fingerprint) -> bool {
        if token.is_cancelled() {
            return false;
        }
        self.loaded = Some(Loaded {
            db,
            stamp,
            last_activity: Instant::now(),
        });
        true
    }

    /// The freshness guard: locks the database if its file is no longer the
    /// one it was read from. Returns the token the lock ended.
    fn lock_if_stale(&mut self, config: &DatabaseConfig) -> Option<CancelToken> {
        let stale = self
            .loaded
            .as_ref()
            .is_some_and(|loaded| !vault::is_unchanged(&config.path, &loaded.stamp));
        stale.then(|| self.lock())
    }
}

/// A database a lock covered, and the token of the unlock the lock ended.
struct Covered {
    name: String,
    token: CancelToken,
}

impl Databases {
    /// One slot per config, all locked. Only the name, path and keyfile of a
    /// config are used.
    pub fn new(configs: Vec<DatabaseConfig>, idle_timeout: Duration) -> Databases {
        let slots = configs
            .iter()
            .map(|_| Slot {
                loaded: None,
                source: CancelSource::new(),
                unlocking: false,
            })
            .collect();
        Databases {
            configs,
            idle_timeout,
            slots: Mutex::new(slots),
            observers: Vec::new(),
            #[cfg(test)]
            scratch: None,
            #[cfg(test)]
            staged: Mutex::default(),
        }
    }

    /// Before the core is shared. Observers are told in registration order.
    pub fn observe(&mut self, observer: Arc<dyn Observer>) {
        self.observers.push(observer);
    }

    /// Every configured database, in config order.
    pub fn configs(&self) -> &[DatabaseConfig] {
        &self.configs
    }

    /// Holds the core's lock while the guard lives. The freshness guard runs
    /// first: a changed file locks the database and says `Stale`.
    pub fn open(&self, name: &str) -> Result<Open<'_>, OpenError> {
        let index = self.index(name).ok_or(OpenError::UnknownDb)?;
        let mut slots = self.slots();
        if let Some(token) = slots[index].lock_if_stale(&self.configs[index]) {
            drop(slots);
            self.tell_locked(&[self.covered(index, token)]);
            return Err(OpenError::Stale);
        }
        if slots[index].loaded.is_none() {
            return Err(OpenError::Locked);
        }
        Ok(Open {
            databases: self,
            slots,
            index,
        })
    }

    /// Name and entry count (None = locked) per database, in config order.
    /// Runs no freshness guard.
    pub fn snapshot(&self) -> Vec<Snapshot> {
        let slots = self.slots();
        self.configs
            .iter()
            .zip(slots.iter())
            .map(|(config, slot)| Snapshot {
                name: config.name.clone(),
                entries: slot
                    .loaded
                    .as_ref()
                    .map(|loaded| vault::entry_count(&loaded.db)),
            })
            .collect()
    }

    pub fn any_unlocked(&self) -> bool {
        self.slots().iter().any(|slot| slot.loaded.is_some())
    }

    /// Locks one database, a locked one included (that ends a prompt waiting
    /// on it), then tells observers.
    pub fn lock(&self, name: &str) -> Result<(), UnknownDb> {
        let index = self.index(name).ok_or(UnknownDb)?;
        let token = self.slots()[index].lock();
        self.tell_locked(&[self.covered(index, token)]);
        Ok(())
    }

    /// Locks every database in one hold; observers are told of each, in
    /// config order, before the call returns.
    pub fn lock_all(&self) {
        let covered: Vec<Covered> = {
            let mut slots = self.slots();
            slots
                .iter_mut()
                .enumerate()
                .map(|(index, slot)| self.covered(index, slot.lock()))
                .collect()
        };
        self.tell_locked(&covered);
    }

    /// Locks each unlocked database idle for `idle_timeout` as of `now`.
    pub fn expire_idle(&self, now: Instant) {
        let covered: Vec<Covered> = {
            let mut slots = self.slots();
            let mut covered = Vec::new();
            for (index, slot) in slots.iter_mut().enumerate() {
                let idle = slot.loaded.as_ref().is_some_and(|loaded| {
                    now.saturating_duration_since(loaded.last_activity) >= self.idle_timeout
                });
                if idle {
                    covered.push(self.covered(index, slot.lock()));
                }
            }
            covered
        };
        for locked in &covered {
            log::info(format_args!(
                "locked {:?} after idle timeout ({:?})",
                locked.name, self.idle_timeout
            ));
        }
        self.tell_locked(&covered);
    }

    /// The freshness guard for the named databases.
    pub fn drop_stale<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        let covered: Vec<Covered> = {
            let mut slots = self.slots();
            names
                .into_iter()
                .filter_map(|name| {
                    let index = self.index(name)?;
                    let token = slots[index].lock_if_stale(&self.configs[index])?;
                    Some(self.covered(index, token))
                })
                .collect()
        };
        self.tell_locked(&covered);
    }

    /// A poisoned mutex is recovered: a panic on one thread must not make
    /// every later call panic too.
    fn slots(&self) -> MutexGuard<'_, Vec<Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.configs.iter().position(|config| config.name == name)
    }

    fn covered(&self, index: usize, token: CancelToken) -> Covered {
        Covered {
            name: self.configs[index].name.clone(),
            token,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    UnknownDb,
    Locked,
    /// The file changed since it was read; the database is locked now.
    Stale,
}

/// The name is not a configured database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownDb;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub name: String,
    /// The entry count, or `None` if the database is locked.
    pub entries: Option<usize>,
}

impl Snapshot {
    pub fn is_locked(&self) -> bool {
        self.entries.is_none()
    }
}

/// An unlocked database, read while the guard holds the core's lock: don't
/// call the core while it lives.
pub struct Open<'a> {
    databases: &'a Databases,
    slots: MutexGuard<'a, Vec<Slot>>,
    index: usize,
}

impl Open<'_> {
    fn slot(&self) -> &Slot {
        &self.slots[self.index]
    }

    fn loaded(&self) -> &Loaded {
        self.slot()
            .loaded
            .as_ref()
            .expect("`open` checks the database is unlocked, and the guard keeps the core's lock")
    }

    /// The configured name of this database.
    pub fn name(&self) -> &str {
        &self.databases.configs[self.index].name
    }

    /// The token of the unlock this database is in: the lock that ends the
    /// unlock cancels it, for good.
    pub fn unlock_token(&self) -> CancelToken {
        self.slot().source.token()
    }

    /// Counts as activity: resets the idle timer.
    pub fn touch(&mut self) {
        let index = self.index;
        if let Some(loaded) = self.slots[index].loaded.as_mut() {
            loaded.last_activity = Instant::now();
        }
    }

    /// Every entry, index only: a protected title, username or URL is
    /// omitted rather than revealed.
    pub fn entries(&self) -> Vec<EntrySummary> {
        vault::list_entries(&self.loaded().db)
    }

    pub fn entry_count(&self) -> usize {
        vault::entry_count(&self.loaded().db)
    }

    /// None: no such entry.
    pub fn entry(&self, uuid: Uuid) -> Option<Entry<'_>> {
        let db = &self.loaded().db;
        vault::entry_exists(db, uuid).then_some(Entry { db, uuid })
    }

    /// Every attachment of every current entry (the SSH key scan).
    pub fn for_each_attachment(&self, visit: impl FnMut(Attachment<'_>)) {
        vault::for_each_attachment(&self.loaded().db, visit);
    }
}

/// One entry of an open database.
pub struct Entry<'a> {
    db: &'a keepass::Database,
    uuid: Uuid,
}

impl Entry<'_> {
    /// None: absent, empty or protected (a log line must not reveal what the
    /// user marked protected).
    pub fn title(&self) -> Option<String> {
        vault::entry_title(self.db, self.uuid)
    }

    /// One field's value, protected or not. None: absent or empty.
    pub fn field(&self, key: &str) -> Option<Zeroizing<String>> {
        vault::entry_field(self.db, self.uuid, key).flatten()
    }

    /// The current code of the entry's `otp` field. None: no such field, or
    /// it doesn't parse.
    pub fn totp(&self) -> Option<Zeroizing<String>> {
        vault::entry_totp(self.db, self.uuid).flatten()
    }

    /// The entry's attachments; none for an entry in the recycle bin.
    pub fn for_each_attachment(&self, visit: impl FnMut(Attachment<'_>)) {
        vault::for_each_entry_attachment(self.db, self.uuid, visit);
    }
}
