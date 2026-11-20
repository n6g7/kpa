//! [`SshState`]: what the agent keeps per database, as an observer of the
//! core. A scan finds a database's keys when it unlocks, the private keys
//! are read at their first signature, and a lock drops all of it. The prompt
//! backoff sits beside them and outlives a lock: an unlock ends it.
//!
//! Lock order: the core's, then this state's own (`hold`), then the
//! approvals'. `unlocked` takes the core's guard before its own lock, and
//! `locked` takes only its own.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ssh_key::{Fingerprint, PrivateKey};

use crate::cancel::CancelToken;
use crate::config::DatabaseConfig;
use crate::databases::{Databases, Observer};
use crate::log;
use crate::ssh::keys::{self, ServedKey, SkipReason};

/// What the agent keeps for each database: the scan of the unlock the
/// database is in, and the backoff.
pub struct SshState {
    /// Where the public-key cache lives, `None` without a cache directory.
    cache_dir: Option<PathBuf>,
    /// How long a cancelled or timed-out prompt holds the database's
    /// prompts back (`docs/ssh-agent.md` § 6.6).
    backoff: Duration,
    inner: Mutex<Inner>,
    /// How many holds have been taken: what a test waits on to know its
    /// signers have looked.
    #[cfg(test)]
    pub(super) holds: std::sync::atomic::AtomicUsize,
}

#[derive(Default)]
pub(super) struct Inner {
    /// Per database, for the unlock it was scanned in. A lock drops it.
    pub(super) scanned: HashMap<String, Scanned>,
    /// Until when no prompt is raised for a database's signatures. A lock
    /// leaves it; an unlock ends it.
    pub(super) backoff: HashMap<String, Instant>,
}

/// The keys of one database's unlock.
pub(super) struct Scanned {
    /// The unlock this was scanned in.
    pub(super) unlock: CancelToken,
    /// The keys this unlock's scan found, as the config serves them.
    pub(super) served: Vec<ServedKey>,
    /// Private keys read at their first signature (`docs/ssh-agent.md`
    /// § 6.4), kept until lock. `ssh-key`'s private key types zeroize their
    /// secret material when they drop (Ed25519, ECDSA and RSA alike), and an
    /// RSA signature's per-signature `rsa::PrivateKey`, built from the key
    /// for that one signature, zeroizes on drop too.
    pub(super) private_keys: HashMap<Fingerprint, PrivateKey>,
}

impl SshState {
    pub fn new(cache_dir: Option<PathBuf>, backoff: Duration) -> SshState {
        SshState {
            cache_dir,
            backoff,
            inner: Mutex::new(Inner::default()),
            #[cfg(test)]
            holds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(super) fn backoff(&self) -> Duration {
        self.backoff
    }

    /// A poisoned mutex is recovered: a panic on one thread must not make
    /// every later call panic too.
    pub(super) fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The keys `cfg`'s database served when it was last unlocked, from the
    /// public-key cache.
    pub(super) fn cached(&self, cfg: &DatabaseConfig) -> Vec<ServedKey> {
        match &self.cache_dir {
            Some(dir) => keys::resolve_cached(cfg, keys::read_cache(dir, &cfg.name)),
            None => Vec::new(),
        }
    }

    /// Writes the public-key cache a scan calls for (`docs/ssh-agent.md`
    /// § 6.4, "after each scan"). Without a cache directory there is nowhere
    /// to write it; a failure is logged, since the database is served all
    /// the same.
    fn write_cache(&self, database: &str, served: &[ServedKey]) {
        let Some(dir) = &self.cache_dir else {
            return;
        };
        let public_keys: Vec<_> = served.iter().map(|key| key.public_key.clone()).collect();
        if let Err(err) = keys::write_cache(dir, database, &public_keys) {
            log::warn(format_args!(
                "ssh key cache: failed to write {database:?}: {err}"
            ));
        }
    }
}

impl Observer for SshState {
    /// Scans `db` for SSH keys under the core's guard, unless it is no
    /// longer the unlock `unlock` names, then writes the cache once the
    /// guard is released.
    fn unlocked(&self, databases: &Databases, db: &str, unlock: &CancelToken) {
        // Whoever unlocked is here, so prompts are no longer held back. The
        // state's lock is released before the core's is taken: `open` can
        // lock a changed file, which tells this observer.
        self.inner().backoff.remove(db);
        let Some(config) = databases
            .configs()
            .iter()
            .find(|config| config.name == db && config.serve_ssh_keys)
        else {
            return;
        };
        // A lock since, or a newer unlock, makes this notification late.
        let Ok(open) = databases.open(db) else {
            return;
        };
        if open.unlock_token() != *unlock {
            return;
        }
        let scan = keys::scan(&open);
        for skipped in &scan.skipped {
            let log = match skipped.reason {
                // The user's key isn't served, and they can fix that.
                SkipReason::ShortEcdsaScalar => log::warn,
                _ => log::debug,
            };
            log(format_args!(
                "ssh key scan: skipped an attachment on entry {} in {db:?}: {}",
                skipped.entry_uuid, skipped.reason
            ));
        }
        let served = keys::resolve(config, &scan.found);
        self.inner().scanned.insert(
            db.to_string(),
            Scanned {
                unlock: unlock.clone(),
                served: served.clone(),
                private_keys: HashMap::new(),
            },
        );
        drop(open);
        self.write_cache(db, &served);
    }

    /// Drops what `db`'s scan of the unlock `unlock` held, which zeroizes the
    /// private keys, and nothing else: a late notification for an old
    /// unlock leaves a new unlock's. The backoff stays.
    fn locked(&self, _: &Databases, db: &str, unlock: &CancelToken) {
        let mut inner = self.inner();
        if inner
            .scanned
            .get(db)
            .is_some_and(|scanned| scanned.unlock == *unlock)
        {
            inner.scanned.remove(db);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::databases::testing::TestEntry;
    use crate::ssh::testing::{database, key_entry, test_key};

    const IDLE: Duration = Duration::from_secs(3600);

    /// `personal` (serving keys) and `work` (not), locked, with the state
    /// registered and its cache under `cache`.
    fn fixture(cache: Option<PathBuf>) -> (Databases, Arc<SshState>) {
        let mut work = database("work", vec![]);
        work.serve_ssh_keys = false;
        let mut databases = Databases::for_test(vec![database("personal", vec![]), work], IDLE);
        let state = Arc::new(SshState::new(cache, IDLE));
        databases.observe(state.clone());
        (databases, state)
    }

    fn github(seed: u64) -> Vec<TestEntry> {
        vec![key_entry("github", &test_key(seed))]
    }

    fn scanned_keys(state: &SshState, db: &str) -> Option<usize> {
        state
            .inner()
            .scanned
            .get(db)
            .map(|scanned| scanned.served.len())
    }

    #[test]
    fn an_unlock_scans_the_database_and_writes_the_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (databases, state) = fixture(Some(dir.path().to_path_buf()));
        databases.install_for_test("personal", github(1));

        assert_eq!(scanned_keys(&state, "personal"), Some(1));
        let cached = keys::read_cache(dir.path(), "personal");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].key_data(), test_key(1).public_key().key_data());
    }

    #[test]
    fn a_database_that_does_not_serve_keys_is_not_scanned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (databases, state) = fixture(Some(dir.path().to_path_buf()));
        databases.install_for_test("work", github(1));

        assert_eq!(scanned_keys(&state, "work"), None);
        assert!(keys::read_cache(dir.path(), "work").is_empty());
    }

    #[test]
    fn a_scan_without_a_cache_directory_writes_nothing() {
        let (databases, state) = fixture(None);
        databases.install_for_test("personal", github(1));
        assert_eq!(scanned_keys(&state, "personal"), Some(1));
        assert!(state.cached(&database("personal", vec![])).is_empty());
    }

    /// A lock drops the keys of the unlock it ended, the private keys read
    /// since included.
    #[test]
    fn a_lock_drops_the_keys_of_its_unlock() {
        let (databases, state) = fixture(None);
        databases.install_for_test("personal", github(1));
        let fingerprint = state.inner().scanned["personal"].served[0].fingerprint;
        state
            .inner()
            .scanned
            .get_mut("personal")
            .unwrap()
            .private_keys
            .insert(fingerprint, test_key(1));

        databases.lock("personal").unwrap();

        assert_eq!(scanned_keys(&state, "personal"), None);
    }

    /// A notification for an old unlock leaves a new unlock's state: a late
    /// `locked` doesn't drop it, and a late `unlocked` doesn't replace it.
    #[test]
    fn a_late_notification_for_an_old_unlock_leaves_a_new_unlocks_state() {
        let (databases, state) = fixture(None);
        databases.install_for_test("personal", github(1));
        let old = databases.open("personal").unwrap().unlock_token();
        databases.lock("personal").unwrap();
        databases.install_for_test("personal", github(2));
        let new = state.inner().scanned["personal"].served[0].fingerprint;

        state.locked(&databases, "personal", &old);
        state.unlocked(&databases, "personal", &old);

        assert_eq!(state.inner().scanned["personal"].served[0].fingerprint, new);
    }

    /// An `unlocked` that comes after the lock of its own unlock finds the
    /// database locked, and scans nothing.
    #[test]
    fn a_notification_after_the_lock_scans_nothing() {
        let (databases, state) = fixture(None);
        databases.install_for_test("personal", github(1));
        let unlock = databases.open("personal").unwrap().unlock_token();
        databases.lock("personal").unwrap();

        state.unlocked(&databases, "personal", &unlock);

        assert_eq!(scanned_keys(&state, "personal"), None);
    }

    /// A lock leaves the backoff, and an unlock ends it.
    #[test]
    fn the_backoff_outlives_a_lock_and_an_unlock_ends_it() {
        let (databases, state) = fixture(None);
        databases.install_for_test("personal", github(1));
        let later = Instant::now() + IDLE;
        state.inner().backoff.insert("personal".to_string(), later);

        databases.lock("personal").unwrap();
        assert_eq!(state.inner().backoff.get("personal"), Some(&later));

        databases.install_for_test("personal", github(1));
        assert!(state.inner().backoff.is_empty());
    }
}
