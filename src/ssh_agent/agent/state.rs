//! [`SshSlot`]: the agent's per-database state, filled by a scan at unlock,
//! by first use and by approvals, and dropped whole at lock, and
//! [`KeyCache`], the public-key cache write that follows each scan.

use std::collections::HashMap;

use keepass::Database;
use ssh_key::{Fingerprint, PrivateKey, PublicKey};

use crate::config::DatabaseConfig;
use crate::log;
use crate::paths::Paths;
use crate::ssh_agent::approve::{GrantedApprovals, PendingRequests};
use crate::ssh_agent::keys::{self, SkipReason};

/// The SSH-agent half of a database's slot (`docs/ssh-agent.md` § 6.4,
/// § 6.7). Empty while locked, or for a database that doesn't serve SSH
/// keys. Plain data: the host replaces the whole value with a default one
/// on lock, the freshness guard's included, and with a scan's result on
/// unlock, so a lock has one field to clear.
#[derive(Default)]
pub struct SshSlot {
    /// The keys this database serves, from its last scan.
    pub(super) served: Vec<keys::ServedKey>,
    /// Private keys read at their first signature (`docs/ssh-agent.md`
    /// § 6.4), kept until lock. `ssh-key`'s private key types zeroize
    /// their secret material when they drop (Ed25519, ECDSA and RSA alike),
    /// and an RSA signature's per-signature `rsa::PrivateKey`, built from
    /// the key for that one signature, zeroizes on drop too.
    pub(super) private_keys: HashMap<Fingerprint, PrivateKey>,
    /// The approvals granted since unlock.
    pub(super) approvals: GrantedApprovals,
    /// The requests refused for want of an approval no prompt could ask
    /// for (`docs/ssh-agent.md` § 6.8).
    pub(super) pending: PendingRequests,
}

impl SshSlot {
    /// Scans `db`, just opened, for SSH keys and resolves `cfg`'s settings
    /// against what it finds. Each skipped attachment is logged by entry
    /// and reason, never by anything the vault holds. The scan parses
    /// every key file in full, so the host runs it before taking its lock
    /// on the slots, and installs the result after.
    pub fn scan(db: &Database, cfg: &DatabaseConfig) -> SshSlot {
        let scan = keys::scan(db);
        for skipped in &scan.skipped {
            let log = match skipped.reason {
                // The user's key isn't served, and they can fix that.
                SkipReason::ShortEcdsaScalar => log::warn,
                _ => log::debug,
            };
            log(format_args!(
                "ssh key scan: skipped an attachment on entry {} in {:?}: {}",
                skipped.entry_uuid, cfg.name, skipped.reason
            ));
        }
        SshSlot {
            served: keys::resolve(cfg, &scan.found),
            ..SshSlot::default()
        }
    }

    /// The public-key cache write this scan calls for
    /// (`docs/ssh-agent.md` § 6.4, "after each scan"), for the host to run
    /// once it has released its lock on the slots.
    pub fn cache(&self, database: &str) -> KeyCache {
        KeyCache {
            database: database.to_string(),
            keys: self
                .served
                .iter()
                .map(|key| key.public_key.clone())
                .collect(),
        }
    }

    /// Whether this holds no keys, served or read: what a lock leaves
    /// behind, along with no approvals.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.served.is_empty() && self.private_keys.is_empty()
    }
}

/// One database's served public keys, to write to the cache.
pub struct KeyCache {
    database: String,
    keys: Vec<PublicKey>,
}

impl KeyCache {
    /// Writes the cache under `paths`' cache directory. Without one, there
    /// is nowhere to write it; a failure is logged, since the database is
    /// served all the same.
    pub fn write(&self, paths: &Paths) {
        let Some(dir) = keys::cache_dir(paths) else {
            return;
        };
        if let Err(err) = keys::write_cache(&dir, &self.database, &self.keys) {
            log::warn(format_args!(
                "ssh key cache: failed to write {:?}: {err}",
                self.database
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_agent::testing::{database, key_database, test_key};

    #[test]
    fn a_scan_serves_the_databases_keys_and_its_cache_holds_their_public_halves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths {
            cache_dir: Some(dir.path().to_path_buf()),
            ..Paths::default()
        };
        let key = test_key(1);
        let db = key_database(&[("github", &key)]);
        let cfg = database("personal", vec![]);

        let slot = SshSlot::scan(&db, &cfg);
        assert_eq!(slot.served.len(), 1);
        assert_eq!(slot.served[0].name, "github");

        slot.cache("personal").write(&paths);
        let cached = keys::read_cache(&keys::cache_dir(&paths).expect("cache dir"), "personal");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].key_data(), key.public_key().key_data());
    }

    #[test]
    fn a_cache_without_a_cache_directory_is_not_written() {
        let key = test_key(2);
        let slot = SshSlot::scan(
            &key_database(&[("github", &key)]),
            &database("personal", vec![]),
        );
        assert!(!slot.is_empty());
        slot.cache("personal").write(&Paths::default());
    }
}
