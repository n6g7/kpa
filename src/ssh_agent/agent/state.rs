//! [`SshSlot`]: the agent's per-database state, filled by a scan at unlock
//! and dropped whole at lock.

use keepass::Database;
use ssh_key::PublicKey;

use crate::config::DatabaseConfig;
use crate::log;
use crate::paths::Paths;
use crate::ssh_agent::keys;
use crate::vault;

/// The SSH-agent half of a database's slot (`docs/ssh-agent.md` § 6.4).
/// Empty while locked, or for a database that doesn't serve SSH keys. The
/// host replaces the whole value with a default one on lock, so a lock has
/// one field to clear.
#[derive(Default)]
pub struct SshSlot {
    /// The keys this database serves, from its last scan.
    pub(super) served: Vec<keys::ServedKey>,
}

impl SshSlot {
    /// Scans `db`, just unlocked, for SSH keys, resolves `cfg`'s settings
    /// against what it finds, and writes the public-key cache under
    /// `paths`' cache directory: everything `docs/ssh-agent.md` § 6.4 says
    /// happens "after each scan". Scanning reads key headers only, so this
    /// can run under the host's lock on its slots without stalling anything
    /// noticeably.
    pub fn scan(&mut self, db: &Database, cfg: &DatabaseConfig, paths: &Paths) {
        let attachments = vault::list_attachments(db);
        let scan = keys::scan(&attachments);
        for skipped in &scan.skipped {
            log::debug(format_args!(
                "ssh key scan: skipped {:?} on {:?}: {:?}",
                skipped.attachment_name, cfg.name, skipped.reason
            ));
        }
        self.served = keys::resolve(cfg, &scan.found);
        let Some(dir) = keys::cache_dir(paths) else {
            return;
        };
        let public_keys: Vec<PublicKey> = self
            .served
            .iter()
            .map(|key| key.public_key.clone())
            .collect();
        if let Err(err) = keys::write_cache(&dir, &cfg.name, &public_keys) {
            log::warn(format_args!(
                "ssh key cache: failed to write {:?}: {err}",
                cfg.name
            ));
        }
    }

    /// Whether this holds nothing: what a lock leaves behind.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.served.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_agent::testing::{database, key_database, test_key};

    #[test]
    fn a_scan_serves_the_databases_keys_and_caches_their_public_halves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths {
            cache_dir: Some(dir.path().to_path_buf()),
            ..Paths::default()
        };
        let key = test_key(1);
        let db = key_database(&[("github", &key)]);
        let cfg = database("personal", vec![]);

        let mut slot = SshSlot::default();
        slot.scan(&db, &cfg, &paths);

        assert_eq!(slot.served.len(), 1);
        assert_eq!(slot.served[0].name, "github");
        let cached = keys::read_cache(&dir.path().join("kpa/ssh-keys"), "personal");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].key_data(), key.public_key().key_data());
    }

    #[test]
    fn a_scan_without_a_cache_directory_still_serves() {
        let key = test_key(2);
        let db = key_database(&[("github", &key)]);
        let cfg = database("personal", vec![]);

        let mut slot = SshSlot::default();
        slot.scan(&db, &cfg, &Paths::default());
        assert_eq!(slot.served.len(), 1);
        assert!(!slot.is_empty());
    }
}
