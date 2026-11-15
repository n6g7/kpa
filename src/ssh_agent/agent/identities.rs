//! Which keys a connection sees (`docs/ssh-agent.md` § 6.4): each opted-in
//! database's served keys, from its slot while unlocked and from the
//! public-key cache while locked, deduped by config order and filtered by
//! the connection's class.

use std::path::Path;

use super::SshHost;
use crate::config::DatabaseConfig;
use crate::log;
use crate::output;
use crate::ssh_agent::bind::ConnectionClass;
use crate::ssh_agent::wire::{self, Identity};
use crate::ssh_agent::{keys, policy};

/// The longest identity comment sent: a key's name, from an override or
/// an entry title, escaped and capped (`docs/ssh-agent.md` § 6.4), so a
/// hostile title can neither drive the terminal `ssh-add -l` prints to
/// nor grow the answer without bound.
const MAX_COMMENT_LEN: usize = 128;

/// Every key a connection of `class` may list right now: a forwarded
/// connection never sees a `forwarded = false` key. Each comment is the
/// key's name, escaped and capped. If the answer would be too big to send,
/// the keys that fit are listed and the rest dropped, with a warning.
pub(super) fn identities(
    host: &impl SshHost,
    cache_dir: Option<&Path>,
    class: &ConnectionClass,
) -> Vec<Identity> {
    let per_database: Vec<Vec<keys::ServedKey>> = host
        .databases()
        .iter()
        .filter(|cfg| cfg.serve_ssh_keys)
        .map(|cfg| served_keys(host, cache_dir, cfg))
        .collect();
    let listed = keys::dedupe_by_config_order(per_database)
        .into_iter()
        .filter(|key| policy::listable(class, key.forwarded))
        .filter_map(|key| {
            let key_blob = key.public_key.to_bytes().ok()?;
            Some(Identity {
                key_blob,
                comment: output::escape_one_line(&key.name, MAX_COMMENT_LEN),
            })
        })
        .collect();
    let (listed, dropped) = wire::fit_identities(listed);
    if dropped > 0 {
        log::warn(format_args!(
            "ssh agent: listed {} keys and dropped {dropped} that didn't fit in one answer",
            listed.len()
        ));
    }
    listed
}

/// `cfg`'s served keys right now: its last scan's if its database is
/// unlocked, the public-key cache's under `cache_dir` if it's locked. The
/// host runs the freshness guard first, so a database whose file changed
/// lists from the cache.
fn served_keys(
    host: &impl SshHost,
    cache_dir: Option<&Path>,
    cfg: &DatabaseConfig,
) -> Vec<keys::ServedKey> {
    let unlocked = host.with_slot(&cfg.name, |slot| {
        slot.db.is_some().then(|| slot.ssh.served.clone())
    });
    match (unlocked, cache_dir) {
        (None, _) => Vec::new(),
        (Some(Some(served)), _) => served,
        (Some(None), None) => Vec::new(),
        (Some(None), Some(dir)) => keys::resolve_cached(cfg, keys::read_cache(dir, &cfg.name)),
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::{HashAlg, PublicKey};

    use super::super::fake::FakeHost;
    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::ssh_agent::testing::{database, key_database, test_key};

    fn cached(seed: u64) -> PublicKey {
        test_key(seed).public_key().clone()
    }

    fn hidden(public_key: &PublicKey) -> SshKeyConfig {
        SshKeyConfig {
            fingerprint: public_key.fingerprint(HashAlg::Sha256),
            name: None,
            confirm: SshKeyConfirm::default(),
            forwarded: true,
            serve: false,
        }
    }

    #[test]
    fn a_locked_database_lists_its_cached_keys_under_a_fallback_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        keys::write_cache(dir.path(), "personal", &[cached(1)]).expect("write cache");
        let host = FakeHost::locked(vec![database("personal", vec![])]);

        let listed = identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound);
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].comment.starts_with("personal SHA256:"),
            "{}",
            listed[0].comment
        );
    }

    #[test]
    fn a_serve_false_override_hides_a_cached_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = cached(1);
        keys::write_cache(dir.path(), "personal", std::slice::from_ref(&key)).expect("write cache");
        let host = FakeHost::locked(vec![database("personal", vec![hidden(&key)])]);

        let listed = identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound);
        assert!(listed.is_empty());
    }

    #[test]
    fn a_locked_database_without_a_cache_directory_lists_nothing() {
        let host = FakeHost::locked(vec![database("personal", vec![])]);
        assert!(identities(&host, None, &ConnectionClass::LocalUnbound).is_empty());
    }

    #[test]
    fn an_unlocked_database_lists_its_scanned_keys_by_entry_title() {
        let key = test_key(1);
        let host = FakeHost::unlocked(
            vec![database("personal", vec![])],
            key_database(&[("github", &key)]),
        );

        let listed = identities(&host, None, &ConnectionClass::LocalUnbound);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].comment, "github");
        assert_eq!(
            listed[0].key_blob,
            key.public_key().to_bytes().expect("key encodes")
        );
    }

    #[test]
    fn a_key_in_two_databases_is_listed_once_from_the_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = cached(1);
        keys::write_cache(dir.path(), "personal", std::slice::from_ref(&key)).expect("write cache");
        keys::write_cache(dir.path(), "work", &[key, cached(2)]).expect("write cache");
        let host = FakeHost::locked(vec![database("personal", vec![]), database("work", vec![])]);

        let listed = identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound);
        let names: Vec<&str> = listed
            .iter()
            .map(|id| id.comment.split(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(names, ["personal", "work"]);
    }

    #[test]
    fn a_database_that_does_not_serve_keys_lists_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        keys::write_cache(dir.path(), "personal", &[cached(1)]).expect("write cache");
        let mut cfg = database("personal", vec![]);
        cfg.serve_ssh_keys = false;
        let host = FakeHost::locked(vec![cfg]);

        assert!(identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound).is_empty());
    }

    /// A hostile entry title is escaped and capped before it becomes a
    /// comment, and a huge one can't make the answer unsendable.
    #[test]
    fn a_hostile_title_is_escaped_and_capped() {
        let key = test_key(1);
        let title = format!("evil\u{1b}]52;c;\n{}", "x".repeat(300 * 1024));
        let host = FakeHost::unlocked(
            vec![database("personal", vec![])],
            key_database(&[(title.as_str(), &key)]),
        );

        let listed = identities(&host, None, &ConnectionClass::LocalUnbound);
        assert_eq!(listed.len(), 1);
        let comment = &listed[0].comment;
        assert!(comment.len() <= MAX_COMMENT_LEN, "{}", comment.len());
        assert!(comment.starts_with("evil\\u001b]52;c;\\u000a"), "{comment}");
        assert!(!comment.contains(['\u{1b}', '\n']));
    }

    /// More keys than fit in one answer: the ones that fit are listed,
    /// never a panic or an empty answer.
    #[test]
    fn more_keys_than_fit_in_one_answer_are_listed_as_far_as_they_fit() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Distinct public keys, made without generating key pairs: an
        // Ed25519 public key is any 32 bytes as far as listing goes.
        let many: Vec<PublicKey> = (0..6000u32)
            .map(|n| {
                let mut bytes = [0u8; 32];
                bytes[..4].copy_from_slice(&n.to_be_bytes());
                PublicKey::new(
                    ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(bytes)),
                    "",
                )
            })
            .collect();
        keys::write_cache(dir.path(), "personal", &many).expect("write cache");
        let host = FakeHost::locked(vec![database("personal", vec![])]);

        let listed = identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound);
        assert!(!listed.is_empty());
        assert!(listed.len() < 6000);
        wire::encode_response(&wire::AgentResponse::IdentitiesAnswer(listed));
    }

    /// A forwarded connection sees no `forwarded = false` key.
    #[test]
    fn a_forwarded_connection_never_lists_a_local_only_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = cached(1);
        keys::write_cache(dir.path(), "personal", std::slice::from_ref(&key)).expect("write cache");
        let local_only = SshKeyConfig {
            forwarded: false,
            serve: true,
            ..hidden(&key)
        };
        let host = FakeHost::locked(vec![database("personal", vec![local_only])]);
        let forwarded = ConnectionClass::Forwarded {
            host: cached(9).key_data().clone(),
            session: vec![1],
            dest: None,
        };

        assert!(identities(&host, Some(dir.path()), &forwarded).is_empty());
        assert_eq!(
            identities(&host, Some(dir.path()), &ConnectionClass::LocalUnbound).len(),
            1
        );
    }
}
