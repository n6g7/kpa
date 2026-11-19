//! Which keys a connection sees (`docs/ssh-agent.md` § 6.4): each opted-in
//! database's served keys, from its slot while unlocked and from the
//! public-key cache while locked, deduped by config order and filtered by
//! the connection's class. A signature request finds its key the same way.
//! For a requester outside the desktop, a key's comment also says what to
//! run to use it (`docs/ssh-agent.md` § 6.8, "The hint"), as the sign flow
//! would refuse it.

use std::path::Path;

use ssh_key::Fingerprint;

use super::SshHost;
use super::sign::{Lacking, lacking};
use crate::authn::Requester;
use crate::authz::on_desktop;
use crate::config::DatabaseConfig;
use crate::frontends::ssh_agent::authz::{authorize_sign, may_list};
use crate::frontends::ssh_agent::bind::ConnectionClass;
use crate::frontends::ssh_agent::classify::Purpose;
use crate::frontends::ssh_agent::wire::{self, Identity};
use crate::log;
use crate::output;
use crate::ssh::keys;

/// The longest identity comment sent: a key's name, from an override or
/// an entry title, escaped and capped (`docs/ssh-agent.md` § 6.4), so a
/// hostile title can neither drive the terminal `ssh-add -l` prints to
/// nor grow the answer without bound.
const MAX_COMMENT_LEN: usize = 128;

/// Every key a connection of `class` may list right now: a forwarded
/// connection never sees a `forwarded = false` key. Each comment is the
/// key's name, escaped and capped, and for a requester outside the desktop
/// followed by the hint [`remedy`] gives. If the answer would be too big to
/// send, the keys that fit are listed and the rest dropped, with a warning.
pub(super) fn identities(
    host: &impl SshHost,
    cache_dir: Option<&Path>,
    class: &ConnectionClass,
    requester: &Requester,
) -> Vec<Identity> {
    let per_database: Vec<Vec<keys::ServedKey>> = host
        .databases()
        .iter()
        .filter(|cfg| cfg.serve_ssh_keys)
        .map(|cfg| served_keys(host, cache_dir, cfg))
        .collect();
    let outside = !on_desktop(requester, &host.display_session());
    let listed = keys::dedupe_by_config_order(per_database)
        .into_iter()
        .filter(|key| may_list(class, key.forwarded))
        .filter_map(|key| {
            let key_blob = key.public_key.to_bytes().ok()?;
            let name = output::escape_one_line(&key.name, MAX_COMMENT_LEN);
            let remedy = outside.then(|| remedy(host, &key, class)).flatten();
            let comment = match remedy {
                Some(remedy) => format!("{name} ({remedy})"),
                None => name,
            };
            Some(Identity { key_blob, comment })
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

/// What a requester outside the desktop has to run before `key` signs for
/// it, as the sign flow would refuse it where no prompt may appear: unlock
/// its database, or approve the request it will be pending as. `ssh` prints
/// the comment when the agent refuses, which is the one place such a
/// requester is told. A key that is refused for no remedy, a forwarded
/// connection's included, has none to give.
fn remedy(host: &impl SshHost, key: &keys::ServedKey, class: &ConnectionClass) -> Option<String> {
    // The purpose only matters to a login's session check, which doesn't
    // change what the key needs.
    let approval = authorize_sign(key, class, &Purpose::Other, None).ok()?;
    host.with_slot(&key.database, |slot| {
        Some(match lacking(&slot, approval.as_ref())? {
            Lacking::Unlock => {
                let database = output::escape_one_line(&key.database, MAX_COMMENT_LEN);
                format!("locked: kpa unlock {database}")
            }
            Lacking::Approval(_) => "needs approval: kpa ssh pending".to_string(),
        })
    })
    .flatten()
}

/// The key `fingerprint` names, as the first opted-in database in config
/// order that lists it serves it (§ 6.4's dedupe rule), from its slot or
/// its cache: its `database` says which. For a locked database that is the
/// cache's key under the config's settings, which is all an unlock prompt
/// and the decision need. The sign flow looks the key up again in that
/// database's slot, under the hold that signs.
pub(super) fn find_key(
    host: &impl SshHost,
    cache_dir: Option<&Path>,
    fingerprint: Fingerprint,
) -> Option<keys::ServedKey> {
    host.databases()
        .iter()
        .filter(|cfg| cfg.serve_ssh_keys)
        .find_map(|cfg| {
            served_keys(host, cache_dir, cfg)
                .into_iter()
                .find(|key| key.fingerprint == fingerprint)
        })
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

    use super::super::fake::{FakeHost, requester};
    use std::time::Duration;

    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::ssh::approvals::Scope;
    use crate::ssh::approvals::SignatureApproval;
    use crate::ssh::testing::{database, key_database, test_key};

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

        let listed = identities(
            &host,
            Some(dir.path()),
            &ConnectionClass::LocalUnbound,
            &requester(),
        );
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

        let listed = identities(
            &host,
            Some(dir.path()),
            &ConnectionClass::LocalUnbound,
            &requester(),
        );
        assert!(listed.is_empty());
    }

    #[test]
    fn a_locked_database_without_a_cache_directory_lists_nothing() {
        let host = FakeHost::locked(vec![database("personal", vec![])]);
        assert!(identities(&host, None, &ConnectionClass::LocalUnbound, &requester()).is_empty());
    }

    #[test]
    fn an_unlocked_database_lists_its_scanned_keys_by_entry_title() {
        let key = test_key(1);
        let host = FakeHost::unlocked(
            vec![database("personal", vec![])],
            key_database(&[("github", &key)]),
        );

        let listed = identities(&host, None, &ConnectionClass::LocalUnbound, &requester());
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

        let listed = identities(
            &host,
            Some(dir.path()),
            &ConnectionClass::LocalUnbound,
            &requester(),
        );
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

        assert!(
            identities(
                &host,
                Some(dir.path()),
                &ConnectionClass::LocalUnbound,
                &requester()
            )
            .is_empty()
        );
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

        let listed = identities(&host, None, &ConnectionClass::LocalUnbound, &requester());
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

        let listed = identities(
            &host,
            Some(dir.path()),
            &ConnectionClass::LocalUnbound,
            &requester(),
        );
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

        assert!(identities(&host, Some(dir.path()), &forwarded, &requester()).is_empty());
        assert_eq!(
            identities(
                &host,
                Some(dir.path()),
                &ConnectionClass::LocalUnbound,
                &requester()
            )
            .len(),
            1
        );
    }

    /// `key` as an unlocked `personal` serves it, named `github`.
    fn serving(key: &ssh_key::PrivateKey, confirm: SshKeyConfirm) -> FakeHost {
        let settings = SshKeyConfig {
            fingerprint: key.public_key().fingerprint(HashAlg::Sha256),
            name: None,
            confirm,
            forwarded: true,
            serve: true,
        };
        FakeHost::unlocked(
            vec![database("personal", vec![settings])],
            key_database(&[("github", key)]),
        )
    }

    fn comment(host: &FakeHost) -> String {
        let listed = identities(host, None, &ConnectionClass::LocalUnbound, &requester());
        assert_eq!(listed.len(), 1);
        listed[0].comment.clone()
    }

    /// A requester outside the desktop is told what to run, and only while
    /// the key needs it. One on the desktop is told nothing.
    #[test]
    fn a_key_that_needs_approval_says_so_to_a_requester_outside_the_desktop() {
        let key = test_key(1);
        let host = serving(&key, SshKeyConfirm::Once).without_prompts();

        assert_eq!(comment(&host), "github (needs approval: kpa ssh pending)");
        assert_eq!(comment(&serving(&key, SshKeyConfirm::Once)), "github");

        let scope = Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None);
        host.with_slot("personal", |slot| slot.ssh.approvals.grant(scope));
        assert_eq!(comment(&host), "github");
    }

    /// An approval for one signature silences the hint while it lasts.
    #[test]
    fn a_one_signature_approval_silences_the_hint_until_it_expires() {
        let key = test_key(1);
        let host = serving(&key, SshKeyConfirm::Always).without_prompts();
        let approval = SignatureApproval {
            scope: Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None),
            remember: false,
        };
        let window = Duration::from_secs(60);
        host.with_slot("personal", |slot| {
            slot.ssh.approvals.approve(approval, slot.now(), window)
        });

        assert_eq!(comment(&host), "github");
        host.advance(window);
        assert_eq!(comment(&host), "github (needs approval: kpa ssh pending)");
    }

    #[test]
    fn a_key_that_needs_nothing_has_no_hint() {
        let key = test_key(1);
        let host = serving(&key, SshKeyConfirm::Never).without_prompts();
        assert_eq!(comment(&host), "github");
    }

    #[test]
    fn a_locked_databases_key_says_to_unlock_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        keys::write_cache(dir.path(), "personal", &[cached(1)]).expect("write cache");
        let listed = |host: &FakeHost| {
            identities(
                host,
                Some(dir.path()),
                &ConnectionClass::LocalUnbound,
                &requester(),
            )
        };
        let locked = || FakeHost::locked(vec![database("personal", vec![])]);

        let may_not_prompt = listed(&locked().without_prompts());
        assert!(
            may_not_prompt[0]
                .comment
                .ends_with(" (locked: kpa unlock personal)"),
            "{}",
            may_not_prompt[0].comment
        );
        assert!(!listed(&locked())[0].comment.contains("kpa unlock"));
    }

    /// A forwarded connection's requester is told nothing: neither remedy
    /// is one it can act on.
    #[test]
    fn a_forwarded_connection_gets_no_hint() {
        let key = test_key(1);
        let host = serving(&key, SshKeyConfirm::Once).without_prompts();
        let forwarded = ConnectionClass::Forwarded {
            host: cached(9).key_data().clone(),
            session: vec![1],
            dest: None,
        };

        let listed = identities(&host, None, &forwarded, &requester());
        assert_eq!(listed[0].comment, "github");
    }
}
