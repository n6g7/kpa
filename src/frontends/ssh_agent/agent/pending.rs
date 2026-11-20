//! The agent's side of `ssh_pending` and `ssh_approve` (`docs/ssh-agent.md`
//! § 6.8): the requests refused for want of an approval, and approving one.
//! The sign flow records them; the daemon's two requests come here, through
//! the same [`SshHost`] access the flow uses, so the freshness guard runs
//! first.

use std::time::Duration;

use uuid::Uuid;

use super::SshHost;
use crate::log;
use crate::ssh::approvals::PendingRequest;

/// Every pending request: each database's in config order, oldest first.
pub fn pending_requests(host: &impl SshHost) -> Vec<PendingRequest> {
    host.databases()
        .iter()
        .filter(|cfg| cfg.serve_ssh_keys)
        .flat_map(|cfg| {
            host.with_slot(&cfg.name, |slot| {
                slot.ssh
                    .pending
                    .list(slot.wall_now())
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        })
        .collect()
}

/// Approves the request `id` names, in whichever database has it: the
/// approval it asked for, which is the one a prompt's `Allow` would have
/// given, except that a one-signature approval is kept for `window`. Every
/// request pending for its scope is answered. `false` if none has that id:
/// it expired, or a lock dropped it, or `id` never named one.
pub fn approve_pending(host: &impl SshHost, id: Uuid, window: Duration) -> bool {
    host.databases()
        .iter()
        .filter(|cfg| cfg.serve_ssh_keys)
        .any(|cfg| {
            let approved = host
                .with_slot(&cfg.name, |slot| {
                    let now = slot.now();
                    let approval = slot.ssh.pending.take(id, slot.wall_now())?;
                    let key = approval.scope.key();
                    slot.ssh.approvals.approve(approval, now, window);
                    Some(key)
                })
                .flatten();
            if let Some(key) = &approved {
                log::info(format_args!(
                    "ssh approve: key {key} approved in {:?} by request id",
                    cfg.name
                ));
            }
            approved.is_some()
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ssh_key::{HashAlg, PrivateKey};

    use super::super::fake::FakeHost;
    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::ssh::approvals::{PENDING_TTL, Scope};
    use crate::ssh::approvals::{RequestDetails, SignatureApproval};
    use crate::ssh::testing::{database, key_database, test_key};

    const WINDOW: Duration = Duration::from_secs(60);

    fn host(key: &PrivateKey, confirm: SshKeyConfirm) -> Arc<FakeHost> {
        let settings = SshKeyConfig {
            fingerprint: key.public_key().fingerprint(HashAlg::Sha256),
            name: None,
            confirm,
            forwarded: true,
            serve: true,
        };
        Arc::new(FakeHost::unlocked(
            vec![database("personal", vec![settings])],
            key_database(&[("github", key)]),
        ))
    }

    fn requested() -> RequestDetails {
        RequestDetails {
            purpose: "other",
            user: None,
            namespace: None,
            class: "local",
            command: Some("ssh".to_string()),
        }
    }

    /// Records a request for `key` unbound, asking for `remember`.
    fn record(host: &FakeHost, key: &PrivateKey, remember: bool) {
        let approval = SignatureApproval {
            scope: Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None),
            remember,
        };
        host.with_slot("personal", |slot| {
            let served = slot
                .served(key.public_key().fingerprint(HashAlg::Sha256))
                .expect("served")
                .clone();
            slot.ssh
                .pending
                .record(approval, served, requested(), slot.wall_now())
        });
    }

    /// The id of the one request pending.
    fn the_id(host: &FakeHost) -> Uuid {
        let listed = pending_requests(host);
        assert_eq!(listed.len(), 1);
        listed[0].id
    }

    fn covered(host: &FakeHost, key: &PrivateKey) -> bool {
        let scope = Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None);
        host.with_slot("personal", |slot| {
            slot.ssh.approvals.covers(&scope, slot.now())
        })
        .expect("a slot")
    }

    #[test]
    fn a_pending_request_is_listed_with_when_it_was_refused_and_what_it_was() {
        let key = test_key(1);
        let host = host(&key, SshKeyConfirm::Once);
        let refused_at = host.wall_now();
        record(&host, &key, true);
        host.advance(Duration::from_secs(5));

        let listed = pending_requests(host.as_ref());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key.database, "personal");
        assert_eq!(
            listed[0].key.fingerprint,
            key.public_key().fingerprint(HashAlg::Sha256)
        );
        assert_eq!(listed[0].key.name, "github");
        assert_eq!(listed[0].key.title.as_deref(), Some("github"));
        assert!(listed[0].key.attachment.is_some());
        assert_eq!(listed[0].approval.scope.destination(), None);
        assert!(listed[0].approval.remember);
        assert_eq!(listed[0].request, requested());
        assert_eq!(listed[0].refused_at, refused_at);
    }

    #[test]
    fn approving_grants_the_recorded_ask_and_answers_the_request() {
        let key = test_key(1);
        let host = host(&key, SshKeyConfirm::Once);
        record(&host, &key, true);
        let id = the_id(&host);

        assert!(approve_pending(host.as_ref(), id, WINDOW));
        assert!(covered(&host, &key));
        assert!(pending_requests(host.as_ref()).is_empty());
        assert!(!approve_pending(host.as_ref(), id, WINDOW));
    }

    /// An `always` key's approval is a one-shot: it covers the retry for the
    /// window, and no longer.
    #[test]
    fn an_always_keys_approval_lasts_the_window() {
        let key = test_key(1);
        let host = host(&key, SshKeyConfirm::Always);
        record(&host, &key, false);

        assert!(approve_pending(host.as_ref(), the_id(&host), WINDOW));
        host.advance(WINDOW - Duration::from_secs(1));
        assert!(covered(&host, &key));
        host.advance(Duration::from_secs(1));
        assert!(!covered(&host, &key));
    }

    #[test]
    fn nothing_is_approved_that_was_not_recorded_or_has_expired() {
        let key = test_key(1);
        let host = host(&key, SshKeyConfirm::Once);
        assert!(!approve_pending(host.as_ref(), Uuid::new_v4(), WINDOW));

        record(&host, &key, true);
        let id = the_id(&host);
        assert!(!approve_pending(host.as_ref(), Uuid::new_v4(), WINDOW));
        host.advance(PENDING_TTL);
        assert!(!approve_pending(host.as_ref(), id, WINDOW));
        assert!(!covered(&host, &key));
    }

    /// An id from before a lock names nothing after it, even for a request
    /// of the same scope.
    #[test]
    fn a_lock_drops_what_is_pending_and_its_ids() {
        let key = test_key(1);
        let host = host(&key, SshKeyConfirm::Once);
        record(&host, &key, true);
        let id = the_id(&host);

        host.lock("personal");
        assert!(pending_requests(host.as_ref()).is_empty());
        host.reopen();
        record(&host, &key, true);
        assert!(!approve_pending(host.as_ref(), id, WINDOW));
        assert_ne!(the_id(&host), id);
    }
}
