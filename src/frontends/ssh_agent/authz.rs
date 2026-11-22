//! Whether a signature goes ahead (`docs/ssh-agent.md` § 5, § 6.3, § 6.7):
//! [`authorize_sign`] says what approval a request needs before its key may
//! sign it (`None`: none), or why it never may. Pure and stateless: no
//! socket, no clock, no mutex, and no store. Whether an approval it asks for
//! is already held, and whether a prompt may appear to ask for one, are the
//! caller's questions.
//! [`may_list`] is the companion question "does this connection even get
//! to ask".

use super::bind::ConnectionClass;
use super::classify::Purpose;
use crate::config::SshKeyConfirm;
use crate::ssh::approvals::{Scope, SignatureApproval};
use crate::ssh::keys::ServedKey;

/// Why a request is never signed, whatever the database's state, as a log
/// line says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The key has `forwarded = false`, and the connection is forwarded.
    #[error("key not allowed on forwarded connections")]
    NotForwardable,
    /// A forwarded connection signs SSH logins only
    /// (`docs/ssh-agent.md` § 6.3).
    #[error("forwarded connections sign logins only")]
    ForwardedNotLogin,
    /// A forwarded connection with no non-forwarding binding: the prompt
    /// couldn't say where the signature will be accepted.
    #[error("forwarded connection with no destination")]
    NoDestination,
    /// The login's own session identifier doesn't match the connection's
    /// bound one (`docs/ssh-agent.md` § 6.3).
    #[error("session mismatch")]
    SessionMismatch,
}

/// What a request to sign with `key` needs (`docs/ssh-agent.md` § 5 and
/// § 6.7), or why it is refused.
///
/// - `class`: the connection's binding state
///   (`bind::SessionBindState::class`). A bound connection's destination
///   is part of the approval's scope.
/// - `purpose`: what the request data actually is (`classify::classify`).
/// - `login_session_id`: the session identifier a login must match, if the
///   connection has any binding at all
///   (`bind::SessionBindState::login_session_id`).
pub fn authorize_sign(
    key: &ServedKey,
    class: &ConnectionClass,
    purpose: &Purpose,
    login_session_id: Option<&[u8]>,
) -> Result<Option<SignatureApproval>, Refusal> {
    let scope = match class {
        ConnectionClass::Forwarded {
            host,
            session,
            dest,
        } => {
            if !key.forwarded {
                return Err(Refusal::NotForwardable);
            }
            let Purpose::Login(login) = purpose else {
                return Err(Refusal::ForwardedNotLogin);
            };
            let dest = dest.as_ref().ok_or(Refusal::NoDestination)?;
            if Some(login.session_id.as_slice()) != login_session_id {
                return Err(Refusal::SessionMismatch);
            }
            // Whatever `confirm` says, a forwarded login needs an approval.
            return Ok(Some(SignatureApproval {
                scope: Scope::forwarded(key, session, host.key(), dest.key()),
                remember: key.confirm != SshKeyConfirm::Always,
            }));
        }
        ConnectionClass::LocalBound { dest } => {
            if let Purpose::Login(login) = purpose
                && Some(login.session_id.as_slice()) != login_session_id
            {
                return Err(Refusal::SessionMismatch);
            }
            Scope::local(key, Some(dest.key()))
        }
        // Any purpose, no binding to check a login's session against.
        ConnectionClass::LocalUnbound => Scope::local(key, None),
    };
    let remember = match key.confirm {
        SshKeyConfirm::Never => return Ok(None),
        SshKeyConfirm::Once => true,
        SshKeyConfirm::Always => false,
    };
    Ok(Some(SignatureApproval { scope, remember }))
}

/// Whether a key with `forwarded` may be listed to a connection of `class`
/// (`docs/ssh-agent.md` § 6.4 "Which keys a connection sees"): a forwarded
/// connection lists only `forwarded = true` keys; every other connection
/// lists every served key.
pub fn may_list(class: &ConnectionClass, forwarded: bool) -> bool {
    match class {
        ConnectionClass::Forwarded { .. } => forwarded,
        ConnectionClass::LocalUnbound | ConnectionClass::LocalBound { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::HashAlg;
    use ssh_key::public::KeyData;

    use super::*;
    use crate::frontends::ssh_agent::classify::LoginRequest;
    use crate::ssh::testing::test_key;

    fn key(confirm: SshKeyConfirm) -> ServedKey {
        let public_key = test_key(1).public_key().clone();
        ServedKey {
            database: "personal".to_string(),
            fingerprint: public_key.fingerprint(HashAlg::Sha256),
            public_key,
            name: "github".to_string(),
            entry_uuid: uuid::Uuid::nil(),
            title: None,
            attachment: None,
            confirm,
            forwarded: true,
        }
    }

    fn host_key(seed: u64) -> KeyData {
        test_key(seed).public_key().key_data().clone()
    }

    fn login(session_id: &[u8]) -> Purpose {
        Purpose::Login(LoginRequest {
            session_id: session_id.to_vec(),
            user: "alice".to_string(),
            hostbound_hostkey: None,
        })
    }

    fn sshsig() -> Purpose {
        Purpose::SshSig {
            namespace: "git".to_string(),
        }
    }

    fn bound() -> ConnectionClass {
        bound_to(2)
    }

    fn bound_to(dest: u64) -> ConnectionClass {
        ConnectionClass::LocalBound {
            dest: host_key(dest).into(),
        }
    }

    fn forwarded(dest: Option<u64>) -> ConnectionClass {
        ConnectionClass::Forwarded {
            host: host_key(9).into(),
            session: vec![1],
            dest: dest.map(|seed| host_key(seed).into()),
        }
    }

    fn approval(
        key: &ServedKey,
        destination: Option<&KeyData>,
        remember: bool,
    ) -> Option<SignatureApproval> {
        Some(SignatureApproval {
            scope: Scope::local(key, destination),
            remember,
        })
    }

    /// S1: a `once` key at the desk needs one approval, for the bound
    /// destination, kept until lock.
    #[test]
    fn s1_a_once_key_needs_an_approval_it_keeps() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            authorize_sign(&key, &bound(), &login(b"sid"), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), true))
        );
        assert_eq!(
            authorize_sign(&key, &ConnectionClass::LocalUnbound, &login(b"sid"), None),
            Ok(approval(&key, None, true))
        );
    }

    #[test]
    fn s1_a_login_on_a_bound_connection_must_match_its_session() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            authorize_sign(&key, &bound(), &login(b"other"), Some(b"sid")),
            Err(Refusal::SessionMismatch)
        );
        assert_eq!(
            authorize_sign(&key, &bound(), &login(b"sid"), None),
            Err(Refusal::SessionMismatch)
        );
    }

    /// S2: signing data has no session to match, bound or not, and an
    /// unbound connection's login has none either.
    #[test]
    fn s2_signing_data_and_unbound_logins_have_no_session_to_match() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            authorize_sign(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), true))
        );
        for purpose in [sshsig(), login(b"anything"), Purpose::Other] {
            assert_eq!(
                authorize_sign(&key, &ConnectionClass::LocalUnbound, &purpose, None),
                Ok(approval(&key, None, true))
            );
        }
    }

    fn forwarded_approval(key: &ServedKey, remember: bool) -> Option<SignatureApproval> {
        Some(SignatureApproval {
            scope: Scope::forwarded(key, &[1], &host_key(9), &host_key(8)),
            remember,
        })
    }

    /// S3: a forwarded login needs an approval, for its forwarding session,
    /// host and destination, whatever the key's `confirm` says.
    #[test]
    fn s3_a_forwarded_login_always_needs_an_approval() {
        for (confirm, remember) in [
            (SshKeyConfirm::Never, true),
            (SshKeyConfirm::Once, true),
            (SshKeyConfirm::Always, false),
        ] {
            let key = key(confirm);
            assert_eq!(
                authorize_sign(&key, &forwarded(Some(8)), &login(b"sid"), Some(b"sid")),
                Ok(forwarded_approval(&key, remember))
            );
        }
    }

    #[test]
    fn s3_a_forwarded_approval_is_for_its_forwarding_session_and_host_only() {
        let key = key(SshKeyConfirm::Once);
        let asked = |class: &ConnectionClass| {
            authorize_sign(&key, class, &login(b"sid"), Some(b"sid"))
                .unwrap()
                .unwrap()
                .scope
        };
        let first = asked(&forwarded(Some(8)));
        let other_session = ConnectionClass::Forwarded {
            host: host_key(9).into(),
            session: vec![2],
            dest: Some(host_key(8).into()),
        };
        let other_host = ConnectionClass::Forwarded {
            host: host_key(7).into(),
            session: vec![1],
            dest: Some(host_key(8).into()),
        };
        assert_ne!(first, asked(&other_session));
        assert_ne!(first, asked(&other_host));
        assert_ne!(first, asked(&forwarded(Some(6))));
        assert_ne!(first, asked(&bound_to(8)));
    }

    #[test]
    fn s3_a_forwarded_connection_refuses_what_it_may_not_sign() {
        let mut local_only = key(SshKeyConfirm::Once);
        local_only.forwarded = false;
        assert_eq!(
            authorize_sign(
                &local_only,
                &forwarded(Some(8)),
                &login(b"sid"),
                Some(b"sid")
            ),
            Err(Refusal::NotForwardable)
        );
        let key = key(SshKeyConfirm::Never);
        for purpose in [sshsig(), Purpose::Other] {
            assert_eq!(
                authorize_sign(&key, &forwarded(Some(8)), &purpose, Some(b"sid")),
                Err(Refusal::ForwardedNotLogin)
            );
        }
        assert_eq!(
            authorize_sign(&key, &forwarded(None), &login(b"sid"), Some(b"sid")),
            Err(Refusal::NoDestination)
        );
        assert_eq!(
            authorize_sign(&key, &forwarded(Some(8)), &login(b"other"), Some(b"sid")),
            Err(Refusal::SessionMismatch)
        );
    }

    #[test]
    fn confirm_always_asks_every_time_and_keeps_nothing() {
        let key = key(SshKeyConfirm::Always);
        assert_eq!(
            authorize_sign(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), false))
        );
    }

    #[test]
    fn confirm_never_needs_nothing() {
        let key = key(SshKeyConfirm::Never);
        assert_eq!(
            authorize_sign(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(None)
        );
        assert_eq!(
            authorize_sign(&key, &ConnectionClass::LocalUnbound, &Purpose::Other, None),
            Ok(None)
        );
    }

    #[test]
    fn may_list_excludes_non_forwarded_keys_from_forwarded_connections() {
        assert!(!may_list(&forwarded(None), false));
        assert!(may_list(&forwarded(None), true));
    }

    #[test]
    fn may_list_includes_every_served_key_locally() {
        for class in [ConnectionClass::LocalUnbound, bound()] {
            assert!(may_list(&class, false));
            assert!(may_list(&class, true));
        }
    }
}
