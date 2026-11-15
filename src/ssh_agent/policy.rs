//! Whether a signature goes ahead (`docs/ssh-agent.md` § 5, § 6.3, § 6.7):
//! [`decide`] says what a request needs before its key may sign it, or why
//! it never may. Pure and stateless: no socket, no clock, no mutex, and no
//! store. Whether an approval it asks for is already held, and whether a
//! prompt may appear to ask for one, are the caller's questions.
//! [`listable`] is the companion question "does this connection even get
//! to ask".

use super::approve::Scope;
use super::bind::ConnectionClass;
use super::classify::Purpose;
use super::keys::ServedKey;
use crate::config::SshKeyConfirm;

/// What a request [`decide`] lets through needs before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Need {
    /// Nothing: sign (`confirm = "never"`).
    Nothing,
    /// The user's approval, unless one already covers its scope.
    Approval(Ask),
}

/// The approval a request needs: what it covers, and whether the user's
/// `Allow` is kept for the next request of that scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub scope: Scope,
    /// Keep the approval until lock (`confirm = "once"`), rather than let
    /// it cover this one signature (`"always"`).
    pub remember: bool,
}

/// Why a request is never signed, whatever the database's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A forwarded connection: none is served yet.
    Forwarded,
    /// The login's own session identifier doesn't match the connection's
    /// bound one (`docs/ssh-agent.md` § 6.3).
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
pub fn decide(
    key: &ServedKey,
    class: &ConnectionClass,
    purpose: &Purpose,
    login_session_id: Option<&[u8]>,
) -> Result<Need, Refusal> {
    let destination = match class {
        ConnectionClass::Forwarded { .. } => return Err(Refusal::Forwarded),
        ConnectionClass::LocalBound { dest } => {
            if let Purpose::Login(login) = purpose
                && Some(login.session_id.as_slice()) != login_session_id
            {
                return Err(Refusal::SessionMismatch);
            }
            Some(dest)
        }
        // Any purpose, no binding to check a login's session against.
        ConnectionClass::LocalUnbound => None,
    };
    let remember = match key.confirm {
        SshKeyConfirm::Never => return Ok(Need::Nothing),
        SshKeyConfirm::Once => true,
        SshKeyConfirm::Always => false,
    };
    Ok(Need::Approval(Ask {
        scope: Scope::new(key.fingerprint, destination),
        remember,
    }))
}

/// Whether a key with `forwarded` may be listed to a connection of `class`
/// (`docs/ssh-agent.md` § 6.4 "Which keys a connection sees"): a forwarded
/// connection lists only `forwarded = true` keys; every other connection
/// lists every served key.
pub fn listable(class: &ConnectionClass, forwarded: bool) -> bool {
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
    use crate::ssh_agent::classify::LoginRequest;
    use crate::ssh_agent::testing::test_key;

    fn key(confirm: SshKeyConfirm) -> ServedKey {
        let public_key = test_key(1).public_key().clone();
        ServedKey {
            database: "personal".to_string(),
            fingerprint: public_key.fingerprint(HashAlg::Sha256),
            public_key,
            name: "github".to_string(),
            entry_uuid: uuid::Uuid::nil(),
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
        ConnectionClass::LocalBound { dest: host_key(2) }
    }

    fn forwarded(dest: Option<u64>) -> ConnectionClass {
        ConnectionClass::Forwarded {
            host: host_key(9),
            session: vec![1],
            dest: dest.map(host_key),
        }
    }

    fn approval(key: &ServedKey, destination: Option<&KeyData>, remember: bool) -> Need {
        Need::Approval(Ask {
            scope: Scope::new(key.fingerprint, destination),
            remember,
        })
    }

    /// S1: a `once` key at the desk needs one approval, for the bound
    /// destination, kept until lock.
    #[test]
    fn s1_a_once_key_needs_an_approval_it_keeps() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            decide(&key, &bound(), &login(b"sid"), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), true))
        );
        assert_eq!(
            decide(&key, &ConnectionClass::LocalUnbound, &login(b"sid"), None),
            Ok(approval(&key, None, true))
        );
    }

    #[test]
    fn s1_a_login_on_a_bound_connection_must_match_its_session() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            decide(&key, &bound(), &login(b"other"), Some(b"sid")),
            Err(Refusal::SessionMismatch)
        );
        assert_eq!(
            decide(&key, &bound(), &login(b"sid"), None),
            Err(Refusal::SessionMismatch)
        );
    }

    /// S2: signing data has no session to match, bound or not, and an
    /// unbound connection's login has none either.
    #[test]
    fn s2_signing_data_and_unbound_logins_have_no_session_to_match() {
        let key = key(SshKeyConfirm::Once);
        assert_eq!(
            decide(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), true))
        );
        for purpose in [sshsig(), login(b"anything"), Purpose::Other] {
            assert_eq!(
                decide(&key, &ConnectionClass::LocalUnbound, &purpose, None),
                Ok(approval(&key, None, true))
            );
        }
    }

    /// S3: no forwarded request is signed yet, whatever it asks for.
    #[test]
    fn s3_a_forwarded_connection_is_refused_whatever_it_signs() {
        for confirm in [SshKeyConfirm::Never, SshKeyConfirm::Once] {
            for (class, purpose) in [
                (forwarded(Some(8)), login(b"sid")),
                (forwarded(None), login(b"sid")),
                (forwarded(Some(8)), sshsig()),
            ] {
                assert_eq!(
                    decide(&key(confirm), &class, &purpose, Some(b"sid")),
                    Err(Refusal::Forwarded)
                );
            }
        }
    }

    #[test]
    fn confirm_always_asks_every_time_and_keeps_nothing() {
        let key = key(SshKeyConfirm::Always);
        assert_eq!(
            decide(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(approval(&key, Some(&host_key(2)), false))
        );
    }

    #[test]
    fn confirm_never_needs_nothing() {
        let key = key(SshKeyConfirm::Never);
        assert_eq!(
            decide(&key, &bound(), &sshsig(), Some(b"sid")),
            Ok(Need::Nothing)
        );
        assert_eq!(
            decide(&key, &ConnectionClass::LocalUnbound, &Purpose::Other, None),
            Ok(Need::Nothing)
        );
    }

    #[test]
    fn listable_excludes_non_forwarded_keys_from_forwarded_connections() {
        assert!(!listable(&forwarded(None), false));
        assert!(listable(&forwarded(None), true));
    }

    #[test]
    fn listable_includes_every_served_key_locally() {
        for class in [ConnectionClass::LocalUnbound, bound()] {
            assert!(listable(&class, false));
            assert!(listable(&class, true));
        }
    }
}
