//! `session-bind@openssh.com` verification and per-connection binding state
//! (`docs/ssh-agent.md` § 6.2).
//!
//! [`wire::SessionBind`](super::wire::SessionBind) is the message read
//! structurally off the wire; [`Bindings`] is what a connection accumulates
//! from a sequence of them, and [`Bindings::class`] is the answer every
//! later decision (which keys to list, what a signature is allowed to be)
//! actually needs.
//!
//! Three rules, mirroring OpenSSH's own `ssh-agent` (`process_ext_session_bind`
//! in `ssh-agent.c`) with one deliberate addition:
//!
//! - At most [`MAX_BINDINGS`] bindings are ever recorded.
//! - Once a binding for authentication (not forwarding) is recorded, no
//!   later binding — forwarding or not — is accepted.
//! - *kpa's addition*: a first binding attempt that fails verification but
//!   claims `is_forwarding` still marks the connection forwarded. OpenSSH's
//!   own agent simply refuses such a message and forgets it; kpa can't
//!   afford to, since forwarded connections are held to the stricter rules
//!   in § 6.3 and § 6.7 — a forged first message must not be able to make
//!   those rules disappear by failing to verify. Once anything does verify,
//!   though, [`Bindings::class`] trusts that over the unverified claim.

use signature::Verifier;
use ssh_key::Signature;
use ssh_key::encoding::{Decode, Reader};
use ssh_key::public::KeyData;

use super::wire::SessionBind;

/// `AGENT_MAX_SESSION_IDS` in OpenSSH's `ssh-agent.c`.
pub const MAX_BINDINGS: usize = 16;

/// `AGENT_MAX_SID_LEN` in OpenSSH's `ssh-agent.c`: a session identifier
/// longer than this is refused outright, signature check skipped.
const MAX_SESSION_ID_LEN: usize = 128;

/// One successfully verified binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    host_key: KeyData,
    session_id: Vec<u8>,
    is_forwarding: bool,
}

/// The first binding attempt's claim, kept only for the case the real
/// bindings list never ends up with anything in it — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardingClaim {
    host_key: KeyData,
    session_id: Vec<u8>,
}

/// A connection's accumulated `session-bind@openssh.com` state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bindings {
    verified: Vec<Binding>,
    forwarding_claim: Option<ForwardingClaim>,
    attempts: usize,
}

impl Default for Bindings {
    fn default() -> Self {
        Self::new()
    }
}

/// What applying one `session-bind@openssh.com` message did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// Recorded (or an identical repeat of an already-recorded binding).
    /// The caller answers `SUCCESS`.
    Accepted,
    /// Not recorded: bad encoding, a signature that didn't verify, a
    /// session identifier too long, a binding attempted after an
    /// authentication binding, or the [`MAX_BINDINGS`] cap. The caller
    /// answers `EXTENSION_FAILURE`.
    Refused,
}

/// How a connection is classified once its bindings (if any) are in,
/// per `docs/ssh-agent.md` § 6.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionClass {
    /// No binding at all: `ssh-keygen -Y sign`, and clients other than
    /// OpenSSH's `ssh`.
    LocalUnbound,
    /// Authentication bindings only. `dest` is the (one and only, since no
    /// further binding can follow it) binding's host key.
    LocalBound { dest: KeyData },
    /// The first binding has `is_forwarding`. `host` is that binding's
    /// host key and `session` its session identifier; `dest` is the last
    /// non-forwarding binding, if the remote `ssh` sent one.
    Forwarded {
        host: KeyData,
        session: Vec<u8>,
        dest: Option<KeyData>,
    },
}

impl Bindings {
    #[must_use]
    pub fn new() -> Self {
        Self {
            verified: Vec::new(),
            forwarding_claim: None,
            attempts: 0,
        }
    }

    /// Apply one `session-bind@openssh.com` message to this connection.
    pub fn apply(&mut self, msg: &SessionBind) -> BindOutcome {
        let is_first_attempt = self.attempts == 0;
        self.attempts += 1;

        let host_key = key_data_from_bytes(&msg.hostkey);

        // The claim is recorded from the very first attempt regardless of
        // whether it goes on to verify — see the module doc. It needs the
        // hostkey to at least parse: without a key there is nothing to
        // name as "the forwarding host" at all.
        if is_first_attempt
            && msg.is_forwarding
            && let Ok(key) = &host_key
        {
            self.forwarding_claim = Some(ForwardingClaim {
                host_key: key.clone(),
                session_id: msg.session_id.clone(),
            });
        }

        let Ok(host_key) = host_key else {
            return BindOutcome::Refused;
        };
        if msg.session_id.len() > MAX_SESSION_ID_LEN {
            return BindOutcome::Refused;
        }
        let Ok(signature) = Signature::try_from(msg.signature.as_slice()) else {
            return BindOutcome::Refused;
        };
        if host_key.verify(&msg.session_id, &signature).is_err() {
            return BindOutcome::Refused;
        }

        // Any already-recorded authentication binding blocks every binding
        // after it, forwarding or not.
        if self.verified.iter().any(|binding| !binding.is_forwarding) {
            return BindOutcome::Refused;
        }

        if let Some(existing) = self
            .verified
            .iter()
            .find(|binding| binding.session_id == msg.session_id)
        {
            return if existing.host_key == host_key && existing.is_forwarding == msg.is_forwarding {
                BindOutcome::Accepted
            } else {
                BindOutcome::Refused
            };
        }

        if self.verified.len() >= MAX_BINDINGS {
            return BindOutcome::Refused;
        }

        self.verified.push(Binding {
            host_key,
            session_id: msg.session_id.clone(),
            is_forwarding: msg.is_forwarding,
        });
        BindOutcome::Accepted
    }

    /// This connection's class, per `docs/ssh-agent.md` § 6.2.
    #[must_use]
    pub fn class(&self) -> ConnectionClass {
        match self.verified.first() {
            Some(first) if first.is_forwarding => {
                let dest = self
                    .verified
                    .iter()
                    .rev()
                    .find(|binding| !binding.is_forwarding)
                    .map(|binding| binding.host_key.clone());
                ConnectionClass::Forwarded {
                    host: first.host_key.clone(),
                    session: first.session_id.clone(),
                    dest,
                }
            }
            // Only one binding can ever exist in this branch: recording a
            // non-forwarding binding blocks every binding after it, so
            // `.last()` and `.first()` name the same entry.
            Some(_) => ConnectionClass::LocalBound {
                dest: self
                    .verified
                    .last()
                    .expect("just matched Some")
                    .host_key
                    .clone(),
            },
            None => match &self.forwarding_claim {
                Some(claim) => ConnectionClass::Forwarded {
                    host: claim.host_key.clone(),
                    session: claim.session_id.clone(),
                    dest: None,
                },
                None => ConnectionClass::LocalUnbound,
            },
        }
    }
}

/// Decode a standalone public-key blob (not `string`-wrapped — the caller
/// already unwrapped that layer), rejecting trailing bytes.
fn key_data_from_bytes(bytes: &[u8]) -> ssh_key::Result<KeyData> {
    let mut reader: &[u8] = bytes;
    let key_data = KeyData::decode(&mut reader)?;
    reader.ensure_finished()?;
    Ok(key_data)
}

#[cfg(test)]
mod tests {
    use signature::Signer;
    use ssh_key::encoding::Encode;
    use ssh_key::{Algorithm, PrivateKey};

    use super::super::wire::AgentRequest;

    use super::*;

    struct TestRng(u64);

    impl TestRng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    impl ssh_key::rand_core::TryRng for TestRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            #[allow(clippy::cast_possible_truncation)]
            Ok(self.next() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next())
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl ssh_key::rand_core::TryCryptoRng for TestRng {}

    fn test_key(seed: u64) -> PrivateKey {
        PrivateKey::random(&mut TestRng(seed), Algorithm::Ed25519).expect("key generation")
    }

    /// A real `session-bind@openssh.com` message for `session_id`, signed
    /// by `host`.
    fn signed_bind(host: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> SessionBind {
        let signature: Signature = host.try_sign(session_id).expect("signing should succeed");
        SessionBind {
            hostkey: host.public_key().to_bytes().expect("key encodes"),
            session_id: session_id.to_vec(),
            signature: signature.encode_vec().expect("signature encodes"),
            is_forwarding,
        }
    }

    fn verified_host(class: &ConnectionClass) -> &KeyData {
        match class {
            ConnectionClass::Forwarded { host, .. } => host,
            other => panic!("expected Forwarded, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_connection_is_unbound() {
        let bindings = Bindings::new();
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);
    }

    #[test]
    fn a_verified_authentication_binding_becomes_local_bound() {
        let host = test_key(1);
        let mut bindings = Bindings::new();
        let msg = signed_bind(&host, b"session-id", false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound {
                dest: host.public_key().key_data().clone()
            }
        );
    }

    #[test]
    fn a_verified_forwarding_binding_becomes_forwarded_with_no_destination_yet() {
        let host = test_key(2);
        let mut bindings = Bindings::new();
        let msg = signed_bind(&host, b"session-id", true);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::Forwarded {
                host: host.public_key().key_data().clone(),
                session: b"session-id".to_vec(),
                dest: None,
            }
        );
    }

    #[test]
    fn a_later_non_forwarding_binding_becomes_the_forwarded_destination() {
        let forwarding_host = test_key(3);
        let dest_host = test_key(4);
        let mut bindings = Bindings::new();
        assert_eq!(
            bindings.apply(&signed_bind(&forwarding_host, b"sid", true)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.apply(&signed_bind(&dest_host, b"sid2", false)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.class(),
            ConnectionClass::Forwarded {
                host: forwarding_host.public_key().key_data().clone(),
                session: b"sid".to_vec(),
                dest: Some(dest_host.public_key().key_data().clone()),
            }
        );
    }

    #[test]
    fn a_binding_after_an_authentication_binding_is_refused() {
        let first = test_key(5);
        let second = test_key(6);
        let mut bindings = Bindings::new();
        assert_eq!(
            bindings.apply(&signed_bind(&first, b"sid", false)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.apply(&signed_bind(&second, b"sid2", false)),
            BindOutcome::Refused
        );
        assert_eq!(
            bindings.apply(&signed_bind(&second, b"sid2", true)),
            BindOutcome::Refused
        );
        // Still classified by the one binding that did succeed.
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound {
                dest: first.public_key().key_data().clone()
            }
        );
    }

    #[test]
    fn an_identical_repeat_binding_is_accepted_without_growing_the_list() {
        let host = test_key(7);
        let mut bindings = Bindings::new();
        let msg = signed_bind(&host, b"sid", true);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(bindings.verified.len(), 1);
    }

    #[test]
    fn the_same_session_id_with_a_different_key_is_refused() {
        let host = test_key(8);
        let other = test_key(9);
        let mut bindings = Bindings::new();
        assert_eq!(
            bindings.apply(&signed_bind(&host, b"sid", true)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.apply(&signed_bind(&other, b"sid", true)),
            BindOutcome::Refused
        );
    }

    #[test]
    fn the_sixteenth_distinct_forwarding_binding_is_the_last_accepted() {
        let host = test_key(10);
        let mut bindings = Bindings::new();
        for i in 0..MAX_BINDINGS {
            let session_id = format!("sid-{i}").into_bytes();
            assert_eq!(
                bindings.apply(&signed_bind(&host, &session_id, true)),
                BindOutcome::Accepted,
                "binding {i} should be accepted"
            );
        }
        let one_too_many = signed_bind(&host, b"sid-overflow", true);
        assert_eq!(bindings.apply(&one_too_many), BindOutcome::Refused);
        assert_eq!(bindings.verified.len(), MAX_BINDINGS);
    }

    #[test]
    fn a_signature_that_doesnt_verify_is_refused_and_not_recorded() {
        let host = test_key(11);
        let wrong_signer = test_key(12);
        let mut bindings = Bindings::new();
        // Signed by the wrong key, but claims to be `host`'s.
        let mut msg = signed_bind(&wrong_signer, b"sid", false);
        msg.hostkey = host.public_key().to_bytes().expect("key encodes");
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);
    }

    #[test]
    fn a_failed_first_attempt_claiming_forwarding_still_marks_the_connection_forwarded() {
        let host = test_key(13);
        let wrong_signer = test_key(14);
        let mut bindings = Bindings::new();
        let mut msg = signed_bind(&wrong_signer, b"sid", true);
        msg.hostkey = host.public_key().to_bytes().expect("key encodes"); // signature now invalid for this key
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);

        let class = bindings.class();
        assert_eq!(
            class,
            ConnectionClass::Forwarded {
                host: host.public_key().key_data().clone(),
                session: b"sid".to_vec(),
                dest: None,
            }
        );
        assert!(bindings.verified.is_empty());
    }

    #[test]
    fn a_failed_first_attempt_not_claiming_forwarding_leaves_the_connection_unbound() {
        let wrong_signer = test_key(15);
        let host = test_key(16);
        let mut bindings = Bindings::new();
        let mut msg = signed_bind(&wrong_signer, b"sid", false);
        msg.hostkey = host.public_key().to_bytes().expect("key encodes");
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);
    }

    #[test]
    fn a_verified_binding_after_a_failed_forwarding_claim_takes_precedence() {
        // The very first attempt (garbage hostkey) can never be pinned
        // down as a key, so no claim is recorded at all; the connection
        // ends up classified by whatever verifies afterwards.
        let host = test_key(17);
        let mut bindings = Bindings::new();
        let garbage = SessionBind {
            hostkey: b"not a key".to_vec(),
            session_id: b"sid".to_vec(),
            signature: b"not a signature".to_vec(),
            is_forwarding: true,
        };
        assert_eq!(bindings.apply(&garbage), BindOutcome::Refused);
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);

        assert_eq!(
            bindings.apply(&signed_bind(&host, b"sid2", false)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound {
                dest: host.public_key().key_data().clone()
            }
        );
    }

    #[test]
    fn an_oversize_session_id_is_refused() {
        let host = test_key(18);
        let mut bindings = Bindings::new();
        let huge_session_id = vec![0u8; MAX_SESSION_ID_LEN + 1];
        let msg = signed_bind(&host, &huge_session_id, false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
    }

    #[test]
    fn a_session_id_exactly_at_the_cap_can_still_bind() {
        let host = test_key(19);
        let mut bindings = Bindings::new();
        let session_id = vec![0u8; MAX_SESSION_ID_LEN];
        let msg = signed_bind(&host, &session_id, false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
    }

    #[test]
    fn a_malformed_hostkey_is_refused() {
        let mut bindings = Bindings::new();
        let msg = SessionBind {
            hostkey: b"garbage".to_vec(),
            session_id: b"sid".to_vec(),
            signature: b"garbage".to_vec(),
            is_forwarding: false,
        };
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        let host = test_key(20);
        let mut bindings = Bindings::new();
        let msg = SessionBind {
            hostkey: host.public_key().to_bytes().expect("key encodes"),
            session_id: b"sid".to_vec(),
            signature: b"garbage".to_vec(),
            is_forwarding: false,
        };
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(Bindings::default(), Bindings::new());
    }

    /// Guards against the helper itself drifting: a real `ssh` client's
    /// signature over the session identifier must verify against its own
    /// claimed host key for any of the above to mean anything.
    #[test]
    fn the_signed_bind_helper_produces_a_binding_that_actually_verifies() {
        let host = test_key(21);
        let mut bindings = Bindings::new();
        let msg = signed_bind(&host, b"sid", true);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            verified_host(&bindings.class()),
            host.public_key().key_data()
        );
    }

    /// A real `session-bind@openssh.com` message, captured from an actual
    /// OpenSSH 10.6 `ssh` authenticating against a local `sshd` (both
    /// unprivileged, throwaway Ed25519 host key, port 2299 on
    /// `127.0.0.1`). `ssh` was pointed at a fake "agent" — a Unix-socket
    /// listener that only recorded the first `EXTENSION
    /// session-bind@openssh.com` message `ssh` sent and answered it
    /// `SSH_AGENT_SUCCESS`, then answered `REQUEST_IDENTITIES` with an
    /// empty list so `ssh` had nothing to sign with and the connection
    /// ended in `Permission denied` — irrelevant here, since the bytes
    /// this test cares about (the `EXTENSION` message itself, type byte
    /// included, no outer frame) had already crossed by then. The
    /// server's host key fingerprint is `SHA256:GPlhdYQP8NhCXJtc7h0vcH/sL2q9s5FcguM+r/ieqww`.
    /// `is_forwarding` is `false`: a plain `ssh`, no `-A`.
    const REAL_SESSION_BIND: &[u8] = include_bytes!("testdata/session_bind.bin");

    #[test]
    fn a_real_openssh_session_bind_decodes_and_verifies() {
        let AgentRequest::SessionBind(msg) = super::super::wire::decode_request(REAL_SESSION_BIND)
        else {
            panic!("the captured vector should decode as a session bind");
        };
        assert!(!msg.is_forwarding);

        let host_key = key_data_from_bytes(&msg.hostkey).expect("hostkey should parse");
        assert_eq!(
            host_key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            "SHA256:GPlhdYQP8NhCXJtc7h0vcH/sL2q9s5FcguM+r/ieqww"
        );

        let mut bindings = Bindings::new();
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound { dest: host_key }
        );
    }
}
