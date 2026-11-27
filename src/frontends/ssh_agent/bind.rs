//! `session-bind@openssh.com` verification and per-connection binding state
//! (`docs/ssh-agent.md` § 6.2).
//!
//! [`wire::SessionBind`](super::wire::SessionBind) is the message read
//! structurally off the wire; [`SessionBindState`] is what a connection
//! accumulates from a sequence of them, and [`SessionBindState::class`] is
//! the answer every later decision (which keys to list, what a signature
//! is allowed to be) actually needs.
//!
//! A binding's host key may be a certificate, as a modern `ssh` offers when
//! the server presents one: the host is the key the certificate certifies,
//! and the signature is checked against that key. The certificate's CA,
//! validity and principals are not checked, and no name is taken from them.
//! OpenSSH's own agent parses it the same way (`sshkey_froms`).
//!
//! Three rules, mirroring OpenSSH's own `ssh-agent` (`process_ext_session_bind`
//! in `ssh-agent.c`) with one deliberate addition:
//!
//! - At most [`MAX_BINDINGS`] bindings are ever recorded.
//! - Once a binding for authentication (not forwarding) is recorded, no
//!   later binding — forwarding or not — is accepted.
//! - *kpa's addition*: a first binding attempt that claims `is_forwarding`
//!   marks the connection forwarded whether or not it verifies. OpenSSH's
//!   own agent simply refuses such a message and forgets it; kpa can't
//!   afford to, since forwarded connections are held to the stricter rules
//!   in § 6.3 and § 6.7 — a forged or unverifiable first message must not be
//!   able to make those rules disappear by failing to verify. Nothing that
//!   verifies afterwards, forwarding or not, unmarks the connection or
//!   replaces the forwarding host and session the claim names: a verified
//!   later binding is a hop (forwarding) or the destination (not).

use signature::Verifier;
use ssh_key::encoding::{Decode, Reader};
use ssh_key::public::KeyData;
use ssh_key::{Certificate, Signature};

use super::wire::SessionBind;

/// `AGENT_MAX_SESSION_IDS` in OpenSSH's `ssh-agent.c`.
pub const MAX_BINDINGS: usize = 16;

/// `AGENT_MAX_SID_LEN` in OpenSSH's `ssh-agent.c`: a session identifier
/// longer than this is refused outright, signature check skipped.
const MAX_SESSION_ID_LEN: usize = 128;

/// The longest certificate kept with a host, as its encoded blob: a host
/// certificate is a few hundred bytes, and a remote host on a forwarded
/// connection can send binds of its own, each as large as a frame.
const MAX_CERTIFICATE_LEN: usize = 4096;

/// A host a connection is bound to: its key, and the certificate it presented
/// for it, if it did. The key is the host: a certificate is kept only to name
/// it (`docs/ssh-agent.md` § 6.2), so two are the same host if their keys are.
#[derive(Debug, Clone)]
pub struct BoundHost {
    key: KeyData,
    certificate: Option<Box<Certificate>>,
}

impl BoundHost {
    /// The host key, which is the certified key if the host presented a
    /// certificate.
    pub fn key(&self) -> &KeyData {
        &self.key
    }

    /// The certificate the host presented, if it did.
    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_deref()
    }
}

impl PartialEq for BoundHost {
    fn eq(&self, other: &BoundHost) -> bool {
        self.key == other.key
    }
}

impl Eq for BoundHost {}

impl From<KeyData> for BoundHost {
    /// A host that presented no certificate.
    fn from(key: KeyData) -> BoundHost {
        BoundHost {
            key,
            certificate: None,
        }
    }
}

/// One successfully verified binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Binding {
    host_key: BoundHost,
    session_id: Vec<u8>,
    is_forwarding: bool,
}

/// The first binding attempt's claim to be forwarding, kept whether or not
/// the attempt verified — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardingClaim {
    host_key: BoundHost,
    session_id: Vec<u8>,
}

/// What one agent connection has proved through `session-bind@openssh.com`
/// messages: which host keys, bound to which SSH sessions, whether
/// forwarding is in play. A connection owns one, created empty when it is
/// accepted and updated with [`SessionBindState::apply`] as messages
/// arrive; [`SessionBindState::class`] turns it into the
/// [`ConnectionClass`] that decisions are made against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBindState {
    verified: Vec<Binding>,
    forwarding_claim: Option<ForwardingClaim>,
    attempts: usize,
}

impl Default for SessionBindState {
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
    /// further binding can follow it) binding's host.
    LocalBound { dest: BoundHost },
    /// The first binding attempt has `is_forwarding`, verified or not.
    /// `host` is that attempt's host and `session` its session identifier;
    /// `onward` are the hosts of the verified forwarding bindings after it,
    /// in the order they arrived, which the first host relayed on
    /// (`docs/ssh-agent.md` § 6.7); `dest` is the non-forwarding binding, if
    /// the remote `ssh` sent one.
    Forwarded {
        host: BoundHost,
        session: Vec<u8>,
        onward: Vec<BoundHost>,
        dest: Option<BoundHost>,
    },
}

impl ConnectionClass {
    pub fn is_forwarded(&self) -> bool {
        matches!(self, ConnectionClass::Forwarded { .. })
    }

    /// The hosts the agent was forwarded through, in the order their
    /// bindings arrived: the forwarding host first, then the hosts it
    /// relayed on. Empty for a connection that isn't forwarded.
    pub fn forwarding_chain(&self) -> Vec<&BoundHost> {
        match self {
            ConnectionClass::Forwarded { host, onward, .. } => {
                std::iter::once(host).chain(onward).collect()
            }
            ConnectionClass::LocalUnbound | ConnectionClass::LocalBound { .. } => Vec::new(),
        }
    }

    /// The class in a few words, for a log line or a listing.
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionClass::LocalUnbound => "local",
            ConnectionClass::LocalBound { .. } => "local, bound",
            ConnectionClass::Forwarded { .. } => "forwarded",
        }
    }
}

impl SessionBindState {
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

        let host_key = host_key_from_bytes(&msg.hostkey);

        // The claim is recorded from the very first attempt regardless of
        // whether it goes on to verify — see the module doc. It needs the
        // hostkey to at least parse: without a key there is nothing to
        // name as "the forwarding host" at all.
        if is_first_attempt
            && msg.is_forwarding
            && let Ok(key) = &host_key
        {
            // The claim's signature is never checked, so what it presents
            // names nothing: only its key is kept.
            self.forwarding_claim = Some(ForwardingClaim {
                host_key: key.key().clone().into(),
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
        if host_key.key().verify(&msg.session_id, &signature).is_err() {
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

    /// The session identifier an SSH login signed over this connection must
    /// equal (`docs/ssh-agent.md` § 6.3): the recorded binding's — the one
    /// binding, for `LocalBound`, or the last one, for `Forwarded` (which,
    /// since an authentication binding blocks every binding after it, is
    /// the destination's exactly when [`ConnectionClass::Forwarded`]'s
    /// `dest` is `Some`). `None` for `LocalUnbound`, where there is no
    /// binding to check against at all.
    pub fn login_session_id(&self) -> Option<&[u8]> {
        self.verified
            .last()
            .map(|binding| binding.session_id.as_slice())
    }

    /// This connection's class, per `docs/ssh-agent.md` § 6.2.
    ///
    /// The first attempt decides once whether the connection is forwarded:
    /// it is when that attempt claimed forwarding (verified or not), or when
    /// the first binding that did verify is a forwarding one. Nothing that
    /// verifies later changes that.
    pub fn class(&self) -> ConnectionClass {
        // The forwarding host and session are the claim's when there is one.
        // A verified binding that is the claim itself stands in for it, to
        // keep the certificate it presented; any other verified forwarding
        // binding is a hop after it.
        let (host, session, head_verified) = match (&self.forwarding_claim, self.verified.first()) {
            (Some(claim), Some(binding))
                if binding.is_forwarding
                    && binding.session_id == claim.session_id
                    && binding.host_key == claim.host_key =>
            {
                (binding.host_key.clone(), binding.session_id.clone(), true)
            }
            (Some(claim), _) => (claim.host_key.clone(), claim.session_id.clone(), false),
            (None, Some(binding)) if binding.is_forwarding => {
                (binding.host_key.clone(), binding.session_id.clone(), true)
            }
            // Only one binding can ever exist here: recording a
            // non-forwarding binding blocks every binding after it.
            (None, Some(binding)) => {
                return ConnectionClass::LocalBound {
                    dest: binding.host_key.clone(),
                };
            }
            (None, None) => return ConnectionClass::LocalUnbound,
        };

        ConnectionClass::Forwarded {
            host,
            session,
            onward: self
                .verified
                .iter()
                .filter(|binding| binding.is_forwarding)
                .skip(usize::from(head_verified))
                .map(|binding| binding.host_key.clone())
                .collect(),
            dest: self
                .verified
                .iter()
                .find(|binding| !binding.is_forwarding)
                .map(|binding| binding.host_key.clone()),
        }
    }
}

/// Decode a standalone host key blob (not `string`-wrapped — the caller
/// already unwrapped that layer), rejecting trailing bytes. A certificate is
/// the key it certifies, and is kept next to it, if it isn't too big, to name
/// the host by.
fn host_key_from_bytes(bytes: &[u8]) -> ssh_key::Result<BoundHost> {
    let mut reader: &[u8] = bytes;
    let key_data = KeyData::decode(&mut reader)?;
    reader.ensure_finished()?;
    Ok(match key_data {
        KeyData::Certificate(certificate) => BoundHost {
            key: certificate.public_key().clone(),
            certificate: (bytes.len() <= MAX_CERTIFICATE_LEN).then_some(certificate),
        },
        plain => BoundHost::from(plain),
    })
}

#[cfg(test)]
mod tests {
    use super::super::testing::{certified_bind, signed_bind};
    use super::super::wire::AgentRequest;
    use ssh_key::PrivateKey;
    use ssh_key::certificate::{Builder, CertType};

    use super::*;
    use crate::ssh::testing::test_key;

    fn verified_host(class: &ConnectionClass) -> &KeyData {
        match class {
            ConnectionClass::Forwarded { host, .. } => host.key(),
            other => panic!("expected Forwarded, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_connection_is_unbound() {
        let bindings = SessionBindState::new();
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);
    }

    #[test]
    fn a_verified_authentication_binding_becomes_local_bound() {
        let host = test_key(1);
        let mut bindings = SessionBindState::new();
        let msg = signed_bind(&host, b"session-id", false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound {
                dest: host.public_key().key_data().clone().into()
            }
        );
    }

    #[test]
    fn a_verified_forwarding_binding_becomes_forwarded_with_no_destination_yet() {
        let host = test_key(2);
        let mut bindings = SessionBindState::new();
        let msg = signed_bind(&host, b"session-id", true);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::Forwarded {
                host: host.public_key().key_data().clone().into(),
                session: b"session-id".to_vec(),
                onward: Vec::new(),
                dest: None,
            }
        );
    }

    #[test]
    fn a_later_non_forwarding_binding_becomes_the_forwarded_destination() {
        let forwarding_host = test_key(3);
        let dest_host = test_key(4);
        let mut bindings = SessionBindState::new();
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
                host: forwarding_host.public_key().key_data().clone().into(),
                session: b"sid".to_vec(),
                onward: Vec::new(),
                dest: Some(dest_host.public_key().key_data().clone().into()),
            }
        );
    }

    #[test]
    fn a_binding_after_an_authentication_binding_is_refused() {
        let first = test_key(5);
        let second = test_key(6);
        let mut bindings = SessionBindState::new();
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
                dest: first.public_key().key_data().clone().into()
            }
        );
    }

    #[test]
    fn an_identical_repeat_binding_is_accepted_without_growing_the_list() {
        let host = test_key(7);
        let mut bindings = SessionBindState::new();
        let msg = signed_bind(&host, b"sid", true);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(bindings.verified.len(), 1);
    }

    #[test]
    fn the_same_session_id_with_a_different_key_is_refused() {
        let host = test_key(8);
        let other = test_key(9);
        let mut bindings = SessionBindState::new();
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
        let mut bindings = SessionBindState::new();
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
        let mut bindings = SessionBindState::new();
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
        let mut bindings = SessionBindState::new();
        let mut msg = signed_bind(&wrong_signer, b"sid", true);
        msg.hostkey = host.public_key().to_bytes().expect("key encodes"); // signature now invalid for this key
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);

        let class = bindings.class();
        assert_eq!(
            class,
            ConnectionClass::Forwarded {
                host: host.public_key().key_data().clone().into(),
                session: b"sid".to_vec(),
                onward: Vec::new(),
                dest: None,
            }
        );
        assert!(bindings.verified.is_empty());
    }

    #[test]
    fn a_failed_first_attempt_not_claiming_forwarding_leaves_the_connection_unbound() {
        let wrong_signer = test_key(15);
        let host = test_key(16);
        let mut bindings = SessionBindState::new();
        let mut msg = signed_bind(&wrong_signer, b"sid", false);
        msg.hostkey = host.public_key().to_bytes().expect("key encodes");
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
        assert_eq!(bindings.class(), ConnectionClass::LocalUnbound);
    }

    /// A bind for `host` whose signature doesn't verify: the one a host key
    /// kpa can't check would produce, as far as kpa can tell.
    fn unverifiable_bind(host: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> SessionBind {
        let mut msg = signed_bind(host, session_id, is_forwarding);
        let last = msg.signature.len() - 1;
        msg.signature[last] ^= 1;
        msg
    }

    /// A first bind that claims forwarding and doesn't verify keeps the
    /// connection forwarded when a non-forwarding bind verifies after it: the
    /// later bind is the destination, and the forwarding host and session
    /// stay the claim's.
    #[test]
    fn a_verified_non_forwarding_binding_after_an_unverified_claim_is_the_destination() {
        let (claimed, dest_host) = (test_key(30), test_key(31));
        let mut bindings = SessionBindState::new();
        assert_eq!(
            bindings.apply(&unverifiable_bind(&claimed, b"claimed-sid", true)),
            BindOutcome::Refused
        );
        assert_eq!(
            bindings.apply(&signed_bind(&dest_host, b"dest-sid", false)),
            BindOutcome::Accepted
        );

        assert_eq!(
            bindings.class(),
            ConnectionClass::Forwarded {
                host: claimed.public_key().key_data().clone().into(),
                session: b"claimed-sid".to_vec(),
                onward: Vec::new(),
                dest: Some(dest_host.public_key().key_data().clone().into()),
            }
        );
        // The destination still ends the bindings.
        assert_eq!(
            bindings.apply(&signed_bind(&dest_host, b"later-sid", true)),
            BindOutcome::Refused
        );
        assert!(bindings.class().is_forwarded());
    }

    /// A forwarding bind that verifies after an unverified claim is a hop
    /// after the claimed host, and doesn't take its place as the forwarding
    /// host or session.
    #[test]
    fn a_verified_forwarding_binding_after_an_unverified_claim_does_not_replace_it() {
        let (claimed, other, dest_host) = (test_key(32), test_key(33), test_key(34));
        let mut bindings = SessionBindState::new();
        assert_eq!(
            bindings.apply(&unverifiable_bind(&claimed, b"claimed-sid", true)),
            BindOutcome::Refused
        );
        assert_eq!(
            bindings.apply(&signed_bind(&other, b"other-sid", true)),
            BindOutcome::Accepted
        );
        assert_eq!(
            bindings.class(),
            ConnectionClass::Forwarded {
                host: claimed.public_key().key_data().clone().into(),
                session: b"claimed-sid".to_vec(),
                onward: vec![other.public_key().key_data().clone().into()],
                dest: None,
            }
        );
        assert_eq!(
            chain_keys(&bindings.class()),
            vec![
                claimed.public_key().key_data().clone(),
                other.public_key().key_data().clone()
            ]
        );

        assert_eq!(
            bindings.apply(&signed_bind(&dest_host, b"dest-sid", false)),
            BindOutcome::Accepted
        );
        let ConnectionClass::Forwarded { host, dest, .. } = bindings.class() else {
            panic!("expected a forwarded connection");
        };
        assert_eq!(host.key(), claimed.public_key().key_data());
        assert_eq!(
            dest.expect("a destination").key(),
            dest_host.public_key().key_data()
        );
    }

    /// A first forwarding bind that verifies is the forwarding host itself,
    /// with the certificate it presented, and not one of the hops after it.
    #[test]
    fn a_verified_first_forwarding_binding_is_the_host_and_keeps_its_certificate() {
        let (host, ca) = (test_key(35), test_key(36));
        let mut bindings = SessionBindState::new();
        assert_eq!(
            bindings.apply(&certified_bind(&host, &ca, "build-box", b"sid", true)),
            BindOutcome::Accepted
        );
        let ConnectionClass::Forwarded {
            host: forwarding,
            onward,
            ..
        } = bindings.class()
        else {
            panic!("expected a forwarded connection");
        };
        assert!(forwarding.certificate().is_some());
        assert!(onward.is_empty());
    }

    #[test]
    fn a_verified_binding_after_a_failed_forwarding_claim_takes_precedence() {
        // The very first attempt (garbage hostkey) can never be pinned
        // down as a key, so no claim is recorded at all; the connection
        // ends up classified by whatever verifies afterwards.
        let host = test_key(17);
        let mut bindings = SessionBindState::new();
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
                dest: host.public_key().key_data().clone().into()
            }
        );
    }

    #[test]
    fn an_oversize_session_id_is_refused() {
        let host = test_key(18);
        let mut bindings = SessionBindState::new();
        let huge_session_id = vec![0u8; MAX_SESSION_ID_LEN + 1];
        let msg = signed_bind(&host, &huge_session_id, false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Refused);
    }

    #[test]
    fn a_session_id_exactly_at_the_cap_can_still_bind() {
        let host = test_key(19);
        let mut bindings = SessionBindState::new();
        let session_id = vec![0u8; MAX_SESSION_ID_LEN];
        let msg = signed_bind(&host, &session_id, false);
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
    }

    #[test]
    fn a_malformed_hostkey_is_refused() {
        let mut bindings = SessionBindState::new();
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
        let mut bindings = SessionBindState::new();
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
        assert_eq!(SessionBindState::default(), SessionBindState::new());
    }

    #[test]
    fn login_session_id_is_none_when_unbound() {
        let bindings = SessionBindState::new();
        assert_eq!(bindings.login_session_id(), None);
    }

    #[test]
    fn login_session_id_is_the_one_binding_for_local_bound() {
        let host = test_key(22);
        let mut bindings = SessionBindState::new();
        bindings.apply(&signed_bind(&host, b"sid", false));
        assert_eq!(bindings.login_session_id(), Some(b"sid".as_slice()));
    }

    /// The destination binding's own session id, distinct from the
    /// forwarding session's — the one a forwarded login must actually
    /// match (`docs/ssh-agent.md` § 6.3), not `ConnectionClass::Forwarded`'s
    /// `session` field (the forwarding session, used for approval scoping
    /// instead).
    #[test]
    fn login_session_id_is_the_destinations_for_forwarded_with_a_destination() {
        let forwarding_host = test_key(23);
        let dest_host = test_key(24);
        let mut bindings = SessionBindState::new();
        bindings.apply(&signed_bind(&forwarding_host, b"forwarding-sid", true));
        bindings.apply(&signed_bind(&dest_host, b"dest-sid", false));
        assert_eq!(bindings.login_session_id(), Some(b"dest-sid".as_slice()));
        assert_ne!(
            bindings.login_session_id(),
            Some(b"forwarding-sid".as_slice())
        );
    }

    #[test]
    fn login_session_id_is_the_forwarding_sessions_with_no_destination_yet() {
        let host = test_key(25);
        let mut bindings = SessionBindState::new();
        bindings.apply(&signed_bind(&host, b"sid", true));
        assert_eq!(bindings.login_session_id(), Some(b"sid".as_slice()));
    }

    /// Guards against the helper itself drifting: a real `ssh` client's
    /// signature over the session identifier must verify against its own
    /// claimed host key for any of the above to mean anything.
    #[test]
    fn the_signed_bind_helper_produces_a_binding_that_actually_verifies() {
        let host = test_key(21);
        let mut bindings = SessionBindState::new();
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

    /// A host that presents a certificate binds by the key it certifies, in
    /// both a plain and a forwarded connection, and the destination is that
    /// key.
    #[test]
    fn a_certificate_host_key_binds_by_the_key_it_certifies() {
        let (host, ca) = (test_key(1), test_key(2));
        let certified = host.public_key().key_data().clone();

        let mut local = SessionBindState::new();
        assert_eq!(
            local.apply(&certified_bind(
                &host,
                &ca,
                "build-box",
                b"session-id",
                false
            )),
            BindOutcome::Accepted
        );
        assert_eq!(
            local.class(),
            ConnectionClass::LocalBound {
                dest: certified.clone().into()
            }
        );

        let mut forwarded = SessionBindState::new();
        let forwarding = certified_bind(&host, &ca, "build-box", b"first", true);
        assert_eq!(forwarded.apply(&forwarding), BindOutcome::Accepted);
        assert_eq!(
            forwarded.apply(&certified_bind(&host, &ca, "build-box", b"second", false)),
            BindOutcome::Accepted
        );
        assert_eq!(
            forwarded.class(),
            ConnectionClass::Forwarded {
                host: certified.clone().into(),
                session: b"first".to_vec(),
                onward: Vec::new(),
                dest: Some(certified.into()),
            }
        );
    }

    /// The signature has to be the certified key's: a certificate for one key
    /// whose signature another made is refused, and a forwarding claim it
    /// makes is still recorded, as any claim is.
    #[test]
    fn a_certificate_whose_certified_key_did_not_sign_is_refused() {
        let (host, other, ca) = (test_key(1), test_key(3), test_key(2));
        let mut forged = certified_bind(&host, &ca, "build-box", b"session-id", true);
        forged.signature = signed_bind(&other, b"session-id", true).signature;

        let mut bindings = SessionBindState::new();
        assert_eq!(bindings.apply(&forged), BindOutcome::Refused);
        assert_eq!(
            verified_host(&bindings.class()),
            host.public_key().key_data()
        );
    }

    /// Nothing of the certificate but its key makes the host: a bind for a key
    /// whose certificate comes from another CA, or names another host, is the
    /// same host.
    #[test]
    fn a_certificates_ca_validity_and_principals_make_no_difference() {
        let host = test_key(1);
        let binds = |ca: u64, principal: &str| {
            let mut bindings = SessionBindState::new();
            let msg = certified_bind(&host, &test_key(ca), principal, b"session-id", false);
            assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
            bindings.class()
        };

        assert_eq!(binds(2, "build-box"), binds(4, "github.com"));
    }

    /// The certificate is kept next to the key it certifies, to name the host
    /// by, and doesn't make two hosts of one key.
    #[test]
    fn a_host_keeps_the_certificate_it_presented_next_to_its_key() {
        let (host, ca) = (test_key(1), test_key(2));
        let mut bindings = SessionBindState::new();
        bindings.apply(&certified_bind(
            &host,
            &ca,
            "build-box",
            b"session-id",
            false,
        ));

        let ConnectionClass::LocalBound { dest } = bindings.class() else {
            panic!("expected a bound connection");
        };

        assert_eq!(dest.key(), host.public_key().key_data());
        assert_eq!(
            dest.certificate()
                .map(|certificate| certificate.valid_principals().to_vec()),
            Some(vec!["build-box".to_string()])
        );
        assert_eq!(dest, BoundHost::from(host.public_key().key_data().clone()));
    }

    /// A certificate too big to keep still binds its key: the host is the
    /// same, and it isn't named by what it presented.
    #[test]
    fn a_certificate_too_big_to_keep_binds_by_its_key_alone() {
        let (host, ca) = (test_key(1), test_key(2));
        let mut builder = Builder::new(
            vec![0; 16],
            host.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .expect("a valid window");
        builder.cert_type(CertType::Host).expect("a type");
        builder
            .key_id("x".repeat(MAX_CERTIFICATE_LEN))
            .expect("a key id");
        builder.valid_principal("build-box").expect("a principal");
        let big = builder.sign(&ca).expect("the CA signs");
        let msg = SessionBind {
            hostkey: big.to_bytes().expect("encodes"),
            ..signed_bind(&host, b"session-id", false)
        };

        let mut bindings = SessionBindState::new();
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);

        let ConnectionClass::LocalBound { dest } = bindings.class() else {
            panic!("expected a bound connection");
        };
        assert_eq!(dest.key(), host.public_key().key_data());
        assert!(dest.certificate().is_none());
    }

    /// A forwarding claim whose signature never verified names nothing: it
    /// keeps its key, and not the certificate it came with.
    #[test]
    fn an_unverified_forwarding_claim_keeps_no_certificate() {
        let (host, other, ca) = (test_key(1), test_key(3), test_key(2));
        let mut forged = certified_bind(&host, &ca, "build-box", b"session-id", true);
        forged.signature = signed_bind(&other, b"session-id", true).signature;

        let mut bindings = SessionBindState::new();
        assert_eq!(bindings.apply(&forged), BindOutcome::Refused);

        let ConnectionClass::Forwarded { host: claimed, .. } = bindings.class() else {
            panic!("expected a forwarded connection");
        };
        assert!(claimed.certificate().is_none());
    }

    fn chain_keys(class: &ConnectionClass) -> Vec<KeyData> {
        class
            .forwarding_chain()
            .into_iter()
            .map(|host| host.key().clone())
            .collect()
    }

    /// The chain is every verified forwarding binding, in the order they
    /// arrived, the first being the forwarding host; the authentication
    /// binding after them is the destination and not a hop.
    #[test]
    fn the_forwarding_chain_is_the_forwarding_bindings_in_order() {
        let hops = [test_key(1), test_key(2), test_key(3)];
        let dest = test_key(4);
        let mut bindings = SessionBindState::new();
        for (n, hop) in hops.iter().enumerate() {
            let session = format!("hop-{n}");
            assert_eq!(
                bindings.apply(&signed_bind(hop, session.as_bytes(), true)),
                BindOutcome::Accepted
            );
        }
        assert_eq!(
            bindings.apply(&signed_bind(&dest, b"login", false)),
            BindOutcome::Accepted
        );

        let class = bindings.class();
        let keys = |keys: &[&ssh_key::PrivateKey]| {
            keys.iter()
                .map(|key| key.public_key().key_data().clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(chain_keys(&class), keys(&[&hops[0], &hops[1], &hops[2]]));
        let ConnectionClass::Forwarded {
            host,
            onward,
            dest: bound,
            ..
        } = class
        else {
            panic!("expected a forwarded connection");
        };
        assert_eq!(host.key(), hops[0].public_key().key_data());
        assert_eq!(onward.len(), 2);
        assert_eq!(
            bound.expect("a destination").key(),
            dest.public_key().key_data()
        );
    }

    /// A binding that fails verification is never a hop, and a later one
    /// that verifies is.
    #[test]
    fn a_binding_that_fails_verification_is_not_in_the_chain() {
        let (first, second, third) = (test_key(1), test_key(2), test_key(3));
        let mut bindings = SessionBindState::new();
        assert_eq!(
            bindings.apply(&signed_bind(&first, b"one", true)),
            BindOutcome::Accepted
        );
        let mut forged = signed_bind(&second, b"two", true);
        forged.signature = signed_bind(&third, b"two", true).signature;
        assert_eq!(bindings.apply(&forged), BindOutcome::Refused);
        assert_eq!(
            bindings.apply(&signed_bind(&third, b"three", true)),
            BindOutcome::Accepted
        );

        assert_eq!(
            chain_keys(&bindings.class()),
            vec![
                first.public_key().key_data().clone(),
                third.public_key().key_data().clone()
            ]
        );
    }

    /// A connection with only the unverified forwarding claim has a chain of
    /// that one host, and one that isn't forwarded has none.
    #[test]
    fn a_claim_alone_is_a_chain_of_one_and_a_local_connection_has_none() {
        let (host, wrong_signer) = (test_key(1), test_key(2));
        let mut bindings = SessionBindState::new();
        assert!(chain_keys(&bindings.class()).is_empty());

        let mut forged = signed_bind(&wrong_signer, b"sid", true);
        forged.hostkey = host.public_key().to_bytes().expect("key encodes");
        assert_eq!(bindings.apply(&forged), BindOutcome::Refused);
        assert_eq!(
            chain_keys(&bindings.class()),
            vec![host.public_key().key_data().clone()]
        );

        let mut local = SessionBindState::new();
        local.apply(&signed_bind(&host, b"sid", false));
        assert!(chain_keys(&local.class()).is_empty());
    }

    #[test]
    fn a_real_openssh_session_bind_decodes_and_verifies() {
        let AgentRequest::SessionBind(msg) = super::super::wire::decode_request(REAL_SESSION_BIND)
        else {
            panic!("the captured vector should decode as a session bind");
        };
        assert!(!msg.is_forwarding);

        let host_key = host_key_from_bytes(&msg.hostkey).expect("hostkey should parse");
        assert_eq!(
            host_key
                .key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            "SHA256:GPlhdYQP8NhCXJtc7h0vcH/sL2q9s5FcguM+r/ieqww"
        );

        let mut bindings = SessionBindState::new();
        assert_eq!(bindings.apply(&msg), BindOutcome::Accepted);
        assert_eq!(
            bindings.class(),
            ConnectionClass::LocalBound { dest: host_key }
        );
    }
}
