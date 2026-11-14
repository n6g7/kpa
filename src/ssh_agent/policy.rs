//! Whether a signature goes ahead (`docs/ssh-agent.md` § 5, § 6.7, § 6.8,
//! § 6.9): [`decide`] is the one decision function behind every situation
//! § 5's table lists, for all three phases (local, unlock on demand and
//! outside the desktop, forwarding) — later tasks only have to wire it in,
//! never extend it. Pure: no socket, no clock beyond what's passed in, no
//! mutex. [`listable`] is the companion question "does this connection even
//! get to ask", and [`is_idle_activity`] decides what counts as activity
//! for the idle timer.

use ssh_key::Fingerprint;

use crate::config::SshKeyConfirm;

use super::approve::Approvals;
use super::bind::ConnectionClass;
use super::classify::Purpose;

/// A key's identity and the two settings [`decide`] needs
/// (`docs/ssh-agent.md` § 7's `[[database.ssh_key]]` table — `name` and
/// `serve` play no part here: naming is the caller's job, and a
/// `serve = false` key never reaches `decide` at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySettings {
    pub fingerprint: Fingerprint,
    /// Local approval policy (`docs/ssh-agent.md` § 6.7). Plays no part in
    /// a forwarded decision — forwarded use always needs its own approval
    /// regardless of `confirm`.
    pub confirm: SshKeyConfirm,
    /// Usable through `ssh -A` at all. `false` and [`decide`] refuses a
    /// forwarded request for this key outright, same as if it were never
    /// listed to that connection ([`listable`]).
    pub forwarded: bool,
}

/// What [`decide`] says to do with a signature request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead and sign.
    Sign,
    /// Ask on screen before signing — raise the approval prompt
    /// (`ssh_agent.confirm_prompt`), then, once it answers `Allow`, grant
    /// the approval this decision was for and sign.
    PromptApprove,
    /// Unlock first — the ordinary `unlock` path. Answering its prompt
    /// counts as this signature's approval (`docs/ssh-agent.md` § 6.6):
    /// grant it the same way `PromptApprove` does, once unlocked, then
    /// sign.
    PromptUnlock,
    /// Don't sign, and don't prompt. The reason is specific enough to log
    /// and, for [`Refusal::NeedsApproval`], to record as pending
    /// (`kpa ssh approve`) and hint in the identity listing.
    Refuse(Refusal),
}

/// Why [`decide`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The key isn't usable over a forwarded connection at all
    /// (`forwarded = false`).
    KeyNotForwardable,
    /// A forwarded connection asked for something other than an SSH login
    /// — forwarded use signs logins only (`docs/ssh-agent.md` § 6.3).
    ForwardedNonLogin,
    /// A forwarded login with no bound destination yet: the first
    /// binding's forwarding claim alone doesn't name a destination to
    /// show truthfully in an approval prompt, so this can't be approved
    /// (`docs/ssh-agent.md` § 6.3).
    NoForwardedDestination,
    /// The login's own session identifier doesn't match the connection's
    /// bound one (`docs/ssh-agent.md` § 6.3) — for a local, bound
    /// connection or a forwarded one with a destination.
    SessionMismatch,
    /// The database is locked, and nothing here can unlock it: prompting
    /// isn't allowed (outside the desktop, or the screen is locked), or
    /// the database is in backoff. Recovered with `kpa unlock` from a
    /// terminal, never recorded as pending.
    Locked,
    /// Unlocked, but not approved, and nothing here can raise an approval
    /// prompt: prompting isn't allowed, or the database is in backoff.
    /// When prompting is merely disallowed (not backoff), the caller
    /// records this as pending for `kpa ssh approve` and hints it in the
    /// identity listing.
    NeedsApproval,
    /// The database is in backoff after a recently cancelled or timed-out
    /// prompt: refused at once, without even trying to prompt
    /// (`docs/ssh-agent.md` § 6.6).
    Backoff,
}

/// The one decision function behind `docs/ssh-agent.md` § 5's table.
///
/// - `key`: the signing key's identity and settings.
/// - `class`: the connection's binding state
///   (`bind::SessionBindState::class`).
/// - `purpose`: what the request data actually is (`classify::classify`).
/// - `login_session_id`: the session identifier a login must match, if the
///   connection has any binding at all
///   (`bind::SessionBindState::login_session_id`).
/// - `locked`: whether the key's database is currently locked.
/// - `approvals`: read-only — [`decide`] never grants or consumes one. The
///   caller grants on `PromptApprove`/`PromptUnlock` once the prompt (or
///   unlock) it raised actually succeeds, and consumes a one-shot
///   approval once the signature it allowed has gone through.
/// - `may_prompt`: whether a prompt may appear on screen at all —
///   `policy::Desk::may_prompt(origin)` (`docs/ssh-agent.md` § 6.8).
/// - `backoff`: whether the key's database is currently in backoff
///   (`docs/ssh-agent.md` § 6.6).
#[allow(clippy::too_many_arguments)]
pub fn decide(
    key: KeySettings,
    class: &ConnectionClass,
    purpose: &Purpose,
    login_session_id: Option<&[u8]>,
    locked: bool,
    approvals: &Approvals,
    may_prompt: bool,
    backoff: bool,
) -> Decision {
    if let Some(refusal) = check_purpose_and_binding(key, class, purpose, login_session_id) {
        return Decision::Refuse(refusal);
    }

    if locked {
        return if backoff {
            Decision::Refuse(Refusal::Backoff)
        } else if may_prompt {
            Decision::PromptUnlock
        } else {
            Decision::Refuse(Refusal::Locked)
        };
    }

    if is_approved(key, class, approvals) {
        return Decision::Sign;
    }
    if backoff {
        Decision::Refuse(Refusal::Backoff)
    } else if may_prompt {
        Decision::PromptApprove
    } else {
        Decision::Refuse(Refusal::NeedsApproval)
    }
}

/// The structural checks that don't depend on lock state, backoff or
/// prompting at all: whether this request is even shaped like something
/// this key, over this connection, could ever be allowed to sign.
fn check_purpose_and_binding(
    key: KeySettings,
    class: &ConnectionClass,
    purpose: &Purpose,
    login_session_id: Option<&[u8]>,
) -> Option<Refusal> {
    match class {
        ConnectionClass::Forwarded { dest, .. } => {
            if !key.forwarded {
                return Some(Refusal::KeyNotForwardable);
            }
            let Purpose::Login(login) = purpose else {
                return Some(Refusal::ForwardedNonLogin);
            };
            if dest.is_none() {
                return Some(Refusal::NoForwardedDestination);
            }
            if Some(login.session_id.as_slice()) != login_session_id {
                return Some(Refusal::SessionMismatch);
            }
            None
        }
        ConnectionClass::LocalBound { .. } => {
            if let Purpose::Login(login) = purpose
                && Some(login.session_id.as_slice()) != login_session_id
            {
                return Some(Refusal::SessionMismatch);
            }
            None
        }
        // Any purpose, no binding to check a login's session against.
        ConnectionClass::LocalUnbound => None,
    }
}

/// Whether `key` is already approved for use over a connection of `class`
/// — `confirm = "never"` counts as always approved for local use; a local
/// approval is checked by its exact (key, destination) scope, a forwarded
/// one by its exact (key, session, host, dest) scope
/// (`docs/ssh-agent.md` § 6.7).
fn is_approved(key: KeySettings, class: &ConnectionClass, approvals: &Approvals) -> bool {
    match class {
        ConnectionClass::Forwarded {
            host,
            session,
            dest,
        } => {
            // `check_purpose_and_binding` already refused a forwarded
            // request with no destination, so `dest` is `Some` here.
            let Some(dest) = dest else {
                return false;
            };
            approvals.is_forwarded_approved(key.fingerprint, session, host, dest)
        }
        ConnectionClass::LocalUnbound => {
            key.confirm == SshKeyConfirm::Never
                || approvals.is_locally_approved(key.fingerprint, None)
        }
        ConnectionClass::LocalBound { dest } => {
            key.confirm == SshKeyConfirm::Never
                || approvals.is_locally_approved(key.fingerprint, Some(dest))
        }
    }
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

/// The comment hint for a key an outside-desktop requester can't get
/// approved on screen (`docs/ssh-agent.md` § 6.8 "The hint"): `<name>
/// (needs approval: kpa ssh approve)`. `name` is the key's already-resolved
/// display name.
pub fn needs_approval_hint(name: &str) -> String {
    format!("{name} (needs approval: kpa ssh approve)")
}

/// The comment hint for a key whose database is locked: `<name> (locked:
/// kpa unlock <database>)`.
pub fn locked_hint(name: &str, database: &str) -> String {
    format!("{name} (locked: kpa unlock {database})")
}

/// Whether a signature counts as activity for its database's idle timer
/// (`docs/ssh-agent.md` § 6.9): only a successful local signature does. A
/// forwarded signature never does, so a remote host's root can't keep the
/// vault unlocked by signing; `signed` must already be `false` for a
/// refused one, since those never count either.
pub fn is_idle_activity(class: &ConnectionClass, signed: bool) -> bool {
    signed && !matches!(class, ConnectionClass::Forwarded { .. })
}

#[cfg(test)]
mod tests {
    use ssh_key::public::KeyData;
    use ssh_key::{Algorithm, PrivateKey};

    use super::super::classify::LoginRequest;
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

    fn host_key(seed: u64) -> KeyData {
        PrivateKey::random(&mut TestRng(seed), Algorithm::Ed25519)
            .expect("key generation")
            .public_key()
            .key_data()
            .clone()
    }

    fn fingerprint(seed: u8) -> Fingerprint {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let low = ALPHABET[(seed as usize) % 64] as char;
        let high = ALPHABET[(seed as usize) / 64] as char;
        let mut base64 = "A".repeat(43);
        base64.replace_range(0..1, &low.to_string());
        base64.replace_range(1..2, &high.to_string());
        format!("SHA256:{base64}")
            .parse()
            .expect("valid test fingerprint")
    }

    fn key(confirm: SshKeyConfirm, forwarded: bool) -> KeySettings {
        KeySettings {
            fingerprint: fingerprint(1),
            confirm,
            forwarded,
        }
    }

    fn login(session_id: &[u8]) -> Purpose {
        Purpose::Login(LoginRequest {
            session_id: session_id.to_vec(),
            user: "alice".to_string(),
            hostbound_hostkey: None,
        })
    }

    const SSHSIG: Purpose = Purpose::SshSig {
        namespace: String::new(),
    };

    fn forwarded_class(session: &[u8], host_seed: u64, dest: Option<u64>) -> ConnectionClass {
        ConnectionClass::Forwarded {
            host: host_key(host_seed),
            session: session.to_vec(),
            dest: dest.map(host_key),
        }
    }

    /// One case from `docs/ssh-agent.md` § 5's S1–S8 table, or one of the
    /// `always`/`never`/`forwarded = false` variants it calls out.
    struct Case {
        name: &'static str,
        key: KeySettings,
        class: ConnectionClass,
        purpose: Purpose,
        login_session_id: Option<&'static [u8]>,
        locked: bool,
        approved: bool,
        may_prompt: bool,
        backoff: bool,
        expect: Decision,
    }

    fn run(case: Case) {
        let mut approvals = Approvals::new();
        if case.approved {
            match &case.class {
                ConnectionClass::Forwarded {
                    host,
                    session,
                    dest,
                } => {
                    let dest = dest.as_ref().expect("test case needs a destination");
                    approvals.grant_forwarded(case.key.fingerprint, session, host, dest);
                }
                ConnectionClass::LocalBound { dest } => {
                    approvals.grant_local(case.key.fingerprint, Some(dest), case.key.confirm);
                }
                ConnectionClass::LocalUnbound => {
                    approvals.grant_local(case.key.fingerprint, None, case.key.confirm);
                }
            }
        }
        let got = decide(
            case.key,
            &case.class,
            &case.purpose,
            case.login_session_id,
            case.locked,
            &approvals,
            case.may_prompt,
            case.backoff,
        );
        assert_eq!(got, case.expect, "case {:?}", case.name);
    }

    #[test]
    fn s1_at_the_desk_local_unbound() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S1 locked",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: true,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::PromptUnlock,
        });
        run(Case {
            name: "S1 unlocked, not yet approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::PromptApprove,
        });
        run(Case {
            name: "S1 unlocked, approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: true,
            may_prompt: true,
            backoff: false,
            expect: Decision::Sign,
        });
    }

    #[test]
    fn s1_local_bound_session_must_match() {
        let key = key(SshKeyConfirm::Never, true);
        run(Case {
            name: "matching session, local bound",
            key,
            class: ConnectionClass::LocalBound { dest: host_key(1) },
            purpose: login(b"sid"),
            login_session_id: Some(b"sid"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Sign,
        });
        run(Case {
            name: "mismatched session, local bound",
            key,
            class: ConnectionClass::LocalBound { dest: host_key(1) },
            purpose: login(b"sid"),
            login_session_id: Some(b"other"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Refuse(Refusal::SessionMismatch),
        });
    }

    /// A local approval is scoped to its destination: approving a key for
    /// one destination (or for unbound use) never signs for another
    /// (`docs/ssh-agent.md` § 6.7).
    #[test]
    fn local_approvals_are_not_reused_across_destinations() {
        let key = key(SshKeyConfirm::Once, true);
        let mut approvals = Approvals::new();
        approvals.grant_local(key.fingerprint, Some(&host_key(1)), key.confirm);

        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalBound { dest: host_key(2) },
                &login(b"sid"),
                Some(b"sid"),
                false,
                &approvals,
                true,
                false,
            ),
            Decision::PromptApprove,
            "a different destination must not reuse the approval"
        );
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalUnbound,
                &login(b"sid"),
                None,
                false,
                &approvals,
                true,
                false,
            ),
            Decision::PromptApprove,
            "a bound approval must not cover unbound use"
        );
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalBound { dest: host_key(1) },
                &login(b"sid"),
                Some(b"sid"),
                false,
                &approvals,
                true,
                false,
            ),
            Decision::Sign,
            "the destination it was actually granted for still signs"
        );
    }

    /// S2: "Commit or tag signing — SSHSIG data, no binding — As S1."
    #[test]
    fn s2_sshsig_unbound_behaves_like_s1() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S2 locked",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: SSHSIG,
            login_session_id: None,
            locked: true,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::PromptUnlock,
        });
        run(Case {
            name: "S2 unlocked, approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: SSHSIG,
            login_session_id: None,
            locked: false,
            approved: true,
            may_prompt: true,
            backoff: false,
            expect: Decision::Sign,
        });
    }

    #[test]
    fn s3_forwarded_login_with_a_destination() {
        let key = key(SshKeyConfirm::Once, true);
        let class = forwarded_class(b"fwd-sid", 2, Some(3));
        let ConnectionClass::Forwarded { .. } = &class else {
            unreachable!()
        };
        run(Case {
            name: "S3 locked",
            key,
            class: class.clone(),
            purpose: login(b"dest-sid"),
            login_session_id: Some(b"dest-sid"),
            locked: true,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::PromptUnlock,
        });
        run(Case {
            name: "S3 unlocked, not yet approved",
            key,
            class: class.clone(),
            purpose: login(b"dest-sid"),
            login_session_id: Some(b"dest-sid"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::PromptApprove,
        });
        run(Case {
            name: "S3 unlocked, approved",
            key,
            class,
            purpose: login(b"dest-sid"),
            login_session_id: Some(b"dest-sid"),
            locked: false,
            approved: true,
            may_prompt: true,
            backoff: false,
            expect: Decision::Sign,
        });
    }

    #[test]
    fn s3_forwarded_key_with_forwarded_false_is_never_usable() {
        let key = key(SshKeyConfirm::Once, false);
        run(Case {
            name: "forwarded = false",
            key,
            class: forwarded_class(b"fwd-sid", 2, Some(3)),
            purpose: login(b"dest-sid"),
            login_session_id: Some(b"dest-sid"),
            locked: false,
            approved: true,
            may_prompt: true,
            backoff: false,
            expect: Decision::Refuse(Refusal::KeyNotForwardable),
        });
    }

    #[test]
    fn s3_forwarded_sshsig_is_refused() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "forwarded SSHSIG",
            key,
            class: forwarded_class(b"fwd-sid", 2, Some(3)),
            purpose: SSHSIG,
            login_session_id: Some(b"dest-sid"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Refuse(Refusal::ForwardedNonLogin),
        });
    }

    #[test]
    fn s3_forwarded_login_without_a_destination_is_refused() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "no destination bound yet",
            key,
            class: forwarded_class(b"fwd-sid", 2, None),
            purpose: login(b"fwd-sid"),
            login_session_id: Some(b"fwd-sid"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Refuse(Refusal::NoForwardedDestination),
        });
    }

    #[test]
    fn s3_forwarded_login_session_mismatch_is_refused() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "session mismatch",
            key,
            class: forwarded_class(b"fwd-sid", 2, Some(3)),
            purpose: login(b"wrong-sid"),
            login_session_id: Some(b"dest-sid"),
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Refuse(Refusal::SessionMismatch),
        });
    }

    /// An approval for one forwarding session, host or destination is
    /// never reused for another.
    #[test]
    fn forwarded_approvals_are_not_reused_across_scopes() {
        let key = key(SshKeyConfirm::Once, true);
        let mut approvals = Approvals::new();
        let host = host_key(2);
        let dest = host_key(3);
        approvals.grant_forwarded(key.fingerprint, b"session-a", &host, &dest);

        let other_session = ConnectionClass::Forwarded {
            host: host.clone(),
            session: b"session-b".to_vec(),
            dest: Some(dest.clone()),
        };
        assert_eq!(
            decide(
                key,
                &other_session,
                &login(b"dest-sid"),
                Some(b"dest-sid"),
                false,
                &approvals,
                true,
                false,
            ),
            Decision::PromptApprove,
            "a different forwarding session must not reuse the approval"
        );

        let other_dest = ConnectionClass::Forwarded {
            host: host.clone(),
            session: b"session-a".to_vec(),
            dest: Some(host_key(4)),
        };
        assert_eq!(
            decide(
                key,
                &other_dest,
                &login(b"dest-sid"),
                Some(b"dest-sid"),
                false,
                &approvals,
                true,
                false,
            ),
            Decision::PromptApprove,
            "a different destination must not reuse the approval"
        );
    }

    #[test]
    fn s4_outside_the_desktop_locked_is_refused_without_a_pending_entry() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S4 locked",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: true,
            approved: false,
            may_prompt: false,
            backoff: false,
            expect: Decision::Refuse(Refusal::Locked),
        });
    }

    #[test]
    fn s4_outside_the_desktop_unapproved_needs_approval() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S4 unlocked, not approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: false,
            may_prompt: false,
            backoff: false,
            expect: Decision::Refuse(Refusal::NeedsApproval),
        });
    }

    #[test]
    fn s4_outside_the_desktop_already_approved_signs() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S4 unlocked, approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: true,
            may_prompt: false,
            backoff: false,
            expect: Decision::Sign,
        });
    }

    /// S5: "Screen locked or machine suspended — Everything is already
    /// locked. No prompt."
    #[test]
    fn s5_screen_locked_refuses_without_prompting() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S5",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: true,
            approved: false,
            may_prompt: false, // Desk::may_prompt is false while the screen is locked
            backoff: false,
            expect: Decision::Refuse(Refusal::Locked),
        });
    }

    /// S6: "Indistinguishable from S1 ... with backoff after a cancel."
    #[test]
    fn s6_backoff_refuses_locked_and_unapproved_alike() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "S6 locked, in backoff",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: true,
            approved: false,
            may_prompt: true,
            backoff: true,
            expect: Decision::Refuse(Refusal::Backoff),
        });
        run(Case {
            name: "S6 unlocked, unapproved, in backoff",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: true,
            expect: Decision::Refuse(Refusal::Backoff),
        });
    }

    /// Backoff never blocks a signature that wouldn't have needed a
    /// prompt anyway — only the prompt-needing path is suppressed
    /// (`docs/ssh-agent.md` § 6.6: "fail at once without prompting").
    #[test]
    fn backoff_does_not_block_an_already_approved_signature() {
        let key = key(SshKeyConfirm::Once, true);
        run(Case {
            name: "backoff, already approved",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: true,
            may_prompt: true,
            backoff: true,
            expect: Decision::Sign,
        });
    }

    #[test]
    fn confirm_never_signs_without_ever_approving() {
        let key = key(SshKeyConfirm::Never, true);
        run(Case {
            name: "confirm = never",
            key,
            class: ConnectionClass::LocalUnbound,
            purpose: login(b"sid"),
            login_session_id: None,
            locked: false,
            approved: false,
            may_prompt: true,
            backoff: false,
            expect: Decision::Sign,
        });
    }

    #[test]
    fn confirm_always_asks_even_when_a_prior_signature_was_approved() {
        let key = key(SshKeyConfirm::Always, true);
        let mut approvals = Approvals::new();
        approvals.grant_local(key.fingerprint, None, key.confirm);
        // Granting records a one-shot approval; decide() itself never
        // consumes it, so it's still visible here...
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalUnbound,
                &login(b"sid"),
                None,
                false,
                &approvals,
                true,
                false,
            ),
            Decision::Sign
        );
        // ...until the caller consumes it once that signature goes
        // through, after which the next one asks again.
        approvals.consume_local(key.fingerprint, None);
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalUnbound,
                &login(b"sid"),
                None,
                false,
                &approvals,
                true,
                false,
            ),
            Decision::PromptApprove
        );
    }

    /// An unlock prompt's answer counts as the signature's approval: once
    /// the caller grants it (simulating what happens after a successful
    /// `PromptUnlock`), the same key signs without asking again.
    #[test]
    fn an_unlock_counts_as_the_approval() {
        let key = key(SshKeyConfirm::Once, true);
        let mut approvals = Approvals::new();
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalUnbound,
                &login(b"sid"),
                None,
                true,
                &approvals,
                true,
                false,
            ),
            Decision::PromptUnlock
        );
        approvals.grant_local(key.fingerprint, None, key.confirm);
        assert_eq!(
            decide(
                key,
                &ConnectionClass::LocalUnbound,
                &login(b"sid"),
                None,
                false,
                &approvals,
                true,
                false,
            ),
            Decision::Sign
        );
    }

    #[test]
    fn listable_excludes_non_forwarded_keys_from_forwarded_connections() {
        let class = forwarded_class(b"sid", 1, Some(2));
        assert!(!listable(&class, false));
        assert!(listable(&class, true));
    }

    #[test]
    fn listable_includes_every_served_key_locally() {
        for class in [
            ConnectionClass::LocalUnbound,
            ConnectionClass::LocalBound { dest: host_key(1) },
        ] {
            assert!(listable(&class, false));
            assert!(listable(&class, true));
        }
    }

    #[test]
    fn hints_match_the_documented_format() {
        assert_eq!(
            needs_approval_hint("github"),
            "github (needs approval: kpa ssh approve)"
        );
        assert_eq!(
            locked_hint("personal SHA256:3fQ…", "personal"),
            "personal SHA256:3fQ… (locked: kpa unlock personal)"
        );
    }

    #[test]
    fn only_a_successful_local_signature_is_idle_activity() {
        assert!(is_idle_activity(&ConnectionClass::LocalUnbound, true));
        assert!(!is_idle_activity(&ConnectionClass::LocalUnbound, false));
        assert!(!is_idle_activity(
            &forwarded_class(b"sid", 1, Some(2)),
            true
        ));
        assert!(!is_idle_activity(
            &forwarded_class(b"sid", 1, Some(2)),
            false
        ));
    }
}
