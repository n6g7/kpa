//! The sign flow (`docs/ssh-agent.md` § 6.3, § 6.6, § 6.7, § 6.9): a
//! `SIGN_REQUEST` becomes a signature, or `Failure` for every refusal.
//!
//! [`Agent::sign_or_refuse`] puts the authorization around
//! [`signer::sign`], which signs and nothing else:
//!
//! 1. Policy: [`authorize_sign`] says whether the request is allowed at
//!    all, and which approval it needs.
//! 2. Sign if the request is ready ([`Agent::sign_if_ready`]): the database
//!    is unlocked and holds the approval, checked and signed in one hold of
//!    the database. Most requests end here, waiting for nobody. A request
//!    that rode on an approval for one signature uses it up in the same
//!    hold.
//! 3. Otherwise the refusal says what is lacking, and the user is asked for
//!    it ([`prompts`](super::prompts)): the unlock of a locked database, then
//!    the approval of the key. A requester who may not be asked is refused
//!    before it waits for its turn, and recorded as pending when it lacks
//!    an approval, for the approval to be granted later (`docs/ssh-agent.md`
//!    § 6.8). A prompt the user cancels, or leaves unanswered, holds the
//!    database's prompts back for a while (backoff).
//! 4. Sign what the user allowed ([`Agent::sign_allowed`]), unless a lock
//!    came in since, or sign if the request is ready now.
//!
//! Every hold runs behind the core's freshness guard, so a database whose
//! file changed is locked, and its token cancelled, before the hold sees it.
//! A forwarded signature is made like any other, with an approval of its own
//! forwarding session, and never resets the idle timer.

use std::time::{SystemTime, UNIX_EPOCH};

use ssh_key::Fingerprint;

use super::hold::Hold;
use super::request::{Request, log_sign};
use super::{Agent, signer};
use crate::authn::Requester;
use crate::cancel::CancelToken;
use crate::databases::VaultError;
use crate::frontends::ssh_agent::authz::{Refusal, authorize_sign};
use crate::frontends::ssh_agent::bind::ConnectionClass;
use crate::frontends::ssh_agent::wire::{AgentResponse, SignRequest};
use crate::output;
use crate::prompt::Declined;
use crate::ssh::approvals::{Approvals, GrantSource, SignatureApproval};
use crate::ssh::keys::ServedKey;
use crate::ssh::known_hosts::HostNames;

/// The longest key name a log line carries: a `[[database.ssh_key]]`
/// override's `name`, escaped and capped like an identity comment.
const MAX_LOGGED_NAME_LEN: usize = 128;

/// Why a request wasn't signed, as its log line says it.
#[derive(Debug, thiserror::Error)]
pub(super) enum Refused {
    #[error("refused: database locked")]
    Locked,
    /// The database doesn't serve the key: the request found it in the
    /// cache just as an unlock came in.
    #[error("refused: key no longer served")]
    NotServed,
    #[error("refused: {0}")]
    Policy(Refusal),
    /// The key needs an approval nothing covers, and no prompt may appear
    /// to ask for one.
    #[error("refused: needs approval")]
    NeedsApproval,
    /// A prompt the user cancelled or left unanswered holds this
    /// database's prompts back for a while, and this signature needs one.
    #[error("refused: prompts held back after a cancel")]
    BackingOff,
    #[error("refused: SHA-1 RSA signature")]
    Sha1Rsa,
    /// An unlock of this database is under way already: a `kpa unlock` is
    /// prompting for it.
    #[error("refused: an unlock is already in progress")]
    UnlockInProgress,
    /// The confirm prompt ended without an `Allow`.
    #[error("approval {0}")]
    Declined(Declined),
    /// The unlock prompt ended without a password.
    #[error("unlock {0}")]
    UnlockDeclined(Declined),
    /// The password didn't open the database, or the file wouldn't read.
    #[error("unlock failed: {0}")]
    UnlockFailed(VaultError),
    #[error("prompt failed: {0}")]
    PromptFailed(std::io::Error),
    #[error("loading or signing failed")]
    SigningFailed,
}

/// What a request still lacks before it can be signed.
pub(super) enum Lacking {
    /// The database is locked.
    Unlock,
    /// The approval the request needs, which nothing covers.
    Approval(Box<Asked>),
}

/// An approval a request needs, and the unlock the database was in when
/// nothing covered it. The user is asked for it, and what they allow is
/// this.
pub(super) struct Asked {
    pub(super) approval: SignatureApproval,
    /// A lock cancels it, for good: it ends the prompt for the approval, and
    /// tells the signature that follows an answer that the answer is stale.
    pub(super) unlock: CancelToken,
}

impl Lacking {
    /// The refusal for a request that can't be asked for it.
    pub(super) fn refusal(&self) -> Refused {
        match self {
            Lacking::Unlock => Refused::Locked,
            Lacking::Approval(_) => Refused::NeedsApproval,
        }
    }
}

impl Hold<'_> {
    /// The key the unlocked database serves under `fingerprint`.
    pub(super) fn served(&self, fingerprint: Fingerprint) -> Result<&ServedKey, Refused> {
        let (_, scanned) = self.unlocked().ok_or(Refused::Locked)?;
        scanned
            .served
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .ok_or(Refused::NotServed)
    }

    /// What the request lacks here: the unlock of a locked database, else
    /// the approval it `needed` that nothing covers. The unlock the approval
    /// is lacking in is taken here, before anything reads the display
    /// session.
    pub(super) fn lacking(
        &self,
        approvals: &Approvals,
        needed: Option<&SignatureApproval>,
    ) -> Option<Lacking> {
        let Some(open) = self.open() else {
            return Some(Lacking::Unlock);
        };
        needed
            .filter(|approval| !approvals.covers(open, &approval.scope, self.now()))
            .map(|approval| {
                Lacking::Approval(Box::new(Asked {
                    approval: approval.clone(),
                    unlock: open.unlock_token(),
                }))
            })
    }
}

impl Agent {
    /// Answers one `SIGN_REQUEST`: a signature, or `Failure` for a key it
    /// doesn't serve and for every refusal.
    pub fn sign(
        &self,
        class: &ConnectionClass,
        sign: &SignRequest,
        login_session_id: Option<&[u8]>,
        requester: &Requester,
    ) -> AgentResponse {
        let Some(request) = Request::parse(class, sign, login_session_id) else {
            return AgentResponse::Failure;
        };
        // `known_hosts` is read once for the request, and what it says about
        // its hosts is what the prompts, the approval and the log line say.
        let request = if request.has_hosts() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            request.named(&HostNames::read(&self.known_hosts), now)
        } else {
            request
        };
        let Some(found) = self.find_key(request.fingerprint) else {
            return AgentResponse::Failure;
        };
        let db = found.database.as_str();
        let outcome = self.sign_or_refuse(&found, &request, requester);
        log_sign(db, self.configured_name(db, &request), &request, &outcome);
        match outcome {
            Ok(signature) => AgentResponse::SignResponse(signature),
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Signs `request` with the key `found` names, if the policy lets it
    /// and, when it has to ask for something first, once the user has
    /// answered. `found` is the key as `find_key` lists it: from its scan if
    /// its database is unlocked, from the cache if not.
    fn sign_or_refuse(
        &self,
        found: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
    ) -> Result<Vec<u8>, Refused> {
        if !signer::supported(request.key.key_data(), request.sign.flags) {
            return Err(Refused::Sha1Rsa);
        }
        let db = found.database.as_str();

        // 1. Policy.
        let approval = authorize_sign(
            found,
            request.class,
            &request.purpose,
            request.login_session_id,
        )
        .map_err(Refused::Policy)?
        .map(|mut approval| {
            approval.scope = approval.scope.with_host_names(
                request
                    .destination
                    .as_ref()
                    .and_then(|host| host.name.clone()),
                request.forwarding_host().and_then(|host| host.name.clone()),
            );
            approval
        });

        // 2. Nothing to ask: sign. Most requests end here, in one hold,
        // waiting for nobody.
        match self.sign_if_ready(db, request, approval.as_ref()) {
            Err(Refused::Locked | Refused::NeedsApproval) => {}
            answer => return answer,
        }

        // 3. Something to ask. Refused here if the user can't be asked.
        self.check_may_prompt(found, request, requester, approval.as_ref())?;

        // 4. Ask. One signature at a time asks for a database, and keeps its
        // turn until it has signed, so the next one finds what this one got.
        // A prompt the user cancelled or left unanswered holds the
        // database's prompts back.
        let _turn = self.wait_for_turn(db)?;
        let allowed = self
            .prompt_for_what_is_lacking(found, request, requester, approval.as_ref())
            .inspect_err(|refused| {
                if refused.starts_backoff() {
                    self.back_off(db);
                }
            })?;

        // 5. Sign.
        match allowed {
            Some(asked) => self.sign_allowed(db, request, asked),
            None => self.sign_if_ready(db, request, approval.as_ref()),
        }
    }

    /// Signs `request`, in one hold of `db`, if the database is unlocked and
    /// holds the approval it `needed`. Refused as [`Refused::Locked`]
    /// or [`Refused::NeedsApproval`] otherwise, which names what to ask
    /// for.
    fn sign_if_ready(
        &self,
        db: &str,
        request: &Request<'_>,
        needed: Option<&SignatureApproval>,
    ) -> Result<Vec<u8>, Refused> {
        let mut hold = self.hold(db)?;
        if let Some(lacking) = hold.lacking(&self.approvals, needed) {
            return Err(lacking.refusal());
        }
        let signature = sign_and_touch(&mut hold, request)?;
        // The approval this request rode on counts the signature, now that
        // it is made, and an approval for one signature is used up: a failed
        // one leaves it for the retry.
        if let Some(approval) = needed {
            let wall = hold.wall();
            let open = hold.open().ok_or(Refused::Locked)?;
            self.approvals.used(open, &approval.scope, wall);
        }
        Ok(signature)
    }

    /// Signs what the user allowed, in one hold of `db`, and records the
    /// approval their answer gave. Refused as [`Refused::Locked`] if a lock
    /// came in since they were asked.
    fn sign_allowed(
        &self,
        db: &str,
        request: &Request<'_>,
        allowed: Asked,
    ) -> Result<Vec<u8>, Refused> {
        let mut hold = self.hold(db)?;
        if allowed.unlock.is_cancelled() {
            return Err(Refused::Locked);
        }
        let signature = sign_and_touch(&mut hold, request)?;
        if allowed.approval.remember {
            let wall = hold.wall();
            let open = hold.open().ok_or(Refused::Locked)?;
            let scope = allowed.approval.scope;
            self.approvals
                .grant(open, scope.clone(), GrantSource::OnScreen, wall);
            // The signature the user allowed is the first one it covers.
            self.approvals.used(open, &scope, wall);
        }
        Ok(signature)
    }

    /// The name `db`'s config gives `request`'s key, if a
    /// `[[database.ssh_key]]` override names it: config, so it may be
    /// logged. Never the resolved `ServedKey::name`, which falls back to the
    /// entry's title, vault content kpa keeps out of its own output (G-4).
    fn configured_name(&self, db: &str, request: &Request<'_>) -> Option<String> {
        self.databases
            .configs()
            .iter()
            .find(|cfg| cfg.name == db)?
            .ssh_key_settings(request.fingerprint)
            .name
            .map(|name| output::escape_one_line(&name, MAX_LOGGED_NAME_LEN))
    }
}

/// Signs `request` with the hold's key and, if the connection is local,
/// resets the database's idle timer. A forwarded signature is a remote
/// host's, and doesn't keep the database unlocked (`docs/ssh-agent.md` § 6.9).
fn sign_and_touch(hold: &mut Hold<'_>, request: &Request<'_>) -> Result<Vec<u8>, Refused> {
    let signature = signer::sign(
        hold,
        request.fingerprint,
        &request.sign.data,
        request.sign.flags,
    )?;
    if !request.class.is_forwarded() {
        hold.touch();
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use ssh_key::encoding::Decode;
    use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
    use zeroize::Zeroizing;

    use super::super::request::sign_line;
    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::databases::testing::PASSWORD;
    use crate::display_session::DisplaySession;
    use crate::frontends::ssh_agent::testing::{
        Fixture, IDLE, Options, SESSION, certified_bind, login_data, outside, outside_running,
        requester, signed_bind,
    };
    use crate::frontends::ssh_agent::wire::SignFlags;
    use crate::prompt::{ConfirmAnswer, PromptOutcome, Step};
    use crate::ssh::approvals::{GrantSource, Scope};
    use crate::ssh::known_hosts::HostNames;
    use crate::ssh::testing::{RSA_3072, database, key_entry, requested, served, test_key};

    /// A fixture whose cancelled prompts hold nothing back: the backoff has
    /// passed by the next request.
    fn no_backoff() -> Options {
        Options {
            backoff: Duration::ZERO,
            ..Options::default()
        }
    }

    /// A prompt that types the master password.
    fn typed() -> Step<Zeroizing<String>> {
        Step::new(PromptOutcome::Answer(Zeroizing::new(PASSWORD.to_string())))
    }

    fn request_with(key: &PrivateKey, flags: u32) -> SignRequest {
        SignRequest {
            key_blob: key.public_key().to_bytes().expect("key encodes"),
            data: b"data to sign".to_vec(),
            flags: SignFlags::new(flags),
        }
    }

    fn sign_as(fx: &Fixture, key: &PrivateKey, class: &ConnectionClass) -> AgentResponse {
        fx.agent
            .sign(class, &request_with(key, 0), None, &requester())
    }

    fn sign(fx: &Fixture, key: &PrivateKey) -> AgentResponse {
        sign_as(fx, key, &ConnectionClass::LocalUnbound)
    }

    /// `key` as `personal` serves it, as `find_key` lists it.
    fn found(fx: &Fixture, key: &PrivateKey) -> ServedKey {
        fx.agent
            .find_key(key.public_key().fingerprint(HashAlg::Sha256))
            .expect("served")
    }

    /// What `sign` would log for an unbound request for `key`.
    fn outcome(fx: &Fixture, key: &PrivateKey) -> Result<Vec<u8>, Refused> {
        let sign = request_with(key, 0);
        let request = Request::parse(&ConnectionClass::LocalUnbound, &sign, None).expect("parses");
        fx.agent
            .sign_or_refuse(&found(fx, key), &request, &requester())
    }

    fn signed(response: &AgentResponse) -> bool {
        matches!(response, AgentResponse::SignResponse(_))
    }

    fn scope(key: &PrivateKey) -> Scope {
        Scope::local(&served(key.public_key()), None)
    }

    /// Whether `key` is approved for unbound use in `personal`.
    fn approved(fx: &Fixture, key: &PrivateKey) -> bool {
        fx.is_approved(&scope(key))
    }

    /// A step that locks `personal`.
    fn locking(fx: &Fixture) -> impl FnOnce() + Send + 'static {
        let databases = Arc::clone(&fx.databases);
        move || databases.lock("personal").expect("configured")
    }

    #[test]
    fn confirm_never_signs_without_prompting_and_the_signature_verifies() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);

        let AgentResponse::SignResponse(raw) = sign(&fx, &key) else {
            panic!("expected a signature");
        };
        let signature = Signature::decode(&mut raw.as_slice()).expect("signature decodes");
        signature::Verifier::verify(key.public_key(), b"data to sign", &signature)
            .expect("verifies");
        assert!(fx.confirms.shown().is_empty());
    }

    #[test]
    fn confirm_once_prompts_for_the_first_signature_only() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow());

        assert!(signed(&sign(&fx, &key)));
        assert!(approved(&fx, &key));
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.confirms.shown(), ["Approve use of key \"github\"?"]);
    }

    #[test]
    fn confirm_always_prompts_for_every_signature_and_stores_nothing() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        fx.confirms.push(Step::allow());
        fx.confirms.push(Step::allow());

        assert!(signed(&sign(&fx, &key)));
        assert!(!approved(&fx, &key));
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.confirms.shown().len(), 2);
    }

    /// A request that arrives while an `always` key's prompt is up gets a
    /// prompt of its own, here answered no, rather than riding on the
    /// first one's `Allow`: one `Allow`, one signature.
    #[test]
    fn a_request_during_the_prompt_gets_its_own_prompt() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        let (second_tx, second) = mpsc::channel();
        let (second_agent, second_key) = (Arc::clone(&fx.agent), key.clone());
        fx.confirms.push(Step::allow().while_up(move || {
            let request = std::thread::spawn(move || {
                second_agent.sign(
                    &ConnectionClass::LocalUnbound,
                    &request_with(&second_key, 0),
                    None,
                    &requester(),
                )
            });
            second_tx.send(request).expect("send");
        }));
        fx.confirms
            .push(Step::new(PromptOutcome::Answer(ConfirmAnswer::Deny)));

        assert!(signed(&sign(&fx, &key)));
        let second = second.recv().expect("second request");
        assert!(!signed(&second.join().expect("second request")));
        assert_eq!(fx.confirms.shown().len(), 2);
    }

    /// A requester who may not be asked is refused at once, while another
    /// signature's prompt for the same database is up: it never waits for
    /// that prompt's turn.
    #[test]
    fn a_requester_who_cannot_be_asked_does_not_wait_for_a_prompt() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let (outcome_tx, outcome) = mpsc::channel();
        let (second_agent, second_key) = (Arc::clone(&fx.agent), key.clone());
        fx.confirms.push(Step::allow().while_up(move || {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let response = second_agent.sign(
                    &ConnectionClass::LocalUnbound,
                    &request_with(&second_key, 0),
                    None,
                    &outside(),
                );
                let _ = tx.send(response);
            });
            outcome_tx
                .send(rx.recv_timeout(Duration::from_secs(5)))
                .expect("send");
        }));

        assert!(signed(&sign(&fx, &key)));
        let refused = outcome
            .recv()
            .expect("outcome")
            .expect("refused without waiting");
        assert!(!signed(&refused));
        assert_eq!(fx.confirms.shown().len(), 1);
    }

    /// Every answer other than `Allow` refuses, and grants nothing: once
    /// any backoff a cancel or a timeout started has passed, the next
    /// request asks again.
    #[test]
    fn a_prompt_that_does_not_allow_refuses_and_grants_nothing() {
        let key = test_key(1);
        let declines = [
            ("deny", PromptOutcome::Answer(ConfirmAnswer::Deny)),
            ("cancel", PromptOutcome::Cancelled),
            ("time out", PromptOutcome::TimedOut),
        ];
        for (name, declined) in declines {
            let fx = Fixture::unlocked_with(&key, SshKeyConfirm::Once, no_backoff());
            fx.confirms.push(Step::new(declined));
            fx.confirms.push(Step::fails());
            assert!(
                matches!(outcome(&fx, &key), Err(Refused::Declined(_))),
                "{name}"
            );
            assert!(
                matches!(outcome(&fx, &key), Err(Refused::PromptFailed(_))),
                "{name}"
            );
            assert_eq!(fx.confirms.shown().len(), 2, "{name}");
            assert!(!approved(&fx, &key), "{name}");
        }
    }

    /// The prompts a cancel or a timeout ended hold the database's prompts
    /// back, and nothing else does: not a deny, nor a prompt that doesn't
    /// run.
    #[test]
    fn only_a_cancel_or_a_timeout_backs_the_database_off() {
        let key = test_key(1);
        let ends = [
            (
                "deny",
                Step::new(PromptOutcome::Answer(ConfirmAnswer::Deny)),
                false,
            ),
            ("fail", Step::fails(), false),
            ("cancel", Step::new(PromptOutcome::Cancelled), true),
            ("time out", Step::new(PromptOutcome::TimedOut), true),
        ];
        for (name, end, backs_off) in ends {
            let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
            fx.confirms.push(end);
            assert!(outcome(&fx, &key).is_err(), "{name}");

            fx.confirms.push(Step::allow());
            let second = outcome(&fx, &key);
            assert_eq!(
                matches!(second, Err(Refused::BackingOff)),
                backs_off,
                "{name}"
            );
            assert_eq!(
                fx.confirms.shown().len(),
                if backs_off { 1 } else { 2 },
                "{name}"
            );
        }
    }

    /// Cancelling a confirm prompt makes the next request that needs a
    /// prompt fail at once, without one, until the backoff has passed; then
    /// it asks again.
    #[test]
    fn a_cancelled_prompt_backs_off_until_the_backoff_has_passed() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::new(PromptOutcome::Cancelled));
        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::Declined(Declined::Cancelled))
        ));
        assert!(matches!(outcome(&fx, &key), Err(Refused::BackingOff)));
        assert!(matches!(outcome(&fx, &key), Err(Refused::BackingOff)));
        assert_eq!(fx.confirms.shown().len(), 1);

        let fx = Fixture::unlocked_with(&key, SshKeyConfirm::Once, no_backoff());
        fx.confirms.push(Step::new(PromptOutcome::Cancelled));
        assert!(outcome(&fx, &key).is_err());
        fx.confirms.push(Step::allow());
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.confirms.shown().len(), 2);
    }

    /// Backoff holds back prompts only: a signature that needs none still
    /// signs, whether its key never asks or is already approved.
    #[test]
    fn a_signature_that_needs_no_prompt_signs_during_a_backoff() {
        let key = test_key(1);
        let backed_off = |confirm| {
            let fx = Fixture::unlocked(&key, confirm);
            fx.agent.back_off("personal");
            fx
        };

        let never = backed_off(SshKeyConfirm::Never);
        assert!(signed(&sign(&never, &key)));
        assert!(never.confirms.shown().is_empty());

        let once = backed_off(SshKeyConfirm::Once);
        assert!(matches!(outcome(&once, &key), Err(Refused::BackingOff)));
        once.grant(scope(&key));
        assert!(signed(&sign(&once, &key)));
        assert!(once.confirms.shown().is_empty());
    }

    /// A lock leaves a backoff in place: the locked database is not
    /// offered an unlock prompt until it has passed.
    #[test]
    fn a_lock_does_not_end_a_backoff() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::new(PromptOutcome::Cancelled));
        assert!(outcome(&fx, &key).is_err());

        fx.databases.lock("personal").expect("configured");

        assert!(matches!(outcome(&fx, &key), Err(Refused::BackingOff)));
        assert!(fx.unlocks.shown().is_empty());
    }

    /// An unlock, whoever prompted for it, ends a backoff: the user is
    /// here and unlocking.
    #[test]
    fn an_unlock_ends_a_backoff() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Once);
        fx.unlocks.push(Step::new(PromptOutcome::Cancelled));
        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::UnlockDeclined(Declined::Cancelled))
        ));
        assert!(matches!(outcome(&fx, &key), Err(Refused::BackingOff)));

        // The user types `kpa unlock`.
        fx.unlock(&key);

        fx.confirms.push(Step::allow());
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(
            fx.confirms.shown(),
            ["Approve use of key \"github\"?".to_string()]
        );
    }

    /// A locked database's signature runs the unlock, which says why and
    /// approves nothing, and asks for the key's approval after it: a `once`
    /// key is approved for good, an `always` key for this signature only,
    /// and a `never` key needs none.
    #[test]
    fn the_unlock_is_asked_first_and_the_approval_after() {
        let key = test_key(1);
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256);
        let named = format!("Unlock database personal to use key \"personal {fingerprint}\"?");
        // The unlock names the key as the locked database's cache does. Once
        // it is unlocked the key is read again, and the approval, which is
        // listed by `kpa ssh grants`, names it by its entry's title.
        let approval = "Approve use of key \"github\"?";
        for (confirm, asked, kept) in [
            (SshKeyConfirm::Once, true, true),
            (SshKeyConfirm::Always, true, false),
            (SshKeyConfirm::Never, false, false),
        ] {
            let fx = Fixture::locked(&key, confirm);
            fx.unlocks.push(typed());
            fx.confirms.push(Step::allow());

            assert!(signed(&sign(&fx, &key)));
            assert_eq!(fx.unlocks.shown(), [named.as_str()]);
            let expected: Vec<&str> = if asked { vec![approval] } else { vec![] };
            assert_eq!(fx.confirms.shown(), expected);
            assert_eq!(approved(&fx, &key), kept);
            let names: Vec<_> = fx
                .grants()
                .iter()
                .map(|g| g.scope.key().name.clone())
                .collect();
            assert_eq!(
                names,
                if kept {
                    vec!["github"]
                } else {
                    Vec::<&str>::new()
                }
            );
        }
    }

    /// Answering the unlock is not the approval: a denied approval after it
    /// signs nothing, and leaves the database unlocked.
    #[test]
    fn an_unlock_that_was_answered_does_not_approve_the_key() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Once);
        fx.unlocks.push(typed());
        fx.confirms
            .push(Step::new(PromptOutcome::Answer(ConfirmAnswer::Deny)));

        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::Declined(Declined::Denied))
        ));
        assert!(fx.is_unlocked());
        assert!(!approved(&fx, &key));
    }

    /// How long a test lets signers it started from inside a prompt run into
    /// the prompt's turn. What the tests assert holds whichever way that race
    /// goes; the pause is what makes them exercise the wait.
    const SETTLE: Duration = Duration::from_millis(300);

    /// Starts `n` signers and gives them time to wait for their turn. Their
    /// handles go to `tx`.
    fn signers(
        n: usize,
        fx: &Fixture,
        key: &PrivateKey,
        tx: &mpsc::Sender<std::thread::JoinHandle<AgentResponse>>,
    ) {
        for _ in 0..n {
            let (agent, key) = (Arc::clone(&fx.agent), key.clone());
            let signer = std::thread::spawn(move || {
                agent.sign(
                    &ConnectionClass::LocalUnbound,
                    &request_with(&key, 0),
                    None,
                    &requester(),
                )
            });
            tx.send(signer).expect("send");
        }
        std::thread::sleep(SETTLE);
    }

    /// The user unlocks while a signature waits for its turn: it looks
    /// again, finds the database unlocked, prompts for no unlock and asks
    /// for the approval alone.
    #[test]
    fn an_unlock_that_finds_the_database_open_is_not_an_approval() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow());

        let turn = fx.agent.turns["personal"].lock().expect("turn");
        let (tx, signer) = mpsc::channel();
        signers(1, &fx, &key, &tx);
        fx.unlock(&key);
        drop(turn);

        assert!(signed(
            &signer.recv().expect("signer").join().expect("signer")
        ));
        assert!(fx.unlocks.shown().is_empty());
        assert_eq!(fx.confirms.shown().len(), 1);
    }

    #[test]
    fn a_cancelled_unlock_refuses_and_backs_off() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        fx.unlocks.push(Step::new(PromptOutcome::TimedOut));

        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::UnlockDeclined(Declined::TimedOut))
        ));
        assert!(matches!(outcome(&fx, &key), Err(Refused::BackingOff)));
        assert_eq!(fx.unlocks.shown().len(), 1);

        let fx = Fixture::locked_with(&key, SshKeyConfirm::Never, no_backoff());
        fx.unlocks.push(Step::new(PromptOutcome::TimedOut));
        assert!(outcome(&fx, &key).is_err());
        fx.unlocks.push(typed());
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.unlocks.shown().len(), 2);
    }

    /// Nobody to answer, no prompt: a locked database is refused without
    /// an unlock prompt and without a backoff.
    #[test]
    fn nothing_prompts_to_unlock_where_no_prompt_may_appear() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Once).without_prompts();

        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(fx.unlocks.shown().is_empty() && fx.confirms.shown().is_empty());
        assert!(!fx.state.inner().backoff.contains_key("personal"));
    }

    /// A display session that is locked takes no prompt either, and the
    /// refusal gives the unlock's claim back.
    #[test]
    fn no_unlock_prompt_is_raised_while_the_display_session_is_locked() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        fx.display.set(DisplaySession::Locked {
            id: SESSION.to_string(),
            active: true,
        });

        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(
            fx.unlocks.shown().is_empty(),
            "a prompt ran behind the locker"
        );
        assert!(matches!(
            fx.databases.begin_unlock("personal"),
            Ok(crate::databases::Begin::Started(_))
        ));
    }

    /// An unlock that is already in progress (a `kpa unlock` is prompting
    /// for it) refuses the signature, with no prompt of its own.
    #[test]
    fn an_unlock_in_progress_refuses_the_signature() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        let claim = fx.databases.begin_unlock("personal").expect("claim");

        assert!(matches!(outcome(&fx, &key), Err(Refused::UnlockInProgress)));
        assert!(fx.unlocks.shown().is_empty());
        drop(claim);
    }

    /// A lock while the unlock prompt is up ends it and fails the
    /// signature, without a backoff: the next request asks again.
    #[test]
    fn a_lock_while_the_unlock_prompt_is_up_fails_the_signature() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        fx.unlocks.push(typed().while_up(locking(&fx)));

        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::UnlockDeclined(Declined::Interrupted))
        ));
        assert!(!fx.is_unlocked());

        fx.unlocks.push(typed());
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.unlocks.shown().len(), 2);
    }

    /// A password that doesn't open the database is the unlock failing, and
    /// holds nothing back: any process can guess offline from the file.
    #[test]
    fn a_failed_unlock_refuses_without_a_backoff() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        fx.unlocks
            .push(Step::new(PromptOutcome::Answer(Zeroizing::new(
                "not the password".to_string(),
            ))));

        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::UnlockFailed(VaultError::WrongCredentials))
        ));
        assert!(!fx.state.inner().backoff.contains_key("personal"));
    }

    /// Two signers for a locked database get one unlock prompt and one
    /// confirm prompt: the second waits for the first, then looks again and
    /// finds the database open and the key approved.
    #[test]
    fn concurrent_signers_share_one_unlock_prompt() {
        let key = test_key(1);
        let fx = Arc::new(Fixture::locked(&key, SshKeyConfirm::Once));
        let (tx, second) = mpsc::channel();
        let (inner, inner_key) = (Arc::clone(&fx), key.clone());
        fx.unlocks
            .push(typed().while_up(move || signers(1, &inner, &inner_key, &tx)));
        fx.confirms.push(Step::allow());

        assert!(signed(&sign(&fx, &key)));
        let second = second.recv().expect("second signer");
        assert!(signed(&second.join().expect("second signer")));
        assert_eq!(fx.unlocks.shown().len(), 1);
        assert_eq!(fx.confirms.shown().len(), 1);
    }

    /// N identical requests for a key that needs an approval show one
    /// confirm prompt, not N.
    #[test]
    fn identical_concurrent_requests_share_one_approval_prompt() {
        let key = test_key(1);
        let fx = Arc::new(Fixture::unlocked(&key, SshKeyConfirm::Once));
        let (tx, others) = mpsc::channel();
        let (inner, inner_key) = (Arc::clone(&fx), key.clone());
        fx.confirms.push(Step::allow().while_up(move || {
            signers(4, &inner, &inner_key, &tx);
        }));

        assert!(signed(&sign(&fx, &key)));
        let others: Vec<_> = others.try_iter().collect();
        assert_eq!(others.len(), 4);
        for other in others {
            assert!(signed(&other.join().expect("signer")));
        }
        assert_eq!(fx.confirms.shown().len(), 1);
    }

    #[test]
    fn no_prompt_where_none_may_appear() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once).without_prompts();

        assert!(matches!(outcome(&fx, &key), Err(Refused::NeedsApproval)));
        assert!(fx.confirms.shown().is_empty());
    }

    /// A key already approved signs where no prompt may appear: there is
    /// nothing left to ask.
    #[test]
    fn an_approved_key_signs_where_no_prompt_may_appear() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once).without_prompts();
        fx.grant(scope(&key));

        assert!(signed(&sign(&fx, &key)));
        assert!(fx.confirms.shown().is_empty());
    }

    const WINDOW: Duration = Duration::from_secs(60);

    /// `key`, unbound, as a requester outside the desktop running `ssh`
    /// asks for it.
    fn sign_from_outside(fx: &Fixture, key: &PrivateKey) -> AgentResponse {
        sign_as_outside(fx, key, &ConnectionClass::LocalUnbound)
    }

    fn sign_as_outside(fx: &Fixture, key: &PrivateKey, class: &ConnectionClass) -> AgentResponse {
        fx.agent
            .sign(class, &request_with(key, 0), None, &outside_running("ssh"))
    }

    /// Approves the first request pending for `key` by its id, for `window`.
    /// `false` if none is.
    fn approve_for(fx: &Fixture, key: &PrivateKey, window: Duration) -> bool {
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256);
        fx.pending()
            .iter()
            .find(|pending| pending.approval.scope.key().fingerprint == fingerprint)
            .is_some_and(|pending| fx.approve(pending.id, window).is_some())
    }

    fn approve_from_terminal(fx: &Fixture, key: &PrivateKey) -> bool {
        approve_for(fx, key, WINDOW)
    }

    /// Approving a refused request, for a `once` key: refused and recorded,
    /// listed, approved, and the retry signs, and so does every one after
    /// it, as after an approval on screen.
    #[test]
    fn a_refused_request_is_pending_and_signs_once_approved() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);

        assert!(!signed(&sign_from_outside(&fx, &key)));
        let pending = fx.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].approval.scope.key().name, "github");
        assert!(pending[0].approval.remember);
        assert_eq!(pending[0].request.purpose, "other");
        assert_eq!(pending[0].request.class, "local");
        assert_eq!(pending[0].request.command.as_deref(), Some("ssh"));

        assert!(approve_from_terminal(&fx, &key));
        assert!(fx.pending().is_empty());
        assert!(signed(&sign_from_outside(&fx, &key)));
        assert!(signed(&sign_from_outside(&fx, &key)));
        assert!(approved(&fx, &key));
    }

    /// An `always` key's approval covers the retry, and only that one: the
    /// next request is refused and pending again.
    #[test]
    fn an_always_keys_approval_covers_one_retry() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);

        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert!(approve_from_terminal(&fx, &key));
        assert!(signed(&sign_from_outside(&fx, &key)));

        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert_eq!(fx.pending().len(), 1);
    }

    /// The retry has the window to come in, and no longer.
    #[test]
    fn a_one_shot_approval_expires() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        assert!(!signed(&sign_from_outside(&fx, &key)));
        // A window that has passed by the retry.
        assert!(approve_for(&fx, &key, Duration::ZERO));

        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert_eq!(fx.pending().len(), 1);

        assert!(approve_for(&fx, &key, Duration::from_secs(3600)));
        assert!(signed(&sign_from_outside(&fx, &key)));
    }

    /// Two concurrent retries of an approved one-signature request sign
    /// once: the approval is checked, spent and signed with in one hold, so
    /// the second finds nothing to spend.
    #[test]
    fn two_concurrent_retries_of_a_one_signature_approval_sign_once() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert!(approve_for(&fx, &key, Duration::from_secs(3600)));

        let retries: Vec<_> = (0..2)
            .map(|_| {
                let (agent, key) = (Arc::clone(&fx.agent), key.clone());
                std::thread::spawn(move || {
                    agent.sign(
                        &ConnectionClass::LocalUnbound,
                        &request_with(&key, 0),
                        None,
                        &outside_running("ssh"),
                    )
                })
            })
            .collect();
        let signatures = retries
            .into_iter()
            .map(|retry| signed(&retry.join().expect("retry")))
            .filter(|signed| *signed)
            .count();

        assert_eq!(signatures, 1);
    }

    /// A lock drops what is pending and every approval, a one-shot's
    /// included, and an approval doesn't come back with the next unlock.
    #[test]
    fn a_lock_clears_pending_requests_and_one_shot_approvals() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert!(approve_from_terminal(&fx, &key));
        fx.databases.lock("personal").expect("configured");
        fx.unlock(&key);

        assert!(fx.pending().is_empty());
        assert!(!approve_from_terminal(&fx, &key));
        assert!(!signed(&sign_from_outside(&fx, &key)));
    }

    /// Identical requests are one pending request, and a request for
    /// another destination is another.
    #[test]
    fn identical_requests_merge_and_other_destinations_do_not() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let bound = |seed: u64| ConnectionClass::LocalBound {
            dest: test_key(seed).public_key().key_data().clone().into(),
        };

        for _ in 0..3 {
            assert!(!signed(&sign_as_outside(&fx, &key, &bound(2))));
        }
        assert!(!signed(&sign_as_outside(&fx, &key, &bound(3))));
        assert!(!signed(&sign_from_outside(&fx, &key)));

        assert_eq!(fx.pending().len(), 3);
    }

    /// A request that may be asked on screen is asked, never recorded as
    /// pending, and neither is one the policy refuses outright.
    #[test]
    fn only_a_request_that_could_not_be_asked_is_pending() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow());
        assert!(signed(&sign(&fx, &key)));
        assert!(fx.pending().is_empty());

        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        assert!(signed(&sign_from_outside(&fx, &key)));
        assert!(fx.pending().is_empty());
    }

    /// A lock while the prompt is up ends it, signs nothing and leaves no
    /// approval behind for the next unlock.
    #[test]
    fn a_lock_while_the_prompt_is_up_signs_nothing() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow().while_up(locking(&fx)));

        assert!(matches!(
            outcome(&fx, &key),
            Err(Refused::Declined(Declined::Interrupted))
        ));
        assert!(!fx.is_unlocked());
        assert!(fx.state.inner().scanned.is_empty());
        assert!(!approved(&fx, &key));
    }

    /// A lock that comes in once the user has allowed, before the signing
    /// hold, signs nothing.
    #[test]
    fn a_lock_after_the_answer_is_in_signs_nothing() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow().then(locking(&fx)));

        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(!fx.is_unlocked());
        assert!(fx.state.inner().scanned.is_empty());
    }

    /// An `Allow` that a lock and a fresh unlock both beat to the signing
    /// hold signs nothing and leaves no approval in the new unlock: the
    /// prompt was raised for the unlock that ended. The next request asks
    /// afresh.
    #[test]
    fn a_lock_and_a_fresh_unlock_after_the_answer_sign_nothing() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let (databases, entries) = (Arc::clone(&fx.databases), vec![key_entry("github", &key)]);
        fx.confirms.push(Step::allow().then(move || {
            databases.lock("personal").expect("configured");
            databases.install_for_test("personal", entries);
        }));

        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(!approved(&fx, &key));
        assert!(fx.is_unlocked());
        assert!(fx.state.inner().scanned["personal"].private_keys.is_empty());

        fx.confirms.push(Step::allow());
        assert!(signed(&sign(&fx, &key)));
        assert_eq!(fx.confirms.shown().len(), 2);
    }

    /// The freshness guard runs in both holds: a database whose file
    /// changed is locked rather than signed with, whether or not a prompt
    /// came first.
    #[test]
    fn a_changed_file_is_never_signed_with() {
        let key = test_key(1);
        let unasked = Fixture::unlocked(&key, SshKeyConfirm::Never).without_prompts();
        unasked.databases.change_file_for_test("personal");
        assert!(matches!(outcome(&unasked, &key), Err(Refused::Locked)));

        let asked = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let databases = Arc::clone(&asked.databases);
        asked
            .confirms
            .push(Step::allow().then(move || databases.change_file_for_test("personal")));
        assert!(matches!(outcome(&asked, &key), Err(Refused::Locked)));
        assert!(!asked.is_unlocked());
        assert_eq!(asked.confirms.shown().len(), 1);
    }

    /// Where no prompt may appear, a locked database is refused rather
    /// than unlocked, and the cache still lists its keys.
    #[test]
    fn a_locked_database_refuses_where_no_prompt_may_appear() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never).without_prompts();

        assert_eq!(
            fx.agent
                .identities(&ConnectionClass::LocalUnbound, &requester())
                .len(),
            1
        );
        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(!signed(&sign(&fx, &key)));
        assert!(fx.confirms.shown().is_empty() && fx.unlocks.shown().is_empty());
    }

    /// A database unlocked but not yet scanned lists from the cache and
    /// refuses a signature as locked, whatever the key's policy, without
    /// asking to unlock what is open.
    #[test]
    fn a_database_unlocked_but_not_yet_scanned_refuses_a_signature_as_locked() {
        let key = test_key(1);
        let fx = Fixture::locked(&key, SshKeyConfirm::Never);
        fx.unlock(&key);
        fx.state.inner().scanned.clear();
        fx.unlocks.push(typed());

        assert_eq!(
            fx.agent
                .identities(&ConnectionClass::LocalUnbound, &requester())
                .len(),
            1
        );
        assert!(matches!(outcome(&fx, &key), Err(Refused::Locked)));
        assert!(fx.unlocks.shown().is_empty());
    }

    /// The forwarded connection of `ssh -A` session `session` through host
    /// key 9, bound to host key 8.
    fn forwarded(session: u8) -> ConnectionClass {
        ConnectionClass::Forwarded {
            host: test_key(9).public_key().key_data().clone().into(),
            session: vec![session],
            onward: Vec::new(),
            dest: Some(test_key(8).public_key().key_data().clone().into()),
        }
    }

    /// `key`'s login on a connection whose last binding is `session`, as
    /// requested by `requester`.
    fn forwarded_login(
        fx: &Fixture,
        key: &PrivateKey,
        class: &ConnectionClass,
        session: &[u8],
        requester: &Requester,
    ) -> AgentResponse {
        let sign = SignRequest {
            data: login_data(key, session, "git"),
            ..request_with(key, 0)
        };
        fx.agent.sign(class, &sign, Some(session), requester)
    }

    /// A forwarded login asks even for a `never` key, once per forwarding
    /// session, and says through which host and to where.
    #[test]
    fn a_forwarded_login_asks_once_per_forwarding_session_even_for_a_never_key() {
        let key = test_key(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!(
                "build-box {}\ngithub.com {}\n",
                test_key(9).public_key().to_openssh().expect("encodes"),
                test_key(8).public_key().to_openssh().expect("encodes"),
            ),
        )
        .expect("write known_hosts");
        let fx = Fixture::unlocked_with(
            &key,
            SshKeyConfirm::Never,
            Options {
                known_hosts: vec![known_hosts],
                ..Options::default()
            },
        );
        for _ in 0..2 {
            fx.confirms.push(Step::allow());
        }
        let login =
            |session: u8| forwarded_login(&fx, &key, &forwarded(session), &[session], &requester());

        assert!(signed(&login(1)));
        assert!(signed(&login(1)));
        assert!(signed(&login(2)));

        let ask = "Approve use of key \"github\" on build-box to log in to git@github.com?";
        assert_eq!(fx.confirms.shown(), [ask, ask]);
        // Neither session's approval covers local use of the key.
        assert!(!approved(&fx, &key));
    }

    #[test]
    fn a_forwarded_always_key_asks_every_time() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        for _ in 0..2 {
            fx.confirms.push(Step::allow());
        }

        for _ in 0..2 {
            assert!(signed(&forwarded_login(
                &fx,
                &key,
                &forwarded(1),
                &[1],
                &requester()
            )));
        }
        assert_eq!(fx.confirms.shown().len(), 2);
    }

    /// Only a login, from a key allowed on forwarded connections, to a
    /// destination, that matches the connection's session is signed.
    #[test]
    fn a_forwarded_request_that_may_not_be_signed_is_refused_without_a_prompt() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);

        let sshsig = SignRequest {
            data: [b"SSHSIG".as_slice(), &[0, 0, 0, 3], b"git"].concat(),
            ..request_with(&key, 0)
        };
        assert!(!signed(&fx.agent.sign(
            &forwarded(1),
            &sshsig,
            Some(&[1]),
            &requester()
        )));
        assert!(!signed(&sign_as(&fx, &key, &forwarded(1))));
        let unbound = ConnectionClass::Forwarded {
            host: test_key(9).public_key().key_data().clone().into(),
            session: vec![1],
            onward: Vec::new(),
            dest: None,
        };
        assert!(!signed(&forwarded_login(
            &fx,
            &key,
            &unbound,
            &[1],
            &requester()
        )));
        let sign = SignRequest {
            data: login_data(&key, &[2], "git"),
            ..request_with(&key, 0)
        };
        assert!(!signed(&fx.agent.sign(
            &forwarded(1),
            &sign,
            Some(&[1]),
            &requester()
        )));
        assert!(fx.confirms.shown().is_empty());
    }

    #[test]
    fn a_key_kept_off_forwarding_is_refused_on_a_forwarded_connection() {
        let key = test_key(1);
        let settings = SshKeyConfig {
            fingerprint: key.public_key().fingerprint(HashAlg::Sha256),
            name: None,
            confirm: SshKeyConfirm::Never,
            forwarded: false,
            serve: true,
        };
        let fx = Fixture::new(
            vec![database("personal", vec![settings])],
            Options::default(),
        );
        fx.unlock(&key);

        assert!(!signed(&forwarded_login(
            &fx,
            &key,
            &forwarded(1),
            &[1],
            &requester()
        )));
        assert!(signed(&sign(&fx, &key)));
        assert!(fx.confirms.shown().is_empty());
    }

    /// A forwarded request from outside the desktop is pending, scoped to
    /// its forwarding session: approving it lets that session's retry sign,
    /// and no other.
    #[test]
    fn a_forwarded_request_from_outside_is_pending_and_approved_for_its_session() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let outside = outside_running("ssh");
        let login =
            |session: u8| forwarded_login(&fx, &key, &forwarded(session), &[session], &outside);

        assert!(!signed(&login(1)));
        let pending = fx.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request.class, "forwarded");
        assert_eq!(
            pending[0]
                .approval
                .scope
                .forwarding_host()
                .map(|host| host.fingerprint),
            Some(test_key(9).public_key().fingerprint(HashAlg::Sha256))
        );
        assert!(approve_from_terminal(&fx, &key));

        assert!(signed(&login(1)));
        assert!(!signed(&login(2)));
        assert_eq!(fx.pending().len(), 1);
        assert!(fx.confirms.shown().is_empty());
    }

    /// A grant counts the signatures it covers: the one the user allowed on
    /// screen, and each one after it. Nothing is granted, so nothing is
    /// counted, for a key that never asks or asks every time.
    #[test]
    fn a_grant_counts_the_signatures_it_covers() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.confirms.push(Step::allow());

        for _ in 0..3 {
            assert!(signed(&sign(&fx, &key)));
        }
        let grants = fx.grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].by, GrantSource::OnScreen);
        assert_eq!(grants[0].uses, 3);

        for confirm in [SshKeyConfirm::Never, SshKeyConfirm::Always] {
            let fx = Fixture::unlocked(&key, confirm);
            fx.confirms.push(Step::allow());
            assert!(signed(&sign(&fx, &key)));
            assert!(fx.grants().is_empty(), "{confirm:?}");
        }
    }

    /// What `kpa ssh approve` approves for a key that asks every time is a
    /// grant given by it, until its one signature.
    #[test]
    fn an_approved_request_is_a_grant_by_ssh_approve_until_its_one_signature() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Always);
        assert!(!signed(&sign_from_outside(&fx, &key)));
        assert!(approve_from_terminal(&fx, &key));

        let grants = fx.grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].by, GrantSource::Cli);
        assert_eq!(grants[0].uses, 0);
        assert!(grants[0].time_left(Instant::now()).is_some());

        assert!(signed(&sign_from_outside(&fx, &key)));
        assert!(fx.grants().is_empty());
    }

    /// A forwarded grant names its forwarding session's host.
    #[test]
    fn a_forwarded_grant_names_its_forwarding_host() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        fx.confirms.push(Step::allow());
        for _ in 0..2 {
            assert!(signed(&forwarded_login(
                &fx,
                &key,
                &forwarded(1),
                &[1],
                &requester()
            )));
        }

        let grants = fx.grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0]
                .scope
                .forwarding_host()
                .map(|host| host.fingerprint),
            Some(test_key(9).public_key().fingerprint(HashAlg::Sha256))
        );
        assert_eq!(grants[0].uses, 2);
    }

    /// A forwarded signature is a remote host's: it doesn't keep the
    /// database unlocked.
    #[test]
    fn a_forwarded_signature_leaves_the_idle_timer_alone() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        fx.confirms.push(Step::allow());
        let installed = Instant::now();
        std::thread::sleep(Duration::from_millis(5));

        assert!(signed(&forwarded_login(
            &fx,
            &key,
            &forwarded(1),
            &[1],
            &requester()
        )));

        fx.databases.expire_idle(installed + IDLE);
        assert!(!fx.is_unlocked(), "the signature reset the timer");
    }

    #[test]
    fn a_key_nobody_serves_is_refused() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        assert!(!signed(&sign(&fx, &test_key(2))));
    }

    /// A SHA-1 RSA request is refused before anyone is asked: the user
    /// never approves a signature that can't be made.
    #[test]
    fn a_sha1_rsa_request_is_refused_without_a_prompt() {
        let key = PrivateKey::from_openssh(RSA_3072).expect("test vector");
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let unbound = ConnectionClass::LocalUnbound;

        let sha1 = request_with(&key, 0);
        let request = Request::parse(&unbound, &sha1, None).expect("parses");
        assert!(matches!(
            fx.agent
                .sign_or_refuse(&found(&fx, &key), &request, &requester()),
            Err(Refused::Sha1Rsa)
        ));
        assert!(fx.confirms.shown().is_empty());

        fx.confirms.push(Step::allow());
        let sha512 = request_with(&key, 4);
        assert!(signed(&fx.agent.sign(
            &unbound,
            &sha512,
            None,
            &requester()
        )));
    }

    /// The log line names a key by the name its config override gives it,
    /// escaped, and never by its entry's title.
    #[test]
    fn the_log_line_names_a_key_only_by_its_configured_name() {
        let key = test_key(1);
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256);
        let override_named = |name: Option<&str>| SshKeyConfig {
            fingerprint,
            name: name.map(str::to_string),
            confirm: SshKeyConfirm::Never,
            forwarded: true,
            serve: true,
        };
        let sign = request_with(&key, 0);
        let request = Request::parse(&ConnectionClass::LocalUnbound, &sign, None).expect("parses");
        let line = |fx: &Fixture| {
            let name = fx.agent.configured_name("personal", &request);
            sign_line("personal", name.as_deref(), &request, &Ok(Vec::new()))
        };

        for (name, logged) in [
            (Some("prod-root"), " named \"prod-root\""),
            (Some("evil\nline"), " named \"evil\\u000aline\""),
            (None, ""),
        ] {
            let fx = Fixture::new(
                vec![database("personal", vec![override_named(name)])],
                Options::default(),
            );
            fx.databases
                .install_for_test("personal", vec![key_entry("secret-entry-title", &key)]);
            assert_eq!(
                line(&fx),
                format!(
                    "ssh sign signed: key {fingerprint}{logged} in \"personal\" (other, local)"
                )
            );
        }
    }

    /// A local signature is activity: it resets the database's idle timer,
    /// and one that isn't made doesn't.
    #[test]
    fn a_local_signature_resets_the_idle_timer() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        let installed = Instant::now();
        std::thread::sleep(Duration::from_millis(5));

        assert!(signed(&sign(&fx, &key)));

        // Idle for `idle` as of the unlock; the signature came later.
        fx.databases.expire_idle(installed + IDLE);
        assert!(fx.is_unlocked(), "the signature didn't reset the timer");
        fx.databases.expire_idle(Instant::now() + IDLE);
        assert!(!fx.is_unlocked());
    }

    /// The log line says a host by its fingerprint, and leads it with the name
    /// `known_hosts` gives it, escaped, when it gives one.
    #[test]
    fn the_log_line_names_a_host_known_hosts_names_next_to_its_fingerprint() {
        const NOW: u64 = 1_000;
        let key = test_key(1);
        let (github, build_box, hostile) = (
            test_key(2).public_key().clone(),
            test_key(3).public_key().clone(),
            test_key(4).public_key().clone(),
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "github.com {}\nbuild-box {}\nevil\u{202e}host {}\n",
                github.to_openssh().expect("encodes"),
                build_box.to_openssh().expect("encodes"),
                hostile.to_openssh().expect("encodes"),
            ),
        )
        .expect("write known_hosts");
        let names = HostNames::read(std::slice::from_ref(&path));
        let print = |key: &PublicKey| key.fingerprint(HashAlg::Sha256);
        let sign = request_with(&key, 0);
        let line = |class: ConnectionClass, names: &HostNames| {
            let request = Request::parse(&class, &sign, None)
                .expect("parses")
                .named(names, NOW);
            sign_line("personal", None, &request, &Ok(Vec::new()))
        };
        let forwarded = |host: &PublicKey, dest: &PublicKey| ConnectionClass::Forwarded {
            host: host.key_data().clone().into(),
            session: vec![1],
            onward: Vec::new(),
            dest: Some(dest.key_data().clone().into()),
        };

        let named = line(forwarded(&build_box, &github), &names);
        assert!(
            named.contains(&format!(
                "dest github.com ({}), via build-box ({})",
                print(&github),
                print(&build_box)
            )),
            "{named}"
        );

        // A host `known_hosts` doesn't name stays its fingerprint, and so
        // do both when there are no names.
        let stranger = key.public_key();
        let partly = line(forwarded(stranger, &github), &names);
        assert!(
            partly.contains(&format!(
                "dest github.com ({}), via {})",
                print(&github),
                print(stranger)
            )),
            "{partly}"
        );
        let unnamed = line(forwarded(stranger, &github), &HostNames::default());
        assert!(
            unnamed.contains(&format!(
                "dest {}, via {})",
                print(&github),
                print(stranger)
            )),
            "{unnamed}"
        );

        // A name is escaped, so it can't drive whatever shows the log.
        let escaped = line(
            ConnectionClass::LocalBound {
                dest: hostile.key_data().clone().into(),
            },
            &names,
        );
        assert!(escaped.contains("dest evil\\u202ehost ("), "{escaped}");
        assert!(!escaped.contains('\u{202e}'));
    }

    /// A destination whose host certificate a CA that `known_hosts` trusts
    /// signed is named by the certificate's principal in the confirm prompt,
    /// in the approval's scope and in the log line, and without that CA line it
    /// is its fingerprint alone.
    #[test]
    fn a_host_a_trusted_ca_certified_is_named_by_its_principal_everywhere() {
        let key = test_key(1);
        let (via, dest, ca) = (test_key(9), test_key(8), test_key(7));
        let fingerprint = |key: &PrivateKey| key.public_key().fingerprint(HashAlg::Sha256);
        let class = {
            let mut bindings = crate::frontends::ssh_agent::bind::SessionBindState::new();
            bindings.apply(&signed_bind(&via, b"first", true));
            bindings.apply(&certified_bind(
                &dest,
                &ca,
                "build-box.example",
                b"second",
                false,
            ));
            bindings.class()
        };
        let dir = tempfile::tempdir().expect("tempdir");

        for (trusted, to) in [
            (true, "to log in to git@build-box.example".to_string()),
            (
                false,
                format!("to log in as git to host key {}", fingerprint(&dest)),
            ),
        ] {
            let known_hosts = dir.path().join(format!("known_hosts-{trusted}"));
            std::fs::write(
                &known_hosts,
                if trusted {
                    format!(
                        "@cert-authority *.example {}\n",
                        ca.public_key().to_openssh().expect("encodes")
                    )
                } else {
                    String::new()
                },
            )
            .expect("write known_hosts");
            let fx = Fixture::unlocked_with(
                &key,
                SshKeyConfirm::Never,
                Options {
                    known_hosts: vec![known_hosts],
                    ..Options::default()
                },
            );
            fx.confirms.push(Step::allow());

            assert!(signed(&forwarded_login(
                &fx,
                &key,
                &class,
                b"second",
                &requester()
            )));

            assert_eq!(
                fx.confirms.shown(),
                [format!(
                    "Approve use of key \"github\" on host key {} {to}?",
                    fingerprint(&via)
                )]
            );
            let grants = fx.grants();
            assert_eq!(
                grants[0]
                    .scope
                    .destination()
                    .and_then(|host| host.name.as_deref()),
                trusted.then_some("build-box.example")
            );
            assert_eq!(
                grants[0]
                    .scope
                    .forwarding_host()
                    .and_then(|host| host.name.as_deref()),
                None
            );
            let sign = SignRequest {
                data: login_data(&key, b"second", "git"),
                ..request_with(&key, 0)
            };
            let request = Request::parse(&class, &sign, Some(b"second"))
                .expect("parses")
                .named(
                    &HostNames::read(&[dir.path().join(format!("known_hosts-{trusted}"))]),
                    1_000,
                );
            assert_eq!(
                request
                    .destination
                    .as_ref()
                    .and_then(|host| host.name.as_deref()),
                trusted.then_some("build-box.example")
            );
            assert_eq!(
                sign_line("personal", None, &request, &Ok(Vec::new()))
                    .contains("dest build-box.example ("),
                trusted
            );
        }
    }

    /// A bound connection's prompt names the destination, by the host
    /// name `known_hosts` gives it, and its approval covers that
    /// destination only.
    #[test]
    fn a_bound_connection_is_approved_per_destination() {
        let key = test_key(1);
        let dest = test_key(2).public_key().clone();
        let other = test_key(3).public_key().clone();
        let dir = tempfile::tempdir().expect("tempdir");
        let known_hosts = dir.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!("github.com {}\n", dest.to_openssh().expect("encodes")),
        )
        .expect("write known_hosts");
        let fx = Fixture::unlocked_with(
            &key,
            SshKeyConfirm::Once,
            Options {
                known_hosts: vec![known_hosts],
                ..Options::default()
            },
        );
        fx.confirms.push(Step::allow());
        fx.confirms.push(Step::allow());
        let bound = |dest: &PublicKey| ConnectionClass::LocalBound {
            dest: dest.key_data().clone().into(),
        };

        assert!(signed(&sign_as(&fx, &key, &bound(&dest))));
        assert!(signed(&sign_as(&fx, &key, &bound(&dest))));
        assert!(signed(&sign_as(&fx, &key, &bound(&other))));
        assert_eq!(
            fx.confirms.shown(),
            [
                "Approve use of key \"github\" on github.com?".to_string(),
                format!(
                    "Approve use of key \"github\" on host key {}?",
                    other.fingerprint(HashAlg::Sha256)
                ),
            ]
        );
    }

    fn asked(key: &PrivateKey, remember: bool) -> SignatureApproval {
        SignatureApproval {
            scope: scope(key),
            remember,
        }
    }

    /// `lacking` on a hold of `personal`, in `fx`.
    fn lacking_in(fx: &Fixture, needed: Option<&SignatureApproval>) -> Option<Lacking> {
        fx.agent
            .hold("personal")
            .expect("configured")
            .lacking(&fx.approvals, needed)
    }

    #[test]
    fn a_request_that_needs_nothing_lacks_nothing() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        assert!(lacking_in(&fx, None).is_none());
    }

    #[test]
    fn a_locked_database_lacks_its_unlock_before_anything_else() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        fx.grant(scope(&key));
        fx.databases.lock("personal").expect("configured");

        for needed in [None, Some(asked(&key, true))] {
            assert!(matches!(
                lacking_in(&fx, needed.as_ref()),
                Some(Lacking::Unlock)
            ));
        }
    }

    #[test]
    fn an_approval_nothing_covers_is_what_the_request_lacks() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let unlock = fx
            .databases
            .open("personal")
            .expect("unlocked")
            .unlock_token();
        for remember in [true, false] {
            let needed = asked(&key, remember);
            let Some(Lacking::Approval(lacked)) = lacking_in(&fx, Some(&needed)) else {
                panic!("expected the approval to be lacking");
            };
            assert_eq!(lacked.approval, needed);
            assert!(
                lacked.unlock == unlock,
                "the unlock it was found lacking in"
            );
        }
    }

    /// An approval kept until lock and one for a single signature both
    /// cover their request: nothing is lacking. The one for a single
    /// signature is spent when its signature is made, and not before.
    #[test]
    fn an_approval_the_database_holds_is_not_lacking() {
        let key = test_key(1);
        for remember in [true, false] {
            let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
            let needed = asked(&key, remember);
            {
                let open = fx.databases.open("personal").expect("unlocked");
                fx.approvals.record(
                    &open,
                    needed.clone(),
                    requested("ssh"),
                    std::time::SystemTime::now(),
                );
            }
            let id = fx.pending()[0].id;
            assert!(fx.approve(id, Duration::from_secs(3600)).is_some());

            assert!(lacking_in(&fx, Some(&needed)).is_none(), "{remember}");
        }
    }
}
