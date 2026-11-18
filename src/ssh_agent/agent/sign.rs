//! The sign flow (`docs/ssh-agent.md` § 6.3, § 6.6, § 6.7, § 6.9): a
//! `SIGN_REQUEST` becomes a signature, or `Failure` for every refusal.
//!
//! [`Agent::sign_or_refuse`] puts the authorization around
//! [`signer::sign`], which signs and nothing else:
//!
//! 1. Policy: [`authorize_sign`] says whether the request is allowed at
//!    all, and which approval it needs.
//! 2. Sign if the request is ready ([`Agent::sign_if_ready`]): the database
//!    is open and holds the approval, checked and signed in one hold of the
//!    database. Most requests end here, waiting for nobody.
//! 3. Otherwise the refusal says what is lacking, and the user is asked for
//!    it ([`prompts`](super::prompts)): the unlock of a locked database, then the
//!    approval of the key. A requester who may not be asked is refused
//!    before it waits for its turn, and a prompt the user cancels, or
//!    leaves unanswered, holds the database's prompts back for a while
//!    (backoff).
//! 4. Sign what the user allowed ([`Agent::sign_allowed`]), unless a lock
//!    came in since, or sign if the request is ready now.
//!
//! Every hold runs behind the freshness guard (`SshHost::with_slot`), so a
//! database whose file changed is locked, and its token cancelled, before
//! the hold sees it. Forwarded connections are refused outright.

use ssh_key::Fingerprint;

use super::prompts::Confirmed;
use super::request::{Request, log_sign};
use super::{Agent, SlotView, SshHost, identities, signer};
use crate::authn::Requester;
use crate::output;
use crate::prompt::Declined;
use crate::proto::UnlockError;
use crate::ssh_agent::authz::{Refusal, SignatureApproval, authorize_sign};
use crate::ssh_agent::bind::ConnectionClass;
use crate::ssh_agent::keys::ServedKey;
use crate::ssh_agent::wire::{AgentResponse, SignRequest};

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
    #[error("approval {0}")]
    Declined(Declined),
    /// The unlock the signature needed didn't open the database.
    #[error("unlock failed: {0:?}")]
    Unlock(UnlockError),
    #[error("confirm prompt failed: {0}")]
    PromptFailed(std::io::Error),
    #[error("loading or signing failed")]
    SigningFailed,
}

/// What a request still lacks before it can be signed.
pub(super) enum Lacking {
    /// The database is locked.
    Unlock,
    /// The approval the request needs, which nothing covers.
    Approval(SignatureApproval),
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

impl SlotView<'_> {
    /// The key the open database serves under `fingerprint`.
    pub(super) fn served(&self, fingerprint: Fingerprint) -> Result<&ServedKey, Refused> {
        if self.db.is_none() {
            return Err(Refused::Locked);
        }
        self.ssh
            .served
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .ok_or(Refused::NotServed)
    }
}

/// What the request lacks in `slot`: the unlock of a locked database, else
/// the approval it `needed` that the database doesn't hold.
pub(super) fn lacking(slot: &SlotView<'_>, needed: Option<&SignatureApproval>) -> Option<Lacking> {
    if !slot.is_open() {
        return Some(Lacking::Unlock);
    }
    needed
        .filter(|approval| !slot.ssh.approvals.covers(&approval.scope))
        .map(|approval| Lacking::Approval(approval.clone()))
}

impl<H: SshHost> Agent<H> {
    /// Answers one `SIGN_REQUEST`: a signature, or `Failure` for a key it
    /// doesn't serve and for every refusal.
    pub(super) fn sign(
        &self,
        class: &ConnectionClass,
        sign: &SignRequest,
        login_session_id: Option<&[u8]>,
        requester: &Requester,
    ) -> AgentResponse {
        let Some(request) = Request::parse(class, sign, login_session_id) else {
            return AgentResponse::Failure;
        };
        let cache_dir = self.cache_dir.as_deref();
        let Some(found) = identities::find_key(self.host.as_ref(), cache_dir, request.fingerprint)
        else {
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
    /// answered. `found` is the key as `identities::find_key` lists it: from
    /// its slot if its database is open, from the cache if not.
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
        .map_err(Refused::Policy)?;

        // 2. Nothing to ask: sign. Most requests end here, in one hold,
        // waiting for nobody.
        match self.sign_if_ready(db, request, approval.as_ref()) {
            Err(Refused::Locked | Refused::NeedsApproval) => {}
            answer => return answer,
        }

        // 3. Something to ask. Refused here if the user can't be asked.
        self.check_may_prompt(db, requester, approval.as_ref())?;

        // 4. Ask. One signature at a time asks for a database, and keeps its
        // turn until it has signed, so the next one finds what this one got.
        // A prompt the user cancelled or left unanswered holds the
        // database's prompts back.
        let _turn = self.wait_for_turn(db)?;
        let confirmed = self
            .prompt_for_what_is_lacking(found, request, requester, approval.as_ref())
            .inspect_err(|refused| {
                if refused.starts_backoff() {
                    self.back_off(db);
                }
            })?;

        // 5. Sign.
        match confirmed {
            Some(confirmed) => self.sign_allowed(db, request, confirmed),
            None => self.sign_if_ready(db, request, approval.as_ref()),
        }
    }

    /// Signs `request`, in one hold of `db`, if the database is open and
    /// holds the approval it `needed`. Refused as [`Refused::Locked`]
    /// or [`Refused::NeedsApproval`] otherwise, which names what to ask
    /// for.
    fn sign_if_ready(
        &self,
        db: &str,
        request: &Request<'_>,
        needed: Option<&SignatureApproval>,
    ) -> Result<Vec<u8>, Refused> {
        self.hold(db, |mut slot| {
            if let Some(lacking) = lacking(&slot, needed) {
                return Err(lacking.refusal());
            }
            sign_and_touch(&mut slot, request)
        })
    }

    /// Signs what the user allowed, in one hold of `db`, and records the
    /// approval their answer gave. Refused as [`Refused::Locked`] if a lock
    /// came in since they were asked.
    fn sign_allowed(
        &self,
        db: &str,
        request: &Request<'_>,
        confirmed: Confirmed,
    ) -> Result<Vec<u8>, Refused> {
        self.hold(db, |mut slot| {
            if confirmed.until_lock.is_cancelled() {
                return Err(Refused::Locked);
            }
            let signature = sign_and_touch(&mut slot, request)?;
            if confirmed.approval.remember {
                slot.ssh.approvals.grant(confirmed.approval.scope);
            }
            Ok(signature)
        })
    }

    /// The name `db`'s config gives `request`'s key, if a
    /// `[[database.ssh_key]]` override names it: config, so it may be
    /// logged. Never the resolved `ServedKey::name`, which falls back to the
    /// entry's title, vault content kpa keeps out of its own output (G-4).
    fn configured_name(&self, db: &str, request: &Request<'_>) -> Option<String> {
        self.host
            .databases()
            .iter()
            .find(|cfg| cfg.name == db)?
            .ssh_key_settings(request.fingerprint)
            .name
            .map(|name| output::escape_one_line(&name, MAX_LOGGED_NAME_LEN))
    }

    /// Runs `f` on `db`'s slot under the host's lock.
    pub(super) fn hold<R>(
        &self,
        db: &str,
        f: impl FnOnce(SlotView<'_>) -> Result<R, Refused>,
    ) -> Result<R, Refused> {
        self.host
            .with_slot(db, f)
            .unwrap_or(Err(Refused::NotServed))
    }
}

/// Signs `request` with the slot's key and resets the database's idle
/// timer.
fn sign_and_touch(slot: &mut SlotView<'_>, request: &Request<'_>) -> Result<Vec<u8>, Refused> {
    let signature = signer::sign(
        slot,
        request.fingerprint,
        &request.sign.data,
        request.sign.flags,
    )?;
    slot.touch();
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use keepass::Database;
    use ssh_key::encoding::Decode;
    use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
    use zeroize::Zeroizing;

    use super::super::SshSlot;
    use super::super::fake::{FakeHost, requester};
    use super::super::request::sign_line;
    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::paths::Paths;
    use crate::prompt::{
        CancelSource, ConfirmAnswer, Declined, Prompt, PromptOutcome, Scripted, Step,
    };
    use crate::proto::UnlockError;
    use crate::ssh_agent::approve::Scope;
    use crate::ssh_agent::keys;
    use crate::ssh_agent::serve::SshSign;
    use crate::ssh_agent::testing::{RSA_3072, database, key_database, test_key};
    use crate::ssh_agent::wire::SignFlags;

    /// One unlocked database, `personal`, serving `key` as `github` with
    /// `confirm`.
    fn host(key: &PrivateKey, confirm: SshKeyConfirm) -> FakeHost {
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

    /// How long a cancelled prompt holds its database's prompts back.
    const BACKOFF: Duration = Duration::from_secs(120);

    /// An agent on `host`, its confirm prompts answered by the returned
    /// script, and its unlock prompts by `host.unlocks()`.
    fn agent(
        host: FakeHost,
        paths: &Paths,
    ) -> (Arc<FakeHost>, Arc<Agent<FakeHost>>, Scripted<ConfirmAnswer>) {
        let prompts = Scripted::new();
        let confirm_prompt = Prompt::new(host.queue(), prompts.clone(), Duration::from_secs(60));
        let host = Arc::new(host);
        let agent = Arc::new(Agent::new(
            Arc::clone(&host),
            confirm_prompt,
            BACKOFF,
            paths,
        ));
        (host, agent, prompts)
    }

    /// `host`, locked as an earlier unlock leaves it: its key cache lists
    /// `key`, in the directory `paths` names.
    fn locked(host: FakeHost, key: &PrivateKey) -> (FakeHost, tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths {
            cache_dir: Some(dir.path().to_path_buf()),
            ..Paths::default()
        };
        let cache = keys::cache_dir(&paths).expect("cache dir");
        keys::write_cache(&cache, "personal", &[key.public_key().clone()]).expect("write cache");
        host.lock("personal");
        (host, dir, paths)
    }

    /// A prompt that types the master password.
    fn typed() -> Step<Zeroizing<String>> {
        Step::new(PromptOutcome::Answer(Zeroizing::new("hunter2".to_string())))
    }

    fn request_with(key: &PrivateKey, flags: u32) -> SignRequest {
        SignRequest {
            key_blob: key.public_key().to_bytes().expect("key encodes"),
            data: b"data to sign".to_vec(),
            flags: SignFlags::new(flags),
        }
    }

    fn sign_as(
        agent: &Agent<FakeHost>,
        key: &PrivateKey,
        class: &ConnectionClass,
    ) -> AgentResponse {
        agent.sign(class, &request_with(key, 0), None, &requester())
    }

    fn sign(agent: &Agent<FakeHost>, key: &PrivateKey) -> AgentResponse {
        sign_as(agent, key, &ConnectionClass::LocalUnbound)
    }

    /// `key` as `personal` serves it, as `find_key` lists it.
    fn found(agent: &Agent<FakeHost>, key: &PrivateKey) -> ServedKey {
        keys::resolve_cached(&agent.host.databases()[0], vec![key.public_key().clone()]).remove(0)
    }

    /// What `sign` would log for an unbound request for `key`.
    fn outcome(agent: &Agent<FakeHost>, key: &PrivateKey) -> Result<Vec<u8>, Refused> {
        let sign = request_with(key, 0);
        let request = Request::parse(&ConnectionClass::LocalUnbound, &sign, None).expect("parses");
        agent.sign_or_refuse(&found(agent, key), &request, &requester())
    }

    fn signed(response: &AgentResponse) -> bool {
        matches!(response, AgentResponse::SignResponse(_))
    }

    /// Whether `key` is approved for unbound use in `personal`.
    fn approved(host: &FakeHost, key: &PrivateKey) -> bool {
        let scope = Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None);
        host.peek("personal", |_, ssh| ssh.approvals.covers(&scope))
    }

    /// A step that locks `personal` on `host`.
    fn locking(host: &Arc<FakeHost>) -> impl FnOnce() + Send + 'static {
        let host = Arc::clone(host);
        move || host.lock("personal")
    }

    #[test]
    fn confirm_never_signs_without_prompting_and_the_signature_verifies() {
        let key = test_key(1);
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Never), &Paths::default());

        let AgentResponse::SignResponse(raw) = sign(&agent, &key) else {
            panic!("expected a signature");
        };
        let signature = Signature::decode(&mut raw.as_slice()).expect("signature decodes");
        signature::Verifier::verify(key.public_key(), b"data to sign", &signature)
            .expect("verifies");
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn confirm_once_prompts_for_the_first_signature_only() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        prompts.push(Step::allow());

        assert!(signed(&sign(&agent, &key)));
        assert!(approved(&host, &key));
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(prompts.shown(), ["Approve use of key \"github\"?"]);
    }

    #[test]
    fn confirm_always_prompts_for_every_signature_and_stores_nothing() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Always), &Paths::default());
        prompts.push(Step::allow());
        prompts.push(Step::allow());

        assert!(signed(&sign(&agent, &key)));
        assert!(!approved(&host, &key));
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(prompts.shown().len(), 2);
    }

    /// A request that arrives while an `always` key's prompt is up gets a
    /// prompt of its own, here answered no, rather than riding on the
    /// first one's `Allow`: one `Allow`, one signature.
    #[test]
    fn a_request_during_the_prompt_gets_its_own_prompt() {
        let key = test_key(1);
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Always), &Paths::default());
        let (second_tx, second) = mpsc::channel();
        let (second_agent, second_key) = (Arc::clone(&agent), key.clone());
        prompts.push(Step::allow().while_up(move || {
            let request = std::thread::spawn(move || sign(&second_agent, &second_key));
            second_tx.send(request).expect("send");
        }));
        prompts.push(Step::new(PromptOutcome::Answer(ConfirmAnswer::Deny)));

        assert!(signed(&sign(&agent, &key)));
        let second = second.recv().expect("second request");
        assert!(!signed(&second.join().expect("second request")));
        assert_eq!(prompts.shown().len(), 2);
    }

    /// A requester who may not be asked is refused at once, while another
    /// signature's prompt for the same database is up: it never waits for
    /// that prompt's turn.
    #[test]
    fn a_requester_who_cannot_be_asked_does_not_wait_for_a_prompt() {
        let key = test_key(1);
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        let (outcome_tx, outcome) = mpsc::channel();
        let (second_agent, second_key) = (Arc::clone(&agent), key.clone());
        prompts.push(Step::allow().while_up(move || {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let outside = Requester {
                    cgroup: Some("0::/system.slice/cron.service\n".to_string()),
                    ..requester()
                };
                let response = second_agent.sign(
                    &ConnectionClass::LocalUnbound,
                    &request_with(&second_key, 0),
                    None,
                    &outside,
                );
                let _ = tx.send(response);
            });
            outcome_tx
                .send(rx.recv_timeout(Duration::from_secs(5)))
                .expect("send");
        }));

        assert!(signed(&sign(&agent, &key)));
        let refused = outcome
            .recv()
            .expect("outcome")
            .expect("refused without waiting");
        assert!(!signed(&refused));
        assert_eq!(prompts.shown().len(), 1);
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
            let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
            prompts.push(Step::new(declined));
            prompts.push(Step::fails());
            assert!(
                matches!(outcome(&agent, &key), Err(Refused::Declined(_))),
                "{name}"
            );
            host.advance(BACKOFF);
            assert!(
                matches!(outcome(&agent, &key), Err(Refused::PromptFailed(_))),
                "{name}"
            );
            assert_eq!(prompts.shown().len(), 2, "{name}");
            assert!(!approved(&host, &key), "{name}");
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
            let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
            prompts.push(end);
            assert!(outcome(&agent, &key).is_err(), "{name}");

            prompts.push(Step::allow());
            let second = outcome(&agent, &key);
            assert_eq!(
                matches!(second, Err(Refused::BackingOff)),
                backs_off,
                "{name}"
            );
            assert_eq!(
                prompts.shown().len(),
                if backs_off { 1 } else { 2 },
                "{name}"
            );
        }
    }

    /// Cancelling a confirm prompt makes the next request that needs a
    /// prompt fail at once, without one, until the backoff has passed.
    #[test]
    fn a_cancelled_prompt_backs_off_until_the_backoff_has_passed() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        prompts.push(Step::new(PromptOutcome::Cancelled));

        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Declined(Declined::Cancelled))
        ));
        assert!(matches!(outcome(&agent, &key), Err(Refused::BackingOff)));
        host.advance(BACKOFF - Duration::from_secs(1));
        assert!(matches!(outcome(&agent, &key), Err(Refused::BackingOff)));
        assert_eq!(prompts.shown().len(), 1);

        host.advance(Duration::from_secs(1));
        prompts.push(Step::allow());
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(prompts.shown().len(), 2);
    }

    /// Backoff holds back prompts only: a signature that needs none still
    /// signs, whether its key never asks or is already approved.
    #[test]
    fn a_signature_that_needs_no_prompt_signs_during_a_backoff() {
        let key = test_key(1);
        let backed_off = |confirm| {
            let (host, agent, prompts) = agent(host(&key, confirm), &Paths::default());
            host.with_slot("personal", |mut slot| slot.back_off(BACKOFF));
            (host, agent, prompts)
        };

        let (_host, never, prompts) = backed_off(SshKeyConfirm::Never);
        assert!(signed(&sign(&never, &key)));
        assert!(prompts.shown().is_empty());

        let (host, once, prompts) = backed_off(SshKeyConfirm::Once);
        assert!(matches!(outcome(&once, &key), Err(Refused::BackingOff)));
        let scope = Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None);
        host.with_slot("personal", |slot| slot.ssh.approvals.grant(scope));
        assert!(signed(&sign(&once, &key)));
        assert!(prompts.shown().is_empty());
    }

    /// A lock leaves a backoff in place: the locked database is not
    /// offered an unlock prompt until it has passed.
    #[test]
    fn a_lock_does_not_end_a_backoff() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        prompts.push(Step::new(PromptOutcome::Cancelled));
        assert!(outcome(&agent, &key).is_err());

        host.lock("personal");

        assert!(matches!(outcome(&agent, &key), Err(Refused::BackingOff)));
        assert!(host.unlocks().shown().is_empty());
    }

    /// An unlock, whoever prompted for it, ends a backoff: the user is
    /// here and unlocking.
    #[test]
    fn an_unlock_ends_a_backoff() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once), &key);
        let (host, agent, prompts) = agent(host, &paths);
        host.unlocks().push(Step::new(PromptOutcome::Cancelled));
        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Unlock(UnlockError::PromptCancelled { .. }))
        ));
        assert!(matches!(outcome(&agent, &key), Err(Refused::BackingOff)));

        // The user types `kpa unlock`.
        host.reopen();

        prompts.push(Step::allow());
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(prompts.shown(), ["Approve use of key \"github\"?"]);
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
        let approval = format!("Approve use of key \"personal {fingerprint}\"?");
        for (confirm, asked, kept) in [
            (SshKeyConfirm::Once, true, true),
            (SshKeyConfirm::Always, true, false),
            (SshKeyConfirm::Never, false, false),
        ] {
            let (host, _dir, paths) = locked(host(&key, confirm), &key);
            let (host, agent, prompts) = agent(host, &paths);
            host.unlocks().push(typed());
            prompts.push(Step::allow());

            assert!(signed(&sign(&agent, &key)));
            assert_eq!(host.unlocks().shown(), [named.as_str()]);
            let expected: Vec<&str> = if asked {
                vec![approval.as_str()]
            } else {
                vec![]
            };
            assert_eq!(prompts.shown(), expected);
            assert_eq!(approved(&host, &key), kept);
        }
    }

    /// Answering the unlock is not the approval: a denied approval after it
    /// signs nothing, and leaves the database unlocked.
    #[test]
    fn an_unlock_that_was_answered_does_not_approve_the_key() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once), &key);
        let (host, agent, prompts) = agent(host, &paths);
        host.unlocks().push(typed());
        prompts.push(Step::new(PromptOutcome::Answer(ConfirmAnswer::Deny)));

        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Declined(Declined::Denied))
        ));
        assert!(host.peek("personal", |open, _| open));
        assert!(!approved(&host, &key));
    }

    /// An unlock that finds the database open already, because the user
    /// unlocked it first, prompted for nothing and approves nothing: the
    /// signature goes on to ask for its approval, naming the key as the
    /// cache lists it.
    #[test]
    fn an_unlock_that_finds_the_database_open_is_not_an_approval() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once), &key);
        let (host, agent, prompts) = agent(host, &paths);
        let user = Arc::clone(&host);
        host.before_unlock(move || user.reopen());
        prompts.push(Step::allow());

        assert!(signed(&sign(&agent, &key)));
        assert!(host.unlocks().shown().is_empty());
        assert_eq!(
            prompts.shown(),
            [format!(
                "Approve use of key \"personal {}\"?",
                key.public_key().fingerprint(HashAlg::Sha256)
            )]
        );
    }

    #[test]
    fn a_cancelled_unlock_refuses_and_backs_off() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Never), &key);
        let (host, agent, _prompts) = agent(host, &paths);
        host.unlocks().push(Step::new(PromptOutcome::TimedOut));

        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Unlock(UnlockError::PromptCancelled { .. }))
        ));
        assert!(matches!(outcome(&agent, &key), Err(Refused::BackingOff)));
        assert_eq!(host.unlocks().shown().len(), 1);

        host.advance(BACKOFF);
        host.unlocks().push(typed());
        assert!(signed(&sign(&agent, &key)));
    }

    /// Nobody to answer, no prompt: a locked database is refused without
    /// an unlock prompt and without a backoff.
    #[test]
    fn nothing_prompts_to_unlock_where_no_prompt_may_appear() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once).without_prompts(), &key);
        let (host, agent, prompts) = agent(host, &paths);

        assert!(matches!(outcome(&agent, &key), Err(Refused::Locked)));
        assert!(host.unlocks().shown().is_empty() && prompts.shown().is_empty());
        assert_eq!(
            host.with_slot("personal", |slot| slot.backing_off()),
            Some(false)
        );
    }

    /// A lock while the unlock prompt is up ends it and fails the
    /// signature, without a backoff: the next request asks again.
    #[test]
    fn a_lock_while_the_unlock_prompt_is_up_fails_the_signature() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Never), &key);
        let (host, agent, _prompts) = agent(host, &paths);
        host.unlocks().push(typed().while_up(locking(&host)));

        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Unlock(UnlockError::LockedDuringUnlock { .. }))
        ));
        assert!(host.peek("personal", |open, _| !open));

        host.unlocks().push(typed());
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(host.unlocks().shown().len(), 2);
    }

    /// Waits until `n` holds on the host's slots have run: the signers a
    /// test started have looked, and are waiting for their turn.
    fn wait_for_holds(host: &FakeHost, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while host.holds() < n {
            assert!(
                std::time::Instant::now() < deadline,
                "the signers never looked"
            );
            std::thread::yield_now();
        }
    }

    /// Starts `n` signers from inside a prompt that is on screen, and
    /// waits until each has looked (a `find_key` hold, an attempt to sign
    /// and a look before asking) and so is waiting for its turn. Their handles go to `tx`.
    fn signers_while_up(
        n: usize,
        agent: &Arc<Agent<FakeHost>>,
        host: &Arc<FakeHost>,
        key: &PrivateKey,
        tx: mpsc::Sender<std::thread::JoinHandle<AgentResponse>>,
    ) -> impl FnOnce() + Send + 'static {
        let (agent, host, key) = (Arc::clone(agent), Arc::clone(host), key.clone());
        move || {
            let before = host.holds();
            for _ in 0..n {
                let (agent, key) = (Arc::clone(&agent), key.clone());
                let signer = std::thread::spawn(move || sign(&agent, &key));
                tx.send(signer).expect("send");
            }
            wait_for_holds(&host, before + 3 * n);
        }
    }

    /// Two signers for a locked database get one unlock prompt and one
    /// confirm prompt: the second waits for the first, then looks again and
    /// finds the database open and the key approved.
    #[test]
    fn concurrent_signers_share_one_unlock_prompt() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once), &key);
        let (host, agent, prompts) = agent(host, &paths);
        let (tx, second) = mpsc::channel();
        host.unlocks()
            .push(typed().while_up(signers_while_up(1, &agent, &host, &key, tx)));

        prompts.push(Step::allow());

        assert!(signed(&sign(&agent, &key)));
        let second = second.recv().expect("second signer");
        assert!(signed(&second.join().expect("second signer")));
        assert_eq!(host.unlocks().shown().len(), 1);
        assert_eq!(prompts.shown().len(), 1);
    }

    /// N identical requests for a key that needs an approval show one
    /// confirm prompt, not N.
    #[test]
    fn identical_concurrent_requests_share_one_approval_prompt() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        let (tx, others) = mpsc::channel();
        prompts.push(Step::allow().while_up(signers_while_up(4, &agent, &host, &key, tx)));

        assert!(signed(&sign(&agent, &key)));
        let others: Vec<_> = others.try_iter().collect();
        assert_eq!(others.len(), 4);
        for other in others {
            assert!(signed(&other.join().expect("signer")));
        }
        assert_eq!(prompts.shown().len(), 1);
    }

    #[test]
    fn no_prompt_where_none_may_appear() {
        let key = test_key(1);
        let (_host, agent, prompts) = agent(
            host(&key, SshKeyConfirm::Once).without_prompts(),
            &Paths::default(),
        );

        assert!(matches!(outcome(&agent, &key), Err(Refused::NeedsApproval)));
        assert!(prompts.shown().is_empty());
    }

    /// A key already approved signs where no prompt may appear: there is
    /// nothing left to ask.
    #[test]
    fn an_approved_key_signs_where_no_prompt_may_appear() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(
            host(&key, SshKeyConfirm::Once).without_prompts(),
            &Paths::default(),
        );
        let scope = Scope::new(key.public_key().fingerprint(HashAlg::Sha256), None);
        host.with_slot("personal", |slot| slot.ssh.approvals.grant(scope));

        assert!(signed(&sign(&agent, &key)));
        assert!(prompts.shown().is_empty());
    }

    /// A lock while the prompt is up ends it, signs nothing and leaves no
    /// approval behind for the next unlock.
    #[test]
    fn a_lock_while_the_prompt_is_up_signs_nothing() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        prompts.push(Step::allow().while_up(locking(&host)));

        assert!(matches!(
            outcome(&agent, &key),
            Err(Refused::Declined(Declined::Interrupted))
        ));
        assert!(host.peek("personal", |open, ssh| !open && ssh.is_empty()));
        assert!(!approved(&host, &key));
    }

    /// A lock that comes in once the user has allowed, before the signing
    /// hold, signs nothing.
    #[test]
    fn a_lock_after_the_answer_is_in_signs_nothing() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        prompts.push(Step::allow().then(locking(&host)));

        assert!(matches!(outcome(&agent, &key), Err(Refused::Locked)));
        assert!(host.peek("personal", |open, ssh| !open && ssh.is_empty()));
    }

    /// An `Allow` that a lock and a fresh unlock both beat to the slot signs
    /// nothing and leaves no approval in the new unlock: the prompt was
    /// raised for the database that locked. The next request asks afresh.
    #[test]
    fn a_lock_and_a_fresh_unlock_after_the_answer_sign_nothing() {
        let key = test_key(1);
        let (host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        let relocker = Arc::clone(&host);
        prompts.push(Step::allow().then(move || {
            relocker.lock("personal");
            relocker.reopen();
        }));

        assert!(matches!(outcome(&agent, &key), Err(Refused::Locked)));
        assert!(!approved(&host, &key));
        assert!(host.peek("personal", |open, ssh| open && ssh.private_keys.is_empty()));

        prompts.push(Step::allow());
        assert!(signed(&sign(&agent, &key)));
        assert_eq!(prompts.shown().len(), 2);
    }

    /// The freshness guard runs in both holds: a database whose file
    /// changed is locked rather than signed with, whether or not a prompt
    /// came first.
    #[test]
    fn a_changed_file_is_never_signed_with() {
        let key = test_key(1);
        let (unasked, unasked_agent, _prompts) = agent(
            host(&key, SshKeyConfirm::Never).without_prompts(),
            &Paths::default(),
        );
        unasked.mark_stale();
        assert!(matches!(
            outcome(&unasked_agent, &key),
            Err(Refused::Locked)
        ));

        let (asked, asked_agent, prompts) =
            agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        let changer = Arc::clone(&asked);
        prompts.push(Step::allow().then(move || changer.mark_stale()));
        assert!(matches!(outcome(&asked_agent, &key), Err(Refused::Locked)));
        assert!(asked.peek("personal", |open, _| !open));
        assert_eq!(prompts.shown().len(), 1);
    }

    /// Where no prompt may appear, a locked database is refused rather
    /// than unlocked, and the cache still lists its keys.
    #[test]
    fn a_locked_database_refuses_where_no_prompt_may_appear() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Never).without_prompts(), &key);
        let (host, agent, prompts) = agent(host, &paths);

        assert_eq!(
            agent
                .ssh_identities(&ConnectionClass::LocalUnbound, &requester())
                .len(),
            1
        );
        assert!(matches!(outcome(&agent, &key), Err(Refused::Locked)));
        assert!(!signed(&sign(&agent, &key)));
        assert!(prompts.shown().is_empty() && host.unlocks().shown().is_empty());
    }

    #[test]
    fn a_forwarded_request_is_refused() {
        let key = test_key(1);
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Never), &Paths::default());
        let forwarded = ConnectionClass::Forwarded {
            host: test_key(9).public_key().key_data().clone(),
            session: vec![1],
            dest: Some(test_key(8).public_key().key_data().clone()),
        };

        assert!(!signed(&sign_as(&agent, &key, &forwarded)));
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn a_key_nobody_serves_is_refused() {
        let key = test_key(1);
        let (_host, agent, _prompts) = agent(host(&key, SshKeyConfirm::Never), &Paths::default());
        assert!(!signed(&sign(&agent, &test_key(2))));
    }

    /// A SHA-1 RSA request is refused before anyone is asked: the user
    /// never approves a signature that can't be made.
    #[test]
    fn a_sha1_rsa_request_is_refused_without_a_prompt() {
        let key = PrivateKey::from_openssh(RSA_3072).expect("test vector");
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &Paths::default());
        let unbound = ConnectionClass::LocalUnbound;

        let sha1 = request_with(&key, 0);
        let request = Request::parse(&unbound, &sha1, None).expect("parses");
        assert!(matches!(
            agent.sign_or_refuse(&found(&agent, &key), &request, &requester()),
            Err(Refused::Sha1Rsa)
        ));
        assert!(prompts.shown().is_empty());

        prompts.push(Step::allow());
        let sha512 = request_with(&key, 4);
        assert!(signed(&agent.sign(&unbound, &sha512, None, &requester())));
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
        let line = |agent: &Agent<FakeHost>| {
            let name = agent.configured_name("personal", &request);
            sign_line("personal", name.as_deref(), &request, &Ok(Vec::new()))
        };

        for (name, logged) in [
            (Some("prod-root"), " named \"prod-root\""),
            (Some("evil\nline"), " named \"evil\\u000aline\""),
            (None, ""),
        ] {
            let host = FakeHost::unlocked(
                vec![database("personal", vec![override_named(name)])],
                key_database(&[("secret-entry-title", &key)]),
            );
            let (_host, agent, _prompts) = agent(host, &Paths::default());
            assert_eq!(
                line(&agent),
                format!(
                    "ssh sign signed: key {fingerprint}{logged} in \"personal\" (other, local)"
                )
            );
        }
    }

    #[test]
    fn a_local_signature_resets_the_idle_timer() {
        let key = test_key(1);
        let (host, agent, _prompts) = agent(host(&key, SshKeyConfirm::Never), &Paths::default());
        let before = host.last_activity("personal");
        std::thread::sleep(Duration::from_millis(5));

        assert!(signed(&sign(&agent, &key)));
        assert!(host.last_activity("personal") > before);
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
        let paths = Paths {
            known_hosts: Some(known_hosts),
            ..Paths::default()
        };
        let (_host, agent, prompts) = agent(host(&key, SshKeyConfirm::Once), &paths);
        prompts.push(Step::allow());
        prompts.push(Step::allow());
        let bound = |dest: &PublicKey| ConnectionClass::LocalBound {
            dest: dest.key_data().clone(),
        };

        assert!(signed(&sign_as(&agent, &key, &bound(&dest))));
        assert!(signed(&sign_as(&agent, &key, &bound(&dest))));
        assert!(signed(&sign_as(&agent, &key, &bound(&other))));
        assert_eq!(
            prompts.shown(),
            [
                "Approve use of key \"github\" on github.com?".to_string(),
                format!(
                    "Approve use of key \"github\" on host key {}?",
                    other.fingerprint(HashAlg::Sha256)
                ),
            ]
        );
    }

    fn approval(remember: bool) -> SignatureApproval {
        let key = test_key(1).public_key().fingerprint(HashAlg::Sha256);
        SignatureApproval {
            scope: Scope::new(key, None),
            remember,
        }
    }

    /// Runs `check` on a database slot that is `open` or locked, and holds
    /// `approved`.
    fn on_slot<R>(
        open: bool,
        approved: Option<SignatureApproval>,
        check: impl FnOnce(&SlotView<'_>) -> R,
    ) -> R {
        let mut ssh = SshSlot::default();
        if let Some(approved) = approved {
            ssh.approvals.grant(approved.scope);
        }
        let db = Database::new();
        let (mut last_activity, lock_signal) = (Instant::now(), CancelSource::new());
        let mut backoff = None;
        let slot = SlotView::new(
            Instant::now(),
            open.then_some(&db),
            &mut ssh,
            &mut last_activity,
            &lock_signal,
            &mut backoff,
        );
        check(&slot)
    }

    #[test]
    fn a_request_that_needs_nothing_lacks_nothing() {
        assert!(on_slot(true, None, |slot| lacking(slot, None)).is_none());
    }

    #[test]
    fn a_locked_database_lacks_its_unlock_before_anything_else() {
        for needed in [None, Some(approval(true))] {
            let lacks = on_slot(false, Some(approval(true)), |slot| {
                lacking(slot, needed.as_ref())
            });
            assert!(matches!(lacks, Some(Lacking::Unlock)));
        }
    }

    #[test]
    fn an_approval_nothing_covers_is_what_the_request_lacks() {
        for remember in [true, false] {
            let needed = approval(remember);
            let lacks = on_slot(true, None, |slot| lacking(slot, Some(&needed)));
            let Some(Lacking::Approval(lacked)) = lacks else {
                panic!("expected the approval to be lacking");
            };
            assert_eq!(lacked, approval(remember));
        }
    }

    #[test]
    fn an_approval_the_database_holds_is_not_lacking() {
        let needed = approval(true);
        assert!(
            on_slot(true, Some(approval(true)), |slot| lacking(
                slot,
                Some(&needed)
            ))
            .is_none()
        );
    }
}
