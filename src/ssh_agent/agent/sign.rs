//! The sign flow (`docs/ssh-agent.md` § 6.3, § 6.6, § 6.7, § 6.9): a
//! `SIGN_REQUEST` becomes a signature, or `Failure` for every refusal.
//!
//! [`Agent::authorized_sign`] puts the authorization around
//! [`signer::sign`], which signs and nothing else, in five steps:
//!
//! 1. Policy: [`authorize_sign`] says whether the request is allowed at
//!    all, and which approval it needs.
//! 2. Look at the database, under the host's lock: is it open, which
//!    approval does the request still lack ([`missing_approval`]), and a
//!    token its next lock cancels. A request that has to ask for something
//!    and may not is refused now ([`refusal_before_prompting`]): the
//!    database is locked, or the approval is lacking, where no prompt may
//!    appear, or prompts are held back after a cancel.
//! 3. Wait for our turn and look again. Only one signature at a time
//!    prompts for a database, and the one before may have unlocked it or
//!    approved the key.
//! 4. SignatureApproval, outside the lock. First the unlock of a locked database:
//!    answering it is the approval too. Then the approval, if it is still
//!    lacking. A prompt the user cancels, or leaves unanswered, holds the
//!    database's prompts back for a while (backoff).
//! 5. Sign and record, under the lock again: the signature, unless the
//!    token says a lock came in since step 2, and the approval the user's
//!    answer gave.
//!
//! Both holds run behind the freshness guard (`SshHost::with_slot`), so a
//! database whose file changed is locked, and its token cancelled, before
//! either sees it. Forwarded connections are refused outright.

use std::sync::MutexGuard;

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::{Agent, SlotView, SshHost, identities, message, signer};
use crate::authn::Requester;
use crate::authz::may_prompt_on_screen;
use crate::log;
use crate::output;
use crate::prompt::{CancelToken, Declined};
use crate::proto::{UnlockError, UnlockRequest, Unlocked};
use crate::ssh_agent::authz::{Refusal, SignatureApproval, authorize_sign};
use crate::ssh_agent::bind::ConnectionClass;
use crate::ssh_agent::classify::{self, Purpose};
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
    #[error("approval prompt failed: {0}")]
    PromptFailed(std::io::Error),
    #[error("loading or signing failed")]
    SigningFailed,
}

impl Refused {
    /// Whether this is the user declining to answer a prompt, as opposed to
    /// answering no, or a lock ending it: what puts the database's prompts
    /// in backoff (`docs/ssh-agent.md` § 6.6).
    fn starts_backoff(&self) -> bool {
        matches!(
            self,
            Refused::Declined(Declined::Cancelled | Declined::TimedOut)
                | Refused::Unlock(UnlockError::PromptCancelled { .. })
        )
    }
}

/// One `SIGN_REQUEST`, as the flow and its log line see it.
struct Request<'a> {
    key: PublicKey,
    fingerprint: Fingerprint,
    purpose: Purpose,
    class: &'a ConnectionClass,
    sign: &'a SignRequest,
    login_session_id: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// `sign`'s request, if its key blob decodes.
    fn parse(
        class: &'a ConnectionClass,
        sign: &'a SignRequest,
        login_session_id: Option<&'a [u8]>,
    ) -> Option<Request<'a>> {
        let key = PublicKey::new(signer::key_data_from_blob(&sign.key_blob).ok()?, "");
        Some(Request {
            fingerprint: key.fingerprint(HashAlg::Sha256),
            purpose: classify::classify(&sign.data, &key),
            key,
            class,
            sign,
            login_session_id,
        })
    }

    /// The connection's bound destination, if it has one.
    fn destination(&self) -> Option<&KeyData> {
        match self.class {
            ConnectionClass::LocalBound { dest } => Some(dest),
            _ => None,
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

/// The approval a request needs, if the database `slot` holds doesn't cover
/// it: what the request still lacks.
fn missing_approval<'n>(
    slot: &SlotView<'_>,
    needed: Option<&'n SignatureApproval>,
) -> Option<&'n SignatureApproval> {
    needed.filter(|approval| !slot.ssh.approvals.covers(&approval.scope))
}

/// Why a request is refused before anyone is asked, if it is. A request
/// that has to ask for something, the unlock of a locked database or the
/// approval it is `missing`, is refused where no prompt may appear
/// (`may_prompt_on_screen`), and while the database's prompts are held back after a
/// cancel. One that has to ask for
/// nothing is never refused here.
fn refusal_before_prompting(
    slot: &SlotView<'_>,
    missing: Option<&SignatureApproval>,
    may_prompt_on_screen: bool,
) -> Option<Refused> {
    let open = slot.is_open();
    if open && missing.is_none() {
        return None;
    }
    if !may_prompt_on_screen {
        return Some(if open {
            Refused::NeedsApproval
        } else {
            Refused::Locked
        });
    }
    slot.backing_off().then_some(Refused::BackingOff)
}

/// What the flow found out about the database, under the host's lock.
///
/// A struct because the three go together: they are looked at again after
/// the prompt lock, all at once, and steps 4 and 5 read all of them.
struct Facts {
    /// The database is unlocked.
    open: bool,
    /// The approval the request still lacks (`missing_approval`).
    missing: Option<SignatureApproval>,
    /// What the database's next lock cancels.
    cancel_token: CancelToken,
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
        let outcome = self.authorized_sign(&found, &request, requester);
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
    fn authorized_sign(
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

        // 2. Look at the database. A request that has to ask for something
        // and may not is refused here.
        let look_at_database = || {
            self.hold(db, |slot| {
                let missing = missing_approval(&slot, approval.as_ref());
                let may_prompt_on_screen =
                    may_prompt_on_screen(requester, &self.host.display_session());
                if let Some(refused) =
                    refusal_before_prompting(&slot, missing, may_prompt_on_screen)
                {
                    return Err(refused);
                }
                Ok(Facts {
                    open: slot.is_open(),
                    missing: missing.cloned(),
                    cancel_token: slot.cancel_token(),
                })
            })
        };
        let mut facts = look_at_database()?;

        // 3. Wait for our turn, and look again. We keep the prompt lock
        // until we have signed, so the next signature sees what our prompts
        // got.
        let has_to_ask = !facts.open || facts.missing.is_some();
        let _prompt_lock = if has_to_ask {
            let prompt_lock = self.prompt_lock(db)?;
            facts = look_at_database()?;
            Some(prompt_lock)
        } else {
            None
        };

        // 4. SignatureApproval, outside the lock.
        let mut approval_missing = facts.missing.is_some();
        if !facts.open {
            match self.unlock_prompt(found, request, requester) {
                // Answering the unlock prompt is the approval.
                Ok(Unlocked::Opened) => approval_missing = false,
                // Someone else's unlock got there first, so nobody was
                // asked: the approval prompt still follows.
                Ok(Unlocked::AlreadyOpen) => {}
                Err(refused) => {
                    if refused.starts_backoff() {
                        self.back_off(db);
                    }
                    return Err(refused);
                }
            }
        }
        if approval_missing {
            match self.approval_prompt(found, request, &facts.cancel_token) {
                Ok(()) => {}
                Err(refused) => {
                    if refused.starts_backoff() {
                        self.back_off(db);
                    }
                    return Err(refused);
                }
            }
        }

        // 5. Sign and record, under the lock again, unless the database
        // locked since step 2.
        self.hold(db, |mut slot| {
            if facts.cancel_token.is_cancelled() {
                return Err(Refused::Locked);
            }
            let signature = signer::sign(
                &mut slot,
                request.fingerprint,
                &request.sign.data,
                request.sign.flags,
            )?;
            if let Some(approval) = facts.missing
                && approval.remember
            {
                slot.ssh.approvals.grant(approval.scope);
            }
            slot.touch();
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
    fn hold<R>(
        &self,
        db: &str,
        f: impl FnOnce(SlotView<'_>) -> Result<R, Refused>,
    ) -> Result<R, Refused> {
        self.host
            .with_slot(db, f)
            .unwrap_or(Err(Refused::NotServed))
    }

    /// Shows the approval prompt for signing `request` with `key`, and
    /// whether the user allowed it. It ends on `cancel_token`.
    ///
    /// `key` is the key as the cache or the open database listed it when
    /// the request came in, so a prompt raised after someone else unlocked
    /// the database names it as the cache does, not by its entry's title.
    fn approval_prompt(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        cancel_token: &CancelToken,
    ) -> Result<(), Refused> {
        let message = message::approval(
            key,
            &request.purpose,
            request.destination(),
            self.known_hosts_name(request).as_deref(),
        );
        self.approval
            .ask(&message, cancel_token)
            .map_err(Refused::PromptFailed)?
            .allowed()
            .map_err(Refused::Declined)
    }

    /// Unlocks `key`'s database as `kpa unlock` does, with a prompt that
    /// says why the signature needs it.
    fn unlock_prompt(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
    ) -> Result<Unlocked, Refused> {
        let message = message::unlock(
            key,
            &request.purpose,
            request.destination(),
            self.known_hosts_name(request).as_deref(),
        );
        let request = UnlockRequest {
            db: key.database.clone(),
            password: None,
        };
        self.host
            .unlock(&request, requester, Some(&message))
            .map_err(Refused::Unlock)
    }

    /// The host name `known_hosts` gives the connection's destination, if
    /// it is bound to one that has one.
    fn known_hosts_name(&self, request: &Request<'_>) -> Option<String> {
        let path = self.known_hosts.as_deref()?;
        message::known_hosts_name(path, request.destination()?)
    }

    /// `db`'s prompt lock, once whoever holds it is done. Held by the one
    /// signature raising a prompt for `db`, until it has signed.
    fn prompt_lock(&self, db: &str) -> Result<MutexGuard<'_, ()>, Refused> {
        let lock = self.prompt_locks.get(db).ok_or(Refused::NotServed)?;
        Ok(lock.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Holds `db`'s prompts back for `backoff` from now, as a prompt the
    /// user cancelled or left unanswered does. A lock doesn't end it; an
    /// unlock does.
    fn back_off(&self, db: &str) {
        let _ = self.hold(db, |mut slot| {
            slot.back_off(self.backoff);
            Ok(())
        });
    }
}

/// One line per `SIGN_REQUEST` for a served key (`docs/ssh-agent.md`
/// § 11), as [`sign_line`] words it. A signature is `info`, everything else
/// `warn`.
fn log_sign(
    db: &str,
    name: Option<String>,
    request: &Request<'_>,
    outcome: &Result<Vec<u8>, Refused>,
) {
    let log = match outcome {
        Ok(_) => log::info,
        Err(_) => log::warn,
    };
    let line = sign_line(db, name.as_deref(), request, outcome);
    log(format_args!("{line}"));
}

/// The log line for one `SIGN_REQUEST`: the key by fingerprint, and by
/// `name` if its database's config names it (already escaped); its
/// database; its purpose; the connection's class; the destination's
/// fingerprint if the connection is bound to one; and what happened. Never
/// the entry's title, which is vault content (G-4).
fn sign_line(
    db: &str,
    name: Option<&str>,
    request: &Request<'_>,
    outcome: &Result<Vec<u8>, Refused>,
) -> String {
    let outcome: &dyn std::fmt::Display = match outcome {
        Ok(_) => &"signed",
        Err(refused) => refused,
    };
    let name = name
        .map(|name| format!(" named \"{name}\""))
        .unwrap_or_default();
    let purpose = match request.purpose {
        Purpose::Login(_) => "login",
        Purpose::SshSig { .. } => "sshsig",
        Purpose::Other => "other",
    };
    let class = match request.class {
        ConnectionClass::LocalUnbound => "local",
        ConnectionClass::LocalBound { .. } => "local, bound",
        ConnectionClass::Forwarded { .. } => "forwarded",
    };
    let destination = request
        .destination()
        .map(|dest| format!(", dest {}", dest.fingerprint(HashAlg::Sha256)))
        .unwrap_or_default();
    format!(
        "ssh sign {outcome}: key {}{name} in {db:?} ({purpose}, {class}{destination})",
        request.fingerprint,
    )
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

    /// An agent on `host`, its approval prompts answered by the returned
    /// script, and its unlock prompts by `host.unlocks()`.
    fn agent(
        host: FakeHost,
        paths: &Paths,
    ) -> (Arc<FakeHost>, Arc<Agent<FakeHost>>, Scripted<ConfirmAnswer>) {
        let prompts = Scripted::new();
        let approval = Prompt::new(host.queue(), prompts.clone(), Duration::from_secs(60));
        let host = Arc::new(host);
        let agent = Arc::new(Agent::new(Arc::clone(&host), approval, BACKOFF, paths));
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
        agent.authorized_sign(&found(agent, key), &request, &requester())
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

    /// Cancelling an approval prompt makes the next request that needs a
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

    /// A locked database's signature runs the unlock, which says why, and
    /// the user's answer to it is that signature's approval: a `once` key
    /// is approved for good, an `always` key for this signature only, and a
    /// `never` key needed none.
    #[test]
    fn the_unlock_prompt_is_the_approval() {
        let key = test_key(1);
        let named = format!(
            "Unlock database personal and use key \"personal {}\"?",
            key.public_key().fingerprint(HashAlg::Sha256)
        );
        for (confirm, kept) in [
            (SshKeyConfirm::Once, true),
            (SshKeyConfirm::Always, false),
            (SshKeyConfirm::Never, false),
        ] {
            let (host, _dir, paths) = locked(host(&key, confirm), &key);
            let (host, agent, prompts) = agent(host, &paths);
            host.unlocks().push(typed());

            assert!(signed(&sign(&agent, &key)));
            assert_eq!(host.unlocks().shown(), [named.as_str()]);
            assert!(prompts.shown().is_empty());
            assert_eq!(approved(&host, &key), kept);
        }
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
    /// test started have looked, and are waiting on the prompt lock.
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
    /// waits until each has looked (a `find_key` hold and a look) and so is
    /// waiting on the gate. Their handles go to `tx`.
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
            wait_for_holds(&host, before + 2 * n);
        }
    }

    /// Two signers for a locked database get one unlock prompt: the second
    /// waits for the first, then looks again and finds the database open
    /// and the key approved.
    #[test]
    fn concurrent_signers_share_one_unlock_prompt() {
        let key = test_key(1);
        let (host, _dir, paths) = locked(host(&key, SshKeyConfirm::Once), &key);
        let (host, agent, prompts) = agent(host, &paths);
        let (tx, second) = mpsc::channel();
        host.unlocks()
            .push(typed().while_up(signers_while_up(1, &agent, &host, &key, tx)));

        assert!(signed(&sign(&agent, &key)));
        let second = second.recv().expect("second signer");
        assert!(signed(&second.join().expect("second signer")));
        assert_eq!(host.unlocks().shown().len(), 1);
        assert!(prompts.shown().is_empty());
    }

    /// N identical requests for a key that needs an approval show one
    /// approval prompt, not N.
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
            agent.authorized_sign(&found(&agent, &key), &request, &requester()),
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

    /// A database as `missing_approval` and `refusal_before_prompting` find
    /// it.
    struct Found {
        open: bool,
        approved: Option<SignatureApproval>,
        backoff: Option<Instant>,
    }

    fn open_db() -> Found {
        Found {
            open: true,
            approved: None,
            backoff: None,
        }
    }

    fn locked_db() -> Found {
        Found {
            open: false,
            ..open_db()
        }
    }

    /// Runs `check` on a slot as `found` describes it.
    fn on_slot<R>(found: Found, now: Instant, check: impl FnOnce(&SlotView<'_>) -> R) -> R {
        let mut ssh = SshSlot::default();
        if let Some(approved) = found.approved {
            ssh.approvals.grant(approved.scope);
        }
        let db = Database::new();
        let (mut last_activity, lock_signal) = (Instant::now(), CancelSource::new());
        let mut backoff = found.backoff;
        let slot = SlotView::new(
            now,
            found.open.then_some(&db),
            &mut ssh,
            &mut last_activity,
            &lock_signal,
            &mut backoff,
        );
        check(&slot)
    }

    fn missing_in(found: Found, needed: Option<&SignatureApproval>) -> Option<SignatureApproval> {
        on_slot(found, Instant::now(), |slot| {
            missing_approval(slot, needed).cloned()
        })
    }

    fn refusal_in(
        found: Found,
        missing: Option<&SignatureApproval>,
        may_prompt_on_screen: bool,
        now: Instant,
    ) -> Option<Refused> {
        on_slot(found, now, |slot| {
            refusal_before_prompting(slot, missing, may_prompt_on_screen)
        })
    }

    #[test]
    fn a_request_that_needs_nothing_lacks_nothing() {
        assert_eq!(missing_in(open_db(), None), None);
    }

    #[test]
    fn an_approval_nothing_covers_is_what_the_request_lacks() {
        for remember in [true, false] {
            let needed = approval(remember);
            assert_eq!(
                missing_in(open_db(), Some(&needed)),
                Some(approval(remember))
            );
        }
    }

    #[test]
    fn an_approval_the_database_holds_is_not_lacking() {
        let needed = approval(true);
        let holding = Found {
            approved: Some(approval(true)),
            ..open_db()
        };
        assert_eq!(missing_in(holding, Some(&needed)), None);
    }

    /// An open database whose request lacks an approval is refused only
    /// where no prompt may appear; a locked one is refused there too.
    #[test]
    fn a_request_that_has_to_ask_is_refused_where_no_prompt_may_appear() {
        let now = Instant::now();
        let missing = approval(true);
        assert!(matches!(
            refusal_in(open_db(), Some(&missing), false, now),
            Some(Refused::NeedsApproval)
        ));
        assert!(refusal_in(open_db(), Some(&missing), true, now).is_none());
        for missing in [None, Some(&missing)] {
            assert!(matches!(
                refusal_in(locked_db(), missing, false, now),
                Some(Refused::Locked)
            ));
            assert!(refusal_in(locked_db(), missing, true, now).is_none());
        }
    }

    #[test]
    fn a_request_that_has_to_ask_nothing_is_never_refused() {
        for may_prompt_on_screen in [true, false] {
            assert!(refusal_in(open_db(), None, may_prompt_on_screen, Instant::now()).is_none());
        }
    }

    /// While prompts are held back, a request that has to ask is refused,
    /// and one that doesn't is not. The backoff ends at its deadline.
    #[test]
    fn a_backoff_refuses_what_has_to_ask_until_it_has_passed() {
        let now = Instant::now();
        let until = now + Duration::from_secs(120);
        let backed_off = |found: Found| Found {
            backoff: Some(until),
            ..found
        };
        let missing = approval(true);

        assert!(matches!(
            refusal_in(backed_off(open_db()), Some(&missing), true, now),
            Some(Refused::BackingOff)
        ));
        assert!(matches!(
            refusal_in(backed_off(locked_db()), None, true, now),
            Some(Refused::BackingOff)
        ));
        assert!(refusal_in(backed_off(open_db()), None, true, now).is_none());
        assert!(refusal_in(backed_off(open_db()), Some(&missing), true, until).is_none());
    }
}
