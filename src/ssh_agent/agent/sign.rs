//! The sign flow (`docs/ssh-agent.md` § 6.3, § 6.7, § 6.9): a
//! `SIGN_REQUEST` becomes a signature, or `Failure` for every refusal.
//!
//! [`Agent::authorized_sign`] puts the authorization around
//! [`signer::sign`], which signs and nothing else, in three steps:
//!
//! 1. Under the host's lock, look at the database: which approval does the
//!    request still lack ([`missing_approval`]), and is it refused as
//!    things stand ([`refusal_before_prompting`])?
//! 2. Outside the lock, ask for the approval it lacks, if any. The prompt
//!    ends when a lock cancels the token step 1 took.
//! 3. Under the lock again: the signature, unless the token says a lock
//!    came in since step 1, and the approval the user's `Allow` keeps.
//!
//! Both holds run behind the freshness guard (`SshHost::with_slot`), so a
//! database whose file changed is locked, and its token cancelled, before
//! either sees it. Forwarded connections are refused outright, and a locked
//! database is refused rather than unlocked on demand.

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::{Agent, SlotView, SshHost, identities, message, signer};
use crate::authn::Requester;
use crate::log;
use crate::output;
use crate::prompt::{CancelToken, Declined};
use crate::ssh_agent::bind::ConnectionClass;
use crate::ssh_agent::classify::{self, Purpose};
use crate::ssh_agent::keys::ServedKey;
use crate::ssh_agent::policy::{self, Ask, Need, Refusal};
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
    #[error("refused: SHA-1 RSA signature")]
    Sha1Rsa,
    #[error("approval {0}")]
    Declined(Declined),
    #[error("approval prompt failed: {0}")]
    PromptFailed(std::io::Error),
    #[error("loading or signing failed")]
    SigningFailed,
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

/// The approval `need` asks for, if the database `slot` holds doesn't cover
/// it: what the request still lacks.
fn missing_approval<'n>(slot: &SlotView<'_>, need: &'n Need) -> Option<&'n Ask> {
    match need {
        Need::Approval(ask) if !slot.ssh.approvals.covers(&ask.scope) => Some(ask),
        Need::Approval(_) | Need::Nothing => None,
    }
}

/// Why a request is refused before anyone is asked, if it is: it lacks an
/// approval, and no prompt may appear (`may_prompt`) to ask for it.
fn refusal_before_prompting(missing: Option<&Ask>, may_prompt: bool) -> Option<Refused> {
    (missing.is_some() && !may_prompt).then_some(Refused::NeedsApproval)
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
        let Some(db) = identities::find_key(self.host.as_ref(), cache_dir, request.fingerprint)
        else {
            return AgentResponse::Failure;
        };
        let outcome = self.authorized_sign(&db, &request, requester);
        log_sign(&db, self.configured_name(&db, &request), &request, &outcome);
        match outcome {
            Ok(signature) => AgentResponse::SignResponse(signature),
            Err(_) => AgentResponse::Failure,
        }
    }

    /// Signs `request` with the key `db` serves, if the policy lets it and,
    /// when it needs an approval nothing covers yet, once the user has
    /// allowed it.
    fn authorized_sign(
        &self,
        db: &str,
        request: &Request<'_>,
        requester: &Requester,
    ) -> Result<Vec<u8>, Refused> {
        if !signer::supported(request.key.key_data(), request.sign.flags) {
            return Err(Refused::Sha1Rsa);
        }
        // 1. Under the lock: look at the database. A request that is refused
        // as things stand ends here.
        let (key, missing, cancel_token) = self.hold(db, |slot| {
            let key = slot.served(request.fingerprint)?.clone();
            let need = policy::decide(
                &key,
                request.class,
                &request.purpose,
                request.login_session_id,
            )
            .map_err(Refused::Policy)?;
            let missing = missing_approval(&slot, &need);
            let may_prompt = self.host.may_prompt(requester);
            if let Some(refused) = refusal_before_prompting(missing, may_prompt) {
                return Err(refused);
            }
            Ok((key, missing.cloned(), slot.cancel_token()))
        })?;
        // 2. Outside the lock: ask for the approval the request lacks.
        if missing.is_some() {
            self.ask(&key, request, &cancel_token)?;
        }
        // 3. Under the lock again: sign, unless the database locked since
        // step 1.
        self.hold(db, |mut slot| {
            if cancel_token.is_cancelled() {
                return Err(Refused::Locked);
            }
            let signature = signer::sign(
                &mut slot,
                request.fingerprint,
                &request.sign.data,
                request.sign.flags,
            )?;
            if let Some(ask) = missing
                && ask.remember
            {
                slot.ssh.approvals.grant(ask.scope);
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
    /// whether the user allowed it. It ends when `cancel_token` is
    /// cancelled.
    fn ask(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        cancel_token: &CancelToken,
    ) -> Result<(), Refused> {
        let destination = request.destination();
        let known_hosts_name = destination.and_then(|dest| {
            let path = self.known_hosts.as_deref()?;
            message::known_hosts_name(path, dest)
        });
        let message = message::message(
            key,
            &request.purpose,
            destination,
            known_hosts_name.as_deref(),
        );
        self.approval
            .ask(&message, cancel_token)
            .map_err(Refused::PromptFailed)?
            .allowed()
            .map_err(Refused::Declined)
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
    use std::time::Duration;

    use ssh_key::encoding::Decode;
    use ssh_key::{PrivateKey, Signature};

    use super::super::SshSlot;
    use super::super::fake::{FakeHost, desktop};
    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::paths::Paths;
    use crate::prompt::{
        Approval, CancelSource, Prompt, PromptOutcome, PromptQueue, Scripted, Step,
    };
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

    /// An agent on `host`, its prompts answered by the returned script.
    fn agent(
        host: FakeHost,
        paths: &Paths,
    ) -> (Arc<FakeHost>, Arc<Agent<FakeHost>>, Scripted<Approval>) {
        let prompts = Scripted::new();
        let approval = Prompt::new(
            Arc::new(PromptQueue::new()),
            prompts.clone(),
            Duration::from_secs(60),
        );
        let host = Arc::new(host);
        let agent = Arc::new(Agent::new(Arc::clone(&host), approval, paths));
        (host, agent, prompts)
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
        agent.sign(class, &request_with(key, 0), None, &desktop())
    }

    fn sign(agent: &Agent<FakeHost>, key: &PrivateKey) -> AgentResponse {
        sign_as(agent, key, &ConnectionClass::LocalUnbound)
    }

    /// What `sign` would log for an unbound request for `key`.
    fn outcome(agent: &Agent<FakeHost>, key: &PrivateKey) -> Result<Vec<u8>, Refused> {
        let sign = request_with(key, 0);
        let request = Request::parse(&ConnectionClass::LocalUnbound, &sign, None).expect("parses");
        agent.authorized_sign("personal", &request, &desktop())
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
        assert_eq!(prompts.shown(), ["Approve github"]);
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
        prompts.push(Step::new(PromptOutcome::Answer(Approval::Deny)));

        assert!(signed(&sign(&agent, &key)));
        let second = second.recv().expect("second request");
        assert!(!signed(&second.join().expect("second request")));
        assert_eq!(prompts.shown().len(), 2);
    }

    /// Every answer other than `Allow` refuses, and grants nothing: the
    /// next request asks again.
    #[test]
    fn a_prompt_that_does_not_allow_refuses_and_grants_nothing() {
        let key = test_key(1);
        let declines = [
            ("deny", PromptOutcome::Answer(Approval::Deny)),
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
            assert!(
                matches!(outcome(&agent, &key), Err(Refused::PromptFailed(_))),
                "{name}"
            );
            assert_eq!(prompts.shown().len(), 2, "{name}");
            assert!(!approved(&host, &key), "{name}");
        }
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
        let (unasked, unasked_agent, _prompts) =
            agent(host(&key, SshKeyConfirm::Never), &Paths::default());
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

    #[test]
    fn a_locked_database_refuses_without_prompting() {
        let key = test_key(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths {
            cache_dir: Some(dir.path().to_path_buf()),
            ..Paths::default()
        };
        let cache = keys::cache_dir(&paths).expect("cache dir");
        keys::write_cache(&cache, "personal", &[key.public_key().clone()]).expect("write cache");
        let (_host, agent, prompts) =
            agent(FakeHost::locked(vec![database("personal", vec![])]), &paths);

        assert_eq!(
            agent
                .ssh_identities(&ConnectionClass::LocalUnbound, &desktop())
                .len(),
            1
        );
        assert!(matches!(outcome(&agent, &key), Err(Refused::Locked)));
        assert!(!signed(&sign(&agent, &key)));
        assert!(prompts.shown().is_empty());
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
            agent.authorized_sign("personal", &request, &desktop()),
            Err(Refused::Sha1Rsa)
        ));
        assert!(prompts.shown().is_empty());

        prompts.push(Step::allow());
        let sha512 = request_with(&key, 4);
        assert!(signed(&agent.sign(&unbound, &sha512, None, &desktop())));
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
                format!(
                    "On github.com ({}): approve github",
                    dest.fingerprint(HashAlg::Sha256)
                ),
                format!("On {}: approve github", other.fingerprint(HashAlg::Sha256)),
            ]
        );
    }

    fn ask(remember: bool) -> Ask {
        let key = test_key(1).public_key().fingerprint(HashAlg::Sha256);
        Ask {
            scope: Scope::new(key, None),
            remember,
        }
    }

    /// `missing_approval` for a database that holds `approved`, if anything.
    fn missing_given(approved: Option<Ask>, need: &Need) -> Option<Ask> {
        let mut ssh = SshSlot::default();
        if let Some(approved) = approved {
            ssh.approvals.grant(approved.scope);
        }
        let (mut last_activity, lock_signal) = (std::time::Instant::now(), CancelSource::new());
        let slot = SlotView::new(None, &mut ssh, &mut last_activity, &lock_signal);
        missing_approval(&slot, need).cloned()
    }

    #[test]
    fn a_request_that_needs_nothing_lacks_nothing() {
        assert_eq!(missing_given(None, &Need::Nothing), None);
    }

    #[test]
    fn an_approval_nothing_covers_is_what_the_request_lacks() {
        for remember in [true, false] {
            let need = Need::Approval(ask(remember));
            assert_eq!(missing_given(None, &need), Some(ask(remember)));
        }
    }

    #[test]
    fn an_approval_the_database_holds_is_not_lacking() {
        let need = Need::Approval(ask(true));
        assert_eq!(missing_given(Some(ask(true)), &need), None);
    }

    #[test]
    fn only_a_missing_approval_with_no_prompt_allowed_is_refused() {
        let missing = ask(true);
        assert!(matches!(
            refusal_before_prompting(Some(&missing), false),
            Some(Refused::NeedsApproval)
        ));
        assert!(refusal_before_prompting(Some(&missing), true).is_none());
        for may_prompt in [true, false] {
            assert!(refusal_before_prompting(None, may_prompt).is_none());
        }
    }
}
