//! Prompting the user for what a signature lacks (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the unlock of a locked database, then the approval of the key.
//! They are two prompts, and answering the first approves nothing.
//!
//! Only one signature at a time asks for a database
//! ([`Agent::wait_for_turn`]). Before it waits, and again before each
//! prompt, it looks at the database ([`Agent::check_may_prompt`]): the
//! requester may not be asked, the prompts may be held back after a cancel,
//! and what the signature lacks may have changed while it waited.
//!
//! The unlock is the agent's own, with the core's steps: begin, whether a
//! prompt may appear on screen, ask with the agent's message, finish.

use std::sync::MutexGuard;

use super::request::Request;
use super::sign::{Asked, Lacking, Refused};
use super::{Agent, message};
use crate::authn::Requester;
use crate::authz::may_prompt_on_screen;
use crate::databases::{Begin, BeginError, UnlockFailure};
use crate::prompt::Declined;
use crate::ssh::approvals::SignatureApproval;
use crate::ssh::keys::ServedKey;

impl Refused {
    /// Whether this is the user declining to answer a prompt, as opposed to
    /// answering no, or a lock ending it: what puts the database's prompts
    /// in backoff (`docs/ssh-agent.md` § 6.6).
    pub(super) fn starts_backoff(&self) -> bool {
        matches!(
            self,
            Refused::Declined(Declined::Cancelled | Declined::TimedOut)
                | Refused::UnlockDeclined(Declined::Cancelled | Declined::TimedOut)
        )
    }
}

impl Agent {
    /// What the request lacks in `key`'s database right now, if the user may
    /// be asked for it: `None` where it lacks nothing. A request that lacks
    /// something is refused where no prompt may appear for the requester, and
    /// while the database's prompts are held back after a cancel. One that
    /// lacks an approval where no prompt may appear is also recorded as
    /// pending, for the approval to be granted later (`docs/ssh-agent.md`
    /// § 6.8).
    pub(super) fn check_may_prompt(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
        needed: Option<&SignatureApproval>,
    ) -> Result<Option<Lacking>, Refused> {
        let hold = self.hold(&key.database)?;
        // The unlock a missing approval is lacking in is taken here, before
        // the display session is read: a screen lock either shows in that
        // read, or cancels the token and ends the prompt it raised.
        let Some(lacking) = hold.lacking(&self.approvals, needed) else {
            return Ok(None);
        };
        if !may_prompt_on_screen(requester, &self.display.get()) {
            if let Lacking::Approval(asked) = &lacking
                && let Some(open) = hold.open()
            {
                self.approvals.record(
                    open,
                    asked.approval.clone(),
                    request.requested(requester),
                    hold.wall(),
                );
            }
            return Err(lacking.refusal());
        }
        if hold.backing_off() {
            return Err(Refused::BackingOff);
        }
        Ok(Some(lacking))
    }

    /// `db`'s turn to be asked about, once whoever has it is done. Held by
    /// the one signature asking about `db`, until it has signed.
    pub(super) fn wait_for_turn(&self, db: &str) -> Result<MutexGuard<'_, ()>, Refused> {
        let turn = self.turns.get(db).ok_or(Refused::NotServed)?;
        Ok(turn.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Asks the user for what the request lacks in `key`'s database: the
    /// unlock if the database is locked, then the confirmation of the
    /// approval if it is still lacking. What they allowed, if they were asked
    /// for an approval, and `None` where nothing is lacking any more or the
    /// answer to the unlock was all that was left.
    pub(super) fn prompt_for_what_is_lacking(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
        needed: Option<&SignatureApproval>,
    ) -> Result<Option<Asked>, Refused> {
        let mut lacking = self.check_may_prompt(key, request, requester, needed)?;
        if matches!(lacking, Some(Lacking::Unlock)) {
            self.prompt_to_unlock(key, request, requester)?;
            // Looks again once: an unlock that left the database unlocked
            // but not yet scanned ends the flow here, and the signature is
            // refused as locked.
            lacking = self.check_may_prompt(key, request, requester, needed)?;
        }
        let Some(Lacking::Approval(mut asked)) = lacking else {
            return Ok(None);
        };
        // The database is unlocked now. The key this request found may be the
        // cache's, which names a key without an override `<database>
        // <fingerprint>`: the scan names it as the unlocked database does, so
        // the confirm prompt and the approval it gives (what `kpa ssh grants`
        // lists) take that name.
        let fresh = self
            .hold(&key.database)?
            .served(request.fingerprint)?
            .clone();
        asked.approval.scope = asked.approval.scope.rekeyed(&fresh);
        self.prompt_to_confirm(request, &asked)?;
        Ok(Some(*asked))
    }

    /// Shows the confirm prompt for signing `request` with the key `asked`'s
    /// approval is for, which ends when the unlock `asked` was found lacking
    /// in is locked.
    fn prompt_to_confirm(&self, request: &Request<'_>, asked: &Asked) -> Result<(), Refused> {
        let question = message::approval(
            asked.approval.scope.key(),
            &request.purpose,
            request.destination.as_ref(),
            request.forwarding_host.as_ref(),
        );
        self.confirm_prompt
            .ask(&question, &asked.unlock)
            .map_err(Refused::PromptFailed)?
            .allowed()
            .map_err(Refused::Declined)
    }

    /// Unlocks `key`'s database with a prompt that says why the signature
    /// needs it. An unlock already in progress (a `kpa unlock` prompting for
    /// it) refuses the signature, and one that finds the database unlocked
    /// already prompts for nothing.
    fn prompt_to_unlock(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
    ) -> Result<(), Refused> {
        let unlocking = match self.databases.begin_unlock(&key.database) {
            Err(BeginError::UnknownDb) => return Err(Refused::NotServed),
            Err(BeginError::InProgress) => return Err(Refused::UnlockInProgress),
            Ok(Begin::AlreadyUnlocked) => return Ok(()),
            Ok(Begin::Started(unlocking)) => unlocking,
        };
        // The display session is read only now that the unlock has its
        // token: a screen lock either shows here and refuses, or cancels the
        // token and ends the prompt, so none is raised behind a locker.
        if !may_prompt_on_screen(requester, &self.display.get()) {
            return Err(Refused::Locked);
        }
        let question = message::unlock(
            key,
            &request.purpose,
            request.destination.as_ref(),
            request.forwarding_host.as_ref(),
        );
        let password = self
            .screen_unlock
            .ask(&question, unlocking.unlock_token())
            .map_err(Refused::PromptFailed)?
            .answered()
            .map_err(Refused::UnlockDeclined)?;
        // An empty answer means "no password": the way to a keyfile-only
        // database from a prompt that always asks.
        unlocking
            .finish(Some(&password).filter(|password| !password.is_empty()))
            .map_err(|failure| match failure {
                UnlockFailure::Vault(err) => Refused::UnlockFailed(err),
                UnlockFailure::LockedMeanwhile => Refused::Locked,
            })
    }

    /// Holds `db`'s prompts back, as a prompt the user cancelled or left
    /// unanswered does. A lock doesn't end it; an unlock does.
    pub(super) fn back_off(&self, db: &str) {
        if let Ok(mut hold) = self.hold(db) {
            hold.back_off();
        }
    }
}
