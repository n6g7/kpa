//! Prompting the user for what a signature lacks (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the unlock of a locked database, then the approval of the key.
//! They are two prompts, and answering the first approves nothing.
//!
//! Only one signature at a time asks for a database
//! ([`Agent::wait_for_turn`]). Before it waits, and again before each
//! prompt, it looks at the database ([`Agent::check_may_prompt`]): the
//! requester may not be asked, the prompts may be held back after a cancel,
//! and what the signature lacks may have changed while it waited.

use std::sync::MutexGuard;

use super::request::Request;
use super::sign::{Lacking, Refused, lacking};
use super::{Agent, SshHost, message};
use crate::authn::Requester;
use crate::authz::may_prompt_on_screen;
use crate::prompt::{CancelToken, Declined};
use crate::proto::{UnlockError, UnlockRequest};
use crate::ssh::approvals::SignatureApproval;
use crate::ssh::keys::ServedKey;

/// What the user confirmed just now: the approval, and the token the
/// database's next lock cancels, so that a confirmation given for a database
/// that has locked since signs nothing.
pub(super) struct Confirmed {
    pub(super) approval: SignatureApproval,
    pub(super) until_lock: CancelToken,
}

impl Refused {
    /// Whether this is the user declining to answer a prompt, as opposed to
    /// answering no, or a lock ending it: what puts the database's prompts
    /// in backoff (`docs/ssh-agent.md` § 6.6).
    pub(super) fn starts_backoff(&self) -> bool {
        matches!(
            self,
            Refused::Declined(Declined::Cancelled | Declined::TimedOut)
                | Refused::Unlock(UnlockError::PromptCancelled { .. })
        )
    }
}

impl<H: SshHost> Agent<H> {
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
        self.hold(&key.database, |slot| {
            let Some(lacking) = lacking(&slot, needed) else {
                return Ok(None);
            };
            if !may_prompt_on_screen(requester, &self.host.display_session()) {
                if let Lacking::Approval(approval) = &lacking
                    && let Ok(served) = slot.served(request.fingerprint)
                {
                    let served = served.clone();
                    let request = request.requested(requester);
                    slot.ssh
                        .pending
                        .record(approval.clone(), served, request, slot.now());
                }
                return Err(lacking.refusal());
            }
            if slot.backing_off() {
                return Err(Refused::BackingOff);
            }
            Ok(Some(lacking))
        })
    }

    /// `db`'s turn to be asked about, once whoever has it is done. Held by
    /// the one signature asking about `db`, until it has signed.
    pub(super) fn wait_for_turn(&self, db: &str) -> Result<MutexGuard<'_, ()>, Refused> {
        let turn = self.turns.get(db).ok_or(Refused::NotServed)?;
        Ok(turn.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Asks the user for what the request lacks in `key`'s database: the
    /// unlock if the database is locked, then the confirmation of the
    /// approval if it is still lacking.
    /// `None` where nothing is lacking any more or the answer to the unlock
    /// was all that was left.
    pub(super) fn prompt_for_what_is_lacking(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
        needed: Option<&SignatureApproval>,
    ) -> Result<Option<Confirmed>, Refused> {
        let mut lacking = self.check_may_prompt(key, request, requester, needed)?;
        if matches!(lacking, Some(Lacking::Unlock)) {
            self.prompt_to_unlock(key, request, requester)?;
            lacking = self.check_may_prompt(key, request, requester, needed)?;
        }
        let Some(Lacking::Approval(approval)) = lacking else {
            return Ok(None);
        };
        self.prompt_to_confirm(key, request, approval).map(Some)
    }

    /// Shows the confirm prompt for signing `request` with `key`, and what
    /// the user confirmed if they allowed it. It ends when the database
    /// locks.
    ///
    /// `key` is the key as the cache or the open database listed it when
    /// the request came in, so a prompt raised after someone else unlocked
    /// the database names it as the cache does, not by its entry's title.
    fn prompt_to_confirm(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        approval: SignatureApproval,
    ) -> Result<Confirmed, Refused> {
        let until_lock = self.hold(&key.database, |slot| Ok(slot.cancel_token()))?;
        let message = message::approval(
            key,
            &request.purpose,
            request.destination(),
            self.known_hosts_name(request).as_deref(),
        );
        self.confirm_prompt
            .ask(&message, &until_lock)
            .map_err(Refused::PromptFailed)?
            .allowed()
            .map_err(Refused::Declined)?;
        Ok(Confirmed {
            approval,
            until_lock,
        })
    }

    /// Unlocks `key`'s database as `kpa unlock` does, with a prompt that
    /// says why the signature needs it.
    fn prompt_to_unlock(
        &self,
        key: &ServedKey,
        request: &Request<'_>,
        requester: &Requester,
    ) -> Result<(), Refused> {
        let message = message::unlock(
            key,
            &request.purpose,
            request.destination(),
            self.known_hosts_name(request).as_deref(),
        );
        let unlock = UnlockRequest {
            db: key.database.clone(),
        };
        self.host
            .unlock(&unlock, requester, Some(&message))
            .map(|_| ())
            .map_err(Refused::Unlock)
    }

    /// The host name `known_hosts` gives the connection's destination, if
    /// it is bound to one that has one.
    fn known_hosts_name(&self, request: &Request<'_>) -> Option<String> {
        let path = self.known_hosts.as_deref()?;
        message::known_hosts_name(path, request.destination()?)
    }

    /// Holds `db`'s prompts back for `backoff` from now, as a prompt the
    /// user cancelled or left unanswered does. A lock doesn't end it; an
    /// unlock does.
    pub(super) fn back_off(&self, db: &str) {
        let _ = self.hold(db, |mut slot| {
            slot.back_off(self.backoff);
            Ok(())
        });
    }
}
