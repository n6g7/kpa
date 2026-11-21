//! The requests refused for want of an approval that `ssh approve` can still
//! grant.

use std::time::{Duration, SystemTime};

use uuid::Uuid;

use super::{PendingRequest, RequestDetails, SignatureApproval};

/// How long a pending request is kept after it was last refused.
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// At most this many requests are pending at once.
const MAX_PENDING: usize = 16;

/// Requests from outside the desktop that were refused for want of an
/// approval no prompt could ask for (`docs/ssh-agent.md` § 6.8), oldest
/// first.
#[derive(Debug, Default)]
pub struct PendingRequests(Vec<PendingRequest>);

impl PendingRequests {
    /// Records that `request` was refused for want of `approval`, which
    /// belongs to forwarding session number `forwarding_session`, if it is
    /// forwarded. A request identical to a pending one is merged into it,
    /// which keeps it and its id another [`PENDING_TTL`]. Past
    /// [`MAX_PENDING`] the oldest goes.
    pub fn record(
        &mut self,
        approval: SignatureApproval,
        forwarding_session: Option<u32>,
        request: RequestDetails,
        now: SystemTime,
    ) {
        self.0.retain(|pending| !expired(pending, now));
        let id = match self
            .0
            .iter()
            .position(|pending| pending.approval == approval && pending.request == request)
        {
            Some(merged) => self.0.remove(merged).id,
            None => Uuid::new_v4(),
        };
        if self.0.len() >= MAX_PENDING {
            self.0.remove(0);
        }
        self.0.push(PendingRequest {
            id,
            approval,
            forwarding_session,
            request,
            refused_at: now,
        });
    }

    /// The forwarding sessions the requests kept refer to.
    pub fn sessions(&self) -> impl Iterator<Item = u32> {
        self.0
            .iter()
            .filter_map(|pending| pending.forwarding_session)
    }

    /// The requests still pending at `now`, oldest first.
    pub fn list(&self, now: SystemTime) -> impl Iterator<Item = &PendingRequest> {
        self.0.iter().filter(move |pending| !expired(pending, now))
    }

    /// Answers the request `id` names: removes it, and every other request
    /// pending for its scope, and returns the approval it recorded. `None` if
    /// none has that id at `now`: it expired, a lock dropped it, or `id` never
    /// named one.
    pub fn take(&mut self, id: Uuid, now: SystemTime) -> Option<SignatureApproval> {
        self.0.retain(|pending| !expired(pending, now));
        let taken = self.0.iter().find(|pending| pending.id == id)?.clone();
        self.0
            .retain(|pending| pending.approval.scope != taken.approval.scope);
        Some(taken.approval)
    }
}

fn expired(pending: &PendingRequest, now: SystemTime) -> bool {
    // A clock set back reads as just refused.
    now.duration_since(pending.refused_at).unwrap_or_default() >= PENDING_TTL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::testing::{approval, requested};

    #[test]
    fn identical_requests_merge_keeping_the_id_and_the_latest_time() {
        let mut pending = PendingRequests::default();
        let t0 = SystemTime::now();
        pending.record(approval(1, None, true), None, requested("ssh"), t0);
        let id = pending.list(t0).next().expect("pending").id;
        pending.record(
            approval(1, None, true),
            None,
            requested("ssh"),
            t0 + Duration::from_secs(200),
        );
        pending.record(
            approval(1, None, true),
            None,
            requested("git"),
            t0 + Duration::from_secs(200),
        );

        // The first is kept past its original 5 minutes by the repeat.
        let at = t0 + Duration::from_secs(400);
        let listed: Vec<_> = pending.list(at).collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].request.command.as_deref(), Some("ssh"));
        assert_eq!(listed[0].id, id);
        assert_ne!(listed[1].id, id);
        assert_eq!(listed[0].refused_at, t0 + Duration::from_secs(200));
    }

    #[test]
    fn a_request_is_kept_for_five_minutes() {
        let mut pending = PendingRequests::default();
        let t0 = SystemTime::now();
        pending.record(approval(1, None, true), None, requested("ssh"), t0);
        let id = pending.list(t0).next().expect("pending").id;

        assert_eq!(
            pending
                .list(t0 + PENDING_TTL - Duration::from_secs(1))
                .count(),
            1
        );
        assert_eq!(pending.list(t0 + PENDING_TTL).count(), 0);
        assert_eq!(pending.take(id, t0 + PENDING_TTL), None);
    }

    #[test]
    fn past_the_cap_the_oldest_goes() {
        let mut pending = PendingRequests::default();
        let t0 = SystemTime::now();
        for command in 0..=MAX_PENDING {
            pending.record(
                approval(1, None, true),
                None,
                requested(&command.to_string()),
                t0,
            );
        }

        let commands: Vec<_> = pending
            .list(t0)
            .map(|listed| listed.request.command.clone().expect("command"))
            .collect();
        assert_eq!(commands.len(), MAX_PENDING);
        assert_eq!(commands[0], "1");
        assert_eq!(commands[MAX_PENDING - 1], MAX_PENDING.to_string());
    }

    /// Answering a request answers every one pending for its scope, and the
    /// approval it returns is the one recorded. An id that names nothing answers
    /// nothing.
    #[test]
    fn taking_an_id_removes_its_scopes_requests_and_returns_the_recorded_ask() {
        let mut pending = PendingRequests::default();
        let now = SystemTime::now();
        pending.record(approval(1, None, false), None, requested("ssh"), now);
        pending.record(approval(1, None, false), None, requested("git"), now);
        pending.record(approval(2, None, true), None, requested("ssh"), now);
        let ids: Vec<_> = pending.list(now).map(|listed| listed.id).collect();

        assert_eq!(pending.take(Uuid::new_v4(), now), None);
        assert_eq!(pending.take(ids[1], now), Some(approval(1, None, false)));
        assert_eq!(pending.take(ids[0], now), None);
        assert_eq!(pending.list(now).count(), 1);
    }
}
