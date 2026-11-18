//! Approvals and pending requests (`docs/ssh-agent.md` § 6.7, § 6.8): the
//! [`Scope`] an approval covers, [`GrantedApprovals`], what the user has approved
//! since unlock, and [`PendingRequests`], the requests refused for want of an
//! approval that an `ssh_approve` can still grant. In memory only, and
//! dropped with the database's SSH-agent state on lock.
//!
//! Neither reads the clock: every method that needs the time takes `now`.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg};
use uuid::Uuid;

use super::authz::SignatureApproval;

/// How long a pending request is kept after it was last refused.
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// At most this many requests are pending at once.
pub const MAX_PENDING: usize = 16;

/// What one approval covers: a key, for one destination — the last
/// binding's host key on a `LocalBound` connection, `None` on a
/// `LocalUnbound` one (`ssh-keygen -Y sign`, and clients other than
/// OpenSSH's `ssh`, which never bind at all). Approving a key for one
/// destination never covers another, or covers unbound use, and vice versa
/// (`docs/ssh-agent.md` § 6.7). Computed once, by
/// [`authorize_sign`](super::authz::authorize_sign), and carried to the lookup and
/// the grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope {
    key: Fingerprint,
    /// The destination's host key, by its SHA-256 fingerprint.
    destination: Option<Fingerprint>,
}

impl Scope {
    pub fn new(key: Fingerprint, destination: Option<&KeyData>) -> Scope {
        Scope {
            key,
            destination: destination.map(|dest| dest.fingerprint(HashAlg::Sha256)),
        }
    }

    pub fn key(&self) -> Fingerprint {
        self.key
    }

    pub fn destination(&self) -> Option<Fingerprint> {
        self.destination
    }
}

/// The scopes approved since the last lock.
#[derive(Debug, Default)]
pub struct GrantedApprovals {
    /// Approved until lock: a `confirm = "once"` key's.
    until_lock: HashSet<Scope>,
    /// Approved for one signature, until the expiry: a `confirm =
    /// "always"` key's, approved by `ssh_approve`.
    one_shots: HashMap<Scope, Instant>,
}

impl GrantedApprovals {
    /// Whether an approval covers `scope` at `now`.
    pub fn covers(&self, scope: &Scope, now: Instant) -> bool {
        self.until_lock.contains(scope)
            || self
                .one_shots
                .get(scope)
                .is_some_and(|expiry| now < *expiry)
    }

    /// Approves `scope` until lock.
    pub fn grant(&mut self, scope: Scope) {
        self.until_lock.insert(scope);
    }

    /// Grants what `approval` asked for, as the user's `Allow` on screen would,
    /// except that an approval for one signature is kept for `window`
    /// rather than ending with a prompt: the retry is a separate request
    /// that comes later.
    pub fn approve(&mut self, approval: SignatureApproval, now: Instant, window: Duration) {
        if approval.remember {
            self.grant(approval.scope);
        } else {
            self.one_shots.retain(|_, expiry| now < *expiry);
            self.one_shots.insert(approval.scope, now + window);
        }
    }

    /// Uses up `scope`'s one-shot approval, if it has one. An approval kept
    /// until lock stays.
    pub fn spend(&mut self, scope: &Scope) {
        self.one_shots.remove(scope);
    }
}

/// What a refused request was, for the user who is asked to approve it.
/// Nothing in it differs between two otherwise identical requests (a
/// login's session identifier is left out), so those merge. Request-derived
/// text (`user`, `namespace`, `command`) is capped by whoever records it
/// and escaped by whoever shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDetails {
    /// The key's name, from its override or its entry's title.
    pub key_name: String,
    /// `Purpose::label`.
    pub purpose: &'static str,
    /// The remote user of a login.
    pub user: Option<String>,
    /// The namespace of an `SSHSIG` request.
    pub namespace: Option<String>,
    /// `ConnectionClass::label`.
    pub class: &'static str,
    /// The requester's command name.
    pub command: Option<String>,
}

#[derive(Debug)]
struct Entry {
    /// What a client names the request by, to approve it. Random, so it
    /// never means another request, and says nothing about the scope.
    id: Uuid,
    approval: SignatureApproval,
    requested: RequestDetails,
    /// When it was last refused.
    at: Instant,
}

/// One pending request, as [`PendingRequests::list`] shows it.
#[derive(Debug)]
pub struct Listed<'a> {
    pub id: Uuid,
    pub approval: &'a SignatureApproval,
    pub requested: &'a RequestDetails,
    /// Since it was last refused.
    pub age: Duration,
}

/// Requests from outside the desktop that were refused for want of an
/// approval no prompt could ask for (`docs/ssh-agent.md` § 6.8), oldest
/// first.
#[derive(Debug, Default)]
pub struct PendingRequests(Vec<Entry>);

impl PendingRequests {
    /// Records that `requested` was refused for want of `approval`'s approval. A
    /// request identical to a pending one is merged into it, which keeps it
    /// and its id another [`PENDING_TTL`]. Past [`MAX_PENDING`] the oldest
    /// goes.
    pub fn record(&mut self, approval: SignatureApproval, requested: RequestDetails, now: Instant) {
        self.0.retain(|entry| !expired(entry, now));
        let id = match self
            .0
            .iter()
            .position(|entry| entry.approval == approval && entry.requested == requested)
        {
            Some(merged) => self.0.remove(merged).id,
            None => Uuid::new_v4(),
        };
        if self.0.len() >= MAX_PENDING {
            self.0.remove(0);
        }
        self.0.push(Entry {
            id,
            approval,
            requested,
            at: now,
        });
    }

    /// The requests still pending at `now`, oldest first.
    pub fn list(&self, now: Instant) -> impl Iterator<Item = Listed<'_>> {
        self.0
            .iter()
            .filter(move |entry| !expired(entry, now))
            .map(move |entry| Listed {
                id: entry.id,
                approval: &entry.approval,
                requested: &entry.requested,
                age: now.saturating_duration_since(entry.at),
            })
    }

    /// Answers the request `id` names: removes it, and every other request
    /// pending for its scope, and returns the approval it recorded. `None` if
    /// none has that id at `now`: it expired, a lock dropped it, or `id`
    /// never named one.
    pub fn take(&mut self, id: Uuid, now: Instant) -> Option<SignatureApproval> {
        self.0.retain(|entry| !expired(entry, now));
        let approval = self.0.iter().find(|entry| entry.id == id)?.approval.clone();
        self.0
            .retain(|entry| entry.approval.scope != approval.scope);
        Some(approval)
    }
}

fn expired(entry: &Entry, now: Instant) -> bool {
    now.saturating_duration_since(entry.at) >= PENDING_TTL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_agent::testing::test_key;

    const WINDOW: Duration = Duration::from_secs(60);

    fn fingerprint(seed: u64) -> Fingerprint {
        test_key(seed)
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
    }

    fn host_key(seed: u64) -> KeyData {
        test_key(seed).public_key().key_data().clone()
    }

    fn approval(key: u64, destination: Option<u64>, remember: bool) -> SignatureApproval {
        SignatureApproval {
            scope: Scope::new(fingerprint(key), destination.map(host_key).as_ref()),
            remember,
        }
    }

    fn requested(command: &str) -> RequestDetails {
        RequestDetails {
            key_name: "github".to_string(),
            purpose: "login",
            user: Some("alice".to_string()),
            namespace: None,
            class: "local",
            command: Some(command.to_string()),
        }
    }

    #[test]
    fn nothing_is_covered_before_a_grant() {
        assert!(
            !GrantedApprovals::default().covers(&Scope::new(fingerprint(1), None), Instant::now())
        );
    }

    #[test]
    fn an_approval_covers_its_key_and_destination_only() {
        let (dest, other) = (host_key(2), host_key(3));
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        approvals.grant(Scope::new(fingerprint(1), Some(&dest)));

        assert!(approvals.covers(&Scope::new(fingerprint(1), Some(&dest)), now));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), Some(&other)), now));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), None), now));
        assert!(!approvals.covers(&Scope::new(fingerprint(4), Some(&dest)), now));
    }

    #[test]
    fn an_unbound_approval_does_not_cover_bound_use() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        approvals.grant(Scope::new(fingerprint(1), None));

        assert!(approvals.covers(&Scope::new(fingerprint(1), None), now));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), Some(&host_key(2))), now));
    }

    #[test]
    fn approving_a_remembered_ask_lasts_until_lock() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        let approval = approval(1, None, true);
        approvals.approve(approval.clone(), now, WINDOW);

        assert!(approvals.covers(&approval.scope, now + WINDOW * 100));
        approvals.spend(&approval.scope);
        assert!(approvals.covers(&approval.scope, now));
    }

    #[test]
    fn approving_a_one_signature_ask_covers_the_window_and_one_spend() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        let approval = approval(1, None, false);
        approvals.approve(approval.clone(), now, WINDOW);

        assert!(approvals.covers(&approval.scope, now + WINDOW - Duration::from_millis(1)));
        assert!(!approvals.covers(&approval.scope, now + WINDOW));
        assert!(approvals.covers(&approval.scope, now));
        approvals.spend(&approval.scope);
        assert!(!approvals.covers(&approval.scope, now));
    }

    #[test]
    fn identical_requests_merge_keeping_the_id_and_the_latest_time() {
        let mut pending = PendingRequests::default();
        let t0 = Instant::now();
        pending.record(approval(1, None, true), requested("ssh"), t0);
        let id = pending.list(t0).next().expect("pending").id;
        pending.record(
            approval(1, None, true),
            requested("ssh"),
            t0 + Duration::from_secs(200),
        );
        pending.record(
            approval(1, None, true),
            requested("git"),
            t0 + Duration::from_secs(200),
        );

        // The first is kept past its original 5 minutes by the repeat.
        let at = t0 + Duration::from_secs(400);
        let listed: Vec<_> = pending.list(at).collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].requested.command.as_deref(), Some("ssh"));
        assert_eq!(listed[0].id, id);
        assert_ne!(listed[1].id, id);
        assert_eq!(listed[0].age, Duration::from_secs(200));
    }

    #[test]
    fn a_request_is_kept_for_five_minutes() {
        let mut pending = PendingRequests::default();
        let t0 = Instant::now();
        pending.record(approval(1, None, true), requested("ssh"), t0);
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
        let t0 = Instant::now();
        for command in 0..=MAX_PENDING {
            pending.record(approval(1, None, true), requested(&command.to_string()), t0);
        }

        let commands: Vec<_> = pending
            .list(t0)
            .map(|listed| listed.requested.command.clone().expect("command"))
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
        let now = Instant::now();
        pending.record(approval(1, None, false), requested("ssh"), now);
        pending.record(approval(1, None, false), requested("git"), now);
        pending.record(approval(2, None, true), requested("ssh"), now);
        let ids: Vec<_> = pending.list(now).map(|listed| listed.id).collect();

        assert_eq!(pending.take(Uuid::new_v4(), now), None);
        assert_eq!(pending.take(ids[1], now), Some(approval(1, None, false)));
        assert_eq!(pending.take(ids[0], now), None);
        assert_eq!(pending.list(now).count(), 1);
    }
}
