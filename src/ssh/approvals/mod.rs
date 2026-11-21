//! What the user has approved and the requests refused for want of an
//! approval (`docs/ssh-agent.md` § 6.7, § 6.8), held per database and per
//! unlock, in memory only. [`Approvals`] is an observer of the core: a lock
//! drops what it ended.
//!
//! Nothing here reads the clock: every call that needs the time takes `now`.
//! Pending requests are dated in wall-clock time, so a client can tell their
//! age from it; approvals' windows are measured on the monotonic clock.

mod granted;
mod pending;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg};
use uuid::Uuid;

use granted::GrantedApprovals;
pub use pending::PENDING_TTL;
use pending::PendingRequests;

use super::keys::ServedKey;
use crate::cancel::CancelToken;
use crate::databases::{Databases, Observer, Open};

/// What one approval covers: a key, for one destination — the last
/// binding's host key on a `LocalBound` connection, `None` on a
/// `LocalUnbound` one (`ssh-keygen -Y sign`, and clients other than
/// OpenSSH's `ssh`, which never bind at all). Approving a key for one
/// destination never covers another, or covers unbound use, and vice versa
/// (`docs/ssh-agent.md` § 6.7). Computed once, by
/// `ssh_agent::authz::authorize_sign`, and carried to the lookup and
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

/// The approval a signature needs: what it covers, and whether the user's
/// confirmation is kept for the next request of that scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureApproval {
    pub scope: Scope,
    /// Keep the approval until lock (`confirm = "once"`), rather than let
    /// it cover this one signature (`"always"`).
    pub remember: bool,
}

/// What a refused request was, for the user who is asked to approve it.
/// Nothing in it differs between two otherwise identical requests (a
/// login's session identifier is left out), so those merge. Request-derived
/// text (`user`, `namespace`, `command`) is capped by whoever records it
/// and escaped by whoever shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDetails {
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

/// One request refused for want of an approval, as [`PendingRequests`] keeps
/// it and [`Approvals::pending`] lists it.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// What names it to [`Approvals::approve`]. Random, so it never means
    /// another request, and says nothing about the scope.
    pub id: Uuid,
    pub approval: SignatureApproval,
    /// The key the approval is for, as the open database serves it.
    pub key: ServedKey,
    pub request: RequestDetails,
    /// When it was last refused.
    pub refused_at: SystemTime,
}

/// Approvals and pending requests, per database and per unlock. Its own lock
/// is the last in the order (databases, the agent's state, approvals) and is
/// never held while calling the core.
///
/// Each call takes the guard of the database it is about, so the caller shows
/// it holds it, and the state a call sees is the one of that guard's unlock.
/// State tagged with another unlock's token reads as empty; a call that writes
/// replaces it.
#[derive(Default)]
pub struct Approvals {
    held: Mutex<HashMap<String, Held>>,
}

struct Held {
    unlock: CancelToken,
    granted: GrantedApprovals,
    pending: PendingRequests,
}

impl Approvals {
    pub fn new() -> Approvals {
        Approvals::default()
    }

    fn held(&self) -> MutexGuard<'_, HashMap<String, Held>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The state of `open`'s unlock, if there is any: what the map holds for
    /// another unlock is not this unlock's.
    fn current<'a>(held: &'a mut HashMap<String, Held>, open: &Open) -> Option<&'a mut Held> {
        let unlock = open.unlock_token();
        held.get_mut(open.name())
            .filter(|state| state.unlock == unlock)
    }

    /// The state of `open`'s unlock, replacing another unlock's.
    fn fresh<'a>(held: &'a mut HashMap<String, Held>, open: &Open) -> &'a mut Held {
        let unlock = open.unlock_token();
        let state = held.entry(open.name().to_string()).or_insert_with(|| Held {
            unlock: unlock.clone(),
            granted: GrantedApprovals::default(),
            pending: PendingRequests::default(),
        });
        if state.unlock != unlock {
            *state = Held {
                unlock,
                granted: GrantedApprovals::default(),
                pending: PendingRequests::default(),
            };
        }
        state
    }

    /// Whether an approval covers `scope` at `now`.
    pub fn covers(&self, open: &Open, scope: &Scope, now: Instant) -> bool {
        Self::current(&mut self.held(), open).is_some_and(|state| state.granted.covers(scope, now))
    }

    /// Approves `scope` until the lock that ends this unlock.
    pub fn grant(&self, open: &Open, scope: Scope) {
        Self::fresh(&mut self.held(), open).granted.grant(scope);
    }

    /// Uses up `scope`'s one-signature approval, if it has one. An approval
    /// kept until lock stays.
    pub fn spend(&self, open: &Open, scope: &Scope) {
        if let Some(state) = Self::current(&mut self.held(), open) {
            state.granted.spend(scope);
        }
    }

    /// Records that `request` was refused for want of `approval`, which is
    /// for `key`: identical requests merge, at most 16 are kept, each for
    /// five minutes.
    pub fn record(
        &self,
        open: &Open,
        approval: SignatureApproval,
        key: ServedKey,
        request: RequestDetails,
        now: SystemTime,
    ) {
        Self::fresh(&mut self.held(), open)
            .pending
            .record(approval, key, request, now);
    }

    /// This database's pending requests at `now`, oldest first.
    pub fn pending(&self, open: &Open, now: SystemTime) -> Vec<PendingRequest> {
        Self::current(&mut self.held(), open)
            .map(|state| state.pending.list(now).cloned().collect())
            .unwrap_or_default()
    }

    /// Approves what request `id` asked for, as the user's `Allow` on screen
    /// would, except that an approval for one signature is kept for `window`
    /// for the retry. Every request pending for the same scope is answered.
    /// Returns the approved key, `None` if no request has that id.
    pub fn approve(
        &self,
        open: &Open,
        id: Uuid,
        now: Instant,
        wall: SystemTime,
        window: Duration,
    ) -> Option<Fingerprint> {
        let mut held = self.held();
        let state = Self::current(&mut held, open)?;
        let approval = state.pending.take(id, wall)?;
        let key = approval.scope.key();
        state.granted.approve(approval, now, window);
        Some(key)
    }
}

impl Observer for Approvals {
    /// Drops `db`'s state if it is tagged with `unlock`, and nothing else: a
    /// late notice for an old unlock leaves a new unlock's state.
    fn locked(&self, _: &Databases, db: &str, unlock: &CancelToken) {
        let mut held = self.held();
        if held.get(db).is_some_and(|state| state.unlock == *unlock) {
            held.remove(db);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::databases::testing::TestEntry;
    use crate::ssh::testing::{approval, database, key, requested};

    const WINDOW: Duration = Duration::from_secs(60);
    const IDLE: Duration = Duration::from_secs(3600);

    /// `personal` and `work`, unlocked, with the state registered.
    fn fixture() -> (Databases, Arc<Approvals>) {
        let mut databases = Databases::for_test(
            vec![database("personal", vec![]), database("work", vec![])],
            IDLE,
        );
        let approvals = Arc::new(Approvals::new());
        databases.observe(approvals.clone());
        databases.install_for_test("personal", vec![TestEntry::new("github")]);
        databases.install_for_test("work", vec![TestEntry::new("deploy")]);
        (databases, approvals)
    }

    fn unlock_again(databases: &Databases, db: &str) {
        databases.lock(db).expect("configured");
        databases.install_for_test(db, vec![TestEntry::new("github")]);
    }

    #[test]
    fn an_approval_until_lock_ends_with_the_lock_and_not_the_next_unlock() {
        let (databases, approvals) = fixture();
        let now = Instant::now();
        let scope = approval(1, None, true).scope;
        approvals.grant(&databases.open("personal").unwrap(), scope.clone());

        let open = databases.open("personal").unwrap();
        assert!(approvals.covers(&open, &scope, now + WINDOW * 100));
        drop(open);
        assert!(!approvals.covers(&databases.open("work").unwrap(), &scope, now));

        unlock_again(&databases, "personal");
        assert!(!approvals.covers(&databases.open("personal").unwrap(), &scope, now));
    }

    #[test]
    fn a_one_signature_approval_lasts_its_window_and_is_spent_once() {
        let (databases, approvals) = fixture();
        let (t0, wall, ask) = (Instant::now(), SystemTime::now(), approval(1, None, false));
        approvals.record(
            &databases.open("personal").unwrap(),
            ask.clone(),
            key(),
            requested("ssh"),
            wall,
        );
        let open = databases.open("personal").unwrap();
        let id = approvals.pending(&open, wall)[0].id;
        assert_eq!(
            approvals.approve(&open, id, t0, wall, WINDOW),
            Some(ask.scope.key())
        );

        assert!(approvals.covers(&open, &ask.scope, t0 + WINDOW - Duration::from_millis(1)));
        assert!(!approvals.covers(&open, &ask.scope, t0 + WINDOW));
        approvals.spend(&open, &ask.scope);
        assert!(!approvals.covers(&open, &ask.scope, t0));
    }

    #[test]
    fn approving_a_remembered_request_grants_until_lock_and_answers_its_scope() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let open = databases.open("personal").unwrap();
        let ask = approval(1, None, true);
        approvals.record(&open, ask.clone(), key(), requested("ssh"), wall);
        approvals.record(&open, ask.clone(), key(), requested("git"), wall);
        approvals.record(
            &open,
            approval(2, None, true),
            key(),
            requested("ssh"),
            wall,
        );
        let pending = approvals.pending(&open, wall);
        assert_eq!(pending.len(), 3);

        assert_eq!(
            approvals.approve(&open, Uuid::new_v4(), now, wall, WINDOW),
            None
        );
        assert!(
            approvals
                .approve(&open, pending[0].id, now, wall, WINDOW)
                .is_some()
        );
        assert!(approvals.covers(&open, &ask.scope, now + WINDOW * 100));
        assert_eq!(approvals.pending(&open, wall).len(), 1);
        assert_eq!(
            approvals.approve(&open, pending[1].id, now, wall, WINDOW),
            None
        );
    }

    #[test]
    fn requests_are_per_database_and_listed_by_asking_each_in_config_order() {
        let (databases, approvals) = fixture();
        let now = SystemTime::now();
        for (db, command) in [("work", "ssh"), ("personal", "git")] {
            approvals.record(
                &databases.open(db).unwrap(),
                approval(1, None, true),
                key(),
                requested(command),
                now,
            );
        }

        let listed: Vec<_> = databases
            .configs()
            .iter()
            .flat_map(|cfg| approvals.pending(&databases.open(&cfg.name).unwrap(), now))
            .map(|pending| pending.request.command.expect("command"))
            .collect();
        assert_eq!(listed, ["git", "ssh"]);
    }

    #[test]
    fn a_lock_drops_pending_requests_and_approvals_of_that_database_only() {
        let (databases, approvals) = fixture();
        let now = SystemTime::now();
        for db in ["personal", "work"] {
            let open = databases.open(db).unwrap();
            let titled = ServedKey {
                title: Some("a secret title".to_string()),
                ..key()
            };
            approvals.record(
                &open,
                approval(1, None, false),
                titled,
                requested("ssh"),
                now,
            );
        }
        databases.lock("personal").unwrap();
        assert!(approvals.held().get("personal").is_none());

        databases.install_for_test("personal", vec![TestEntry::new("github")]);
        assert!(
            approvals
                .pending(&databases.open("personal").unwrap(), now)
                .is_empty()
        );
        let work = approvals.pending(&databases.open("work").unwrap(), now);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].key.title.as_deref(), Some("a secret title"));
    }

    #[test]
    fn a_late_notice_for_an_old_unlock_leaves_the_new_unlocks_state() {
        let (databases, approvals) = fixture();
        let old = databases.open("personal").unwrap().unlock_token();
        unlock_again(&databases, "personal");
        let now = SystemTime::now();
        let open = databases.open("personal").unwrap();
        approvals.record(
            &open,
            approval(1, None, false),
            key(),
            requested("ssh"),
            now,
        );

        approvals.locked(&databases, "personal", &old);
        assert_eq!(approvals.pending(&open, now).len(), 1);
    }

    #[test]
    fn state_of_another_unlock_reads_as_empty_and_a_write_replaces_it() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let scope = approval(1, None, true).scope;
        approvals.grant(&databases.open("personal").unwrap(), scope.clone());
        // The old unlock's state is still in the map, as if its notice were late.
        let stale = approvals.held().remove("personal").unwrap();
        unlock_again(&databases, "personal");
        approvals.held().insert("personal".to_string(), stale);

        let open = databases.open("personal").unwrap();
        assert!(!approvals.covers(&open, &scope, now));
        approvals.spend(&open, &scope);
        approvals.record(
            &open,
            approval(2, None, true),
            key(),
            requested("ssh"),
            wall,
        );
        assert!(!approvals.covers(&open, &scope, now));
        assert_eq!(approvals.pending(&open, wall).len(), 1);
    }
}
