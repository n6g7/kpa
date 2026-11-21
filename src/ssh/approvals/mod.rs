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
mod sessions;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg};
use uuid::Uuid;

use granted::GrantedApprovals;
pub use granted::{Grant, GrantSource, Lasts};
pub use pending::PENDING_TTL;
use pending::PendingRequests;
use sessions::ForwardingSessions;

use super::keys::ServedKey;
use crate::cancel::CancelToken;
use crate::databases::{Databases, Observer, Open};

/// What one approval covers: a key, for one destination — the last
/// binding's host key on a bound connection, `None` on a `LocalUnbound` one
/// (`ssh-keygen -Y sign`, and clients other than OpenSSH's `ssh`, which never
/// bind at all) — and, on a forwarded connection, one forwarding session.
/// Approving a key for one destination never covers another, or covers
/// unbound use, and vice versa. A forwarded approval covers its forwarding
/// session only: not another `ssh -A`, not local use, and not the same
/// destination reached through another forwarding host (`docs/ssh-agent.md`
/// § 6.7). Computed once, by `ssh_agent::authz::authorize_sign`, and carried
/// to the lookup and the grant.
///
/// The scope holds the key as the open database serves it, so whatever shows
/// an approval can name the key. Two scopes are the same when their keys have
/// the same fingerprint and their destination and forwarding session match:
/// the key's other fields (its name, title, database) describe it, and don't
/// change within an unlock.
#[derive(Debug, Clone)]
pub struct Scope {
    key: ServedKey,
    /// The destination's host key, by its SHA-256 fingerprint.
    destination: Option<Fingerprint>,
    /// The forwarding session, for a forwarded connection.
    forwarding: Option<Box<Forwarding>>,
}

/// The forwarding session a [`Scope`] is limited to: the session identifier
/// the local `ssh` bound before the remote side could send anything, and the
/// host it forwarded to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Forwarding {
    session: Vec<u8>,
    host: Fingerprint,
}

impl PartialEq for Scope {
    fn eq(&self, other: &Scope) -> bool {
        self.key.fingerprint == other.key.fingerprint
            && self.destination == other.destination
            && self.forwarding == other.forwarding
    }
}

impl Eq for Scope {}

impl std::hash::Hash for Scope {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.fingerprint.hash(state);
        self.destination.hash(state);
        self.forwarding.hash(state);
    }
}

impl Scope {
    /// A local connection's scope for `key`, and for `destination` if it is
    /// bound to one.
    pub fn local(key: &ServedKey, destination: Option<&KeyData>) -> Scope {
        Scope {
            key: key.clone(),
            destination: destination.map(|dest| dest.fingerprint(HashAlg::Sha256)),
            forwarding: None,
        }
    }

    /// A forwarded connection's scope: forwarding session `session`, to
    /// `host`, signing for `destination`.
    pub fn forwarded(
        key: &ServedKey,
        session: &[u8],
        host: &KeyData,
        destination: &KeyData,
    ) -> Scope {
        Scope {
            key: key.clone(),
            destination: Some(destination.fingerprint(HashAlg::Sha256)),
            forwarding: Some(Box::new(Forwarding {
                session: session.to_vec(),
                host: host.fingerprint(HashAlg::Sha256),
            })),
        }
    }

    /// The key the approval is for, as the open database serves it.
    pub fn key(&self) -> &ServedKey {
        &self.key
    }

    pub fn destination(&self) -> Option<Fingerprint> {
        self.destination
    }

    /// The host key of the forwarding host, for a forwarded connection's
    /// scope. The session identifier is never shown.
    pub fn forwarding_host(&self) -> Option<Fingerprint> {
        self.forwarding.as_ref().map(|forwarding| forwarding.host)
    }

    /// Whether this is a forwarded connection's scope.
    fn is_forwarded(&self) -> bool {
        self.forwarding.is_some()
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
    sessions: ForwardingSessions,
}

impl Held {
    fn new(unlock: CancelToken) -> Held {
        Held {
            unlock,
            granted: GrantedApprovals::default(),
            pending: PendingRequests::default(),
            sessions: ForwardingSessions::default(),
        }
    }

    /// Forgets the numbers of forwarding sessions that no grant and no
    /// pending request refers to.
    fn drop_unused_sessions(&mut self) {
        let (granted, pending) = (&self.granted, &self.pending);
        self.sessions
            .retain(|forwarding| granted.refers_to(forwarding) || pending.refers_to(forwarding));
    }
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
        let state = held
            .entry(open.name().to_string())
            .or_insert_with(|| Held::new(unlock.clone()));
        if state.unlock != unlock {
            *state = Held::new(unlock);
        }
        state
    }

    /// Whether an approval covers `scope` at `now`.
    pub fn covers(&self, open: &Open, scope: &Scope, now: Instant) -> bool {
        Self::current(&mut self.held(), open).is_some_and(|state| state.granted.covers(scope, now))
    }

    /// Approves `scope` until the lock that ends this unlock.
    pub fn grant(&self, open: &Open, scope: Scope, by: GrantSource, wall: SystemTime) {
        let mut held = self.held();
        let state = Self::fresh(&mut held, open);
        state.sessions.note(&scope);
        state.granted.grant(scope, by, wall);
        state.drop_unused_sessions();
    }

    /// Records a signature `scope`'s approval covered at `wall`, once it is
    /// made: a one-signature approval is used up, and one kept until lock
    /// counts it.
    pub fn used(&self, open: &Open, scope: &Scope, wall: SystemTime) {
        if let Some(state) = Self::current(&mut self.held(), open) {
            state.granted.used(scope, wall);
            state.drop_unused_sessions();
        }
    }

    /// This database's grants at `now`, oldest first.
    pub fn granted(&self, open: &Open, now: Instant) -> Vec<Grant> {
        Self::current(&mut self.held(), open)
            .map(|state| state.granted.list(now).cloned().collect())
            .unwrap_or_default()
    }

    /// The number of the forwarding session `scope` is for, 1, 2, … in the
    /// order this unlock's grants and pending requests first referred to
    /// them. `None` for a scope that isn't forwarded.
    pub fn forwarding_session(&self, open: &Open, scope: &Scope) -> Option<u32> {
        Self::current(&mut self.held(), open)?
            .sessions
            .number(scope)
    }

    /// Records that `request` was refused for want of `approval`: identical
    /// requests merge, at most 16 are kept, each for five minutes.
    pub fn record(
        &self,
        open: &Open,
        approval: SignatureApproval,
        request: RequestDetails,
        now: SystemTime,
    ) {
        let mut held = self.held();
        let state = Self::fresh(&mut held, open);
        state.sessions.note(&approval.scope);
        state.pending.record(approval, request, now);
        state.drop_unused_sessions();
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
        let approved = approval.scope.key().fingerprint;
        state.sessions.note(&approval.scope);
        state.granted.approve(approval, now, wall, window);
        state.drop_unused_sessions();
        Some(approved)
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
    use crate::ssh::testing::{approval, database, host_key, key, requested};

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

    /// Grants `scope` on screen, as of now.
    fn grant(approvals: &Approvals, open: &Open, scope: Scope) {
        approvals.grant(open, scope, GrantSource::OnScreen, SystemTime::now());
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
        grant(
            &approvals,
            &databases.open("personal").unwrap(),
            scope.clone(),
        );

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
            requested("ssh"),
            wall,
        );
        let open = databases.open("personal").unwrap();
        let id = approvals.pending(&open, wall)[0].id;
        assert_eq!(
            approvals.approve(&open, id, t0, wall, WINDOW),
            Some(ask.scope.key().fingerprint)
        );

        assert!(approvals.covers(&open, &ask.scope, t0 + WINDOW - Duration::from_millis(1)));
        assert!(!approvals.covers(&open, &ask.scope, t0 + WINDOW));
        approvals.used(&open, &ask.scope, SystemTime::now());
        assert!(!approvals.covers(&open, &ask.scope, t0));
    }

    #[test]
    fn approving_a_remembered_request_grants_until_lock_and_answers_its_scope() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let open = databases.open("personal").unwrap();
        let ask = approval(1, None, true);
        approvals.record(&open, ask.clone(), requested("ssh"), wall);
        approvals.record(&open, ask.clone(), requested("git"), wall);
        approvals.record(&open, approval(2, None, true), requested("ssh"), wall);
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
            let ask = SignatureApproval {
                scope: Scope::local(&titled, None),
                remember: false,
            };
            approvals.record(&open, ask, requested("ssh"), now);
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
        assert_eq!(
            work[0].approval.scope.key().title.as_deref(),
            Some("a secret title")
        );
    }

    #[test]
    fn a_late_notice_for_an_old_unlock_leaves_the_new_unlocks_state() {
        let (databases, approvals) = fixture();
        let old = databases.open("personal").unwrap().unlock_token();
        unlock_again(&databases, "personal");
        let now = SystemTime::now();
        let open = databases.open("personal").unwrap();
        approvals.record(&open, approval(1, None, false), requested("ssh"), now);

        approvals.locked(&databases, "personal", &old);
        assert_eq!(approvals.pending(&open, now).len(), 1);
    }

    #[test]
    fn state_of_another_unlock_reads_as_empty_and_a_write_replaces_it() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let scope = approval(1, None, true).scope;
        grant(
            &approvals,
            &databases.open("personal").unwrap(),
            scope.clone(),
        );
        // The old unlock's state is still in the map, as if its notice were late.
        let stale = approvals.held().remove("personal").unwrap();
        unlock_again(&databases, "personal");
        approvals.held().insert("personal".to_string(), stale);

        let open = databases.open("personal").unwrap();
        assert!(!approvals.covers(&open, &scope, now));
        approvals.used(&open, &scope, SystemTime::now());
        approvals.record(&open, approval(2, None, true), requested("ssh"), wall);
        assert!(!approvals.covers(&open, &scope, now));
        assert_eq!(approvals.pending(&open, wall).len(), 1);
    }

    #[test]
    fn grants_are_listed_per_database_with_their_uses_and_gone_with_the_lock() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let scope = approval(1, None, true).scope;
        let open = databases.open("personal").unwrap();
        approvals.grant(&open, scope.clone(), GrantSource::OnScreen, wall);
        approvals.used(&open, &scope, SystemTime::now());

        let granted = approvals.granted(&open, now);
        assert_eq!(granted.len(), 1);
        assert_eq!((granted[0].uses, granted[0].granted_at), (1, wall));
        drop(open);
        assert!(
            approvals
                .granted(&databases.open("work").unwrap(), now)
                .is_empty()
        );

        unlock_again(&databases, "personal");
        assert!(
            approvals
                .granted(&databases.open("personal").unwrap(), now)
                .is_empty()
        );
    }

    /// A scope is its key's fingerprint, destination and forwarding session:
    /// the key's other fields describe it and take no part.
    #[test]
    fn scopes_are_told_apart_by_fingerprint_destination_and_session_only() {
        let renamed = ServedKey {
            name: "another name".to_string(),
            title: Some("a title".to_string()),
            ..key()
        };
        let scope = approval(1, None, true).scope;
        assert_eq!(scope, Scope::local(&renamed, None));
        assert_ne!(scope, Scope::local(&key(), Some(&host_key(2))));
        assert_ne!(scope, approval(3, None, true).scope);
        let (host, dest) = (host_key(4), host_key(5));
        assert_ne!(
            Scope::forwarded(&key(), &[1], &host, &dest),
            Scope::forwarded(&key(), &[2], &host, &dest)
        );
        let hashed = |scope: &Scope| {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            scope.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hashed(&scope), hashed(&Scope::local(&renamed, None)));
    }

    /// Forwarding sessions are numbered in the order a grant or a pending
    /// request first refers to them, and a number is dropped once neither
    /// does: the session gets a new one if it comes back.
    #[test]
    fn forwarding_sessions_are_numbered_while_a_grant_or_a_pending_request_has_them() {
        let (databases, approvals) = fixture();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let open = databases.open("personal").unwrap();
        let forwarded = |session: u8| {
            let scope = Scope::forwarded(&key(), &[session], &host_key(2), &host_key(3));
            SignatureApproval {
                scope,
                remember: false,
            }
        };
        let local = approval(1, None, true).scope;

        approvals.grant(&open, forwarded(1).scope, GrantSource::OnScreen, wall);
        approvals.grant(&open, local, GrantSource::OnScreen, wall);
        approvals.record(&open, forwarded(2), requested("ssh"), wall);
        approvals.record(&open, forwarded(1), requested("scp"), wall);

        let number = |scope: &Scope| approvals.forwarding_session(&open, scope);
        assert_eq!(number(&forwarded(1).scope), Some(1));
        assert_eq!(number(&forwarded(2).scope), Some(2));
        assert_eq!(number(&approval(1, None, true).scope), None);
        let pending = approvals.pending(&open, wall);

        // Approving session 2's request grants it under its number, and using
        // that one-signature grant leaves nothing referring to session 2.
        approvals.approve(&open, pending[0].id, now, wall, WINDOW);
        assert_eq!(number(&forwarded(2).scope), Some(2));
        approvals.used(&open, &forwarded(2).scope, wall);
        assert_eq!(number(&forwarded(2).scope), None);
        approvals.record(&open, forwarded(2), requested("ssh"), wall);
        assert_eq!(number(&forwarded(2).scope), Some(3));
        assert_eq!(number(&forwarded(1).scope), Some(1));
    }
}
