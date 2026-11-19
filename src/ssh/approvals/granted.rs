//! What the user has approved since an unlock.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::{Scope, SignatureApproval};

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

#[cfg(test)]
mod tests {
    use super::super::fixtures::{approval, fingerprint, host_key};
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

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
}
