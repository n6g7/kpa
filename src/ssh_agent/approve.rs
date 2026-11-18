//! Approvals (`docs/ssh-agent.md` § 6.7): the [`Scope`] an approval
//! covers, and [`Approvals`], what the user has approved since unlock. In
//! memory only, and dropped with the database's SSH-agent state on lock.

use std::collections::HashSet;

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg};

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
}

/// The scopes approved since the last lock.
#[derive(Debug, Default)]
pub struct Approvals(HashSet<Scope>);

impl Approvals {
    /// Whether an approval covers `scope`.
    pub fn covers(&self, scope: &Scope) -> bool {
        self.0.contains(scope)
    }

    /// Approves `scope` until lock.
    pub fn grant(&mut self, scope: Scope) {
        self.0.insert(scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_agent::testing::test_key;

    fn fingerprint(seed: u64) -> Fingerprint {
        test_key(seed)
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
    }

    fn host_key(seed: u64) -> KeyData {
        test_key(seed).public_key().key_data().clone()
    }

    #[test]
    fn nothing_is_covered_before_a_grant() {
        assert!(!Approvals::default().covers(&Scope::new(fingerprint(1), None)));
    }

    #[test]
    fn an_approval_covers_its_key_and_destination_only() {
        let (dest, other) = (host_key(2), host_key(3));
        let mut approvals = Approvals::default();
        approvals.grant(Scope::new(fingerprint(1), Some(&dest)));

        assert!(approvals.covers(&Scope::new(fingerprint(1), Some(&dest))));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), Some(&other))));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), None)));
        assert!(!approvals.covers(&Scope::new(fingerprint(4), Some(&dest))));
    }

    #[test]
    fn an_unbound_approval_does_not_cover_bound_use() {
        let mut approvals = Approvals::default();
        approvals.grant(Scope::new(fingerprint(1), None));

        assert!(approvals.covers(&Scope::new(fingerprint(1), None)));
        assert!(!approvals.covers(&Scope::new(fingerprint(1), Some(&host_key(2)))));
    }
}
