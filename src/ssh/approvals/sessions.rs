//! The numbers a user tells forwarding sessions apart by.

use super::{Forwarding, Scope};

/// Numbers the forwarding sessions the grants and pending requests of one
/// unlock refer to, 1, 2, … in the order it first sees them
/// (`docs/ssh-agent.md` § 6.8). `ssh -A` sessions through the same host look
/// the same to a user; a number is how they tell them apart. It is made up
/// here and never derived from the session identifier, which is never shown.
///
/// A session keeps its number while a grant or a pending request refers to it
/// ([`ForwardingSessions::retain`]), so the table is bounded by what they
/// hold. The number is looked up from a scope's session, and is stored with
/// neither.
/// One that comes back after its number was dropped gets a new one, and no
/// number is used twice in an unlock.
#[derive(Debug, Default)]
pub struct ForwardingSessions {
    numbered: Vec<(Forwarding, u32)>,
    last: u32,
}

impl ForwardingSessions {
    /// Gives `scope`'s forwarding session the next number if it has none. A
    /// scope that isn't forwarded has no session.
    pub fn note(&mut self, scope: &Scope) {
        let Some(forwarding) = scope.forwarding.as_deref() else {
            return;
        };
        if self.numbered.iter().any(|(known, _)| known == forwarding) {
            return;
        }
        self.last += 1;
        self.numbered.push((forwarding.clone(), self.last));
    }

    /// `scope`'s forwarding session number: `None` for a scope that isn't
    /// forwarded, or whose session no grant and no pending request refers to.
    pub fn number(&self, scope: &Scope) -> Option<u32> {
        let forwarding = scope.forwarding.as_deref()?;
        self.numbered
            .iter()
            .find(|(known, _)| known == forwarding)
            .map(|(_, number)| *number)
    }

    /// Forgets the sessions that `in_use` says nothing refers to.
    pub fn retain(&mut self, in_use: impl Fn(&Forwarding) -> bool) {
        self.numbered.retain(|(forwarding, _)| in_use(forwarding));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::testing::{host_key, served_key};

    fn forwarded(session: u8, host: u64) -> Scope {
        Scope::forwarded(&served_key(1), &[session], &host_key(host), &host_key(3))
    }

    #[test]
    fn sessions_are_numbered_in_the_order_they_are_first_seen() {
        let mut sessions = ForwardingSessions::default();

        for (session, host) in [(7, 2), (8, 2), (7, 2), (7, 4)] {
            sessions.note(&forwarded(session, host));
        }

        assert_eq!(sessions.number(&forwarded(7, 2)), Some(1));
        assert_eq!(sessions.number(&forwarded(8, 2)), Some(2));
        // The same session identifier through another host is another session.
        assert_eq!(sessions.number(&forwarded(7, 4)), Some(3));
    }

    #[test]
    fn a_local_scope_has_no_session() {
        let mut sessions = ForwardingSessions::default();

        let local = Scope::local(&served_key(1), None);
        sessions.note(&local);

        assert_eq!(sessions.number(&local), None);
    }

    #[test]
    fn a_dropped_session_that_comes_back_gets_a_new_number() {
        let mut sessions = ForwardingSessions::default();
        sessions.note(&forwarded(1, 2));
        sessions.note(&forwarded(2, 2));

        sessions.retain(|forwarding| *forwarding == *forwarded(2, 2).forwarding.unwrap());

        assert_eq!(sessions.number(&forwarded(1, 2)), None);
        assert_eq!(sessions.number(&forwarded(2, 2)), Some(2));
        sessions.note(&forwarded(1, 2));
        assert_eq!(sessions.number(&forwarded(1, 2)), Some(3));
    }
}
