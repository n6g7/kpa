//! What the user has approved since an unlock.

use std::time::{Duration, Instant, SystemTime};

use super::{Scope, SignatureApproval};

/// At most this many forwarded scopes are approved until lock at once. Every
/// `ssh -A` is a new forwarding session that no later one reuses, so without
/// a cap they would only pile up. Past it the oldest goes.
const MAX_FORWARDED: usize = 64;

/// How long a [`Grant`] covers its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lasts {
    /// Until the lock that ends this unlock: a `confirm = "once"` key's, or
    /// a forwarded login's.
    UntilLock,
    /// For one signature, which has to come before `until`: a `confirm =
    /// "always"` key's, approved by `kpa ssh approve`.
    OneSignature { until: Instant },
}

/// How the user gave a [`Grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSource {
    /// `Allow` on the confirm prompt.
    OnScreen,
    /// The command line: `kpa ssh approve`, for a request that was
    /// refused.
    Cli,
}

/// One approval the user gave: what it covers, how long, and what it has
/// been used for since.
#[derive(Debug, Clone)]
pub struct Grant {
    pub scope: Scope,
    /// The number of its forwarding session, if it is forwarded.
    pub forwarding_session: Option<u32>,
    pub lasts: Lasts,
    /// When it was given, by the wall clock, so a client can tell its age.
    pub granted_at: SystemTime,
    pub by: GrantSource,
    /// The signatures it has covered. A one-signature grant is gone with its
    /// first, so it never lists any.
    pub uses: u64,
    /// When it last covered a signature, by the wall clock. A user who sees
    /// a forwarding session's approval stop being used knows the session is
    /// over: kpa sees no session end.
    pub last_used_at: Option<SystemTime>,
}

impl Grant {
    /// How long a one-signature grant still waits for its signature at
    /// `now`, `None` for one kept until lock.
    pub fn time_left(&self, now: Instant) -> Option<Duration> {
        match self.lasts {
            Lasts::UntilLock => None,
            Lasts::OneSignature { until } => Some(until.saturating_duration_since(now)),
        }
    }

    fn covers(&self, scope: &Scope, now: Instant) -> bool {
        self.scope == *scope
            && match self.lasts {
                Lasts::UntilLock => true,
                Lasts::OneSignature { until } => now < until,
            }
    }

    fn expired(&self, now: Instant) -> bool {
        matches!(self.lasts, Lasts::OneSignature { until } if until <= now)
    }
}

/// The grants since the last lock, oldest first.
#[derive(Debug, Default)]
pub struct GrantedApprovals(Vec<Grant>);

impl GrantedApprovals {
    /// Whether an approval covers `scope` at `now`.
    pub fn covers(&self, scope: &Scope, now: Instant) -> bool {
        self.0.iter().any(|grant| grant.covers(scope, now))
    }

    /// The grants that haven't expired at `now`, oldest first.
    pub fn list(&self, now: Instant) -> impl Iterator<Item = &Grant> {
        self.0.iter().filter(move |grant| !grant.expired(now))
    }

    /// The forwarding sessions the grants kept refer to.
    pub fn sessions(&self) -> impl Iterator<Item = u32> {
        self.0.iter().filter_map(|grant| grant.forwarding_session)
    }

    /// Approves `scope`, which is forwarding session number
    /// `forwarding_session` if it is forwarded, until lock. A scope that is
    /// approved until lock already keeps its grant.
    pub fn grant(
        &mut self,
        scope: Scope,
        forwarding_session: Option<u32>,
        by: GrantSource,
        wall: SystemTime,
    ) {
        if self
            .0
            .iter()
            .any(|grant| grant.scope == scope && grant.lasts == Lasts::UntilLock)
        {
            return;
        }
        if scope.is_forwarded() {
            let forwarded = |grant: &Grant| grant.scope.is_forwarded();
            if self.0.iter().filter(|grant| forwarded(grant)).count() >= MAX_FORWARDED
                && let Some(oldest) = self.0.iter().position(forwarded)
            {
                self.0.remove(oldest);
            }
        }
        self.0.push(Grant {
            scope,
            forwarding_session,
            lasts: Lasts::UntilLock,
            granted_at: wall,
            by,
            uses: 0,
            last_used_at: None,
        });
    }

    /// Grants what `approval` asked for, as the user's `Allow` on
    /// screen would, except that an approval for one signature is kept for
    /// `window` rather than ending with a prompt: the retry is a separate
    /// request that comes later. It is given by `kpa ssh approve`.
    pub fn approve(
        &mut self,
        approval: SignatureApproval,
        forwarding_session: Option<u32>,
        now: Instant,
        wall: SystemTime,
        window: Duration,
    ) {
        if approval.remember {
            self.grant(approval.scope, forwarding_session, GrantSource::Cli, wall);
        } else {
            self.0
                .retain(|grant| grant.scope != approval.scope && !grant.expired(now));
            self.0.push(Grant {
                scope: approval.scope,
                forwarding_session,
                lasts: Lasts::OneSignature {
                    until: now + window,
                },
                granted_at: wall,
                by: GrantSource::Cli,
                uses: 0,
                last_used_at: None,
            });
        }
    }

    /// Records a signature `scope`'s approval covered at `wall`: a
    /// one-signature grant is used up, and a grant kept until lock counts it.
    pub fn used(&mut self, scope: &Scope, wall: SystemTime) {
        if let Some(spent) = self.0.iter().position(|grant| {
            grant.scope == *scope && matches!(grant.lasts, Lasts::OneSignature { .. })
        }) {
            self.0.remove(spent);
        } else if let Some(grant) = self.0.iter_mut().find(|grant| grant.scope == *scope) {
            grant.uses += 1;
            grant.last_used_at = Some(wall);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::testing::{approval, host_key, served_key};

    const WINDOW: Duration = Duration::from_secs(60);

    fn grant(approvals: &mut GrantedApprovals, scope: Scope) {
        approvals.grant(scope, None, GrantSource::OnScreen, SystemTime::now());
    }

    fn approve(approvals: &mut GrantedApprovals, ask: SignatureApproval, now: Instant) {
        approvals.approve(ask, None, now, SystemTime::now(), WINDOW);
    }

    #[test]
    fn nothing_is_covered_before_a_grant() {
        assert!(
            !GrantedApprovals::default()
                .covers(&Scope::local(&served_key(1), None), Instant::now())
        );
    }

    #[test]
    fn an_approval_covers_its_key_and_destination_only() {
        let (dest, other) = (host_key(2), host_key(3));
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        grant(&mut approvals, Scope::local(&served_key(1), Some(&dest)));

        assert!(approvals.covers(&Scope::local(&served_key(1), Some(&dest)), now));
        assert!(!approvals.covers(&Scope::local(&served_key(1), Some(&other)), now));
        assert!(!approvals.covers(&Scope::local(&served_key(1), None), now));
        assert!(!approvals.covers(&Scope::local(&served_key(4), Some(&dest)), now));
    }

    #[test]
    fn an_unbound_approval_does_not_cover_bound_use() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        grant(&mut approvals, Scope::local(&served_key(1), None));

        assert!(approvals.covers(&Scope::local(&served_key(1), None), now));
        assert!(!approvals.covers(&Scope::local(&served_key(1), Some(&host_key(2))), now));
    }

    #[test]
    fn approving_a_remembered_ask_lasts_until_lock() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        let ask = approval(1, None, true);
        approve(&mut approvals, ask.clone(), now);

        assert!(approvals.covers(&ask.scope, now + WINDOW * 100));
        approvals.used(&ask.scope, SystemTime::now());
        assert!(approvals.covers(&ask.scope, now));
    }

    #[test]
    fn approving_a_one_signature_ask_covers_the_window_and_one_use() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        let ask = approval(1, None, false);
        approve(&mut approvals, ask.clone(), now);

        assert!(approvals.covers(&ask.scope, now + WINDOW - Duration::from_millis(1)));
        assert!(!approvals.covers(&ask.scope, now + WINDOW));
        assert!(approvals.covers(&ask.scope, now));
        approvals.used(&ask.scope, SystemTime::now());
        assert!(!approvals.covers(&ask.scope, now));
        assert_eq!(approvals.list(now).count(), 0);
    }

    #[test]
    fn a_grant_remembers_its_source_its_time_and_its_uses() {
        let mut approvals = GrantedApprovals::default();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let scope = Scope::local(&served_key(1), None);
        approvals.grant(scope.clone(), None, GrantSource::OnScreen, wall);
        approvals.used(&scope, SystemTime::now());
        approvals.used(&scope, SystemTime::now());
        // Granting again keeps the first grant, its time and its count.
        approvals.grant(
            scope.clone(),
            None,
            GrantSource::Cli,
            wall + Duration::from_secs(5),
        );

        let [granted] = approvals.list(now).collect::<Vec<_>>()[..] else {
            panic!("one grant");
        };
        assert_eq!(granted.scope, scope);
        assert_eq!(granted.by, GrantSource::OnScreen);
        assert_eq!(granted.granted_at, wall);
        assert_eq!(granted.uses, 2);
        assert_eq!(granted.time_left(now), None);
    }

    #[test]
    fn a_grant_remembers_when_it_last_covered_a_signature() {
        let mut approvals = GrantedApprovals::default();
        let (now, wall) = (Instant::now(), SystemTime::now());
        let scope = Scope::local(&served_key(1), None);
        grant(&mut approvals, scope.clone());
        assert_eq!(approvals.list(now).next().unwrap().last_used_at, None);

        approvals.used(&scope, wall);
        approvals.used(&scope, wall + Duration::from_secs(9));

        let used = approvals.list(now).next().unwrap().last_used_at;
        assert_eq!(used, Some(wall + Duration::from_secs(9)));
    }

    #[test]
    fn a_one_signature_grant_lists_the_time_left_until_it_expires() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        approve(&mut approvals, approval(1, None, false), now);

        let later = now + Duration::from_secs(15);
        let listed: Vec<_> = approvals.list(later).collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].by, GrantSource::Cli);
        assert_eq!(
            listed[0].time_left(later),
            Some(WINDOW - Duration::from_secs(15))
        );
        assert_eq!(approvals.list(now + WINDOW).count(), 0);
    }

    fn forwarded(session: u8) -> Scope {
        Scope::forwarded(&served_key(1), &[session], &host_key(2), &host_key(3))
    }

    #[test]
    fn a_forwarded_approval_covers_its_forwarding_session_only() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        grant(&mut approvals, forwarded(1));

        assert!(approvals.covers(&forwarded(1), now));
        assert!(!approvals.covers(&forwarded(2), now));
        assert!(!approvals.covers(&Scope::local(&served_key(1), Some(&host_key(3))), now));
        let other_host = Scope::forwarded(&served_key(1), &[1], &host_key(4), &host_key(3));
        assert!(!approvals.covers(&other_host, now));
    }

    #[test]
    fn past_the_cap_the_oldest_forwarded_approval_goes() {
        let mut approvals = GrantedApprovals::default();
        let now = Instant::now();
        let local = Scope::local(&served_key(1), None);
        grant(&mut approvals, local.clone());
        for session in 0..=MAX_FORWARDED as u8 {
            grant(&mut approvals, forwarded(session));
            grant(&mut approvals, forwarded(session));
        }

        assert!(!approvals.covers(&forwarded(0), now));
        for session in 1..=MAX_FORWARDED as u8 {
            assert!(approvals.covers(&forwarded(session), now));
        }
        assert!(approvals.covers(&local, now));
    }
}
