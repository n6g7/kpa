//! Approvals and pending requests (`docs/ssh-agent.md` § 6.7, § 6.8): what
//! [`policy::decide`](super::policy::decide) consults to turn a repeat
//! signature into [`Sign`](super::policy::Decision::Sign) instead of
//! [`PromptApprove`](super::policy::Decision::PromptApprove), and what a
//! request from outside the desktop is recorded as while it waits for
//! `kpa ssh approve`.
//!
//! Both stores are in-memory only and cleared on lock
//! ([`Approvals::clear`], [`PendingStore::clear`]) — nothing here survives
//! past the database it belongs to locking.

use std::time::{Duration, Instant};

use ssh_key::Fingerprint;
use ssh_key::public::KeyData;

use crate::config::SshKeyConfirm;

use super::bind::ConnectionClass;
use super::classify::Purpose;

/// How long a pending request is kept before it expires on its own
/// (`docs/ssh-agent.md` § 6.8).
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// At most this many pending requests are kept at once
/// (`docs/ssh-agent.md` § 6.8); the oldest is dropped to make room for a
/// new, distinct one.
pub const MAX_PENDING: usize = 16;

/// A local approval's scope, decided once at grant time from the key's
/// `confirm` setting: a `once` key's approval survives every later check
/// until lock; an `always` key's is good for exactly the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalApproval {
    /// `confirm = "once"`: left in place by [`Approvals::consume_local`].
    Persistent,
    /// `confirm = "always"`: removed by the next
    /// [`Approvals::consume_local`] — "it covers one signature: the retry"
    /// (`docs/ssh-agent.md` § 6.8), whether that grant came from an
    /// on-screen approval or `kpa ssh approve`.
    OneShot,
}

/// A local approval's scope: the key and its destination — the last
/// binding's host key on a `LocalBound` connection, `None` on a
/// `LocalUnbound` one (`ssh-keygen -Y sign`, and clients other than
/// OpenSSH's `ssh`, which never bind at all). Approving a key for one
/// destination never covers another, or covers unbound use, and vice
/// versa (`docs/ssh-agent.md` § 6.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LocalScope {
    key: Fingerprint,
    destination: Option<KeyData>,
}

/// A forwarded approval's scope: the key, the forwarding session, the
/// forwarding host, and the destination — all four, so an approval never
/// carries over to a different forwarding session, host or destination
/// (`docs/ssh-agent.md` § 6.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ForwardedScope {
    key: Fingerprint,
    session: Vec<u8>,
    host: KeyData,
    dest: KeyData,
}

/// Which keys (and, for forwarding, which scopes) have already been
/// approved since the last lock.
#[derive(Debug, Default)]
pub struct Approvals {
    local: std::collections::HashMap<LocalScope, LocalApproval>,
    forwarded: std::collections::HashSet<ForwardedScope>,
}

impl Approvals {
    pub fn new() -> Approvals {
        Approvals::default()
    }

    /// Whether `key` has a local approval for `destination` right now.
    /// Does not consume a one-shot approval —
    /// [`Approvals::consume_local`] does that, once the signature it was
    /// for has actually gone through.
    pub fn is_locally_approved(&self, key: Fingerprint, destination: Option<&KeyData>) -> bool {
        self.local.contains_key(&LocalScope {
            key,
            destination: destination.cloned(),
        })
    }

    /// Records a local approval for (`key`, `destination`), scoped per
    /// `confirm` (`docs/ssh-agent.md` § 6.7): `once` persists until lock,
    /// `always` is good for one signature. Never call this for
    /// `confirm = "never"` — such a key's signatures never consult an
    /// approval at all ([`super::policy::decide`]).
    pub fn grant_local(
        &mut self,
        key: Fingerprint,
        destination: Option<&KeyData>,
        confirm: SshKeyConfirm,
    ) {
        let approval = match confirm {
            SshKeyConfirm::Always => LocalApproval::OneShot,
            SshKeyConfirm::Once | SshKeyConfirm::Never => LocalApproval::Persistent,
        };
        self.local.insert(
            LocalScope {
                key,
                destination: destination.cloned(),
            },
            approval,
        );
    }

    /// Call once the signature a local approval allowed has actually gone
    /// through: drops a one-shot (`always`) approval, leaves a persistent
    /// (`once`) one in place. A no-op if (`key`, `destination`) has no
    /// approval at all.
    pub fn consume_local(&mut self, key: Fingerprint, destination: Option<&KeyData>) {
        let scope = LocalScope {
            key,
            destination: destination.cloned(),
        };
        if matches!(self.local.get(&scope), Some(LocalApproval::OneShot)) {
            self.local.remove(&scope);
        }
    }

    /// Whether (`key`, `session`, `host`, `dest`) has already been
    /// approved for forwarded use.
    pub fn is_forwarded_approved(
        &self,
        key: Fingerprint,
        session: &[u8],
        host: &KeyData,
        dest: &KeyData,
    ) -> bool {
        self.forwarded.contains(&ForwardedScope {
            key,
            session: session.to_vec(),
            host: host.clone(),
            dest: dest.clone(),
        })
    }

    /// Records a forwarded approval for (`key`, `session`, `host`,
    /// `dest`). Persistent — unlike a local `always` approval, a forwarded
    /// one is never one-shot (`confirm` doesn't apply to forwarded use at
    /// all, `docs/ssh-agent.md` § 7's settings table) — until lock or the
    /// forwarding session ends, whichever comes first
    /// ([`Approvals::end_forwarding_session`]).
    pub fn grant_forwarded(
        &mut self,
        key: Fingerprint,
        session: &[u8],
        host: &KeyData,
        dest: &KeyData,
    ) {
        self.forwarded.insert(ForwardedScope {
            key,
            session: session.to_vec(),
            host: host.clone(),
            dest: dest.clone(),
        });
    }

    /// Drops every forwarded approval scoped to `session` — "until lock or
    /// the forwarding session ends, whichever comes first"
    /// (`docs/ssh-agent.md` § 6.7). Call when the forwarded connection that
    /// session identifies closes.
    pub fn end_forwarding_session(&mut self, session: &[u8]) {
        self.forwarded.retain(|scope| scope.session != session);
    }

    /// Drops every approval, local and forwarded — a lock.
    pub fn clear(&mut self) {
        self.local.clear();
        self.forwarded.clear();
    }
}

/// One signature request kpa couldn't approve on screen because it came
/// from outside the desktop (`docs/ssh-agent.md` § 6.8). Compared for
/// equality to merge identical repeats; the time it was recorded lives
/// alongside it in [`PendingStore`], not here, so that comparison never
/// depends on when each copy arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub key: Fingerprint,
    pub purpose: Purpose,
    /// Carries the forwarding host, session and destination for a
    /// forwarded request — § 6.8 lists them as their own fields, but
    /// they're already exactly what `ConnectionClass::Forwarded` holds.
    pub class: ConnectionClass,
    /// The requester's command name (e.g. `ssh`, `git`), for display.
    pub command: String,
}

/// A [`PendingRequest`] together with when it was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEntry {
    pub request: PendingRequest,
    pub recorded_at: Instant,
}

/// Refused requests from outside the desktop, waiting for `kpa ssh
/// approve` (`docs/ssh-agent.md` § 6.8). `now` is a parameter on every
/// method that needs the current time, rather than read from the clock
/// here, so expiry is testable without real sleeping.
#[derive(Debug, Default)]
pub struct PendingStore {
    entries: Vec<PendingEntry>,
}

impl PendingStore {
    pub fn new() -> PendingStore {
        PendingStore::default()
    }

    /// Records `request`, unless an identical one is already pending (in
    /// which case this is a no-op — "identical ones merged"). Expired
    /// entries are dropped first; if the store is then at
    /// [`MAX_PENDING`], the oldest entry is dropped to make room.
    pub fn record(&mut self, request: PendingRequest, now: Instant) {
        self.prune(now);
        if self.entries.iter().any(|entry| entry.request == request) {
            return;
        }
        if self.entries.len() >= MAX_PENDING {
            // `entries` is kept in arrival order, so the oldest is first.
            self.entries.remove(0);
        }
        self.entries.push(PendingEntry {
            request,
            recorded_at: now,
        });
    }

    /// Every pending request, oldest first, with anything past
    /// [`PENDING_TTL`] already dropped.
    pub fn list(&mut self, now: Instant) -> &[PendingEntry] {
        self.prune(now);
        &self.entries
    }

    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|entry| now.saturating_duration_since(entry.recorded_at) < PENDING_TTL);
    }

    /// Drops every pending request — a lock.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct, valid `SHA256:…` fingerprint per `seed` (256 possible
    /// values, more than enough for these tests): a 43-character unpadded
    /// base64 string — the length a real SHA-256 digest encodes to — with
    /// its first two characters swapped in from `seed`'s two base-64
    /// "digits", so every `seed` decodes to a distinct 32 bytes.
    fn fingerprint(seed: u8) -> Fingerprint {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let low = ALPHABET[(seed as usize) % 64] as char;
        let high = ALPHABET[(seed as usize) / 64] as char;
        let mut base64 = "A".repeat(43);
        base64.replace_range(0..1, &low.to_string());
        base64.replace_range(1..2, &high.to_string());
        format!("SHA256:{base64}")
            .parse()
            .expect("valid test fingerprint")
    }

    fn host_key(seed: u64) -> KeyData {
        use ssh_key::Algorithm;
        test_private_key(seed, Algorithm::Ed25519)
            .public_key()
            .key_data()
            .clone()
    }

    /// A deterministic, non-cryptographic stand-in for `OsRng` — matches
    /// `bind`'s and `classify`'s own test helper, duplicated here since
    /// each module's tests compile independently.
    struct TestRng(u64);

    impl TestRng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    impl ssh_key::rand_core::TryRng for TestRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            #[allow(clippy::cast_possible_truncation)]
            Ok(self.next() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next())
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl ssh_key::rand_core::TryCryptoRng for TestRng {}

    fn test_private_key(seed: u64, algorithm: ssh_key::Algorithm) -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::random(&mut TestRng(seed), algorithm).expect("key generation")
    }

    #[test]
    fn a_fresh_key_has_no_local_approval() {
        let approvals = Approvals::new();
        assert!(!approvals.is_locally_approved(fingerprint(1), None));
    }

    #[test]
    fn a_once_approval_survives_being_consumed() {
        let mut approvals = Approvals::new();
        let key = fingerprint(2);
        approvals.grant_local(key, None, SshKeyConfirm::Once);
        assert!(approvals.is_locally_approved(key, None));
        approvals.consume_local(key, None);
        assert!(
            approvals.is_locally_approved(key, None),
            "a once approval must survive consumption"
        );
    }

    #[test]
    fn an_always_approval_is_consumed_exactly_once() {
        let mut approvals = Approvals::new();
        let key = fingerprint(3);
        approvals.grant_local(key, None, SshKeyConfirm::Always);
        assert!(approvals.is_locally_approved(key, None));
        approvals.consume_local(key, None);
        assert!(
            !approvals.is_locally_approved(key, None),
            "an always approval must not survive consumption"
        );
    }

    #[test]
    fn consuming_an_ungranted_key_does_nothing() {
        let mut approvals = Approvals::new();
        approvals.consume_local(fingerprint(4), None); // must not panic
    }

    #[test]
    fn clear_drops_every_local_approval() {
        let mut approvals = Approvals::new();
        approvals.grant_local(fingerprint(5), None, SshKeyConfirm::Once);
        approvals.clear();
        assert!(!approvals.is_locally_approved(fingerprint(5), None));
    }

    #[test]
    fn a_local_approval_is_scoped_to_its_destination() {
        let mut approvals = Approvals::new();
        let key = fingerprint(16);
        let dest_a = host_key(108);
        let dest_b = host_key(109);

        approvals.grant_local(key, Some(&dest_a), SshKeyConfirm::Once);

        assert!(approvals.is_locally_approved(key, Some(&dest_a)));
        assert!(
            !approvals.is_locally_approved(key, Some(&dest_b)),
            "a different destination must not be approved"
        );
        assert!(
            !approvals.is_locally_approved(key, None),
            "approving one destination must not approve unbound use"
        );
    }

    #[test]
    fn an_unbound_approval_does_not_cover_bound_use_or_the_reverse() {
        let mut approvals = Approvals::new();
        let key = fingerprint(17);
        let dest = host_key(110);

        approvals.grant_local(key, None, SshKeyConfirm::Once);
        assert!(approvals.is_locally_approved(key, None));
        assert!(
            !approvals.is_locally_approved(key, Some(&dest)),
            "an unbound approval must not cover bound use for a destination"
        );

        let mut approvals = Approvals::new();
        approvals.grant_local(key, Some(&dest), SshKeyConfirm::Once);
        assert!(
            !approvals.is_locally_approved(key, None),
            "a bound approval must not cover unbound use"
        );
    }

    #[test]
    fn a_forwarded_approval_is_scoped_to_its_session_host_and_destination() {
        let mut approvals = Approvals::new();
        let key = fingerprint(6);
        let host = host_key(100);
        let dest = host_key(101);
        let other_dest = host_key(102);
        let other_host = host_key(103);

        approvals.grant_forwarded(key, b"session-a", &host, &dest);

        assert!(approvals.is_forwarded_approved(key, b"session-a", &host, &dest));
        assert!(
            !approvals.is_forwarded_approved(key, b"session-b", &host, &dest),
            "a different forwarding session must not be approved"
        );
        assert!(
            !approvals.is_forwarded_approved(key, b"session-a", &host, &other_dest),
            "a different destination must not be approved"
        );
        assert!(
            !approvals.is_forwarded_approved(key, b"session-a", &other_host, &dest),
            "a different forwarding host must not be approved"
        );
        assert!(
            !approvals.is_forwarded_approved(fingerprint(7), b"session-a", &host, &dest),
            "a different key must not be approved"
        );
    }

    #[test]
    fn ending_a_forwarding_session_drops_only_its_own_approvals() {
        let mut approvals = Approvals::new();
        let key = fingerprint(8);
        let host = host_key(104);
        let dest = host_key(105);
        approvals.grant_forwarded(key, b"session-a", &host, &dest);
        approvals.grant_forwarded(key, b"session-b", &host, &dest);

        approvals.end_forwarding_session(b"session-a");

        assert!(!approvals.is_forwarded_approved(key, b"session-a", &host, &dest));
        assert!(approvals.is_forwarded_approved(key, b"session-b", &host, &dest));
    }

    #[test]
    fn clear_drops_forwarded_approvals_too() {
        let mut approvals = Approvals::new();
        let key = fingerprint(9);
        let host = host_key(106);
        let dest = host_key(107);
        approvals.grant_forwarded(key, b"session", &host, &dest);
        approvals.clear();
        assert!(!approvals.is_forwarded_approved(key, b"session", &host, &dest));
    }

    fn pending(key: Fingerprint, command: &str) -> PendingRequest {
        PendingRequest {
            key,
            purpose: Purpose::Other,
            class: ConnectionClass::LocalUnbound,
            command: command.to_string(),
        }
    }

    #[test]
    fn a_recorded_request_is_listed() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        store.record(pending(fingerprint(10), "ssh"), now);
        assert_eq!(store.list(now).len(), 1);
    }

    #[test]
    fn identical_requests_are_merged_not_duplicated() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        store.record(pending(fingerprint(11), "ssh"), now);
        store.record(
            pending(fingerprint(11), "ssh"),
            now + Duration::from_secs(1),
        );
        assert_eq!(store.list(now).len(), 1);
    }

    #[test]
    fn distinct_requests_are_kept_separately() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        store.record(pending(fingerprint(12), "ssh"), now);
        store.record(pending(fingerprint(13), "ssh"), now);
        assert_eq!(store.list(now).len(), 2);
    }

    #[test]
    fn a_request_expires_after_its_ttl() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        store.record(pending(fingerprint(14), "ssh"), now);
        assert_eq!(
            store.list(now + PENDING_TTL - Duration::from_secs(1)).len(),
            1
        );
        assert_eq!(store.list(now + PENDING_TTL).len(), 0);
    }

    #[test]
    fn the_oldest_entry_is_dropped_once_the_cap_is_reached() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        for i in 0..MAX_PENDING {
            #[allow(clippy::cast_possible_truncation)]
            store.record(pending(fingerprint(i as u8), "ssh"), now);
        }
        assert_eq!(store.list(now).len(), MAX_PENDING);

        let newest = fingerprint(200);
        store.record(pending(newest, "ssh"), now);

        let entries = store.list(now);
        assert_eq!(entries.len(), MAX_PENDING);
        assert!(
            !entries.iter().any(|e| e.request.key == fingerprint(0)),
            "the oldest entry should have been dropped"
        );
        assert!(entries.iter().any(|e| e.request.key == newest));
    }

    #[test]
    fn clear_drops_every_pending_request() {
        let mut store = PendingStore::new();
        let now = Instant::now();
        store.record(pending(fingerprint(15), "ssh"), now);
        store.clear();
        assert_eq!(store.list(now).len(), 0);
    }
}
