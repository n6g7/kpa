//! [`Hold`]: one database as the agent reads it, over the core and the
//! agent's own state.
//!
//! A hold on an unlocked, scanned database has the core's guard, and the
//! state's lock after it. A hold on a locked one has the state's lock alone:
//! it still reads what outlives a lock (the prompt backoff). A database that
//! is unlocked but not yet scanned is held the same way, so it lists from
//! the cache and refuses a signature as locked, until the scan is in.
//!
//! A hold holds the core's lock: don't call the core, or wait on the user,
//! while one is alive. A flow that prompts between two reads takes the
//! unlock's token in the first and checks it in the second.

use std::sync::MutexGuard;
use std::time::{Duration, Instant, SystemTime};

use super::state::{Inner, Scanned, SshState};
use crate::databases::{Databases, Open, OpenError};

pub(super) struct Hold<'a> {
    db: &'a str,
    /// The core's guard, `None` unless the database is unlocked and scanned
    /// in the unlock it is in.
    open: Option<Open<'a>>,
    state: MutexGuard<'a, Inner>,
    backoff: Duration,
    /// The time of this hold, which backoff deadlines are measured from.
    now: Instant,
    /// The wall-clock time of this hold, which pending requests are dated in.
    wall: SystemTime,
}

impl SshState {
    /// `db` as the agent sees it at `now`. The core's freshness guard runs
    /// first, in the same hold as the read: a database whose file changed is
    /// locked before the hold sees it. `None` for a database the core
    /// doesn't know.
    pub(super) fn hold<'a>(
        &'a self,
        databases: &'a Databases,
        db: &'a str,
        now: Instant,
        wall: SystemTime,
    ) -> Option<Hold<'a>> {
        // Before this state's own lock: `open` can lock a changed file, and
        // that tells this state.
        let open = match databases.open(db) {
            Ok(open) => Some(open),
            Err(OpenError::Locked | OpenError::Stale) => None,
            Err(OpenError::UnknownDb) => return None,
        };
        let state = self.inner();
        let open = open.filter(|open| {
            state
                .scanned
                .get(db)
                .is_some_and(|scanned| scanned.unlock == open.unlock_token())
        });
        Some(Hold {
            db,
            open,
            state,
            backoff: self.backoff(),
            now,
            wall,
        })
    }
}

impl<'a> Hold<'a> {
    pub(super) fn now(&self) -> Instant {
        self.now
    }

    pub(super) fn wall(&self) -> SystemTime {
        self.wall
    }

    /// The core's guard, for the approvals' calls: `None` where the
    /// database is locked, or unlocked and not yet scanned.
    pub(super) fn open(&self) -> Option<&Open<'a>> {
        self.open.as_ref()
    }

    /// The guard and what the scan of its unlock found.
    pub(super) fn unlocked(&self) -> Option<(&Open<'a>, &Scanned)> {
        let open = self.open.as_ref()?;
        Some((open, self.state.scanned.get(self.db)?))
    }

    /// [`Hold::unlocked`], with the scan's private keys to fill.
    pub(super) fn unlocked_mut(&mut self) -> Option<(&Open<'a>, &mut Scanned)> {
        let open = self.open.as_ref()?;
        Some((open, self.state.scanned.get_mut(self.db)?))
    }

    /// Resets the database's idle timer, if it is unlocked.
    pub(super) fn touch(&mut self) {
        if let Some(open) = &mut self.open {
            open.touch();
        }
    }

    /// Whether prompts are held back.
    pub(super) fn backing_off(&self) -> bool {
        self.state
            .backoff
            .get(self.db)
            .is_some_and(|until| self.now < *until)
    }

    /// Holds prompts back from now.
    pub(super) fn back_off(&mut self) {
        if let Some(until) = self.now.checked_add(self.backoff) {
            self.state.backoff.insert(self.db.to_string(), until);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::ssh::testing::{database, key_entry, test_key};

    const IDLE: Duration = Duration::from_secs(3600);
    const BACKOFF: Duration = Duration::from_secs(120);

    fn fixture() -> (Databases, Arc<SshState>) {
        let mut databases = Databases::for_test(vec![database("personal", vec![])], IDLE);
        let state = Arc::new(SshState::new(None, BACKOFF));
        databases.observe(state.clone());
        (databases, state)
    }

    fn hold<'a>(databases: &'a Databases, state: &'a SshState) -> Hold<'a> {
        state
            .hold(databases, "personal", Instant::now(), SystemTime::now())
            .expect("a configured database")
    }

    #[test]
    fn a_hold_on_an_unlocked_scanned_database_has_the_guard_and_the_keys() {
        let (databases, state) = fixture();
        databases.install_for_test("personal", vec![key_entry("github", &test_key(1))]);

        let hold = hold(&databases, &state);
        let (open, scanned) = hold.unlocked().expect("unlocked");
        assert_eq!(open.name(), "personal");
        assert_eq!(scanned.served.len(), 1);
    }

    #[test]
    fn a_hold_on_a_locked_database_has_no_guard() {
        let (databases, state) = fixture();
        assert!(hold(&databases, &state).unlocked().is_none());
    }

    #[test]
    fn a_hold_on_an_unknown_database_is_none() {
        let (databases, state) = fixture();
        let now = (Instant::now(), SystemTime::now());
        assert!(state.hold(&databases, "nope", now.0, now.1).is_none());
    }

    /// An unlocked database the state was never told of reads as locked,
    /// and doesn't keep the core's lock.
    #[test]
    fn an_unlocked_database_that_is_not_scanned_reads_as_locked() {
        let databases = Databases::for_test(vec![database("personal", vec![])], IDLE);
        let state = SshState::new(None, BACKOFF);
        // The state isn't registered: the unlock goes by unnoticed.
        databases.install_for_test("personal", vec![key_entry("github", &test_key(1))]);

        let held = hold(&databases, &state);
        assert!(held.unlocked().is_none() && held.open().is_none());
        // The core's lock is free: this would deadlock otherwise.
        assert!(databases.any_unlocked());
    }

    /// The state of another unlock is not this unlock's: after a lock and a
    /// new unlock whose scan hasn't come in, the old keys aren't read.
    #[test]
    fn keys_of_another_unlock_are_not_read() {
        let (databases, state) = fixture();
        databases.install_for_test("personal", vec![key_entry("github", &test_key(1))]);
        let old = databases.open("personal").unwrap().unlock_token();
        databases.lock("personal").unwrap();
        // The old unlock's state is back in the map, as if its notice were late.
        let stale = Scanned {
            unlock: old,
            served: Vec::new(),
            private_keys: Default::default(),
        };
        databases.install_for_test("personal", vec![]);
        state.inner().scanned.insert("personal".to_string(), stale);

        assert!(hold(&databases, &state).unlocked().is_none());
    }

    /// A backoff holds until its deadline: the instant before it, and not
    /// the instant of it.
    #[test]
    fn a_backoff_runs_from_the_hold_that_started_it() {
        let (databases, state) = fixture();
        let t0 = Instant::now();
        let wall = SystemTime::now();
        let at = |now| state.hold(&databases, "personal", now, wall).unwrap();

        assert!(!at(t0).backing_off());
        at(t0).back_off();
        assert!(at(t0).backing_off());
        assert!(at(t0 + BACKOFF - Duration::from_millis(1)).backing_off());
        assert!(!at(t0 + BACKOFF).backing_off());
    }

    /// `open` locks a changed file itself and tells the state, which takes
    /// its own lock: a hold that took the state's lock first would deadlock.
    #[test]
    fn a_changed_file_locks_the_database_before_the_hold_sees_it() {
        let (databases, state) = fixture();
        databases.install_for_test("personal", vec![key_entry("github", &test_key(1))]);
        databases.change_file_for_test("personal");

        assert!(hold(&databases, &state).unlocked().is_none());
        assert!(!databases.any_unlocked());
        assert!(state.inner().scanned.is_empty(), "the lock told the state");
    }
}
