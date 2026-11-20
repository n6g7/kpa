//! The freshness guard: a database whose file is no longer the one it was
//! read from is locked before anything reads it (`docs/threat-model.md`
//! T-12).
//!
//! The `stat` runs without the core's lock. A `stat` can stall for good on a
//! network or FUSE mount whose server is gone, and with the core's one mutex
//! held that would stall every lock behind it. So a check copies what it
//! needs under the lock, releases it, `stat`s on helper threads under a
//! deadline, takes the lock again and applies the verdict only if no lock has
//! come in meanwhile: the slot's token is the one it copied.

use std::path::PathBuf;
use std::sync::MutexGuard;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::vault::{self, Fingerprint};
use super::{Covered, Databases, Slot};
use crate::cancel::CancelToken;
use crate::config::DatabaseConfig;

/// How long a check waits for its `stat`s. A file that hasn't answered by
/// then counts as changed, which locks its database: the fail-safe answer.
///
/// A healthy mount answers in milliseconds, so this only bounds how long the
/// caller of `open`, `begin_unlock` or `drop_stale` waits; the locks don't
/// wait behind a `stat` at all. A thread per file, rather than one worker
/// for all, keeps a hung mount from reading as a change on every other
/// mount. And threads don't pile up behind a hung one: the timeout locks the
/// database, and a locked database is not `stat`ed again until it is unlocked
/// again, so a hung `stat` costs a thread until its call returns, plus the
/// callers that were already inside the check.
const STAT_DEADLINE: Duration = Duration::from_secs(2);

/// What a check copies under the core's lock.
struct Check {
    path: PathBuf,
    /// The fingerprint the file had when it was read.
    stamp: Fingerprint,
    /// The unlock the stamp belongs to: a lock replaces the slot's source, so
    /// this token is still the slot's only while no lock has come in.
    token: CancelToken,
}

impl Slot {
    /// What the freshness guard needs to check this slot's file, `None` if
    /// the database is locked.
    fn freshness_check(&self, config: &DatabaseConfig) -> Option<Check> {
        let loaded = self.loaded.as_ref()?;
        Some(Check {
            path: config.path.clone(),
            stamp: loaded.stamp,
            token: self.source.token(),
        })
    }
}

impl Databases {
    /// The core's lock, with `index`'s freshness check applied: if its file
    /// has changed, or did not answer in time, the database is locked, and the
    /// token of the unlock that ended is returned for the caller to tell the
    /// observers of, once it has released the lock.
    ///
    /// The check is made before the lock is handed back and nothing can lock
    /// or unlock the database in between, so a caller that goes on under the
    /// lock goes on with a database that was checked. The `stat` itself is
    /// still before its use: a file can change after it (`docs/threat-model.md`
    /// T-12).
    pub(super) fn checked_slots(
        &self,
        index: usize,
    ) -> (MutexGuard<'_, Vec<Slot>>, Option<CancelToken>) {
        // Looks again when a lock came in during the `stat`. That can't spin:
        // a pass is repeated only if the database was locked and then unlocked
        // again meanwhile (a lock alone leaves nothing to check), and each
        // pass needs a lock and a fresh unlock in between.
        loop {
            let slots = self.slots();
            let Some(check) = slots[index].freshness_check(&self.configs[index]) else {
                return (slots, None);
            };
            drop(slots);

            let unchanged = self.unchanged([(check.path, check.stamp)])[0];

            let mut slots = self.slots();
            if slots[index].source.token() != check.token {
                continue;
            }
            if unchanged {
                return (slots, None);
            }
            let ended = slots[index].lock();
            return (slots, Some(ended));
        }
    }

    /// The freshness guard for the named databases: locks each whose file has
    /// changed, or did not answer in time, then tells the observers. One
    /// deadline covers all the files.
    pub fn drop_stale<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        let mut indices = Vec::new();
        for name in names {
            if let Some(index) = self.index(name)
                && !indices.contains(&index)
            {
                indices.push(index);
            }
        }
        let checks: Vec<(usize, Check)> = {
            let slots = self.slots();
            indices
                .into_iter()
                .filter_map(|index| {
                    let check = slots[index].freshness_check(&self.configs[index])?;
                    Some((index, check))
                })
                .collect()
        };
        if checks.is_empty() {
            return;
        }
        let verdicts = self.unchanged(
            checks
                .iter()
                .map(|(_, check)| (check.path.clone(), check.stamp)),
        );

        let covered: Vec<Covered> = {
            let mut slots = self.slots();
            checks
                .into_iter()
                .zip(verdicts)
                .filter(|(_, unchanged)| !unchanged)
                .filter_map(|((index, check), _)| {
                    // A lock since the copy has made the verdict moot.
                    (slots[index].source.token() == check.token)
                        .then(|| self.covered(index, slots[index].lock()))
                })
                .collect()
        };
        self.tell_locked(&covered);
    }

    /// Whether each file is still the one its stamp was taken from, in the
    /// order given. The `stat`s run on threads of their own, all under one
    /// deadline: a file that has not answered by then, and one whose thread
    /// could not be started, count as changed.
    fn unchanged(&self, files: impl IntoIterator<Item = (PathBuf, Fingerprint)>) -> Vec<bool> {
        let files: Vec<_> = files.into_iter().collect();
        let (answers, answered) = mpsc::channel();
        for (position, (path, stamp)) in files.iter().enumerate() {
            let (path, stamp) = (path.clone(), *stamp);
            #[cfg(test)]
            let hook = self.stat_hook.clone();
            let answers = answers.clone();
            // A thread that can't be started never answers, which reads as
            // changed.
            let _ = std::thread::Builder::new()
                .name("freshness-stat".to_string())
                .spawn(move || {
                    #[cfg(test)]
                    if let Some(hook) = hook {
                        let _ = answers.send((position, hook(&path, &stamp)));
                        return;
                    }
                    let _ = answers.send((position, vault::is_unchanged(&path, &stamp)));
                });
        }
        drop(answers);

        let mut verdicts = vec![false; files.len()];
        let deadline = Instant::now() + self.stat_deadline();
        // Ends when every thread has answered, or at the deadline.
        while let Ok((position, unchanged)) =
            answered.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            verdicts[position] = unchanged;
        }
        verdicts
    }

    fn stat_deadline(&self) -> Duration {
        #[cfg(test)]
        if let Some(deadline) = self.stat_deadline {
            return deadline;
        }
        STAT_DEADLINE
    }
}
