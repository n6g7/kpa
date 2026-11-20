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

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use super::vault::{self, Fingerprint};
use super::{Covered, Databases, Slot};
use crate::cancel::CancelToken;
use crate::config::DatabaseConfig;
use crate::log;

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

/// Why the freshness guard locked a database.
enum Why {
    /// Its file is no longer the one it was read from.
    Changed,
    /// Its file did not answer within the deadline.
    Unanswered(Duration),
}

impl Why {
    /// Why a file with `verdict` (`None`: no answer) is locked, `None` if it
    /// is unchanged.
    fn of(verdict: Option<bool>, deadline: Duration) -> Option<Why> {
        match verdict {
            Some(true) => None,
            Some(false) => Some(Why::Changed),
            None => Some(Why::Unanswered(deadline)),
        }
    }
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Why::Changed => write!(f, "file changed"),
            Why::Unanswered(deadline) => write!(f, "file did not answer in {deadline:?}"),
        }
    }
}

/// A lock the guard made: the token of the unlock it ended, and why.
pub(super) struct Ended {
    token: CancelToken,
    why: Why,
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
    /// lock is returned for the caller to log and tell the observers of
    /// ([`Databases::logged`]), once it has released the core's lock.
    ///
    /// The check is made before the lock is handed back and nothing can lock
    /// or unlock the database in between, so a caller that goes on under the
    /// lock goes on with a database that was checked. The `stat` itself is
    /// still before its use: a file can change after it (`docs/threat-model.md`
    /// T-12).
    pub(super) fn checked_slots(&self, index: usize) -> (MutexGuard<'_, Vec<Slot>>, Option<Ended>) {
        self.checked_slots_with(index, vault::is_unchanged, STAT_DEADLINE)
    }

    /// [`Databases::checked_slots`] with the `stat` and its deadline given,
    /// so that a test can make the `stat` stall.
    pub(super) fn checked_slots_with<S>(
        &self,
        index: usize,
        stat: S,
        deadline: Duration,
    ) -> (MutexGuard<'_, Vec<Slot>>, Option<Ended>)
    where
        S: Fn(&Path, &Fingerprint) -> bool + Send + Sync + 'static,
    {
        let stat = Arc::new(stat);
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

            let verdict = unchanged_within([(check.path, check.stamp)], deadline, &stat)[0];

            let mut slots = self.slots();
            if slots[index].source.token() != check.token {
                continue;
            }
            let Some(why) = Why::of(verdict, deadline) else {
                return (slots, None);
            };
            let token = slots[index].lock();
            return (slots, Some(Ended { token, why }));
        }
    }

    /// The freshness guard for the named databases: locks each whose file has
    /// changed, or did not answer in time, then tells the observers. One
    /// deadline covers all the files.
    pub fn drop_stale<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        self.drop_stale_with(names, vault::is_unchanged, STAT_DEADLINE);
    }

    /// [`Databases::drop_stale`] with the `stat` and its deadline given.
    pub(super) fn drop_stale_with<'a, S>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
        stat: S,
        deadline: Duration,
    ) where
        S: Fn(&Path, &Fingerprint) -> bool + Send + Sync + 'static,
    {
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
        let verdicts = unchanged_within(
            checks
                .iter()
                .map(|(_, check)| (check.path.clone(), check.stamp)),
            deadline,
            &Arc::new(stat),
        );

        let ended: Vec<(usize, Ended)> = {
            let mut slots = self.slots();
            checks
                .into_iter()
                .zip(verdicts)
                .filter_map(|((index, check), verdict)| {
                    // A lock since the copy has made the verdict moot.
                    if slots[index].source.token() != check.token {
                        return None;
                    }
                    let why = Why::of(verdict, deadline)?;
                    let token = slots[index].lock();
                    Some((index, Ended { token, why }))
                })
                .collect()
        };
        let covered: Vec<Covered> = ended
            .into_iter()
            .map(|(index, ended)| self.logged(index, ended))
            .collect();
        self.tell_locked(&covered);
    }

    /// Logs a lock the guard made, with its reason, and says which database
    /// and unlock it covered. Not under the core's lock: a write to the log
    /// can stall.
    pub(super) fn logged(&self, index: usize, ended: Ended) -> Covered {
        log::info(format_args!(
            "locked {:?} ({})",
            self.configs[index].name, ended.why
        ));
        self.covered(index, ended.token)
    }
}

/// Whether each file is still the one its stamp was taken from, in the order
/// given, `None` for one that has not answered. `stat` runs for each on a
/// thread of its own, all under one `deadline`: a file that has not answered
/// by then, and one whose thread could not be started, have no answer, which
/// the guard reads as changed.
fn unchanged_within<S>(
    files: impl IntoIterator<Item = (PathBuf, Fingerprint)>,
    deadline: Duration,
    stat: &Arc<S>,
) -> Vec<Option<bool>>
where
    S: Fn(&Path, &Fingerprint) -> bool + Send + Sync + 'static,
{
    let files: Vec<_> = files.into_iter().collect();
    let (answers, answered) = mpsc::channel();
    for (position, (path, stamp)) in files.iter().enumerate() {
        let (path, stamp) = (path.clone(), *stamp);
        let stat = Arc::clone(stat);
        let answers = answers.clone();
        // A thread that can't be started never answers.
        let _ = std::thread::Builder::new()
            .name("freshness-stat".to_string())
            .spawn(move || {
                let _ = answers.send((position, stat(&path, &stamp)));
            });
    }
    drop(answers);

    let mut verdicts = vec![None; files.len()];
    let deadline = Instant::now() + deadline;
    // Ends when every thread has answered, or at the deadline.
    while let Ok((position, unchanged)) =
        answered.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        verdicts[position] = Some(unchanged);
    }
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: Duration = Duration::from_secs(2);

    /// A file that answered "unchanged" is not locked; a changed one and one
    /// that didn't answer are, each for its own reason, as the log says it.
    #[test]
    fn a_lock_says_whether_the_file_changed_or_did_not_answer() {
        assert!(Why::of(Some(true), DEADLINE).is_none());
        assert_eq!(
            Why::of(Some(false), DEADLINE).unwrap().to_string(),
            "file changed"
        );
        assert_eq!(
            Why::of(None, DEADLINE).unwrap().to_string(),
            "file did not answer in 2s"
        );
    }
}
