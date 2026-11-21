//! The core alone: the state machine, with in-memory databases and observers
//! that record what they are told.

use std::ffi::OsStr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::testing::{PASSWORD, TestEntry, build};
use super::vault::{self, Fingerprint};
use super::{
    Begin, BeginError, Databases, Observer, OpenError, UnknownDb, UnlockFailure, Unlocking,
    VaultError,
};
use zeroize::Zeroizing;

use crate::cancel::CancelToken;
use crate::config::DatabaseConfig;

const HOUR: Duration = Duration::from_secs(3600);

fn config(name: &str) -> DatabaseConfig {
    DatabaseConfig {
        name: name.to_string(),
        path: PathBuf::new(),
        keyfile: None,
        serve_ssh_keys: false,
        ssh_keys: Vec::new(),
    }
}

fn databases(names: &[&str]) -> Databases {
    Databases::for_test(names.iter().map(|name| config(name)).collect(), HOUR)
}

fn started<'a>(databases: &'a Databases, name: &str) -> Unlocking<'a> {
    match databases.begin_unlock(name) {
        Ok(Begin::Started(unlocking)) => unlocking,
        _ => panic!("expected to start an unlock of {name}"),
    }
}

/// What `finish` would install, for an unlock that skips the file read.
fn opened(databases: &Databases, name: &str) -> (keepass::Database, Fingerprint) {
    let path = &databases
        .configs()
        .iter()
        .find(|c| c.name == name)
        .unwrap()
        .path;
    (build(Vec::new()), Fingerprint::from_file(path).unwrap())
}

fn is_unlocked(databases: &Databases, name: &str) -> bool {
    databases
        .snapshot()
        .iter()
        .any(|snapshot| snapshot.name == name && !snapshot.is_locked())
}

/// Records every notification as `"<observer>:<event>:<db>"`, and what
/// `open` says about the database from inside a `locked` call.
struct Recorder {
    id: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    tokens: Mutex<Vec<(String, CancelToken)>>,
}

impl Recorder {
    fn new(id: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Arc<Recorder> {
        Arc::new(Recorder {
            id,
            log: Arc::clone(log),
            tokens: Mutex::new(Vec::new()),
        })
    }

    fn tokens(&self) -> Vec<(String, CancelToken)> {
        self.tokens.lock().unwrap().clone()
    }
}

impl Observer for Recorder {
    fn unlocked(&self, _databases: &Databases, db: &str, unlock: &CancelToken) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:unlocked:{db}", self.id));
        self.tokens
            .lock()
            .unwrap()
            .push((db.to_string(), unlock.clone()));
    }

    fn locked(&self, databases: &Databases, db: &str, unlock: &CancelToken) {
        // The core's lock is free: this would deadlock otherwise.
        let seen = match databases.open(db) {
            Ok(_) => "open",
            Err(OpenError::Locked) => "locked",
            Err(_) => "other",
        };
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:locked:{db}:{seen}", self.id));
        self.tokens
            .lock()
            .unwrap()
            .push((db.to_string(), unlock.clone()));
    }
}

fn observed(names: &[&str]) -> (Databases, Arc<Recorder>, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder::new("a", &log);
    let mut databases = databases(names);
    databases.observe(recorder.clone());
    (databases, recorder, log)
}

#[test]
fn a_lock_beats_an_unlock() {
    let (databases, recorder, _) = observed(&["work"]);
    let unlocking = started(&databases, "work");
    databases.lock("work").unwrap();

    let (db, stamp) = opened(&databases, "work");
    let result = unlocking.install(db, stamp);

    assert!(matches!(result, Err(UnlockFailure::LockedMeanwhile)));
    assert!(!is_unlocked(&databases, "work"));
    assert!(
        recorder
            .tokens()
            .iter()
            .all(|(_, token)| token.is_cancelled())
    );
    assert!(!databases.any_unlocked());
}

#[test]
fn an_unlock_without_a_lock_installs_and_tells_observers() {
    let (databases, _, log) = observed(&["work"]);
    let unlocking = started(&databases, "work");
    let (db, stamp) = opened(&databases, "work");
    unlocking.install(db, stamp).unwrap();

    assert!(is_unlocked(&databases, "work"));
    assert_eq!(*log.lock().unwrap(), ["a:unlocked:work"]);
}

#[test]
fn a_token_is_cancelled_for_good_by_the_lock_that_ends_its_unlock() {
    let (databases, recorder, _) = observed(&["work"]);
    let begun = started(&databases, "work").unlock_token().clone();
    databases.install_for_test("work", vec![]);
    let token = databases.open("work").ok().unwrap().unlock_token();
    // One unlock: the token begin_unlock took, the one Open reports and the
    // one the observer heard are equal.
    assert_eq!(begun, token);
    assert_eq!(recorder.tokens()[0].1, token);
    assert!(!token.is_cancelled());

    databases.lock("work").unwrap();
    assert!(token.is_cancelled());
    assert_eq!(recorder.tokens()[1].1, token);

    // The next unlock has another token, and the cancelled one stays so.
    databases.install_for_test("work", vec![]);
    let next = databases.open("work").ok().unwrap().unlock_token();
    assert_ne!(next, token);
    assert!(token.is_cancelled());
    assert!(!next.is_cancelled());
}

#[test]
fn a_lock_replaces_the_source_even_for_a_locked_database() {
    let databases = databases(&["work", "home"]);
    let unlocking = started(&databases, "work");
    let token = unlocking.unlock_token().clone();

    databases.lock("work").unwrap();
    assert!(token.is_cancelled(), "the database was locked all along");

    // A lock of another database leaves it be.
    let other = started(&databases, "home").unlock_token().clone();
    databases.lock("work").unwrap();
    assert!(!other.is_cancelled());
    databases.lock_all();
    assert!(other.is_cancelled());
    assert_eq!(databases.lock("nope"), Err(UnknownDb));
}

#[test]
fn one_unlock_at_a_time_and_every_way_out_clears_the_claim() {
    let databases = databases(&["work"]);
    fn begin(databases: &Databases) -> Result<Begin<'_>, BeginError> {
        databases.begin_unlock("work")
    }

    // Dropped without finishing.
    let first = started(&databases, "work");
    assert!(matches!(begin(&databases), Err(BeginError::InProgress)));
    drop(first);
    assert!(matches!(begin(&databases), Ok(Begin::Started(_))));

    // `finish` that fails: the placeholder file is no database.
    let failed = started(&databases, "work").finish(None);
    assert!(matches!(failed, Err(UnlockFailure::Vault(_))));
    assert!(matches!(begin(&databases), Ok(Begin::Started(_))));

    // A panic while the claim is held.
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        let _claim = started(&databases, "work");
        panic!("the front end failed");
    }));
    assert!(panicked.is_err());
    assert!(matches!(begin(&databases), Ok(Begin::Started(_))));

    // Overtaken by a lock.
    let unlocking = started(&databases, "work");
    databases.lock("work").unwrap();
    let (db, stamp) = opened(&databases, "work");
    assert!(unlocking.install(db, stamp).is_err());
    assert!(matches!(begin(&databases), Ok(Begin::Started(_))));

    // Done: the next begin finds it unlocked, and after a lock can claim.
    let (db, stamp) = opened(&databases, "work");
    started(&databases, "work").install(db, stamp).unwrap();
    assert!(matches!(begin(&databases), Ok(Begin::AlreadyUnlocked)));
    databases.lock("work").unwrap();
    assert!(matches!(begin(&databases), Ok(Begin::Started(_))));

    assert!(matches!(
        databases.begin_unlock("nope"),
        Err(BeginError::UnknownDb)
    ));
}

#[test]
fn a_late_drop_does_not_clear_a_newer_claim() {
    let databases = databases(&["work"]);
    let old = started(&databases, "work");
    // Overtaken and installed, then locked and claimed again by another
    // unlock before `old` is dropped: its drop must leave that claim alone.
    let (db, stamp) = opened(&databases, "work");
    old.install(db, stamp).unwrap();
    databases.lock("work").unwrap();
    let _newer = started(&databases, "work");
    assert!(matches!(
        databases.begin_unlock("work"),
        Err(BeginError::InProgress)
    ));
}

#[test]
fn a_changed_file_is_locked_first_by_open() {
    let (databases, recorder, log) = observed(&["work"]);
    databases.install_for_test("work", vec![]);
    databases.change_file_for_test("work");

    assert_eq!(databases.open("work").err(), Some(OpenError::Stale));
    assert!(!is_unlocked(&databases, "work"));
    assert_eq!(databases.open("work").err(), Some(OpenError::Locked));
    assert_eq!(log.lock().unwrap()[1], "a:locked:work:locked");
    assert!(recorder.tokens()[1].1.is_cancelled());
    assert_eq!(databases.open("nope").err(), Some(OpenError::UnknownDb));
}

#[test]
fn a_changed_file_is_locked_first_by_begin_unlock() {
    let (databases, _, log) = observed(&["work"]);
    databases.install_for_test("work", vec![]);
    databases.change_file_for_test("work");

    // Not `AlreadyUnlocked`: the stale database was locked first.
    assert!(matches!(
        databases.begin_unlock("work"),
        Ok(Begin::Started(_))
    ));
    assert_eq!(log.lock().unwrap()[1], "a:locked:work:locked");
}

#[test]
fn a_changed_file_is_locked_first_by_drop_stale() {
    let (databases, _, log) = observed(&["work", "home"]);
    databases.install_for_test("work", vec![]);
    databases.install_for_test("home", vec![]);
    databases.change_file_for_test("work");

    databases.drop_stale(["work", "home", "nope"]);

    assert!(!is_unlocked(&databases, "work"));
    assert!(is_unlocked(&databases, "home"));
    let told: Vec<_> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.contains(":locked:"))
        .cloned()
        .collect();
    assert_eq!(told, ["a:locked:work:locked"]);
}

#[test]
fn snapshot_runs_no_freshness_guard() {
    let databases = databases(&["work"]);
    databases.install_for_test("work", vec![TestEntry::new("one")]);
    databases.change_file_for_test("work");
    assert_eq!(databases.snapshot()[0].entries, Some(1));
}

#[test]
fn idle_expiry_is_per_database_and_touch_resets_it() {
    let databases = databases(&["work", "home"]);
    databases.install_for_test("work", vec![]);
    databases.install_for_test("home", vec![]);
    let after_install = Instant::now();

    std::thread::sleep(Duration::from_millis(20));
    databases.open("home").ok().unwrap().touch();

    // Just short of the timeout since the installs: nothing is idle.
    databases.expire_idle(after_install + HOUR - Duration::from_secs(1));
    assert!(databases.any_unlocked() && is_unlocked(&databases, "work"));

    // At the timeout since the installs, only the untouched one is idle.
    databases.expire_idle(after_install + HOUR);
    assert!(!is_unlocked(&databases, "work"));
    assert!(is_unlocked(&databases, "home"));

    databases.expire_idle(Instant::now() + HOUR + HOUR);
    assert!(!databases.any_unlocked());
}

#[test]
fn the_idle_time_left_counts_down_from_the_last_activity_and_reading_it_resets_nothing() {
    let databases = databases(&["work"]);
    databases.install_for_test("work", vec![]);
    let after_install = Instant::now();

    let open = databases.open("work").ok().unwrap();
    assert!(open.idle_left(after_install) <= HOUR);
    assert!(open.idle_left(after_install) > HOUR - Duration::from_secs(5));
    assert_eq!(
        open.idle_left(after_install + HOUR / 2) + HOUR / 2,
        open.idle_left(after_install)
    );
    assert_eq!(open.idle_left(after_install + HOUR * 2), Duration::ZERO);
    drop(open);

    // Reading it above counted as no activity: the timer still ends at the
    // timeout since the install.
    databases.expire_idle(after_install + HOUR);
    assert!(!databases.any_unlocked());
}

#[test]
fn an_unlock_still_in_progress_is_not_idle_locked() {
    let databases = databases(&["work"]);
    let unlocking = started(&databases, "work");
    databases.expire_idle(Instant::now() + HOUR + HOUR);
    assert!(!unlocking.unlock_token().is_cancelled());
}

#[test]
fn observers_run_in_registration_order_each_told_of_every_database() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut databases = databases(&["work", "home"]);
    databases.observe(Recorder::new("a", &log));
    databases.observe(Recorder::new("b", &log));
    databases.install_for_test("work", vec![]);
    log.lock().unwrap().clear();

    // Covers a locked database too.
    databases.lock_all();

    // Each saw `open` fail as locked, so the core's lock was not held.
    assert_eq!(
        *log.lock().unwrap(),
        [
            "a:locked:work:locked",
            "a:locked:home:locked",
            "b:locked:work:locked",
            "b:locked:home:locked",
        ]
    );
}

#[test]
fn observers_are_told_before_the_call_returns_in_every_kind_of_lock() {
    let (databases, _, log) = observed(&["work", "home"]);
    let told = || {
        log.lock()
            .unwrap()
            .iter()
            .filter(|e| e.contains(":locked:"))
            .count()
    };

    databases.install_for_test("work", vec![]);
    databases.lock("work").unwrap();
    assert_eq!(told(), 1);

    databases.install_for_test("work", vec![]);
    databases.expire_idle(Instant::now() + HOUR + HOUR);
    assert_eq!(told(), 2);

    databases.install_for_test("work", vec![]);
    databases.change_file_for_test("work");
    databases.drop_stale(["work"]);
    assert_eq!(told(), 3);
}

#[test]
fn open_reads_entries_fields_and_attachments() {
    let databases = databases(&["work"]);
    databases.install_for_test(
        "work",
        vec![
            TestEntry::new("site")
                .field("Password", "hunter2")
                .attachment("id_ed25519", b"KEY".to_vec()),
            TestEntry::new("old")
                .attachment("gone.key", b"OLD".to_vec())
                .in_recycle_bin(),
        ],
    );
    let open = databases.open("work").ok().unwrap();

    assert_eq!(open.name(), "work");
    assert_eq!(open.entry_count(), 2);
    let entries = open.entries();
    let uuid = |title: &str| {
        entries
            .iter()
            .find(|entry| entry.title.as_deref() == Some(title))
            .unwrap()
            .uuid
    };

    let site = open.entry(uuid("site")).unwrap();
    assert_eq!(site.title().as_deref(), Some("site"));
    assert_eq!(site.field("Password").unwrap().as_str(), "hunter2");
    assert!(site.field("Missing").is_none());
    assert!(site.totp().is_none());
    assert!(open.entry(uuid::Uuid::new_v4()).is_none());

    let mut names = Vec::new();
    open.for_each_attachment(|a| names.push(a.name.to_string()));
    assert_eq!(names, ["id_ed25519"], "the recycle bin is skipped");
    let mut one = Vec::new();
    site.for_each_attachment(|a| one.push(a.data.to_vec()));
    assert_eq!(one, [b"KEY".to_vec()]);
    let mut none = 0;
    open.entry(uuid("old"))
        .unwrap()
        .for_each_attachment(|_| none += 1);
    assert_eq!(none, 0);
}

/// A database written for a test is read by `finish` as any file is: the
/// right password installs it and tells the observers, a wrong one is
/// refused, and a lock beats it as it beats any unlock.
#[test]
fn a_written_database_is_read_by_finish_like_any_file() {
    let (databases, _recorder, log) = observed(&["work"]);
    databases.write_for_test("work", vec![TestEntry::new("site")]);
    let typed = |password: &str| Some(Zeroizing::new(password.to_string()));

    let wrong = typed("not it");
    assert!(matches!(
        started(&databases, "work").finish(wrong.as_ref()),
        Err(UnlockFailure::Vault(VaultError::WrongCredentials))
    ));
    assert!(!is_unlocked(&databases, "work"));

    let right = typed(PASSWORD);
    started(&databases, "work").finish(right.as_ref()).unwrap();
    assert_eq!(databases.open("work").ok().unwrap().entry_count(), 1);
    assert_eq!(*log.lock().unwrap(), ["a:unlocked:work"]);

    databases.lock("work").unwrap();
    let unlocking = started(&databases, "work");
    databases.lock("work").unwrap();
    assert!(matches!(
        unlocking.finish(right.as_ref()),
        Err(UnlockFailure::LockedMeanwhile)
    ));
    assert!(!is_unlocked(&databases, "work"));
}

/// A `stat` that blocks until it is released, for the files `blocks` names,
/// and the handles to watch and release it. A `stat` that is let through
/// answers as the real one does.
struct Stall {
    /// A message for each `stat` that has begun.
    entered: mpsc::Receiver<()>,
    /// How many have begun.
    calls: Arc<AtomicUsize>,
    /// Dropping it releases every blocked `stat`, now and later.
    release: mpsc::Sender<()>,
}

impl Stall {
    fn wait_until_entered(&self) {
        self.entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the check never began its stat");
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// What a check is given to `stat` with, and the handles to it.
type StallingStat = Box<dyn Fn(&Path, &Fingerprint) -> bool + Send + Sync>;

fn stalling(blocks: impl Fn(&Path) -> bool + Send + Sync + 'static) -> (StallingStat, Stall) {
    let (entered_tx, entered) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let released = Mutex::new(released);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let stat = move |path: &Path, stamp: &Fingerprint| {
        counted.fetch_add(1, Ordering::SeqCst);
        if blocks(path) {
            let _ = entered_tx.send(());
            // An error is the sender dropping: the release.
            let _ = released.lock().unwrap().recv();
        }
        vault::is_unchanged(path, stamp)
    };
    (
        Box::new(stat),
        Stall {
            entered,
            calls,
            release,
        },
    )
}

/// `f`'s result, failing rather than hanging if it doesn't come.
fn promptly<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(f());
    });
    finished
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} is blocked behind the stat"))
}

/// What the freshness check made of `work`, as `open` would see it: it found
/// it stale, or locked, or fresh.
fn checked(databases: &Databases, stat: StallingStat, deadline: Duration) -> &'static str {
    let (slots, stale) = databases.checked_slots_with(0, stat, deadline);
    match (stale, slots[0].loaded.is_some()) {
        (Some(_), _) => "stale",
        (None, false) => "locked",
        (None, true) => "fresh",
    }
}

/// The two checks, each as a call that says what it came to.
type Check = fn(&Databases, StallingStat, Duration) -> &'static str;

fn checks() -> [(&'static str, Check); 2] {
    [
        ("checked_slots", checked),
        ("drop_stale", |databases, stat, deadline| {
            databases.drop_stale_with(["work"], stat, deadline);
            "done"
        }),
    ]
}

/// A stalled `stat` holds nothing the locks and reads need: while a check
/// waits for it, `lock_all`, `lock`, `snapshot`, `any_unlocked` and
/// `expire_idle` return, and the check that was waiting finds the database
/// locked.
#[test]
fn a_stalled_stat_does_not_hold_up_the_locks() {
    for (name, check) in checks() {
        let databases = Arc::new(databases(&["work"]));
        let (stat, stall) = stalling(|_| true);
        databases.install_for_test("work", vec![]);
        let checking = {
            let databases = Arc::clone(&databases);
            std::thread::spawn(move || check(&databases, stat, Duration::from_secs(60)))
        };
        stall.wait_until_entered();

        let d = Arc::clone(&databases);
        assert_eq!(
            promptly("snapshot", move || d.snapshot()[0].entries),
            Some(0),
            "{name}"
        );
        let d = Arc::clone(&databases);
        assert!(promptly("any_unlocked", move || d.any_unlocked()), "{name}");
        let d = Arc::clone(&databases);
        promptly("expire_idle", move || d.expire_idle(Instant::now()));
        let d = Arc::clone(&databases);
        promptly("lock_all", move || d.lock_all());
        let d = Arc::clone(&databases);
        promptly("lock", move || d.lock("work").unwrap());
        assert!(!is_unlocked(&databases, "work"), "{name}");

        drop(stall.release);
        let came_to = checking.join().expect("the check");
        let expected = if name == "drop_stale" {
            "done"
        } else {
            "locked"
        };
        assert_eq!(came_to, expected, "{name}");
        assert!(!is_unlocked(&databases, "work"), "{name}");
    }
}

/// A file that doesn't answer within the deadline reads as changed: the
/// database is locked, and it is not `stat`ed again while it stays locked.
#[test]
fn a_stat_that_does_not_answer_in_time_locks_the_database() {
    let databases = databases(&["work"]);
    let (stat, stall) = stalling(|_| true);
    databases.install_for_test("work", vec![]);

    let came_to = checked(&databases, stat, Duration::from_millis(100));

    assert_eq!(came_to, "stale");
    assert!(!is_unlocked(&databases, "work"));
    let (stat, second) = stalling(|_| true);
    assert_eq!(
        checked(&databases, stat, Duration::from_millis(100)),
        "locked"
    );
    assert_eq!(stall.calls(), 1);
    assert_eq!(second.calls(), 0, "a locked database is not stat'ed");
}

/// `drop_stale` locks a file that doesn't answer in time and tells the
/// observers, once.
#[test]
fn drop_stale_locks_a_file_that_does_not_answer_in_time() {
    let (databases, _, log) = observed(&["work"]);
    let (stat, _stall) = stalling(|_| true);
    databases.install_for_test("work", vec![]);

    databases.drop_stale_with(["work", "work"], stat, Duration::from_millis(100));

    assert!(!is_unlocked(&databases, "work"));
    let told: Vec<_> = log
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.contains(":locked:"))
        .cloned()
        .collect();
    assert_eq!(told, ["a:locked:work:locked"]);
}

/// A verdict about an unlock that a lock has since ended is moot, even a
/// "changed" one: the fresh unlock that follows is not locked by it, and is
/// checked in its turn.
#[test]
fn a_lock_and_a_fresh_unlock_during_the_stat_make_the_check_look_again() {
    let databases = Arc::new(databases(&["work"]));
    let (stat, stall) = stalling(|_| true);
    databases.install_for_test("work", vec![]);
    let checking = {
        let databases = Arc::clone(&databases);
        std::thread::spawn(move || checked(&databases, stat, Duration::from_secs(60)))
    };
    stall.wait_until_entered();

    // The file changes, and the user locks and unlocks it again.
    databases.change_file_for_test("work");
    databases.lock("work").unwrap();
    databases.install_for_test("work", vec![]);
    let calls = Arc::clone(&stall.calls);
    drop(stall.release);

    assert_eq!(checking.join().expect("the check"), "fresh");
    assert!(
        is_unlocked(&databases, "work"),
        "the fresh unlock was left alone"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// A hung mount reads as changed for its own databases only.
#[test]
fn a_stalled_stat_of_one_database_leaves_the_others_alone() {
    let databases = databases(&["work", "home"]);
    let (stat, _stall) = stalling(|path| path.file_stem() == Some(OsStr::new("work")));
    databases.install_for_test("work", vec![]);
    databases.install_for_test("home", vec![]);

    databases.drop_stale_with(["work", "home"], stat, Duration::from_millis(200));

    assert!(!is_unlocked(&databases, "work"));
    assert!(is_unlocked(&databases, "home"));
}
