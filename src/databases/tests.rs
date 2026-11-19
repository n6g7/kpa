//! The core alone: the state machine, with in-memory databases and observers
//! that record what they are told.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::testing::{TestEntry, build};
use super::vault::Fingerprint;
use super::{
    Begin, BeginError, Databases, Observer, OpenError, UnknownDb, UnlockFailure, Unlocking,
};
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
