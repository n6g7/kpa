//! The daemon: socket lifecycle, and the vault state behind it
//! (`docs/plan.md` step 2).
//!
//! `Server` is the implementation of the protocol's four op traits
//! (`proto::Status`/`Unlock`/`Lock`/`List`) — it answers what each op
//! means against a real vault, and `proto::dispatch` is what turns those
//! answers into responses. So nothing here builds a `Response` except the
//! pre-dispatch failures, which by definition never reach an op.
//!
//! No tray or clipboard yet — those are later steps. Unlocking still needs a
//! password from somewhere, so this step already runs the configured `prompt` command (`docs/design.md`
//! decision #9) to get one; nothing about that requires the later pieces.
//!
//! The limits below (request size, I/O timeouts, concurrent connections)
//! exist because one crashed daemon loses every unlocked database at once:
//! nothing a client sends, and nothing the host refuses, should be able to
//! take it down. See `docs/review-2026-09-robustness.md` findings 1–4, 7, 9.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use keepass::Database;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::clip::{self, Clipboard};
use crate::config::Config;
use crate::log;
use crate::policy;
use crate::proto::{
    self, CopyEntry, CopyError, CopyOutcome, CopyRequest, DatabaseStatus, DecodeError, Field, List,
    ListError, ListRequest, Lock, LockError, LockRequest, ProtocolError, Response, Status, Unlock,
    UnlockError, UnlockRequest, WireEntry,
};
use crate::socket;
use crate::vault::{self, Fingerprint, VaultError};

/// Longest request line accepted. The largest legitimate request is well
/// under 200 bytes; this only exists so that a line with no newline can't
/// grow a buffer until the process aborts.
const MAX_REQUEST_LEN: u64 = 64 * 1024;

/// How long a client gets to send its request, and to take its response.
/// An `unlock` can take much longer end to end — the user is typing — but
/// that time is spent between the read and the write, not inside either.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections handled at once; past this, new ones are refused by
/// closing them. Each holds a thread, and a flood should degrade into
/// refusals rather than into the host refusing a thread spawn.
const MAX_CONNECTIONS: usize = 64;

/// Longest prompt output accepted, in bytes — the prompt's stdout is read
/// into a buffer of exactly this size, which never grows (see
/// `prompt_password` for why that matters).
const MAX_PASSWORD_LEN: usize = 4096;

/// One configured database's state.
struct Slot {
    db: Option<Database>,
    /// The configured path, and the fingerprint of the file `db` was opened
    /// from. `drop_if_stale` checks the path against it before each use.
    path: PathBuf,
    stamp: Option<Fingerprint>,
    /// When this database was last read by a successful `list` or installed
    /// by an `unlock`. Its idle timer runs from here, independently of every
    /// other database. Only meaningful while `db` is `Some`.
    last_activity: Instant,
    /// Bumped by every `lock` that covers this database. An `unlock` reads
    /// it before prompting and only stores what it opened if it is still
    /// the same afterwards, so a lock issued mid-unlock can't be undone by
    /// the unlock finishing.
    lock_epoch: u64,
    /// An unlock is prompting or deriving the key right now. A second one
    /// is refused rather than opening a second prompt.
    unlocking: bool,
    /// While an unlock is prompting: the other end of the socket pair its
    /// prompt watches (`read_prompt`). Dropping it ends the prompt.
    prompt_cancel: Option<UnixStream>,
}

impl Slot {
    /// Drops the database, if any, ends a prompt in flight for it, and
    /// bumps the epoch so an unlock that is still prompting or deriving
    /// the key cannot install what it opened.
    fn lock(&mut self) {
        self.db = None;
        self.stamp = None;
        self.prompt_cancel = None;
        self.lock_epoch = self.lock_epoch.wrapping_add(1);
    }

    /// Installs a freshly opened database, with the fingerprint it was opened
    /// from, and starts its idle timer.
    fn install(&mut self, db: Database, stamp: Fingerprint) {
        self.db = Some(db);
        self.stamp = Some(stamp);
        self.touch();
    }

    /// Resets this database's idle timer to now.
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// This database's entries, or `None` if it is locked.
    fn entries(&self, name: &str) -> Option<Vec<WireEntry>> {
        self.db.as_ref().map(|db| wire_entries(name, db))
    }
}

impl Default for Slot {
    fn default() -> Slot {
        Slot {
            db: None,
            path: PathBuf::new(),
            stamp: None,
            last_activity: Instant::now(),
            lock_epoch: 0,
            unlocking: false,
            prompt_cancel: None,
        }
    }
}

/// Daemon state. `dbs` keys on the configured database name; a key's
/// *absence* means "not a configured database" (`ErrorCode::UnknownDb`).
///
/// The mutex is held only for bookkeeping, never across the slow part of
/// `unlock` (the prompt and the key derivation, milliseconds to minutes).
/// Holding it there would stall every other request behind someone typing
/// a password; not holding it is what makes the lock epoch necessary.
pub struct Server {
    config: Config,
    dbs: Mutex<HashMap<String, Slot>>,
    /// Told about each successful unlock, so the lock policy can take its
    /// sleep inhibitor. Set once by `set_policy_events`; absent in tests.
    policy_events: OnceLock<Sender<policy::Event>>,
    /// The clipboard `copy` hands secrets to. `Arc` so the thread that
    /// schedules an offer's expiry (spawned by `copy`, below) can outlive
    /// the request that started it.
    clip: Arc<Clipboard>,
    /// Which database the clipboard's current offer, if any, was copied
    /// from — `None` once nothing is offered. `copy` sets this on a
    /// successful handoff; every lock path (`Lock::lock`,
    /// `policy::Locks::lock_all`, `expire_idle`) and the freshness guard
    /// (`drop_stale`) read it to decide whether the database being locked
    /// or dropped is the one holding the clipboard, in which case
    /// `docs/threat-model.md` G-6 ("lock clears what kpa owns") says the
    /// offer must end too, not just outlive its own `clipboard_timeout`.
    /// `Clipboard` itself stays database-agnostic
    /// (see `clip.rs`'s doc comment) — this is the one place that
    /// association is tracked. `Arc` so `copy`'s own expiry thread (which
    /// outlives the request, same as `clip` above) can clear it too, once
    /// its natural timeout fires with nothing newer having replaced it.
    clip_db: Arc<Mutex<Option<String>>>,
    /// The screen is known to be locked (`policy::Event::DeskLocked`).
    /// `unlock` raises no prompt while it is.
    desk_locked: AtomicBool,
}

impl Server {
    pub fn new(config: Config) -> Server {
        Server::with_clipboard(config, clip::WaylandBackend)
    }

    /// Like `new`, but with an injected clipboard backend — real tests use
    /// `new`; unit tests that need to control the clipboard without a
    /// Wayland connection use this with a fake `clip::Backend`.
    pub fn with_clipboard(config: Config, backend: impl clip::Backend + 'static) -> Server {
        let dbs = config
            .databases
            .iter()
            .map(|db| {
                let slot = Slot {
                    path: db.path.clone(),
                    ..Slot::default()
                };
                (db.name.clone(), slot)
            })
            .collect();
        Server {
            config,
            dbs: Mutex::new(dbs),
            policy_events: OnceLock::new(),
            clip: Arc::new(Clipboard::new(backend)),
            clip_db: Arc::new(Mutex::new(None)),
            desk_locked: AtomicBool::new(false),
        }
    }

    /// Lock each unlocked database that has had no successful `list` and no
    /// unlock for `idle_timeout` as of `now`, judged per database. Returns
    /// the names it locked.
    ///
    /// Only databases that are unlocked get their epoch bumped: an unlock
    /// still prompting for a locked database is not idle-locked out from
    /// under the user, and with nothing unlocked there is nothing to do.
    pub fn expire_idle(&self, now: Instant) -> Vec<String> {
        let locked = {
            let mut dbs = slots(&self.dbs);
            let mut locked = Vec::new();
            for (name, slot) in dbs.iter_mut() {
                let idle =
                    now.saturating_duration_since(slot.last_activity) >= self.config.idle_timeout;
                if slot.db.is_some() && idle {
                    slot.lock();
                    locked.push(name.clone());
                }
            }
            locked
        };
        // Outside the `dbs` guard, same reasoning as `Lock::lock`: ending
        // a clipboard offer is a round trip to the backend, not bookkeeping.
        for name in &locked {
            self.end_clipboard_for(name);
        }
        // Logged after the guard is released: a stalled stdout must not
        // hold up every other request.
        for name in &locked {
            log::info(format_args!(
                "locked {name:?} after idle timeout ({:?})",
                self.config.idle_timeout
            ));
        }
        locked
    }

    /// Ends the clipboard's current offer if (and only if) it was copied
    /// from database `name` — see `clip_db`'s doc. A lock of some other
    /// database, or a lock while the clipboard holds nothing, is a no-op.
    fn end_clipboard_for(&self, name: &str) {
        let mut clip_db = self.clip_db.lock().unwrap_or_else(|e| e.into_inner());
        if clip_db.as_deref() == Some(name) {
            *clip_db = None;
            drop(clip_db);
            self.clip.end_now();
        }
    }

    /// Ends the clipboard's current offer unconditionally, whichever
    /// database it came from — for the "every database locks" paths
    /// (`Lock::lock`'s bare `lock` form, and `policy::Locks::lock_all`,
    /// which screen lock, suspend and bus loss all go through), where
    /// nothing stays unlocked for a copied secret to legitimately belong
    /// to anymore.
    fn end_clipboard_all(&self) {
        *self.clip_db.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.clip.end_now();
    }

    /// Freshness guard (`docs/threat-model.md` T-12) for the databases
    /// named in `names`: drops each one whose file has changed since it
    /// was unlocked (`drop_if_stale`), ends its clipboard offer, and
    /// returns the names it dropped — in the order `names` was given, so
    /// a caller that needs a deterministic one back (`list`'s
    /// all-databases form) can just take the first. `status`, `unlock`,
    /// `list` and `copy` all run this before using an unlocked database,
    /// instead of calling `drop_if_stale` and ending the offer separately.
    ///
    /// The check (one `stat`) and the drop happen atomically under the
    /// slots mutex, same as before this existed. Ending an offer is a
    /// round trip to the clipboard backend, so that part always happens
    /// after the mutex is released, never while it's held. What a caller
    /// does afterward — reading the in-memory database — opens no new
    /// window: a file change after the `stat` is served exactly as it
    /// always was, and a `lock` landing between this call and that read
    /// just makes the read see a locked database instead.
    fn drop_stale<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let dropped: Vec<String> = {
            let mut dbs = slots(&self.dbs);
            names
                .into_iter()
                .filter(|name| dbs.get_mut(*name).is_some_and(drop_if_stale))
                .map(str::to_string)
                .collect()
        };
        for name in &dropped {
            self.end_clipboard_for(name);
        }
        dropped
    }

    /// Where to report unlocks. Called once, before the server takes requests.
    pub fn set_policy_events(&self, events: Sender<policy::Event>) {
        let _ = self.policy_events.set(events);
    }

    /// Whether any database is unlocked right now.
    pub fn any_unlocked(&self) -> bool {
        slots(&self.dbs).values().any(|slot| slot.db.is_some())
    }

    /// The shape both `status()` and `tray.rs`'s poll report — name, lock
    /// state, entry count — built from whatever `dbs` currently holds,
    /// without itself running the freshness guard (`drop_stale`) on any
    /// configured database. `status()` runs that guard first and then
    /// calls this to build its response from what's left; `tray.rs` calls
    /// this directly, skipping the guard.
    ///
    /// Running the freshness check on every tick, the way `status()`
    /// does for an explicit client request, would make an autonomous
    /// background poll the thing that decides which client request
    /// discovers a stale database — nondeterministically stealing the
    /// `stale` error from whichever op would otherwise have reported it
    /// (`docs/threat-model.md` T-12; this is what `tests/server.rs`'s
    /// staleness tests caught when the tray's poll first called
    /// `status()` directly). A stale-but-not-yet-noticed database still
    /// reads as unlocked here, for up to one poll tick — harmless, since
    /// nothing reached through this method ever serves data from it. The
    /// authoritative check stays exactly where it was: `status`, `list`,
    /// `unlock`, and `copy`, on every real use.
    pub fn snapshot(&self) -> Vec<DatabaseStatus> {
        let dbs = slots(&self.dbs);
        self.config
            .databases
            .iter()
            .map(|cfg| {
                let entries = dbs
                    .get(&cfg.name)
                    .and_then(|slot| slot.db.as_ref().map(vault::entry_count));
                DatabaseStatus {
                    name: cfg.name.clone(),
                    locked: entries.is_none(),
                    entries,
                }
            })
            .collect()
    }

    fn notify_unlocked(&self) {
        if let Some(events) = self.policy_events.get() {
            let _ = events.send(policy::Event::Unlocked);
        }
    }

    /// Told about every explicit `lock`, so the policy can release its
    /// sleep inhibitor if that was the last unlocked database. Without
    /// this, manually locking the last database leaves the inhibitor held
    /// until some unrelated event (a screen lock, a sleep attempt, or an
    /// unlock) happens to run `Policy::reconcile` again.
    fn notify_locked(&self) {
        if let Some(events) = self.policy_events.get() {
            let _ = events.send(policy::Event::Locked);
        }
    }
}

impl policy::Locks for Server {
    fn lock_all(&self) {
        slots(&self.dbs).values_mut().for_each(Slot::lock);
        self.end_clipboard_all();
    }

    fn any_unlocked(&self) -> bool {
        Server::any_unlocked(self)
    }

    fn set_desk_locked(&self, locked: bool) {
        self.desk_locked.store(locked, Ordering::SeqCst);
    }
}

/// The poisoned case recovers rather than propagating: a panic on one
/// request thread shouldn't make every later request panic too.
fn slots(dbs: &Mutex<HashMap<String, Slot>>) -> MutexGuard<'_, HashMap<String, Slot>> {
    dbs.lock().unwrap_or_else(|e| e.into_inner())
}

/// Freshness guard (`docs/threat-model.md` T-12): if the file behind `slot`
/// is no longer the one its database was opened from, drops the database
/// and returns `true`. Only called by `drop_stale`, which also ends the
/// clipboard offer a drop implies — `status`, `unlock`, `list` and `copy`
/// all go through that, never this directly.
///
/// The stat runs under the slots mutex. That is one `stat` call, cheap enough
/// to keep the check and the drop atomic with respect to other requests.
fn drop_if_stale(slot: &mut Slot) -> bool {
    let stale = match (&slot.db, &slot.stamp) {
        (Some(_), Some(stamp)) => !vault::is_unchanged(&slot.path, stamp),
        // A database without its fingerprint cannot be checked, so it is
        // dropped rather than trusted.
        (Some(_), None) => true,
        (None, _) => false,
    };
    if stale {
        slot.lock();
    }
    stale
}

impl Status for Server {
    fn status(&self) -> Vec<DatabaseStatus> {
        // A stale database is dropped here, so it is reported as locked
        // by `snapshot` below. `status` has no error to return.
        self.drop_stale(self.config.databases.iter().map(|cfg| cfg.name.as_str()));
        self.snapshot()
    }
}

/// Clears a slot's `unlocking` flag and its prompt's cancel channel when
/// dropped, so every way out of `unlock` — early returns and panics alike —
/// releases them. A flag left set would refuse every later unlock of that
/// database until a restart.
struct UnlockingFlag<'a> {
    dbs: &'a Mutex<HashMap<String, Slot>>,
    name: &'a str,
}

impl Drop for UnlockingFlag<'_> {
    fn drop(&mut self) {
        if let Some(slot) = slots(self.dbs).get_mut(self.name) {
            slot.unlocking = false;
            slot.prompt_cancel = None;
        }
    }
}

impl Unlock for Server {
    fn unlock(&self, request: &UnlockRequest) -> Result<String, UnlockError> {
        let name = request.db.as_str();
        let db = || name.to_string();

        let Some(cfg) = self.config.databases.iter().find(|cfg| cfg.name == name) else {
            return Err(UnlockError::UnknownDb { db: db() });
        };

        // Runs first and on its own, before the mutex below: a stale
        // database must not keep serving a clipboard offer just because
        // this unlock then loses the `unlocking` race and returns
        // `InProgress` without installing anything.
        self.drop_stale([name]);

        let (cancel, cancelled) = UnixStream::pair().map_err(|err| UnlockError::PromptFailed {
            db: db(),
            detail: err.to_string(),
        })?;

        let epoch = {
            let mut dbs = slots(&self.dbs);
            let Some(slot) = dbs.get_mut(name) else {
                return Err(UnlockError::UnknownDb { db: db() });
            };
            // Already unlocked: `drop_stale` above already dropped it if
            // its file had changed, so finding it still installed here
            // means the file is unchanged — succeed without re-prompting.
            if slot.db.is_some() {
                return Ok(db());
            }
            // Read under the mutex: the policy marks the desk before its
            // `lock_all` takes it, so either this sees the mark or that
            // lock sees `prompt_cancel` below and ends the prompt.
            if self.desk_locked.load(Ordering::SeqCst) {
                return Err(UnlockError::NoDisplay { db: db() });
            }
            if slot.unlocking {
                return Err(UnlockError::InProgress { db: db() });
            }
            slot.unlocking = true;
            slot.prompt_cancel = Some(cancel);
            slot.lock_epoch
        };
        // Declared before `dbs` below, so it drops after that guard has
        // released the mutex — `UnlockingFlag::drop` takes it again.
        let _unlocking = UnlockingFlag {
            dbs: &self.dbs,
            name,
        };

        log::debug(format_args!("prompting for {name:?}"));
        let timeout = self.config.prompt_timeout;
        let password = match prompt_password(&self.config.prompt, timeout, &cancelled) {
            Ok(PromptOutcome::Cancelled) => return Err(UnlockError::PromptCancelled { db: db() }),
            Ok(PromptOutcome::TimedOut) => {
                log::info(format_args!(
                    "prompt for {name:?} unanswered after {timeout:?}"
                ));
                return Err(UnlockError::PromptCancelled { db: db() });
            }
            // A lock ended the prompt, and has already told its own client
            // the database is locked.
            Ok(PromptOutcome::Interrupted) => {
                return Err(UnlockError::LockedDuringUnlock { db: db() });
            }
            // Empty means "no password" — the only way to reach a
            // keyfile-only database from a prompt that always asks.
            Ok(PromptOutcome::Password(password)) if password.is_empty() => None,
            Ok(PromptOutcome::Password(password)) => Some(password),
            Err(err) => {
                return Err(UnlockError::PromptFailed {
                    db: db(),
                    detail: err.to_string(),
                });
            }
        };

        // Note: a file with pathological KDF parameters can make this hang
        // indefinitely or abort the process — upstream in `keepass`, which
        // applies no ceilings; see the note on `vault::open`. The unlocking
        // flag at least bounds it to one stuck thread per database.
        let (opened, stamp) = vault::open(&cfg.path, password.as_ref(), cfg.keyfile.as_deref())
            .map_err(|err| unlock_error(name, err))?;

        let mut dbs = slots(&self.dbs);
        let Some(slot) = dbs.get_mut(name) else {
            return Err(UnlockError::UnknownDb { db: db() });
        };
        if slot.lock_epoch != epoch {
            // A lock arrived while we were prompting. It already told its
            // client the database is locked; `opened` is dropped here so
            // that stays true.
            return Err(UnlockError::LockedDuringUnlock { db: db() });
        }
        slot.install(opened, stamp);
        drop(dbs);
        self.notify_unlocked();
        Ok(db())
    }
}

impl Lock for Server {
    fn lock(&self, request: &LockRequest) -> Result<Option<String>, LockError> {
        let mut dbs = slots(&self.dbs);
        let result = match request.db.as_deref() {
            Some(name) => {
                let Some(slot) = dbs.get_mut(name) else {
                    return Err(LockError::UnknownDb {
                        db: name.to_string(),
                    });
                };
                slot.lock();
                drop(dbs);
                self.end_clipboard_for(name);
                Ok(Some(name.to_string()))
            }
            None => {
                dbs.values_mut().for_each(Slot::lock);
                drop(dbs);
                self.end_clipboard_all();
                Ok(None)
            }
        };
        self.notify_locked();
        result
    }
}

impl List for Server {
    fn list(&self, request: &ListRequest) -> Result<Vec<WireEntry>, ListError> {
        // Each database a successful list reads gets its own timer reset;
        // the others keep running.
        match request.db.as_deref() {
            Some(name) => {
                if !self.drop_stale([name]).is_empty() {
                    return Err(ListError::Stale {
                        db: name.to_string(),
                    });
                }
                let mut dbs = slots(&self.dbs);
                match dbs.get_mut(name) {
                    None => Err(ListError::UnknownDb {
                        db: name.to_string(),
                    }),
                    Some(slot) => match slot.entries(name) {
                        None => Err(ListError::Locked {
                            db: name.to_string(),
                        }),
                        Some(entries) => {
                            slot.touch();
                            Ok(entries)
                        }
                    },
                }
            }
            None => {
                // A stale database fails the whole listing, naming it,
                // rather than being skipped as if it were locked. Once
                // dropped it is skipped by later listings. `drop_stale`
                // reports what it dropped in the order `names` was given
                // here — config order — so naming its first entry is
                // deterministic, unlike the `HashMap` the loop below
                // iterates over.
                let names = self.config.databases.iter().map(|cfg| cfg.name.as_str());
                if let Some(name) = self.drop_stale(names).into_iter().next() {
                    return Err(ListError::Stale { db: name });
                }

                let mut dbs = slots(&self.dbs);
                let mut entries = Vec::new();
                for (db_name, slot) in dbs.iter_mut() {
                    if let Some(read) = slot.entries(db_name) {
                        entries.extend(read);
                        slot.touch();
                    }
                }
                Ok(entries)
            }
        }
    }
}

impl CopyEntry for Server {
    fn copy(&self, request: &CopyRequest) -> Result<CopyOutcome, CopyError> {
        let name = request.db.as_str();
        let db = || name.to_string();

        if !self.drop_stale([name]).is_empty() {
            return Err(CopyError::Stale { db: db() });
        }

        // The lookup happens with the mutex held — it's an in-memory read,
        // sub-millisecond like `list` — but the clipboard handoff below
        // does not: offering to the backend is a Wayland round trip,
        // which must not stall every other request behind it, the same
        // reasoning that keeps `unlock`'s prompt-and-KDF step outside the
        // mutex too.
        let value = {
            let mut dbs = slots(&self.dbs);
            let Some(slot) = dbs.get_mut(name) else {
                return Err(CopyError::UnknownDb { db: db() });
            };
            let Some(database) = slot.db.as_ref() else {
                return Err(CopyError::Locked { db: db() });
            };
            match resolve_field(database, request.uuid, &request.field) {
                None => return Err(CopyError::UnknownUuid { db: db() }),
                Some(None) => return Err(CopyError::FieldEmpty { db: db() }),
                Some(Some(value)) => (
                    value,
                    vault::entry_title(database, request.uuid)
                        .unwrap_or_else(|| request.uuid.to_string()),
                ),
            }
        };
        let (value, entry) = value;

        let offer = self.clip.offer(value).map_err(|err| CopyError::Clipboard {
            db: db(),
            detail: err.to_string(),
        })?;
        // Recorded immediately after a successful handoff, so `lock`
        // (`end_clipboard_for`) knows which database's lock should end
        // this offer early. A narrow window remains between the offer
        // actually becoming current (inside `self.clip.offer`, just
        // above) and this line — a `lock` of `name` landing in between
        // would see the old `clip_db` value and miss ending this offer,
        // which then only expires via its own `clipboard_timeout`. Same
        // shape as the two-round-trip race `clip.rs` already documents
        // for `WaylandOffer::end`, not closed for the same reason: doing
        // so needs the bookkeeping and the backend handoff to be one
        // atomic step, which `Clipboard`'s backend-agnostic design (see
        // its doc comment) deliberately doesn't expose.
        *self.clip_db.lock().unwrap_or_else(|e| e.into_inner()) = Some(name.to_string());

        // Only a successful handoff counts as activity — a failed one read
        // nothing the user didn't already have, the same rule `list`
        // applies to a refused read.
        if let Some(slot) = slots(&self.dbs).get_mut(name) {
            slot.touch();
        }

        let timeout = self.config.clipboard_timeout;
        let clip = Arc::clone(&self.clip);
        let clip_db = Arc::clone(&self.clip_db);
        let db_name = name.to_string();
        let _ = thread::Builder::new().spawn(move || {
            thread::sleep(timeout);
            clip.expire(&offer);
            // Best-effort bookkeeping: if nothing newer has claimed the
            // clipboard since, there is nothing left to end early on a
            // future lock either.
            let mut guard = clip_db.lock().unwrap_or_else(|e| e.into_inner());
            if guard.as_deref() == Some(db_name.as_str()) {
                *guard = None;
            }
        });

        Ok(CopyOutcome {
            db: db(),
            entry,
            field: request.field.clone(),
            expires_in: timeout.as_secs(),
        })
    }
}

/// Resolves `copy`'s wire `Field` against one entry: `None` means `uuid`
/// doesn't name an entry in this database; `Some(None)` means it does but
/// there is nothing to copy for this field — absent, empty, or a bare
/// `title` (never copyable). Kept in `server.rs` rather than `proto::copy`
/// or `vault.rs`, same reasoning as the `field_key` this replaces: it is
/// the one place that bridges the wire vocabulary and the `keepass` field
/// keys.
fn resolve_field(
    database: &Database,
    uuid: Uuid,
    field: &Field,
) -> Option<Option<Zeroizing<String>>> {
    use keepass::db::fields;

    match field {
        Field::Username => vault::entry_field(database, uuid, fields::USERNAME),
        Field::Password => vault::entry_field(database, uuid, fields::PASSWORD),
        Field::Url => vault::entry_field(database, uuid, fields::URL),
        Field::Notes => vault::entry_field(database, uuid, fields::NOTES),
        // Generated at copy time from the `otp` field's otpauth:// URL —
        // the field itself only ever holds the seed; this is the only
        // `Field` variant that doesn't read a field's value straight
        // through.
        Field::Totp => vault::entry_totp(database, uuid),
        Field::Custom(key) => vault::entry_field(database, uuid, key),
        // `title` is reserved but never copyable (see `Field`'s doc
        // comment) — there is nothing to look up but whether the entry
        // itself exists, to still distinguish `UnknownUuid` from
        // `FieldEmpty`.
        Field::ReservedTitle => vault::entry_exists(database, uuid).then_some(None),
    }
}

/// `EntrySummary` implements `Drop` (via `ZeroizeOnDrop`), which forbids
/// moving individual fields out of it — hence `.clone()` here. Both it and
/// `WireEntry` zeroize on drop, so neither copy outlives the response.
fn wire_entries(db_name: &str, db: &Database) -> Vec<WireEntry> {
    vault::list_entries(db)
        .iter()
        .map(|entry| WireEntry {
            db: db_name.to_string(),
            uuid: entry.uuid,
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            group: entry.group.clone(),
            fields: entry.fields.clone(),
        })
        .collect()
}

/// Maps a `VaultError` to the `unlock`-specific error type. `unlock` is the
/// only op that opens a file, so this is the only place vault errors enter
/// the protocol.
///
/// Deliberately drops `VaultError::Corrupt`'s inner message rather than
/// carrying it as `detail`: that string can embed raw bytes out of the
/// decrypted database (see the doc comment on `VaultError::Corrupt`), and a
/// socket client is exactly the sink that comment warns is now reachable.
fn unlock_error(name: &str, err: VaultError) -> UnlockError {
    let db = name.to_string();
    match err {
        VaultError::NotFound(_) | VaultError::KeyfileNotFound(_) => UnlockError::NotFound { db },
        VaultError::WrongCredentials => UnlockError::WrongCredentials { db },
        VaultError::Corrupt(_) => UnlockError::Corrupt { db },
        VaultError::Io(_) => UnlockError::Io { db },
        VaultError::Changed => UnlockError::Stale { db },
    }
}

enum PromptOutcome {
    /// The command exited unsuccessfully — e.g. the user dismissed a
    /// dmenu-style prompt — rather than printing a password.
    Cancelled,
    /// Nothing was entered within `prompt_timeout`; the prompt was killed.
    TimedOut,
    /// A lock ended the prompt (`Slot::prompt_cancel`); it was killed.
    Interrupted,
    Password(Zeroizing<String>),
}

/// Run the configured prompt command (`docs/design.md` decision #9,
/// `Config::prompt`) and capture its stdout as a password.
///
/// The prompt runs in its own process group. It is killed, with everything
/// it started, once `timeout` passes without it finishing, or as soon as
/// the other end of `cancel` is dropped.
///
/// The output is read into a zeroizing buffer of fixed size that never
/// grows. That's the point: `Command::output()` collects into a `Vec` that
/// reallocates as it fills, and every reallocation frees an unwiped copy of
/// what it held so far — for a long passphrase, most of it survived both
/// unlock and lock (`docs/review-2026-09-secrets.md` finding 1). Output
/// longer than `MAX_PASSWORD_LEN` is refused rather than accommodated.
///
/// Trailing `\n`/`\r` are stripped, since dmenu-style prompts
/// newline-terminate their output. The copies kpa can't reach are the ones
/// inside the prompt program itself.
fn prompt_password(
    argv: &[String],
    timeout: Duration,
    cancel: &UnixStream,
) -> std::io::Result<PromptOutcome> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::process::CommandExt;

    let Some((program, args)) = argv.split_first() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "prompt command is empty",
        ));
    };

    // `None` for a timeout too large to add: a deadline that never arrives.
    let deadline = Instant::now().checked_add(timeout);
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;

    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_LEN]);
    let len = match read_prompt(&mut child, &mut buf, deadline, cancel) {
        Ok(Ok(len)) => len,
        Ok(Err(ended)) => {
            kill_prompt(&mut child);
            return Ok(ended);
        }
        Err(err) => {
            kill_prompt(&mut child);
            return Err(err);
        }
    };

    if !child.wait()?.success() {
        return Ok(PromptOutcome::Cancelled);
    }

    let mut end = len;
    while end > 0 && matches!(buf[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let text = std::str::from_utf8(&buf[..end])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "prompt output is not valid UTF-8"))?;

    // Sized exactly, so `push_str` doesn't reallocate either.
    let mut password = Zeroizing::new(String::with_capacity(text.len()));
    password.push_str(text);
    Ok(PromptOutcome::Password(password))
}

/// Read the child's stdout into `buf` until EOF, returning how much was
/// read. Errors rather than growing when `buf` fills up. Stops early with
/// `TimedOut` at `deadline`, or `Interrupted` once `cancel` is readable or
/// hung up: either beats the output, so a lock wins over a prompt that
/// answers at the same moment.
fn read_prompt(
    child: &mut Child,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel: &UnixStream,
) -> std::io::Result<Result<usize, PromptOutcome>> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::io::{Error, ErrorKind};

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("prompt stdout was not captured"))?;
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("prompt output exceeds {MAX_PASSWORD_LEN} bytes"),
            ));
        }
        let left = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(Err(PromptOutcome::TimedOut));
                }
                Some(Timespec {
                    tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
                    tv_nsec: left.subsec_nanos().into(),
                })
            }
            None => None,
        };
        let (output, cancelled) = {
            let mut fds = [
                PollFd::new(&stdout, PollFlags::IN),
                PollFd::new(cancel, PollFlags::IN),
            ];
            match poll(&mut fds, left.as_ref()) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) => return Err(err.into()),
            }
            (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
        };
        if cancelled {
            return Ok(Err(PromptOutcome::Interrupted));
        }
        if !output {
            continue;
        }
        match stdout.read(&mut buf[len..]) {
            Ok(0) => return Ok(Ok(len)),
            Ok(n) => len += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// Kill the prompt's whole process group, so a wrapper's own prompt window
/// goes too, then reap the prompt. The group is signalled before the reap:
/// until then the prompt holds the group's id, so the signal can't reach a
/// recycled one.
fn kill_prompt(child: &mut Child) {
    use rustix::process::{Pid, Signal, kill_process_group};

    if let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
    let _ = child.wait();
}

/// Holds one of the `MAX_CONNECTIONS` slots; releases it when dropped,
/// including when the thread it was moved into never gets to run.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<ConnectionSlot> {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnectionSlot(Arc::clone(active)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections forever, handling each on its own thread.
///
/// Nothing here can end the loop or the process: an `accept` error (out of
/// file descriptors, say) pauses briefly instead of spinning; a connection
/// over `MAX_CONNECTIONS`, or one the host won't spawn a thread for, is
/// dropped — the client sees it closed — and the loop carries on.
pub fn serve(server: Arc<Server>, listener: UnixListener) {
    let watcher = Arc::clone(&server);
    let _ = thread::Builder::new().spawn(move || watch_idle(&watcher));

    let active = Arc::new(AtomicUsize::new(0));
    let owner = rustix::process::geteuid().as_raw();
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(slot) = ConnectionSlot::acquire(&active) else {
            continue;
        };
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            continue;
        }
        let server = Arc::clone(&server);
        // On failure the closure — stream and slot with it — is dropped,
        // which closes the connection and releases the slot.
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle_connection(&server, stream, owner);
        });
    }
}

/// Check the idle timer on a fixed tick for as long as the daemon runs.
/// The tick is a tenth of `idle_timeout`, clamped to between 10 ms and
/// 1 s, so a lock lands within about a tenth of the timeout after expiry.
fn watch_idle(server: &Server) {
    let tick =
        (server.config.idle_timeout / 10).clamp(Duration::from_millis(10), Duration::from_secs(1));
    loop {
        thread::sleep(tick);
        server.expire_idle(Instant::now());
    }
}

/// Log the operations that change what the daemon is holding, one line per
/// event on stderr (see `crate::log`), for whatever is supervising the
/// daemon to collect. Successes are `info`; a failed or refused request is
/// `warn`.
///
/// **Reads are deliberately silent.** `status` and `list` change nothing,
/// and `list` in particular carries entry titles and usernames — a log is
/// the last place that should accumulate, since it outlives the unlocked
/// session that produced it and lands somewhere far less guarded than the
/// socket did. What gets logged is that an operation happened and to which
/// database. The one piece of vault content that does appear is the title
/// of the entry a `copy` took a field from: a record of which secret left
/// is the point of logging a copy. Never a secret, and never a title the
/// user marked protected.
///
/// Failures are logged too, not just successes: a failed `unlock` is the
/// event most worth having a record of.
///
/// `pub(crate)` rather than private: `tray.rs` calls `Lock`/`Unlock`
/// directly (not through `dispatch`) for the same reason this function
/// exists at all — a tray-triggered lock or unlock is exactly as worth
/// logging as a socket-triggered one, and this is the one place that
/// knows how.
pub(crate) fn log_response(response: &Response) {
    match response {
        Response::Unlock(Ok(db)) => log::info(format_args!("unlocked {db:?}")),
        Response::Unlock(Err(err)) => log::warn(format_args!("unlock failed: {err:?}")),

        Response::Lock(Ok(Some(db))) => log::info(format_args!("locked {db:?}")),
        Response::Lock(Ok(None)) => log::info(format_args!("locked every database")),
        Response::Lock(Err(err)) => log::warn(format_args!("lock failed: {err:?}")),

        Response::Protocol(err) => log::warn(format_args!("rejected request: {err:?}")),

        // `copy` is an access worth recording, same reasoning as `unlock`
        // and `lock` above — unlike `list`/`status`, which stay silent
        // (see the note on `Response::Status { .. } | Response::List(_)`
        // below). The field, the entry's title and the database are logged,
        // never the secret — and never a protected title.
        Response::Copy(Ok(outcome)) => log::info(format_args!(
            "copied {:?} of {:?} from {:?}",
            outcome.field, outcome.entry, outcome.db
        )),
        Response::Copy(Err(err)) => log::warn(format_args!("copy failed: {err:?}")),

        // Listed above rather than caught by a `_` arm on purpose: adding
        // an op should be a decision about whether it belongs in the log,
        // not something a wildcard answers silently.
        Response::Status { .. } | Response::List(_) => {}
    }
}

/// A `Write` that only counts, for sizing a buffer before filling it.
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialize `response` and send it, newline-terminated.
///
/// Serialized twice on purpose: once to measure, once into a zeroizing
/// buffer allocated at exactly that size. A `list` response holds every
/// entry's title, username and URL, and a buffer that grows while being
/// filled frees an unwiped copy at each reallocation — which is what
/// survived a lock before (`docs/review-2026-09-secrets.md` finding 5).
fn write_response(stream: &mut UnixStream, response: &Response) {
    let mut counter = ByteCounter(0);
    if serde_json::to_writer(&mut counter, response).is_err() {
        return;
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(counter.0 + 1));
    if serde_json::to_writer(&mut *buf, response).is_err() {
        return;
    }
    buf.push(b'\n');
    let _ = stream.write_all(&buf);
}

/// One connection: read exactly one request line, respond with exactly one
/// response line, done (`docs/design.md` § Protocol — one-shot connections
/// by design, not a limitation).
///
/// A request that doesn't fit — longer than `MAX_REQUEST_LEN` without a
/// newline, or not UTF-8 — gets `malformed_request`. A socket error, or a
/// client that sends nothing within `IO_TIMEOUT`, just drops the
/// connection; there's no one left to tell. The reply is written before
/// the event is logged, so a slow or broken stdout can't cost the client
/// its answer.
///
/// A peer whose uid isn't `owner` (or whose credentials can't be read) is
/// dropped without a reply and without being read from. The socket's mode
/// already keeps other users out; this check covers a mode that ever
/// came out wrong.
fn handle_connection(server: &Server, mut stream: UnixStream, owner: u32) {
    match socket::peer_uid(&stream) {
        Ok(uid) if uid == owner => {}
        Ok(uid) => {
            log::warn(format_args!("rejected connection from uid {uid}"));
            return;
        }
        Err(err) => {
            log::warn(format_args!(
                "rejected connection: peer credentials unavailable: {err}"
            ));
            return;
        }
    }

    let mut line = Vec::new();
    let read = BufReader::new((&stream).take(MAX_REQUEST_LEN)).read_until(b'\n', &mut line);

    let response = match read {
        Ok(0) | Err(_) => return,
        Ok(n) if n as u64 == MAX_REQUEST_LEN && !line.ends_with(b"\n") => {
            Response::Protocol(ProtocolError::MalformedRequest)
        }
        Ok(_) => match std::str::from_utf8(&line).map(proto::decode_request) {
            Ok(Ok(request)) => proto::dispatch(server, &request),
            Ok(Err(DecodeError::VersionMismatch(client_v))) => {
                Response::Protocol(ProtocolError::VersionMismatch { client_v })
            }
            Ok(Err(DecodeError::MalformedRequest)) | Err(_) => {
                Response::Protocol(ProtocolError::MalformedRequest)
            }
        },
    };

    // Log first: once a client has seen the response, the operation is
    // already in the log. (Logging after the write lets a client that
    // reads the log right after its reply, as the tests do, miss the line.)
    log_response(&response);
    write_response(&mut stream, &response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clip::Offer as _;

    /// Held by every test here that spawns a process, and by the one that
    /// needs a socket to be genuinely dead. Spawning a child briefly
    /// duplicates every open file descriptor into it until it execs; if a
    /// prompt test forks at the wrong moment, the "stale" socket below is
    /// still held open by that child, and `socket::bind_socket` rightly refuses to
    /// delete a socket that's still live.
    static SPAWN_LOCK: Mutex<()> = Mutex::new(());

    fn spawn_lock() -> MutexGuard<'static, ()> {
        SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn empty_server() -> Server {
        Server::new(Config::parse("").expect("an empty config is valid"))
    }

    /// Send `request` bytes to `handle_connection` over a socket pair and
    /// return whatever it replies.
    fn exchange(request: &[u8]) -> String {
        let server = empty_server();
        let owner = rustix::process::geteuid().as_raw();
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&server, theirs, owner));
            let mut ours = ours;
            // The handler may stop reading early (at the size cap) and
            // reply; a write error from that is expected, not a failure.
            let _ = ours.write_all(request);
            let _ = ours.shutdown(std::net::Shutdown::Write);
            let mut reply = String::new();
            let _ = ours.read_to_string(&mut reply);
            reply
        })
    }

    #[test]
    fn an_unterminated_oversized_request_is_refused_not_buffered() {
        let reply = exchange(&vec![b'a'; 1 << 20]);
        assert!(reply.contains("malformed_request"), "got {reply:?}");
    }

    #[test]
    fn a_non_utf8_request_gets_an_answer() {
        let reply = exchange(b"\xff\xfe\n");
        assert!(reply.contains("malformed_request"), "got {reply:?}");
    }

    #[test]
    fn a_valid_request_is_still_answered() {
        let reply = exchange(b"{\"v\":1,\"op\":\"status\"}\n");
        assert_eq!(
            reply,
            format!(
                "{{\"v\":1,\"ok\":true,\"databases\":[],\"version\":{:?}}}\n",
                crate::VERSION
            )
        );
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    /// Runs `script` as the prompt, with a timeout long enough never to
    /// fire and nobody to cancel it.
    fn prompt(script: &str) -> std::io::Result<PromptOutcome> {
        let (_cancel, cancelled) = UnixStream::pair().expect("socket pair");
        prompt_password(&sh(script), Duration::from_secs(60), &cancelled)
    }

    #[test]
    fn prompt_output_has_its_line_ending_stripped() {
        let _spawning = spawn_lock();
        let Ok(PromptOutcome::Password(password)) = prompt("printf 'hunter2\\r\\n'") else {
            panic!("expected a password");
        };
        assert_eq!(password.as_str(), "hunter2");
    }

    #[test]
    fn a_failing_prompt_is_a_cancellation() {
        let _spawning = spawn_lock();
        assert!(matches!(prompt("exit 1"), Ok(PromptOutcome::Cancelled)));
    }

    /// The buffer never grows, so over-long output is an error rather than
    /// a reallocation that would strand an unwiped copy.
    #[test]
    fn over_long_prompt_output_is_refused() {
        let _spawning = spawn_lock();
        let script = format!("head -c {} /dev/zero | tr '\\0' a", MAX_PASSWORD_LEN + 1);
        assert!(prompt(&script).is_err());
    }

    #[test]
    fn an_unanswered_prompt_times_out() {
        let _spawning = spawn_lock();
        let (_cancel, cancelled) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        let outcome = prompt_password(
            &sh("sleep 30; printf hunter2"),
            Duration::from_millis(200),
            &cancelled,
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn dropping_the_cancel_end_interrupts_the_prompt() {
        let _spawning = spawn_lock();
        let (cancel, cancelled) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        let outcome = thread::scope(|scope| {
            scope.spawn(move || {
                thread::sleep(Duration::from_millis(200));
                drop(cancel);
            });
            prompt_password(
                &sh("sleep 30; printf hunter2"),
                Duration::from_secs(60),
                &cancelled,
            )
        });
        assert!(matches!(outcome, Ok(PromptOutcome::Interrupted)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A prompt can be a wrapper that starts the real prompt window. Ending
    /// the prompt ends what it started too, so no window stays on screen.
    #[test]
    fn ending_a_prompt_kills_what_it_started() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("survived");
        let script = format!("(sleep 1; touch '{}') & sleep 30", marker.display());
        let (_cancel, cancelled) = UnixStream::pair().expect("socket pair");
        let outcome = prompt_password(&sh(&script), Duration::from_millis(200), &cancelled);
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the prompt's child outlived it");
    }

    #[test]
    fn handle_connection_drops_a_peer_of_another_uid() {
        let server = empty_server();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        ours.write_all(b"{\"v\":1,\"op\":\"status\"}\n")
            .expect("write");
        // Any uid other than ours stands in for a peer we must refuse.
        let other = rustix::process::geteuid().as_raw().wrapping_add(1);

        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&server, theirs, other));
        });
        // The server closes with the request still unread, so the kernel may
        // reset the connection instead of ending it. Either way, no reply.
        let mut reply = Vec::new();
        let _ = ours.read_to_end(&mut reply);
        assert!(reply.is_empty(), "a refused peer got {reply:?}");
    }

    #[test]
    fn handle_connection_answers_a_peer_of_our_uid() {
        let server = empty_server();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        ours.write_all(b"{\"v\":1,\"op\":\"status\"}\n")
            .expect("write");
        let owner = rustix::process::geteuid().as_raw();

        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&server, theirs, owner));
        });
        let mut reply = String::new();
        ours.read_to_string(&mut reply).expect("read");
        assert!(reply.starts_with('{'), "expected a reply, got {reply:?}");
    }

    /// Two configured databases, both locked, with the given idle timeout.
    fn idle_server(timeout: &str) -> Server {
        let config = format!(
            "idle_timeout = \"{timeout}\"\n\
             [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
             [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n"
        );
        Server::new(Config::parse(&config).expect("valid config"))
    }

    /// Like `idle_server`, but with a recording clipboard backend instead
    /// of the real `WaylandBackend` — for idle-timer tests that need
    /// `copy` to succeed with no Wayland connection available.
    fn copy_idle_server(timeout: &str) -> Server {
        let config = format!(
            "idle_timeout = \"{timeout}\"\n\
             [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n"
        );
        let (backend, _offered) = clip::RecordingBackend::new();
        Server::with_clipboard(Config::parse(&config).expect("valid config"), backend)
    }

    /// Stands in for a successful unlock without a file or a prompt. Does not
    /// touch the timer, so each test controls it directly.
    /// The database is stamped from a fresh empty file, so the freshness
    /// check passes until a test changes that file.
    fn unlock_directly(server: &Server, name: &str) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "kpa-unit-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"").expect("temp file");
        let stamp = vault::Fingerprint::from_file(&path).expect("stat temp file");
        let mut dbs = slots(&server.dbs);
        let slot = dbs.get_mut(name).expect("configured");
        slot.path = path;
        slot.stamp = Some(stamp);
        slot.db = Some(Database::new());
    }

    fn is_unlocked(server: &Server, name: &str) -> bool {
        slots(&server.dbs)[name].db.is_some()
    }

    /// Like `unlock_directly`, but the installed database holds one entry
    /// with a password set, so `copy` has something to find. Returns the
    /// entry's uuid.
    fn unlock_with_entry(server: &Server, name: &str) -> uuid::Uuid {
        use keepass::db::fields;

        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_protected(fields::PASSWORD, "entrypass1");
            entry.id().uuid()
        };

        // A distinct prefix from `unlock_directly`'s own counter below:
        // two independent function-local `static`s both starting at 0
        // could otherwise race to the same path when tests run in
        // parallel, and the loser's write would make the other's
        // freshness check see a changed file.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "kpa-unit-copy-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"").expect("temp file");
        let stamp = vault::Fingerprint::from_file(&path).expect("stat temp file");
        let mut dbs = slots(&server.dbs);
        let slot = dbs.get_mut(name).expect("configured");
        slot.path = path;
        slot.stamp = Some(stamp);
        slot.db = Some(db);
        uuid
    }

    /// A server with one configured, locked database and a recording
    /// clipboard backend — no real Wayland connection anywhere in this
    /// test module. The returned handle is what the backend recorded.
    fn copy_server() -> (Server, Arc<Mutex<Vec<String>>>) {
        let (backend, offered) = clip::RecordingBackend::new();
        let server = Server::with_clipboard(
            Config::parse("[[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n")
                .expect("valid config"),
            backend,
        );
        (server, offered)
    }

    #[test]
    fn copy_of_an_unknown_db_is_unknown_db() {
        let (server, _offered) = copy_server();
        let err = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "nope".to_string(),
                uuid: uuid::Uuid::nil(),
                field: Field::Password,
            },
        )
        .expect_err("no such database");
        assert_eq!(
            err,
            CopyError::UnknownDb {
                db: "nope".to_string()
            }
        );
    }

    #[test]
    fn copy_of_a_locked_db_is_locked() {
        let (server, _offered) = copy_server();
        let err = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid: uuid::Uuid::nil(),
                field: Field::Password,
            },
        )
        .expect_err("database is locked");
        assert_eq!(
            err,
            CopyError::Locked {
                db: "personal".to_string()
            }
        );
    }

    #[test]
    fn copy_of_an_unknown_uuid_is_unknown_uuid() {
        let (server, _offered) = copy_server();
        unlock_with_entry(&server, "personal");

        let err = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid: uuid::Uuid::new_v4(),
                field: Field::Password,
            },
        )
        .expect_err("no such entry");
        assert_eq!(
            err,
            CopyError::UnknownUuid {
                db: "personal".to_string()
            }
        );
    }

    #[test]
    fn copy_of_an_absent_field_is_field_empty() {
        let (server, _offered) = copy_server();
        let uuid = unlock_with_entry(&server, "personal");

        let err = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Url,
            },
        )
        .expect_err("url was never set");
        assert_eq!(
            err,
            CopyError::FieldEmpty {
                db: "personal".to_string()
            }
        );
    }

    /// The field the request asked for reaches the clipboard backend
    /// verbatim — including when `list` would have withheld it for being
    /// protected, which `copy` must not do (see `vault::entry_field`'s
    /// doc).
    #[test]
    fn a_successful_copy_reaches_the_clipboard() {
        let (server, offered) = copy_server();
        let uuid = unlock_with_entry(&server, "personal");

        let outcome = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");

        assert_eq!(outcome.field, Field::Password);
        assert_eq!(outcome.db, "personal");
        assert_eq!(*offered.lock().unwrap(), vec!["entrypass1".to_string()]);
    }

    /// What `clip::RecordingBackend::new_tracking` hands back: every offer
    /// made so far, each independently queryable for liveness. Named so
    /// the tracking test fixtures below don't each spell out the nested
    /// generic.
    type TrackedOffers = Arc<Mutex<Vec<Arc<clip::RecordedOffer>>>>;

    /// A server with two configured, locked databases and a recording
    /// clipboard backend that tracks per-offer liveness — for the
    /// lock-clears-clipboard tests below, which need to tell whether
    /// `lock` actually ended the offer `copy` started.
    fn copy_server_two_dbs_tracking() -> (Server, TrackedOffers) {
        let (backend, _offered, offers) = clip::RecordingBackend::new_tracking();
        let server = Server::with_clipboard(
            Config::parse(
                "[[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n",
            )
            .expect("valid config"),
            backend,
        );
        (server, offers)
    }

    /// `docs/threat-model.md` G-6 ("lock clears what kpa owns"): locking
    /// the very database a secret was just `copy`'d from must end that
    /// clipboard offer immediately, not leave it being served until its
    /// own `clipboard_timeout` — otherwise a copied password outlives the
    /// lock the user just asked for.
    #[test]
    fn locking_the_db_a_copy_came_from_ends_the_clipboard_offer() {
        let (server, offers) = copy_server_two_dbs_tracking();
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();
        assert!(offer.is_live(), "sanity: nothing has ended it yet");

        Lock::lock(
            &server,
            &LockRequest {
                db: Some("personal".to_string()),
            },
        )
        .expect("personal is configured");

        assert!(
            !offer.is_live(),
            "locking the database the clipboard content came from must end the offer"
        );
    }

    /// The flip side: locking an *unrelated* database must leave an
    /// active clipboard offer alone — `copy` and `lock` not naming the
    /// same database is not a reason to clear what's still a legitimately
    /// unexpired secret from a database that's still unlocked.
    #[test]
    fn locking_an_unrelated_db_does_not_end_the_clipboard_offer() {
        let (server, offers) = copy_server_two_dbs_tracking();
        let uuid = unlock_with_entry(&server, "personal");
        unlock_directly(&server, "work");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();

        Lock::lock(
            &server,
            &LockRequest {
                db: Some("work".to_string()),
            },
        )
        .expect("work is configured");

        assert!(
            offer.is_live(),
            "locking a different database must not touch the clipboard"
        );
    }

    /// `Lock::lock` with no `db` locks every database — and with nothing
    /// left unlocked for a copied secret to legitimately belong to, the
    /// clipboard offer must end too.
    #[test]
    fn locking_every_database_ends_the_clipboard_offer() {
        let (server, offers) = copy_server_two_dbs_tracking();
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();

        Lock::lock(&server, &LockRequest { db: None }).expect("locking everything always succeeds");

        assert!(
            !offer.is_live(),
            "locking every database must end an outstanding clipboard offer"
        );
    }

    /// Screen lock, suspend and bus loss all go through
    /// `policy::Locks::lock_all` directly, bypassing `Lock::lock` — this
    /// path needs the same clipboard-clearing behavior.
    #[test]
    fn policy_lock_all_ends_the_clipboard_offer() {
        let (server, offers) = copy_server_two_dbs_tracking();
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();

        policy::Locks::lock_all(&server);

        assert!(
            !offer.is_live(),
            "policy::Locks::lock_all must end an outstanding clipboard offer"
        );
    }

    /// The idle timer locking a database on its own (`watch_idle` /
    /// `expire_idle`, no client request involved) must end that
    /// database's clipboard offer too, the same as an explicit `lock`.
    #[test]
    fn idle_lock_ends_the_clipboard_offer_for_that_db() {
        let (backend, _offered, offers) = clip::RecordingBackend::new_tracking();
        let server = Server::with_clipboard(
            Config::parse(
                "idle_timeout = \"1s\"\n\
                 [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n",
            )
            .expect("valid config"),
            backend,
        );
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();
        age_activity(&server, "personal", Duration::from_secs(5));

        let locked = server.expire_idle(Instant::now());

        assert_eq!(locked, ["personal"]);
        assert!(
            !offer.is_live(),
            "an idle-timeout lock must end that database's clipboard offer"
        );
    }

    /// A successful `copy` resets the idle timer, the same rule `list`
    /// follows for a successful read.
    #[test]
    fn a_successful_copy_extends_the_timeout() {
        let server = copy_idle_server("1s");
        let uuid = unlock_with_entry(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        assert!(
            CopyEntry::copy(
                &server,
                &CopyRequest {
                    db: "personal".to_string(),
                    uuid,
                    field: Field::Password,
                },
            )
            .is_ok()
        );
        assert!(!idle_lock_fires(&server));
        assert!(is_unlocked(&server, "personal"));
    }

    /// A refused `copy` (unknown uuid) is not activity, the same rule a
    /// refused `list` follows.
    #[test]
    fn a_refused_copy_does_not_extend_the_timeout() {
        let server = copy_idle_server("1s");
        unlock_with_entry(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        let refused = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid: uuid::Uuid::new_v4(),
                field: Field::Password,
            },
        );
        assert!(refused.is_err());
        assert!(idle_lock_fires(&server));
    }

    /// Makes the named database's last activity look `by` ago, so the next
    /// check sees its timeout as already spent. Leaves every other database's
    /// timer alone.
    fn age_activity(server: &Server, name: &str, by: Duration) {
        slots(&server.dbs)
            .get_mut(name)
            .expect("configured")
            .last_activity = Instant::now() - by;
    }

    /// Whether the timer locks anything at the real current time. A touch
    /// made by the request under test moves that database's activity to now,
    /// and then nothing is idle.
    fn idle_lock_fires(server: &Server) -> bool {
        !server.expire_idle(Instant::now()).is_empty()
    }

    #[test]
    fn nothing_locks_before_the_timeout() {
        let server = idle_server("30m");
        unlock_directly(&server, "personal");
        assert!(server.expire_idle(Instant::now()).is_empty());
        assert!(is_unlocked(&server, "personal"));
    }

    #[test]
    fn idle_timeout_locks_every_idle_unlocked_database() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        unlock_directly(&server, "work");
        age_activity(&server, "personal", Duration::from_secs(5));
        age_activity(&server, "work", Duration::from_secs(5));

        let mut locked = server.expire_idle(Instant::now());
        locked.sort();
        assert_eq!(locked, ["personal", "work"]);
        assert!(!is_unlocked(&server, "personal"));
        assert!(!is_unlocked(&server, "work"));
    }

    /// The reset rule: `status` is not activity, so a poller can't keep a
    /// database unlocked.
    #[test]
    fn status_does_not_extend_the_timeout() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        let _ = Status::status(&server);
        assert!(idle_lock_fires(&server));
        assert!(!is_unlocked(&server, "personal"));
    }

    /// `lock` is not activity, even when it names a database that is locked
    /// already.
    #[test]
    fn lock_does_not_extend_the_timeout() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        let _ = Lock::lock(
            &server,
            &LockRequest {
                db: Some("work".into()),
            },
        );
        assert!(idle_lock_fires(&server));
        assert!(!is_unlocked(&server, "personal"));
    }

    /// A refused `list` reads nothing, so it is not activity either.
    #[test]
    fn a_refused_list_does_not_extend_the_timeout() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        let refused = List::list(
            &server,
            &ListRequest {
                db: Some("work".into()),
            },
        );
        assert!(refused.is_err());
        assert!(idle_lock_fires(&server));
    }

    #[test]
    fn a_successful_list_extends_the_timeout() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        assert!(List::list(&server, &ListRequest { db: None }).is_ok());
        assert!(!idle_lock_fires(&server));
        assert!(is_unlocked(&server, "personal"));
    }

    /// The timers are per database: a successful `list` of A does not keep
    /// an idle B unlocked, and B locks on its own schedule.
    #[test]
    fn using_one_database_does_not_keep_another_unlocked() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        unlock_directly(&server, "work");
        age_activity(&server, "personal", Duration::from_secs(5));
        age_activity(&server, "work", Duration::from_secs(5));

        assert!(
            List::list(
                &server,
                &ListRequest {
                    db: Some("personal".into())
                }
            )
            .is_ok()
        );
        assert_eq!(server.expire_idle(Instant::now()), ["work"]);
        assert!(is_unlocked(&server, "personal"));
        assert!(!is_unlocked(&server, "work"));
    }

    /// A list of everything resets only the databases it actually read: an
    /// unlocked one is refreshed, a locked one has no timer to refresh.
    #[test]
    fn a_list_of_all_resets_each_unlocked_database_it_reads() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));

        assert!(List::list(&server, &ListRequest { db: None }).is_ok());
        assert!(!idle_lock_fires(&server));
        assert!(is_unlocked(&server, "personal"));
        assert!(!is_unlocked(&server, "work"));
    }

    /// Only unlocked databases are touched by the timer: a locked one keeps
    /// its epoch, so an unlock still prompting for it is not cancelled.
    #[test]
    fn an_idle_lock_leaves_locked_databases_and_their_epochs_alone() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));
        let epoch_before = slots(&server.dbs)["work"].lock_epoch;

        assert_eq!(server.expire_idle(Instant::now()), ["personal"]);
        assert_eq!(slots(&server.dbs)["work"].lock_epoch, epoch_before);
    }

    /// Two configured, locked databases and a recording clipboard backend
    /// that tracks per-offer liveness, with a prompt that fails instantly
    /// rather than the default `fuzzel` (which may hang or not exist) —
    /// for the freshness-guard tests below, which drive `unlock` far
    /// enough to re-prompt without needing it to succeed.
    fn stale_drop_test_server() -> (Server, TrackedOffers) {
        let (backend, _offered, offers) = clip::RecordingBackend::new_tracking();
        let server = Server::with_clipboard(
            Config::parse(
                "prompt = [\"/bin/sh\", \"-c\", \"exit 1\"]\n\
                 [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n",
            )
            .expect("valid config"),
            backend,
        );
        (server, offers)
    }

    /// Appends a byte to the file behind `name`'s slot, changing its size
    /// so the next freshness check (`drop_if_stale`) sees it as changed —
    /// the same technique `tests/server.rs`'s
    /// `a_changed_size_makes_the_database_stale` uses against the real
    /// daemon, chosen because it doesn't depend on timestamp resolution.
    fn make_stale(server: &Server, name: &str) {
        let path = slots(&server.dbs)[name].path.clone();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        file.write_all(b"x").expect("append a byte");
    }

    /// `personal` holds a live clipboard offer and has just gone stale on
    /// disk; `work` is untouched. Returns the offer so a test can check
    /// whether the guard it drives ended it.
    fn stale_copy_setup() -> (Server, TrackedOffers, Arc<clip::RecordedOffer>) {
        let (server, offers) = stale_drop_test_server();
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();
        assert!(offer.is_live(), "sanity: nothing has ended it yet");
        make_stale(&server, "personal");
        (server, offers, offer)
    }

    /// `docs/threat-model.md` T-8 ("a clipboard offer outliving its
    /// database's lock"): `status` runs the freshness guard on every
    /// configured database, and dropping a stale one must end its
    /// clipboard offer the same as any other lock path, not leave it
    /// being served until its own `clipboard_timeout`.
    #[test]
    fn status_ends_the_clipboard_offer_for_a_stale_database() {
        let (server, _offers, offer) = stale_copy_setup();

        let _ = Status::status(&server);

        assert!(
            !offer.is_live(),
            "status dropping a stale database must end its clipboard offer"
        );
    }

    /// Same as above, through `list` naming the stale database.
    #[test]
    fn list_named_ends_the_clipboard_offer_for_a_stale_database() {
        let (server, _offers, offer) = stale_copy_setup();

        let _ = List::list(
            &server,
            &ListRequest {
                db: Some("personal".to_string()),
            },
        );

        assert!(
            !offer.is_live(),
            "list of the stale database must end its clipboard offer"
        );
    }

    /// Same as above, through `list` of every database.
    #[test]
    fn list_all_ends_the_clipboard_offer_for_a_stale_database() {
        let (server, _offers, offer) = stale_copy_setup();

        let _ = List::list(&server, &ListRequest { db: None });

        assert!(
            !offer.is_live(),
            "list of all databases must end the stale database's clipboard offer"
        );
    }

    /// Same as above, through `unlock`'s re-prompt branch — reached when
    /// the database it names is already unlocked but stale.
    #[test]
    fn unlock_ends_the_clipboard_offer_for_a_stale_database() {
        let _spawning = spawn_lock();
        let (server, _offers, offer) = stale_copy_setup();

        let _ = Unlock::unlock(
            &server,
            &UnlockRequest {
                db: "personal".to_string(),
            },
        );

        assert!(
            !offer.is_live(),
            "unlock's re-prompt branch dropping a stale database must end its clipboard offer"
        );
    }

    /// Same as above, through `copy`'s pre-check.
    #[test]
    fn copy_ends_the_clipboard_offer_for_a_stale_database() {
        let (server, _offers, offer) = stale_copy_setup();

        let _ = CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid: uuid::Uuid::nil(),
                field: Field::Password,
            },
        );

        assert!(
            !offer.is_live(),
            "copy's staleness pre-check dropping a stale database must end its clipboard offer"
        );
    }

    /// `drop_stale` runs before the `unlocking` check, so a stale
    /// database that is also mid-unlock elsewhere (a second `unlock`
    /// losing the race to a first one still prompting) must still have
    /// its clipboard offer ended — the `InProgress` error that follows
    /// must not skip that bookkeeping.
    #[test]
    fn unlock_ends_the_clipboard_offer_even_when_a_second_unlock_is_racing() {
        let (server, _offers, offer) = stale_copy_setup();
        slots(&server.dbs)
            .get_mut("personal")
            .expect("configured")
            .unlocking = true;

        let result = Unlock::unlock(
            &server,
            &UnlockRequest {
                db: "personal".to_string(),
            },
        );

        assert_eq!(
            result,
            Err(UnlockError::InProgress {
                db: "personal".to_string()
            })
        );
        assert!(
            !offer.is_live(),
            "a stale database racing a second unlock must still end its clipboard offer"
        );
    }

    /// `list` of every database must not stop at the first stale one it
    /// finds: every configured database that's gone stale gets dropped
    /// and, for whichever of them was actually holding the clipboard's
    /// current offer, that offer ends too — not skipped because a
    /// different (earlier, in config order) database happened to be
    /// reported as the `stale` error. The error itself still names the
    /// first stale database in config order, deterministically, rather
    /// than whatever order the underlying `HashMap` happens to iterate.
    #[test]
    fn list_all_with_two_stale_databases_ends_the_offer_and_reports_the_first_in_config_order() {
        let (server, offers) = stale_drop_test_server();
        // The live offer belongs to "work" — the *second* name in
        // config order — so ending it proves `list` kept going past
        // "personal" instead of stopping there.
        let uuid = unlock_with_entry(&server, "work");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "work".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();
        assert!(offer.is_live(), "sanity: nothing has ended it yet");
        unlock_directly(&server, "personal");
        make_stale(&server, "personal");
        make_stale(&server, "work");

        let result = List::list(&server, &ListRequest { db: None });

        assert_eq!(
            result,
            Err(ListError::Stale {
                db: "personal".to_string()
            }),
            "the first stale database in config order must be the one reported"
        );
        assert!(
            !offer.is_live(),
            "dropping every stale database must end the offer belonging to whichever \
             one actually held it, even when that one isn't first in config order"
        );
        assert!(!is_unlocked(&server, "personal"));
        assert!(!is_unlocked(&server, "work"));
    }

    /// The flip side, same as the unrelated-lock tests above: dropping a
    /// stale database must not end a *different* database's clipboard
    /// offer.
    #[test]
    fn dropping_a_stale_database_does_not_end_an_unrelated_offer() {
        let (server, offers) = stale_drop_test_server();
        let uuid = unlock_with_entry(&server, "work");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "work".to_string(),
                uuid,
                field: Field::Password,
            },
        )
        .expect("entry and field exist");
        let offer = offers.lock().unwrap()[0].clone();
        unlock_directly(&server, "personal");
        make_stale(&server, "personal");

        let _ = Status::status(&server);

        assert!(
            offer.is_live(),
            "dropping a different database's staleness must not touch this offer"
        );
    }

    /// Two configured, locked databases whose prompt runs `script`.
    fn prompt_server(script: &str) -> Server {
        Server::new(
            Config::parse(&format!(
                "prompt = [\"/bin/sh\", \"-c\", \"{script}\"]\n\
                 [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n"
            ))
            .expect("valid config"),
        )
    }

    fn unlock(server: &Server, name: &str) -> Result<String, UnlockError> {
        Unlock::unlock(
            server,
            &UnlockRequest {
                db: name.to_string(),
            },
        )
    }

    /// Starts unlocking `name` on another thread, runs `then` once its
    /// prompt is up, and returns what the unlock ended with and how long
    /// it took after `then`.
    fn unlock_then(
        server: &Server,
        name: &str,
        then: impl FnOnce(),
    ) -> (Result<String, UnlockError>, Duration) {
        thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock(server, name));
            let deadline = Instant::now() + Duration::from_secs(5);
            while slots(&server.dbs)[name].prompt_cancel.is_none() {
                assert!(Instant::now() < deadline, "the prompt never started");
                thread::sleep(Duration::from_millis(10));
            }
            thread::sleep(Duration::from_millis(100));
            then();
            let started = Instant::now();
            let result = unlocking.join().expect("unlock thread panicked");
            (result, started.elapsed())
        })
    }

    #[test]
    fn no_prompt_is_raised_while_the_desk_is_locked() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("prompted");
        let server = prompt_server(&format!("touch '{}'; exit 1", marker.display()));

        policy::Locks::set_desk_locked(&server, true);
        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::NoDisplay {
                db: "personal".to_string()
            })
        );
        assert!(!marker.exists(), "a prompt ran behind the locker");

        policy::Locks::set_desk_locked(&server, false);
        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::PromptCancelled {
                db: "personal".to_string()
            })
        );
        assert!(
            marker.exists(),
            "the prompt runs again once the desk is unlocked"
        );
    }

    #[test]
    fn lock_all_ends_a_prompt_in_flight() {
        let _spawning = spawn_lock();
        let server = prompt_server("sleep 30");

        let (result, took) = unlock_then(&server, "personal", || {
            policy::Locks::lock_all(&server);
        });

        assert_eq!(
            result,
            Err(UnlockError::LockedDuringUnlock {
                db: "personal".to_string()
            })
        );
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert!(slots(&server.dbs)["personal"].prompt_cancel.is_none());
    }

    #[test]
    fn locking_the_database_ends_its_prompt() {
        let _spawning = spawn_lock();
        let server = prompt_server("sleep 30");

        let (result, took) = unlock_then(&server, "personal", || {
            let _ = Lock::lock(
                &server,
                &LockRequest {
                    db: Some("personal".to_string()),
                },
            );
        });

        assert_eq!(
            result,
            Err(UnlockError::LockedDuringUnlock {
                db: "personal".to_string()
            })
        );
        assert!(took < Duration::from_secs(5), "took {took:?}");
    }

    /// Locking another database leaves this one's prompt open; it ends
    /// on its own, by timing out here.
    #[test]
    fn locking_another_database_leaves_the_prompt_alone() {
        let _spawning = spawn_lock();
        let mut server = prompt_server("sleep 30");
        server.config.prompt_timeout = Duration::from_millis(500);

        let (result, _) = unlock_then(&server, "personal", || {
            let _ = Lock::lock(
                &server,
                &LockRequest {
                    db: Some("work".to_string()),
                },
            );
        });

        assert_eq!(
            result,
            Err(UnlockError::PromptCancelled {
                db: "personal".to_string()
            })
        );
    }
}
