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
//! password from somewhere, so this step already asks a `prompt::Prompt`
//! for one (`docs/design.md` decision #9); nothing about that requires the
//! later pieces.
//!
//! The limits below (request size, I/O timeouts, concurrent connections)
//! exist because one crashed daemon loses every unlocked database at once:
//! nothing a client sends, and nothing the host refuses, should be able to
//! take it down. See `docs/review-2026-09-robustness.md` findings 1–4, 7, 9.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use keepass::Database;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::clip::{self, Clipboard};
use crate::config::{Config, DatabaseConfig};
use crate::io::ByteCounter;
use crate::log;
use crate::origin::{self, Origin, PeerOrigin};
use crate::paths::Paths;
use crate::policy;
use crate::prompt::{
    self, CancelSource, ConfirmProgram, Prompt, PromptOutcome, PromptQueue, SecretProgram,
};
use crate::proto::{
    self, CopyEntry, CopyError, CopyOutcome, CopyRequest, DatabaseStatus, DecodeError, Field, List,
    ListError, ListRequest, Lock, LockError, LockRequest, ProtocolError, Response, SshKeys,
    SshKeysError, SshKeysReport, SshKeysRequest, Status, Unlock, UnlockError, UnlockRequest,
    WireEntry, WireSkippedKey, WireSshKey,
};
use crate::socket;
use crate::ssh_agent::{self, Agent, SlotView, SshHost, SshSlot};
use crate::vault::{self, Fingerprint, VaultError};

/// Longest request line accepted, and the size of the zeroizing buffer
/// each one is read into. The largest legitimate request is an `unlock`
/// carrying a `MAX_PASSWORD_LEN` password, about 5.5 KiB of base64.
const MAX_REQUEST_LEN: usize = 64 * 1024;

/// How long a client gets to send its request, and to take its response.
/// An `unlock` can take much longer end to end — the user is typing — but
/// that time is spent between the read and the write, not inside either.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections handled at once; past this, new ones are refused by
/// closing them. Each holds a thread, and a flood should degrade into
/// refusals rather than into the host refusing a thread spawn.
const MAX_CONNECTIONS: usize = 64;

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
    /// Replaced by every `lock` that covers this database, which cancels
    /// every token taken from the one before. An `unlock` takes a token
    /// before prompting: its prompt ends as soon as a lock comes in, and it
    /// only stores what it opened if its token is still live afterwards,
    /// so a lock issued mid-unlock can't be undone by the unlock finishing.
    /// The SSH agent takes one the same way for each signature
    /// (`SlotView::cancel_token`), for its approval prompt and its signing
    /// hold.
    lock_signal: CancelSource,
    /// An unlock is prompting or deriving the key right now. A second one
    /// is refused rather than opening a second prompt.
    unlocking: bool,
    /// The SSH agent's state for this database (`docs/ssh-agent.md`
    /// § 6.4): the keys its last scan found, the private keys read since
    /// and the approvals granted. Empty while locked, or for a database
    /// that doesn't serve SSH keys.
    ssh: SshSlot,
}

impl Slot {
    /// Drops the database, if any, and the SSH agent's state for it, and
    /// replaces the lock signal, even for a database that is already
    /// locked: that ends a prompt in flight for it, and keeps an unlock
    /// that is still prompting or deriving the key from installing what it
    /// opened.
    fn lock(&mut self) {
        self.db = None;
        self.stamp = None;
        self.ssh = SshSlot::default();
        self.lock_signal = CancelSource::new();
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
            lock_signal: CancelSource::new(),
            unlocking: false,
            ssh: SshSlot::default(),
        }
    }
}

/// Daemon state. `dbs` keys on the configured database name; a key's
/// *absence* means "not a configured database" (`ErrorCode::UnknownDb`).
///
/// The mutex is held only for bookkeeping, never across the slow part of
/// `unlock` (the prompt and the key derivation, milliseconds to minutes).
/// Holding it there would stall every other request behind someone typing
/// a password; not holding it is what makes the lock signal necessary.
pub struct Server {
    config: Config,
    /// The file locations `main.rs` resolved at startup: where an unlock
    /// writes the SSH public-key cache, and where the SSH agent reads it
    /// back.
    paths: Paths,
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
    /// The desk's state, as the lock policy last published it
    /// (`policy::Event::Desk`). Each connection is classified against its
    /// display session (`origin`), and `unlock` asks it whether a prompt
    /// may be raised (`Desk::may_prompt`).
    desk: Mutex<policy::Desk>,
    /// Set by `assume_origin` only.
    assumed_origin: OnceLock<Origin>,
    /// The daemon's one prompt queue, so only one prompt is ever on screen
    /// (`docs/ssh-agent.md` § 6.7): the unlock prompt's, and the SSH
    /// agent's approval prompts, which `serve_ssh_agent` builds on it.
    prompt_queue: Arc<PromptQueue>,
    /// The unlock prompt (`Config::prompt`), in `prompt_queue`.
    unlock_prompt: Prompt<Zeroizing<String>>,
}

impl Server {
    pub fn new(config: Config, paths: Paths) -> Server {
        Server::with_clipboard(config, paths, clip::WaylandBackend)
    }

    /// Like `new`, but with an injected clipboard backend — real tests use
    /// `new`; unit tests that need to control the clipboard without a
    /// Wayland connection use this with a fake `clip::Backend`.
    pub fn with_clipboard(
        config: Config,
        paths: Paths,
        backend: impl clip::Backend + 'static,
    ) -> Server {
        let unlock_prompt = SecretProgram::new(config.prompt.clone());
        Server::with_backends(config, paths, backend, unlock_prompt)
    }

    /// Like `with_clipboard`, but with an injected unlock prompt backend
    /// too, for unit tests that answer prompts without running a program.
    fn with_backends(
        config: Config,
        paths: Paths,
        clipboard: impl clip::Backend + 'static,
        unlock_prompt: impl prompt::Backend<Zeroizing<String>> + 'static,
    ) -> Server {
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
        let prompt_queue = Arc::new(PromptQueue::new());
        let unlock_prompt = Prompt::new(
            Arc::clone(&prompt_queue),
            unlock_prompt,
            config.prompt_timeout,
        );
        Server {
            config,
            paths,
            dbs: Mutex::new(dbs),
            policy_events: OnceLock::new(),
            clip: Arc::new(Clipboard::new(clipboard)),
            clip_db: Arc::new(Mutex::new(None)),
            desk: Mutex::new(policy::Desk::NoSession),
            assumed_origin: OnceLock::new(),
            prompt_queue,
            unlock_prompt,
        }
    }

    /// Lock each unlocked database that has had no successful `list` and no
    /// unlock for `idle_timeout` as of `now`, judged per database. Returns
    /// the names it locked.
    ///
    /// Only databases that are unlocked get their lock signal replaced: an
    /// unlock still prompting for a locked database is not idle-locked out
    /// from under the user, and with nothing unlocked there is nothing to
    /// do.
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

    /// The desk's state, as the lock policy last published it. No display
    /// session until the logind watch says otherwise.
    pub fn desk(&self) -> policy::Desk {
        self.desk.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Treat every connection as coming from `origin` instead of reading
    /// the peer's cgroup, for tests that run the daemon in-process and
    /// drive it with the real CLI. Only code that builds its own `Server`
    /// can call this: `main.rs` never does, and no CLI flag, environment
    /// variable, config key or request field reaches it.
    #[doc(hidden)]
    pub fn assume_origin(&self, origin: Origin) {
        let _ = self.assumed_origin.set(origin);
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

    fn set_desk(&self, desk: policy::Desk) {
        *self.desk.lock().unwrap_or_else(|e| e.into_inner()) = desk;
    }
}

/// The poisoned case recovers rather than propagating: a panic on one
/// request thread shouldn't make every later request panic too.
fn slots(dbs: &Mutex<HashMap<String, Slot>>) -> MutexGuard<'_, HashMap<String, Slot>> {
    dbs.lock().unwrap_or_else(|e| e.into_inner())
}

/// Freshness guard (`docs/threat-model.md` T-12): if the file behind `slot`
/// is no longer the one its database was opened from, drops the database
/// and returns `true`. Called by `drop_stale`, which also ends the
/// clipboard offer a drop implies — `status`, `unlock`, `list` and `copy`
/// all go through that — and by `SshHost::with_slot`, which ends the offer
/// the same way and runs the SSH agent's own work in the same hold.
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

/// Clears a slot's `unlocking` flag when dropped, so every way out of
/// `unlock` — early returns and panics alike — releases it. A flag left
/// set would refuse every later unlock of that database until a restart.
struct UnlockingFlag<'a> {
    dbs: &'a Mutex<HashMap<String, Slot>>,
    name: &'a str,
}

impl Drop for UnlockingFlag<'_> {
    fn drop(&mut self) {
        if let Some(slot) = slots(self.dbs).get_mut(self.name) {
            slot.unlocking = false;
        }
    }
}

impl Unlock for Server {
    fn unlock(&self, request: &UnlockRequest, origin: Origin) -> Result<String, UnlockError> {
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

        // How a lock ends this unlock: the token is cancelled by the next
        // `Slot::lock`, which kills the prompt and keeps what this opens
        // from being installed.
        let cancel_token = {
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
            // No prompt where nobody can answer it: from outside the
            // desktop, or behind a locker. Read under the mutex: the policy
            // marks the desk before its `lock_all` takes it, so either this
            // sees the mark or that lock cancels the token taken below and
            // ends the prompt. A request that carries its password needs no
            // prompt, so it goes ahead from anywhere: that is how an
            // unlock from outside the desktop is answered.
            if request.password.is_none() && !self.desk().may_prompt(origin) {
                return Err(UnlockError::NoDisplay);
            }
            if slot.unlocking {
                return Err(UnlockError::InProgress { db: db() });
            }
            slot.unlocking = true;
            slot.lock_signal.token()
        };
        // Declared before `dbs` below, so it drops after that guard has
        // released the mutex — `UnlockingFlag::drop` takes it again.
        let _unlocking = UnlockingFlag {
            dbs: &self.dbs,
            name,
        };

        let prompted;
        let password = match &request.password {
            // A request that carries a password never prompts. A wrong one
            // fails like a wrong one typed at the prompt, with no backoff:
            // any same-uid process can read the `.kdbx` and guess offline.
            Some(password) => password.as_zeroizing(),
            None => {
                log::debug(format_args!("prompting for {name:?}"));
                let timeout = self.config.prompt_timeout;
                prompted = match self
                    .unlock_prompt
                    .ask(&format!("Unlock {name}"), &cancel_token)
                {
                    Ok(PromptOutcome::Cancelled) => {
                        return Err(UnlockError::PromptCancelled { db: db() });
                    }
                    Ok(PromptOutcome::TimedOut) => {
                        log::info(format_args!(
                            "prompt for {name:?} unanswered after {timeout:?}"
                        ));
                        return Err(UnlockError::PromptCancelled { db: db() });
                    }
                    // A lock ended the prompt, and has already told its own
                    // client the database is locked.
                    Ok(PromptOutcome::Interrupted) => {
                        return Err(UnlockError::LockedDuringUnlock { db: db() });
                    }
                    Ok(PromptOutcome::Answer(password)) => password,
                    Err(err) => {
                        return Err(UnlockError::PromptFailed {
                            db: db(),
                            detail: err.to_string(),
                        });
                    }
                };
                &prompted
            }
        };
        // Empty means "no password" — the only way to reach a keyfile-only
        // database from a prompt that always asks.
        let password = Some(password).filter(|password| !password.is_empty());

        // Note: a file with pathological KDF parameters can make this hang
        // indefinitely or abort the process — upstream in `keepass`, which
        // applies no ceilings; see the note on `vault::open`. The unlocking
        // flag at least bounds it to one stuck thread per database.
        let (opened, stamp) = vault::open(&cfg.path, password, cfg.keyfile.as_deref())
            .map_err(|err| unlock_error(name, err))?;
        // The SSH key scan parses every key file, so it runs here, before
        // the mutex, like the key derivation above.
        let ssh = cfg.serve_ssh_keys.then(|| SshSlot::scan(&opened, cfg));

        let mut dbs = slots(&self.dbs);
        let Some(slot) = dbs.get_mut(name) else {
            return Err(UnlockError::UnknownDb { db: db() });
        };
        if cancel_token.is_cancelled() {
            // A lock arrived while we were prompting or deriving the key.
            // It already told its client the database is locked; `opened`
            // is dropped here so that stays true.
            return Err(UnlockError::LockedDuringUnlock { db: db() });
        }
        slot.install(opened, stamp);
        let cache = ssh.map(|ssh| {
            let cache = ssh.cache(name);
            slot.ssh = ssh;
            cache
        });
        drop(dbs);
        // A file write with an fsync: after the mutex, never under it.
        if let Some(cache) = cache {
            cache.write(&self.paths);
        }
        self.notify_unlocked();
        // Logged here rather than in `log_response`: only this path knows
        // the database was actually opened, as opposed to already unlocked.
        log::info(format_args!("unlocked {name:?}"));
        Ok(db())
    }
}

impl PeerOrigin for Server {
    /// Where the peer on `stream` runs (`docs/headless.md` § 3).
    fn origin_of(&self, stream: &UnixStream, owner: u32) -> Origin {
        match self.assumed_origin.get() {
            Some(origin) => *origin,
            None => origin::of_peer(stream, owner, self.desk().session()),
        }
    }
}

/// What the SSH agent needs from the daemon, as a thin adapter over the
/// slots: the agent's own logic stays in `ssh_agent`.
impl SshHost for Server {
    fn databases(&self) -> &[DatabaseConfig] {
        &self.config.databases
    }

    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R> {
        let (result, stale) = {
            let mut dbs = slots(&self.dbs);
            let slot = dbs.get_mut(db)?;
            let stale = drop_if_stale(slot);
            let view = SlotView::new(
                slot.db.as_ref(),
                &mut slot.ssh,
                &mut slot.last_activity,
                &slot.lock_signal,
            );
            (f(view), stale)
        };
        // As `drop_stale` does: the clipboard is ended after the mutex.
        if stale {
            self.end_clipboard_for(db);
        }
        Some(result)
    }

    fn may_prompt(&self, origin: Origin) -> bool {
        self.desk().may_prompt(origin)
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

impl SshKeys for Server {
    /// Scans the unlocked databases again, under the mutex: a database
    /// can't leave it, and the scan parses only the few key attachments a
    /// vault holds. Like `list`, a request for every database reports a
    /// stale one by name and fails, and one that names a database fails
    /// on it if it is locked.
    fn ssh_keys(&self, request: &SshKeysRequest) -> Result<SshKeysReport, SshKeysError> {
        let names: Vec<&str> = match &request.db {
            Some(name) => vec![name.as_str()],
            None => self
                .config
                .databases
                .iter()
                .map(|cfg| cfg.name.as_str())
                .collect(),
        };
        if let Some(db) = self.drop_stale(names.iter().copied()).into_iter().next() {
            return Err(SshKeysError::Stale { db });
        }
        let mut dbs = slots(&self.dbs);
        let mut report = SshKeysReport::default();
        for name in names {
            let db = || name.to_string();
            let slot = dbs
                .get_mut(name)
                .ok_or_else(|| SshKeysError::UnknownDb { db: db() })?;
            let Some(database) = slot.db.as_ref() else {
                if request.db.is_some() {
                    return Err(SshKeysError::Locked { db: db() });
                }
                report.locked.push(db());
                continue;
            };
            let scan = ssh_agent::keys::scan(database);
            slot.touch();
            report
                .keys
                .extend(scan.found.into_iter().map(|key| WireSshKey {
                    db: db(),
                    key_type: key.public_key.algorithm().to_string(),
                    fingerprint: key.fingerprint.to_string(),
                    title: key.entry_title,
                    attachment: key.attachment_name,
                }));
            report
                .skipped
                .extend(scan.skipped.into_iter().map(|skipped| WireSkippedKey {
                    db: db(),
                    title: skipped.entry_title,
                    attachment: skipped.attachment_name,
                    reason: skipped.reason.to_string(),
                }));
        }
        Ok(report)
    }
}

impl CopyEntry for Server {
    fn copy(&self, request: &CopyRequest, origin: Origin) -> Result<CopyOutcome, CopyError> {
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
        let desk = self.desk();
        let value = {
            let mut dbs = slots(&self.dbs);
            let Some(slot) = dbs.get_mut(name) else {
                return Err(CopyError::UnknownDb { db: db() });
            };
            // No secret reaches the clipboard where nobody can paste it
            // from (`docs/headless.md` § 5) — checked here, same place
            // `unlock` reads `Desk::may_prompt`, and before the `Locked`
            // check below so an outside caller learns no more than an
            // unknown database does.
            if !desk.may_copy(origin) {
                return Err(CopyError::NoDisplay);
            }
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
        // `may_copy` only passes with a display session.
        let session = desk.session().unwrap_or_default();

        let offer = self
            .clip
            .offer(value, session)
            .map_err(|err| CopyError::Clipboard {
                db: db(),
                detail: err.to_string(),
            })?;
        // Recorded immediately after a successful handoff, so `lock`
        // (`end_clipboard_for`) knows which database's lock should end
        // this offer early. A narrow window remains between the offer
        // actually becoming current (inside `self.clip.offer`, just
        // above) and this line — a `lock` of `name` landing in between
        // would see the old `clip_db` value and miss ending this offer,
        // which then only expires via its own `clipboard_timeout`. Closing
        // it needs the bookkeeping and the backend handoff to be one
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

/// Serves the SSH agent (`docs/ssh-agent.md`) for `server` on `listener`
/// forever, each connection on its own thread, as `serve` does the JSON
/// socket. Its approval prompt runs `ssh_agent.confirm_prompt`, with
/// `Config::confirm_prompt_timeout`, and waits its turn in `unlock`'s
/// queue, so only one prompt is ever on screen.
pub fn serve_ssh_agent(server: Arc<Server>, listener: UnixListener) {
    let approval = Prompt::new(
        Arc::clone(&server.prompt_queue),
        ConfirmProgram::new(server.config.ssh_agent.confirm_prompt.clone()),
        server.config.confirm_prompt_timeout(),
    );
    let agent = Agent::new(Arc::clone(&server), approval, &server.paths);
    ssh_agent::serve::serve(Arc::new(agent), listener);
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
        // Success is logged by `Unlock::unlock` itself, and only when it
        // actually opened the database.
        Response::Unlock(Ok(_)) => {}
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
        // not something a wildcard answers silently. `ssh_keys` carries
        // entry titles, which stay out of the log like `list`'s.
        Response::Status { .. } | Response::List(_) | Response::SshKeys(_) => {}
    }
}

/// Serialize `response` and send it, newline-terminated.
///
/// Serialized twice on purpose: once to measure (into the shared
/// [`ByteCounter`], also used by `proto::encode_request` for the CLI's
/// outbound requests), once into a zeroizing buffer allocated at exactly
/// that size. A `list` response holds every entry's title, username and
/// URL, and a buffer that grows while being filled frees an unwiped copy
/// at each reallocation — which is what survived a lock before
/// (`docs/review-2026-09-secrets.md` finding 5).
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

/// What `read_request` found on the socket.
enum RequestLine {
    /// The client closed the connection without sending anything.
    Closed,
    /// `MAX_REQUEST_LEN` bytes with no newline among them.
    TooLong,
    /// The line's length, newline excluded. A client that closes its end
    /// without a newline has still sent a line.
    Line(usize),
}

/// Read one request line into `buf`, which never grows.
///
/// Read straight from the socket rather than through a `BufReader`: an
/// `unlock` line can carry the master password, and a `BufReader`'s own
/// buffer (like a `Vec` grown as the line arrives) would be freed without
/// being wiped. Whatever is read past the newline lands in `buf` too, and
/// is ignored: a connection carries one request.
fn read_request(mut stream: &UnixStream, buf: &mut [u8]) -> std::io::Result<RequestLine> {
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Ok(RequestLine::TooLong);
        }
        let n = match stream.read(&mut buf[len..]) {
            Ok(0) if len == 0 => return Ok(RequestLine::Closed),
            Ok(0) => return Ok(RequestLine::Line(len)),
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if let Some(newline) = buf[len..len + n].iter().position(|&byte| byte == b'\n') {
            return Ok(RequestLine::Line(len + newline));
        }
        len += n;
    }
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

    let origin = server.origin_of(&stream, owner);
    log::debug(format_args!("connection from {origin:?}"));

    // The request, and the buffer it was read into, are dropped (and so
    // wiped) at the end of this block, before the response goes anywhere.
    let response = {
        let mut buf = Zeroizing::new(vec![0u8; MAX_REQUEST_LEN]);
        match read_request(&stream, &mut buf) {
            Ok(RequestLine::Closed) | Err(_) => return,
            Ok(RequestLine::TooLong) => Response::Protocol(ProtocolError::MalformedRequest),
            Ok(RequestLine::Line(len)) => {
                match std::str::from_utf8(&buf[..len]).map(proto::decode_request) {
                    Ok(Ok(request)) => proto::dispatch(server, &request, origin),
                    Ok(Err(DecodeError::VersionMismatch(client_v))) => {
                        Response::Protocol(ProtocolError::VersionMismatch { client_v })
                    }
                    Ok(Err(DecodeError::MalformedRequest)) | Err(_) => {
                        Response::Protocol(ProtocolError::MalformedRequest)
                    }
                }
            }
        }
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
    use crate::prompt::{Scripted, Step};

    fn empty_server() -> Server {
        Server::new(
            Config::parse("").expect("an empty config is valid"),
            Paths::default(),
        )
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

    /// Runs `read_request` on a socket pair whose other end writes
    /// `pieces` a moment apart, so each tends to arrive as its own read.
    fn read_written(pieces: &[&[u8]], buf_len: usize) -> (std::io::Result<RequestLine>, Vec<u8>) {
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut buf = vec![0u8; buf_len];
        let read = thread::scope(|scope| {
            scope.spawn(move || {
                for piece in pieces {
                    let _ = ours.write_all(piece);
                    thread::sleep(Duration::from_millis(20));
                }
            });
            read_request(&theirs, &mut buf)
        });
        (read, buf)
    }

    #[test]
    fn read_request_stops_at_the_first_newline() {
        let (read, buf) = read_written(&[b"{\"v\":1,", b"\"op\":\"status\"}\nrest\n"], 64);
        let Ok(RequestLine::Line(len)) = read else {
            panic!("expected a line");
        };
        assert_eq!(&buf[..len], b"{\"v\":1,\"op\":\"status\"}");
    }

    #[test]
    fn read_request_accepts_a_newline_in_the_last_byte_and_no_further() {
        let (read, _) = read_written(&[b"abc\n"], 4);
        assert!(matches!(read, Ok(RequestLine::Line(3))));
        let (read, _) = read_written(&[b"abcd\n"], 4);
        assert!(matches!(read, Ok(RequestLine::TooLong)));
    }

    #[test]
    fn read_request_takes_an_unterminated_line_at_eof() {
        let (read, _) = read_written(&[b"abc"], 64);
        assert!(matches!(read, Ok(RequestLine::Line(3))));
        let (read, _) = read_written(&[], 64);
        assert!(matches!(read, Ok(RequestLine::Closed)));
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
        Server::new(
            Config::parse(&config).expect("valid config"),
            Paths::default(),
        )
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
        let server = Server::with_clipboard(
            Config::parse(&config).expect("valid config"),
            Paths::default(),
            backend,
        );
        allow_copy(&server);
        server
    }

    /// Marks the desk active and unlocked, so `CopyEntry::copy` with
    /// `Origin::Desktop` passes its gate — every copy test below that
    /// isn't itself about the gate calls this on its server, the same way
    /// those tests always ran before `may_copy` existed.
    fn allow_copy(server: &Server) {
        policy::Locks::set_desk(
            server,
            policy::Desk::Unlocked {
                session: "31".to_string(),
                active: true,
            },
        );
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

    /// What an unlock's scan found for a database goes with it on lock,
    /// so none of it outlives the database.
    #[test]
    fn a_lock_resets_the_ssh_agent_state() {
        use crate::ssh_agent::testing::{key_database, test_key};

        let server = Server::new(
            Config::parse(
                "[ssh_agent]\nconfirm_prompt = [\"true\"]\n\n\
                 [[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 serve_ssh_keys = true\n",
            )
            .expect("valid config"),
            Paths::default(),
        );
        unlock_directly(&server, "personal");
        {
            let mut dbs = slots(&server.dbs);
            let slot = dbs.get_mut("personal").expect("configured");
            let db = key_database(&[("github", &test_key(1))]);
            slot.ssh = SshSlot::scan(&db, &server.config.databases[0]);
            slot.db = Some(db);
            assert!(!slot.ssh.is_empty(), "sanity: the scan found the key");
        }

        Lock::lock(
            &server,
            &LockRequest {
                db: Some("personal".to_string()),
            },
        )
        .expect("personal is configured");

        assert!(slots(&server.dbs)["personal"].ssh.is_empty());
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
            Paths::default(),
            backend,
        );
        allow_copy(&server);
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
            Origin::Desktop,
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
            Origin::Desktop,
        )
        .expect_err("database is locked");
        assert_eq!(
            err,
            CopyError::Locked {
                db: "personal".to_string()
            }
        );
    }

    /// `docs/headless.md` § 5: `copy` is refused with `no_display` for a
    /// requester outside the desktop, a desk that's locked, inactive, or
    /// has no display session at all — and the gate fires before it even
    /// gets to `Locked`, so an outside caller learns no more than that.
    #[test]
    fn copy_is_refused_without_a_desktop_requester_on_an_active_unlocked_desk() {
        let request = || CopyRequest {
            db: "personal".to_string(),
            uuid: uuid::Uuid::nil(),
            field: Field::Password,
        };
        let refused = CopyError::NoDisplay;

        let (server, _offered) = copy_server();
        unlock_with_entry(&server, "personal");

        assert_eq!(
            CopyEntry::copy(&server, &request(), Origin::Outside),
            Err(refused.clone()),
            "a requester outside the desktop"
        );

        for desk in [
            policy::Desk::Locked {
                session: "31".to_string(),
                active: true,
            },
            policy::Desk::Unlocked {
                session: "31".to_string(),
                active: false,
            },
            policy::Desk::NoSession,
        ] {
            policy::Locks::set_desk(&server, desk.clone());
            assert_eq!(
                CopyEntry::copy(&server, &request(), Origin::Desktop),
                Err(refused.clone()),
                "desk {desk:?}"
            );
        }
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
            Origin::Desktop,
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
            Origin::Desktop,
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
            Origin::Desktop,
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
    type TrackedOffers = Arc<Mutex<Vec<Arc<clip::Offer>>>>;

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
            Paths::default(),
            backend,
        );
        allow_copy(&server);
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
            Origin::Desktop,
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
            Origin::Desktop,
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
            Origin::Desktop,
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
            Origin::Desktop,
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
            Paths::default(),
            backend,
        );
        allow_copy(&server);
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
            Origin::Desktop,
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
                Origin::Desktop,
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
            Origin::Desktop,
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
    /// its lock signal, so an unlock still prompting for it is not
    /// cancelled.
    #[test]
    fn an_idle_lock_leaves_locked_databases_and_their_lock_signals_alone() {
        let server = idle_server("1s");
        unlock_directly(&server, "personal");
        age_activity(&server, "personal", Duration::from_secs(5));
        let unlocking_work = slots(&server.dbs)["work"].lock_signal.token();

        assert_eq!(server.expire_idle(Instant::now()), ["personal"]);
        assert!(!unlocking_work.is_cancelled());
    }

    /// Two configured, locked databases and a recording clipboard backend
    /// that tracks per-offer liveness, with one prompt scripted to be
    /// dismissed — for the freshness-guard tests below, which drive
    /// `unlock` far enough to re-prompt without needing it to succeed.
    fn stale_drop_test_server() -> (Server, TrackedOffers) {
        let (backend, _offered, offers) = clip::RecordingBackend::new_tracking();
        let prompts = Scripted::new();
        prompts.push(Step::new(PromptOutcome::Cancelled));
        let server = Server::with_backends(
            Config::parse(
                "[[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n",
            )
            .expect("valid config"),
            Paths::default(),
            backend,
            prompts,
        );
        allow_copy(&server);
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
    fn stale_copy_setup() -> (Server, TrackedOffers, Arc<clip::Offer>) {
        let (server, offers) = stale_drop_test_server();
        let uuid = unlock_with_entry(&server, "personal");
        CopyEntry::copy(
            &server,
            &CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            },
            Origin::Desktop,
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
        let (server, _offers, offer) = stale_copy_setup();

        let _ = Unlock::unlock(
            &server,
            &UnlockRequest {
                db: "personal".to_string(),
                password: None,
            },
            Origin::Desktop,
        );

        assert!(
            !offer.is_live(),
            "unlock's re-prompt branch dropping a stale database must end its clipboard offer"
        );
    }

    /// Same as above, through the SSH agent's slot access, which drops the
    /// stale database before the agent sees it.
    #[test]
    fn the_ssh_agents_slot_access_ends_the_clipboard_offer_for_a_stale_database() {
        let (server, _offers, offer) = stale_copy_setup();

        assert_eq!(SshHost::with_slot(&server, "personal", |_| ()), Some(()));

        assert!(!is_unlocked(&server, "personal"));
        assert!(
            !offer.is_live(),
            "the agent's freshness guard dropping a stale database must end its clipboard offer"
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
            Origin::Desktop,
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
                password: None,
            },
            Origin::Desktop,
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
            Origin::Desktop,
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
            Origin::Desktop,
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

    /// Two configured, locked databases whose prompts answer as the
    /// returned script says. `Arc`, so a step can lock the server while its
    /// prompt is up.
    fn prompt_server() -> (Arc<Server>, Scripted<Zeroizing<String>>) {
        let prompts = Scripted::new();
        let server = Server::with_backends(
            Config::parse(
                "[[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n\
                 [[database]]\nname = \"work\"\npath = \"work.kdbx\"\n",
            )
            .expect("valid config"),
            Paths::default(),
            clip::WaylandBackend,
            prompts.clone(),
        );
        (Arc::new(server), prompts)
    }

    fn unlock(server: &Server, name: &str) -> Result<String, UnlockError> {
        unlock_from(server, name, Origin::Desktop)
    }

    fn unlock_from(server: &Server, name: &str, origin: Origin) -> Result<String, UnlockError> {
        Unlock::unlock(
            server,
            &UnlockRequest {
                db: name.to_string(),
                password: None,
            },
            origin,
        )
    }

    /// A prompt that types a password, unless something ends it first.
    fn typed() -> Step<Zeroizing<String>> {
        Step::new(PromptOutcome::Answer(Zeroizing::new("hunter2".to_string())))
    }

    #[test]
    fn no_prompt_is_raised_while_the_desk_is_locked() {
        let (server, prompts) = prompt_server();
        prompts.push(Step::new(PromptOutcome::Cancelled));

        policy::Locks::set_desk(
            &*server,
            policy::Desk::Locked {
                session: "1".to_string(),
                active: true,
            },
        );
        assert_eq!(unlock(&server, "personal"), Err(UnlockError::NoDisplay));
        assert!(prompts.shown().is_empty(), "a prompt ran behind the locker");

        policy::Locks::set_desk(
            &*server,
            policy::Desk::Unlocked {
                session: "1".to_string(),
                active: true,
            },
        );
        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::PromptCancelled {
                db: "personal".to_string()
            })
        );
        assert_eq!(
            prompts.shown(),
            ["Unlock personal"],
            "the prompt runs again once the desk is unlocked"
        );
    }

    #[test]
    fn no_prompt_is_raised_for_a_requester_outside_the_desktop() {
        let (server, prompts) = prompt_server();
        prompts.push(Step::new(PromptOutcome::Cancelled));
        policy::Locks::set_desk(
            &*server,
            policy::Desk::Unlocked {
                session: "1".to_string(),
                active: true,
            },
        );

        assert_eq!(
            unlock_from(&server, "personal", Origin::Outside),
            Err(UnlockError::NoDisplay)
        );
        assert!(
            prompts.shown().is_empty(),
            "a prompt ran for a requester outside"
        );

        assert_eq!(
            unlock_from(&server, "personal", Origin::Desktop),
            Err(UnlockError::PromptCancelled {
                db: "personal".to_string()
            })
        );
        assert_eq!(
            prompts.shown(),
            ["Unlock personal"],
            "the prompt runs for the desktop"
        );
    }

    /// A request that carries its password needs no prompt, so neither
    /// gate applies: it goes ahead from outside the desktop, and behind a
    /// locker. Here it reaches the vault, whose file doesn't exist.
    #[test]
    fn a_request_carrying_its_password_goes_ahead_from_anywhere() {
        let (server, prompts) = prompt_server();

        for desk in [
            policy::Desk::NoSession,
            policy::Desk::Locked {
                session: "1".to_string(),
                active: true,
            },
        ] {
            policy::Locks::set_desk(&*server, desk);
            let result = Unlock::unlock(
                &*server,
                &UnlockRequest {
                    db: "personal".to_string(),
                    password: Some(crate::proto::Password::new(Zeroizing::new(
                        "hunter2".to_string(),
                    ))),
                },
                Origin::Outside,
            );
            assert_eq!(
                result,
                Err(UnlockError::NotFound {
                    db: "personal".to_string()
                })
            );
        }
        assert!(
            prompts.shown().is_empty(),
            "a request with a password prompted"
        );
    }

    #[test]
    fn lock_all_ends_a_prompt_in_flight() {
        let (server, prompts) = prompt_server();
        let locker = Arc::clone(&server);
        prompts.push(typed().while_up(move || policy::Locks::lock_all(&*locker)));

        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::LockedDuringUnlock {
                db: "personal".to_string()
            })
        );
        assert!(!slots(&server.dbs)["personal"].unlocking);
    }

    #[test]
    fn locking_the_database_ends_its_prompt() {
        let (server, prompts) = prompt_server();
        let locker = Arc::clone(&server);
        prompts.push(typed().while_up(move || {
            let _ = Lock::lock(
                &*locker,
                &LockRequest {
                    db: Some("personal".to_string()),
                },
            );
        }));

        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::LockedDuringUnlock {
                db: "personal".to_string()
            })
        );
    }

    /// Locking another database leaves this one's prompt open; it ends
    /// on its own, dismissed here.
    #[test]
    fn locking_another_database_leaves_the_prompt_alone() {
        let (server, prompts) = prompt_server();
        let locker = Arc::clone(&server);
        prompts.push(Step::new(PromptOutcome::Cancelled).while_up(move || {
            let _ = Lock::lock(
                &*locker,
                &LockRequest {
                    db: Some("work".to_string()),
                },
            );
        }));

        assert_eq!(
            unlock(&server, "personal"),
            Err(UnlockError::PromptCancelled {
                db: "personal".to_string()
            })
        );
    }
}
