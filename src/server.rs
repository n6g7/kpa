//! The daemon: socket lifecycle, and the vault state behind it
//! (`docs/plan.md` step 2).
//!
//! `Server` is the implementation of the protocol's four op traits
//! (`proto::Status`/`Unlock`/`Lock`/`List`) — it answers what each op
//! means against a real vault, and `proto::dispatch` is what turns those
//! answers into responses. So nothing here builds a `Response` except the
//! pre-dispatch failures, which by definition never reach an op.
//!
//! No freshness guard, idle timeout, tray, or clipboard yet — those are
//! later steps. Unlocking still needs a password from somewhere, so this
//! step already runs the configured `prompt` command (`docs/design.md`
//! decision #9) to get one; nothing about that requires the later pieces.
//!
//! The limits below (request size, I/O timeouts, concurrent connections)
//! exist because one crashed daemon loses every unlocked database at once:
//! nothing a client sends, and nothing the host refuses, should be able to
//! take it down. See `docs/review-2026-09-robustness.md` findings 1–4, 7, 9.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use keepass::Database;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::proto::{
    self, DatabaseStatus, DecodeError, List, ListError, ListRequest, Lock, LockError, LockRequest,
    ProtocolError, Response, Status, Unlock, UnlockError, UnlockRequest, WireEntry,
};
use crate::vault::{self, VaultError};

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
}

impl Slot {
    /// Drops the database, if any, and bumps the epoch so an unlock that is
    /// still prompting for it cannot install what it opened.
    fn lock(&mut self) {
        self.db = None;
        self.lock_epoch = self.lock_epoch.wrapping_add(1);
    }

    /// Installs a freshly opened database and starts its idle timer.
    fn install(&mut self, db: Database) {
        self.db = Some(db);
        self.last_activity = Instant::now();
    }
}

impl Default for Slot {
    fn default() -> Slot {
        Slot {
            db: None,
            last_activity: Instant::now(),
            lock_epoch: 0,
            unlocking: false,
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
}

impl Server {
    pub fn new(config: Config) -> Server {
        let dbs = config
            .databases
            .iter()
            .map(|db| (db.name.clone(), Slot::default()))
            .collect();
        Server {
            config,
            dbs: Mutex::new(dbs),
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
        // Logged after the guard is released: a stalled stdout must not
        // hold up every other request.
        for name in &locked {
            log(format_args!("locked {name:?} after idle timeout"));
        }
        locked
    }
}

/// The poisoned case recovers rather than propagating: a panic on one
/// request thread shouldn't make every later request panic too.
fn slots(dbs: &Mutex<HashMap<String, Slot>>) -> MutexGuard<'_, HashMap<String, Slot>> {
    dbs.lock().unwrap_or_else(|e| e.into_inner())
}

impl Status for Server {
    fn status(&self) -> Vec<DatabaseStatus> {
        let dbs = slots(&self.dbs);
        self.config
            .databases
            .iter()
            .map(
                |cfg| match dbs.get(&cfg.name).and_then(|slot| slot.db.as_ref()) {
                    Some(db) => DatabaseStatus {
                        name: cfg.name.clone(),
                        locked: false,
                        entries: Some(vault::entry_count(db)),
                    },
                    None => DatabaseStatus {
                        name: cfg.name.clone(),
                        locked: true,
                        entries: None,
                    },
                },
            )
            .collect()
    }
}

/// Clears a slot's `unlocking` flag when dropped, so every way out of
/// `unlock` — early returns and panics alike — releases it. A flag left set
/// would refuse every later unlock of that database until a restart.
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
    fn unlock(&self, request: &UnlockRequest) -> Result<String, UnlockError> {
        let name = request.db.as_str();
        let db = || name.to_string();

        let Some(cfg) = self.config.databases.iter().find(|cfg| cfg.name == name) else {
            return Err(UnlockError::UnknownDb { db: db() });
        };

        let epoch = {
            let mut dbs = slots(&self.dbs);
            let Some(slot) = dbs.get_mut(name) else {
                return Err(UnlockError::UnknownDb { db: db() });
            };
            if slot.db.is_some() {
                // Already unlocked: succeed without re-prompting.
                return Ok(db());
            }
            if slot.unlocking {
                return Err(UnlockError::InProgress { db: db() });
            }
            slot.unlocking = true;
            slot.lock_epoch
        };
        // Declared before `dbs` below, so it drops after that guard has
        // released the mutex — `UnlockingFlag::drop` takes it again.
        let _unlocking = UnlockingFlag {
            dbs: &self.dbs,
            name,
        };

        let password = match prompt_password(&self.config.prompt) {
            Ok(PromptOutcome::Cancelled) => return Err(UnlockError::PromptCancelled { db: db() }),
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
        let opened = vault::open(&cfg.path, password.as_ref(), cfg.keyfile.as_deref())
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
        slot.install(opened);
        Ok(db())
    }
}

impl Lock for Server {
    fn lock(&self, request: &LockRequest) -> Result<Option<String>, LockError> {
        let mut dbs = slots(&self.dbs);
        let lock_slot = |slot: &mut Slot| slot.lock();
        match request.db.as_deref() {
            Some(name) => {
                let Some(slot) = dbs.get_mut(name) else {
                    return Err(LockError::UnknownDb {
                        db: name.to_string(),
                    });
                };
                lock_slot(slot);
                Ok(Some(name.to_string()))
            }
            None => {
                dbs.values_mut().for_each(lock_slot);
                Ok(None)
            }
        }
    }
}

impl List for Server {
    fn list(&self, request: &ListRequest) -> Result<Vec<WireEntry>, ListError> {
        let mut dbs = slots(&self.dbs);
        let now = Instant::now();

        // Each database a successful list reads gets its own timer reset;
        // the others keep running.
        match request.db.as_deref() {
            Some(name) => match dbs.get_mut(name) {
                None => Err(ListError::UnknownDb {
                    db: name.to_string(),
                }),
                Some(slot) => match &slot.db {
                    None => Err(ListError::Locked {
                        db: name.to_string(),
                    }),
                    Some(db) => {
                        let entries = wire_entries(name, db);
                        slot.last_activity = now;
                        Ok(entries)
                    }
                },
            },
            None => {
                let mut entries = Vec::new();
                for (db_name, slot) in dbs.iter_mut() {
                    if let Some(db) = &slot.db {
                        entries.extend(wire_entries(db_name, db));
                        slot.last_activity = now;
                    }
                }
                Ok(entries)
            }
        }
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
    }
}

enum PromptOutcome {
    /// The command exited unsuccessfully — e.g. the user dismissed a
    /// dmenu-style prompt — rather than printing a password.
    Cancelled,
    Password(Zeroizing<String>),
}

/// Run the configured prompt command (`docs/design.md` decision #9,
/// `Config::prompt`) and capture its stdout as a password.
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
fn prompt_password(argv: &[String]) -> std::io::Result<PromptOutcome> {
    use std::io::{Error, ErrorKind};

    let Some((program, args)) = argv.split_first() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "prompt command is empty",
        ));
    };

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_LEN]);
    let len = match read_prompt(&mut child, &mut buf) {
        Ok(len) => len,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
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
/// read. Errors rather than growing when `buf` fills up.
fn read_prompt(child: &mut Child, buf: &mut [u8]) -> std::io::Result<usize> {
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
        match stdout.read(&mut buf[len..]) {
            Ok(0) => return Ok(len),
            Ok(n) => len += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// Bind the daemon's Unix socket at `path`, mode `0600` (`docs/design.md`
/// § Protocol).
///
/// A missing parent directory is created with mode `0700`. An existing one
/// is left exactly as it is — `--socket ~/kpa.sock` must not change a home
/// directory's permissions, and `--socket /tmp/kpa.sock` must not try to
/// change `/tmp`'s.
///
/// Handles the stale-socket case: a previous `kpa serve` that didn't shut
/// down cleanly leaves its socket behind, and `bind` fails on an existing
/// path whether or not anything still listens there. Only a *socket* that
/// refuses connections is removed; anything else at the path — a live
/// daemon, a regular file — is an error, never silently deleted.
pub fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    match UnixListener::bind(path) {
        Ok(listener) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            Ok(listener)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            if !fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(err);
            }
            fs::remove_file(path)?;
            let listener = UnixListener::bind(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            Ok(listener)
        }
        Err(err) => Err(err),
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
            handle_connection(&server, stream);
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

/// One line on stdout. Never panics, unlike `println!`: a closed or broken
/// stdout must not take the daemon down with it.
fn log(args: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stdout().lock(), "kpa: {args}");
}

/// Log the operations that change what the daemon is holding, one line per
/// event on stdout, for whatever is supervising the daemon to collect. No
/// timestamps: a supervisor stamps its own, and inventing a second clock
/// here would only disagree with it.
///
/// **Reads are deliberately silent.** `status` and `list` change nothing,
/// and `list` in particular carries entry titles and usernames — a log is
/// the last place that should accumulate, since it outlives the unlocked
/// session that produced it and lands somewhere far less guarded than the
/// socket did. What gets logged is that an operation happened and to which
/// database, never what was in one.
///
/// Failures are logged too, not just successes: a failed `unlock` is the
/// event most worth having a record of.
fn log_response(response: &Response) {
    match response {
        Response::Unlock(Ok(db)) => log(format_args!("unlocked {db:?}")),
        Response::Unlock(Err(err)) => log(format_args!("unlock failed: {err:?}")),

        Response::Lock(Ok(Some(db))) => log(format_args!("locked {db:?}")),
        Response::Lock(Ok(None)) => log(format_args!("locked every database")),
        Response::Lock(Err(err)) => log(format_args!("lock failed: {err:?}")),

        Response::Protocol(err) => log(format_args!("rejected request: {err:?}")),

        // Listed above rather than caught by a `_` arm on purpose: adding
        // an op should be a decision about whether it belongs in the log,
        // not something a wildcard answers silently. `copy` (step 3) is
        // the next one, and it *is* an access worth recording.
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
fn handle_connection(server: &Server, mut stream: UnixStream) {
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

    write_response(&mut stream, &response);
    log_response(&response);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Held by every test here that spawns a process, and by the one that
    /// needs a socket to be genuinely dead. Spawning a child briefly
    /// duplicates every open file descriptor into it until it execs; if a
    /// prompt test forks at the wrong moment, the "stale" socket below is
    /// still held open by that child, and `bind_socket` rightly refuses to
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
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&server, theirs));
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
        assert_eq!(reply, "{\"v\":1,\"ok\":true,\"databases\":[]}\n");
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn prompt_output_has_its_line_ending_stripped() {
        let _spawning = spawn_lock();
        let Ok(PromptOutcome::Password(password)) = prompt_password(&sh("printf 'hunter2\\r\\n'"))
        else {
            panic!("expected a password");
        };
        assert_eq!(password.as_str(), "hunter2");
    }

    #[test]
    fn a_failing_prompt_is_a_cancellation() {
        let _spawning = spawn_lock();
        assert!(matches!(
            prompt_password(&sh("exit 1")),
            Ok(PromptOutcome::Cancelled)
        ));
    }

    /// The buffer never grows, so over-long output is an error rather than
    /// a reallocation that would strand an unwiped copy.
    #[test]
    fn over_long_prompt_output_is_refused() {
        let _spawning = spawn_lock();
        let script = format!("head -c {} /dev/zero | tr '\\0' a", MAX_PASSWORD_LEN + 1);
        assert!(prompt_password(&sh(&script)).is_err());
    }

    #[test]
    fn bind_refuses_to_replace_a_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sock");
        fs::write(&path, "precious").expect("write");

        assert!(bind_socket(&path).is_err());
        assert_eq!(fs::read_to_string(&path).expect("read"), "precious");
    }

    #[test]
    fn bind_leaves_an_existing_parent_directory_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");

        let _listener = bind_socket(&dir.path().join("sock")).expect("bind");

        let mode = fs::metadata(dir.path()).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn bind_creates_a_missing_parent_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("kpa");

        let _listener = bind_socket(&parent.join("sock")).expect("bind");

        let mode = fs::metadata(&parent).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn bind_replaces_a_stale_socket() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sock");
        drop(UnixListener::bind(&path).expect("first bind"));

        if let Err(err) = bind_socket(&path) {
            panic!("bind_socket failed: {err:?}");
        }
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

    /// Stands in for a successful unlock without a file or a prompt. Does not
    /// touch the timer, so each test controls it directly.
    fn unlock_directly(server: &Server, name: &str) {
        slots(&server.dbs).get_mut(name).expect("configured").db = Some(Database::new());
    }

    fn is_unlocked(server: &Server, name: &str) -> bool {
        slots(&server.dbs)[name].db.is_some()
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
}
