//! Thin wrapper around the `keepass` crate.
//!
//! Kept deliberately dumb: open a `.kdbx` given a password and/or keyfile,
//! and list or count what's in it. No caching and no locking — that is
//! daemon state, and it lives in `databases`. The freshness fingerprint is
//! taken here, because it has to bracket the read.
//!
//! Every field/method name below was checked against the vendored source
//! for `keepass` 0.15.0 (`~/.cargo/registry/src/*/keepass-0.15.0/src/`)
//! rather than assumed from memory: `with_password`/`with_keyfile` are
//! methods on `DatabaseKey`, not Cargo features — there is no feature flag
//! needed to unlock with a password or a keyfile, only `challenge_response`,
//! `totp`, `save_kdbx4` and `serialization` are real feature names, and v1
//! needs none of them.

use std::fs::File;
use std::io::{Cursor, Read};
use std::os::unix::fs::MetadataExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use keepass::config::DatabaseVersion;
use keepass::db::DatabaseOpenError;
use keepass::error::{CryptographyError, DatabaseKeyError};
use keepass::{Database, DatabaseKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Errors opening or reading a `.kdbx` file.
///
/// Deliberately collapses `keepass`'s much finer-grained error types (it
/// distinguishes XML errors, block-stream HMAC errors, cipher config errors,
/// ...) down to the handful of buckets a caller actually needs to act on.
/// Everything that isn't a credentials problem or an I/O problem gets
/// folded into `Corrupt` with the original message preserved via `Display` —
/// there is no useful *different* action to take for "bad XML" vs. "bad
/// HMAC block", they're both "this file is not a valid database".
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The `.kdbx` file itself doesn't exist at the given path.
    #[error("database file not found: {0}")]
    NotFound(PathBuf),

    /// The keyfile doesn't exist at the given path.
    #[error("keyfile not found: {0}")]
    KeyfileNotFound(PathBuf),

    /// Password and/or keyfile didn't decrypt the database — or the file
    /// has been modified or corrupted, which surfaces identically.
    /// `keepass` itself can't tell a wrong password from a wrong keyfile
    /// apart — both feed the same key-derivation step — and for KDBX3 it
    /// can't reliably tell either apart from certain corruption (see the
    /// `InvalidPadding` match arm below) — so neither can we.
    #[error("wrong password or keyfile, or the file has been modified")]
    WrongCredentials,

    /// The file was readable but isn't a valid (or isn't a supported)
    /// KeePass database: truncated, garbage bytes, unsupported version,
    /// bad checksum, etc.
    ///
    /// Deliberately content-free in `Display`: `keepass`'s own error text
    /// can embed raw bytes out of the decrypted database (e.g. its
    /// `cs_bool` deserializer echoes the offending element's text
    /// verbatim). That must never cross a process boundary — today the
    /// only sink is `probe`'s stderr, but `docs/design.md` already plans
    /// `detail` strings reaching a socket client. The original message is
    /// kept for developers via `Debug` (`{err:?}`), which nothing currently
    /// prints.
    #[error("database file is malformed or corrupt")]
    Corrupt(String),

    /// Any other I/O error reading the database or keyfile (permissions,
    /// I/O failure mid-read, ...) — deliberately not `NotFound`, which is
    /// its own variant so callers can special-case "run `kpa unlock` after
    /// creating the file" vs. a generic failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The database's file changed while it was being read, so the bytes
    /// that were read may not match the fingerprint taken around them.
    #[error("database file changed while it was being read")]
    Changed,
}

/// The file identity the freshness guard compares.
///
/// `(dev, ino, size, mtime, ctime)`, with nanosecond precision on both
/// times. `open` takes one with `fstat` on the fd it reads, before and
/// after the read; `is_unchanged` takes one with `stat` on the path. Any
/// difference means the file is no longer the one that was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl Fingerprint {
    fn from_metadata(meta: &std::fs::Metadata) -> Fingerprint {
        Fingerprint {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }

    /// Fingerprint of the file behind `path`, by `stat`. Follows symlinks,
    /// the same way `open` does.
    pub fn from_file(path: &Path) -> std::io::Result<Fingerprint> {
        std::fs::metadata(path).map(|meta| Fingerprint::from_metadata(&meta))
    }

    /// Whether `self` and `other` describe the same file identity.
    pub fn matches(self, other: Fingerprint) -> bool {
        self == other
    }
}

/// Whether the file at `path` is still the one `expected` was taken from.
/// A file that can no longer be stat'd counts as changed.
pub fn is_unchanged(path: &Path, expected: &Fingerprint) -> bool {
    Fingerprint::from_file(path).is_ok_and(|now| now.matches(*expected))
}

impl From<DatabaseOpenError> for VaultError {
    fn from(err: DatabaseOpenError) -> Self {
        match err {
            DatabaseOpenError::Key(key_err) => match key_err {
                DatabaseKeyError::IncorrectKey => VaultError::WrongCredentials,
                other => VaultError::Corrupt(other.to_string()),
            },

            // Empirically verified (not assumed): keepassxc-cli 2.7.12's
            // `db-create` defaults to **KDBX3**, not KDBX4. KDBX3's wrong-key
            // detection decrypts the payload with CBC first and only *then*
            // compares a stream-start marker to decide `IncorrectKey`
            // (`format/kdbx3.rs`) — there is no pre-decryption HMAC check
            // like KDBX4 has. A wrong key very often produces invalid PKCS7
            // padding during that CBC decrypt, which surfaces as
            // `CryptographyError::InvalidPadding` *before* the code ever
            // reaches the stream-start comparison that would yield
            // `IncorrectKey`. Confirmed against the fixture: a wrong
            // password on `fixture.kdbx` actually returns this variant, not
            // `Key(IncorrectKey)` — so it has to be treated as a
            // credentials error too, not folded into `Corrupt`.
            DatabaseOpenError::Cryptography(CryptographyError::InvalidPadding(_)) => {
                VaultError::WrongCredentials
            }

            DatabaseOpenError::Io(io_err) => VaultError::Io(io_err),
            other => VaultError::Corrupt(other.to_string()),
        }
    }
}

/// One entry, index-only — matches the shape of the design doc's `list`
/// response (`docs/design.md` § Protocol). No password, no notes: `list` is
/// an index, never a secret dump — and that holds for *any* field the user
/// marked protected in their KeePass client, not just Password: a protected
/// `Title`/`UserName`/`URL` is omitted here rather than de-protected (see
/// `unprotected_field`). String fields zeroize on drop since they hold
/// plaintext read out of the decrypted database.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EntrySummary {
    #[zeroize(skip)]
    pub uuid: Uuid,
    pub title: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    /// Name of the immediate parent group (not a full path — the design
    /// doc's example response uses a bare name like `"Dev"`).
    pub group: String,
    /// Field *names* `copy` can be asked for on this entry — see
    /// `copyable_field_names`. Never a value, so protectedness never hides
    /// an entry here the way it hides `title`/`username`/`url` above.
    pub fields: Vec<String>,
}

/// Open a `.kdbx` file with a password and/or a keyfile.
///
/// Also returns the file's `Fingerprint`, taken by `fstat` on the fd that
/// was read, before and after the read. If the two differ, the file changed
/// under the read and this fails with `VaultError::Changed`. Keep the
/// returned fingerprint and compare it later with `is_unchanged`.
///
/// At least one of `password`/`keyfile` must be `Some` or `keepass` itself
/// rejects the key as empty (`DatabaseKeyError::EmptyKey`, surfaced here as
/// `Corrupt` since it's not really a credentials mistake so much as a
/// caller bug).
///
/// `password` is `&Zeroizing<String>` rather than `&str` so callers are
/// pushed into holding it in a wiped-on-drop buffer instead of a plain
/// `String` — `&str` alone can't carry that guarantee. The daemon reads it
/// from its configured prompt command straight into `Zeroizing` buffers
/// (`control`'s unlock). That covers the copies kpa holds; the ones it can't reach
/// are inside the prompt program itself and inside `keepass`, whose
/// key-derivation intermediates are not zeroized — half of
/// `sha256(password)`, which is password-equivalent, survives a lock
/// (`docs/review-2026-09-secrets.md` finding 4; fix is upstream).
///
/// **Never panics.** `keepass` indexes past the end of short header fields
/// in several places and panics on them (`docs/review-2026-09-robustness.md`
/// finding 8; fix is upstream), so the parse runs under `catch_unwind` and
/// a panic comes back as `Corrupt`. See the comment at that call for when
/// this stops holding.
///
/// Upstream hazards this cannot catch, all in `keepass` 0.15.0:
///
/// - **KDF parameters are unbounded.** A corrupted `TransformRounds` makes
///   a KDBX3 open hang indefinitely (AES-KDF has no rounds ceiling), and an
///   implausible Argon2 memory cost aborts the process on allocation
///   failure — no unwind, so `catch_unwind` doesn't help. Random corruption
///   reaches this for KDBX3 only; KDBX4's header HMAC rejected every
///   mutation tried (robustness finding 6). In the daemon the stakes are
///   higher than in a one-shot CLI: a hung unlock keeps its core busy and
///   its file descriptor open after the client gives up, each retry stacks
///   another, and an abort ends every unlocked session at once. Rust
///   threads can't be cancelled, so a timeout here would not help either.
///   The fix is ceilings in `keepass` before the KDF runs; a header
///   pre-check in this repo is the fallback if upstream hasn't moved by
///   the time the daemon is meant to run unattended (`docs/plan.md` step 5).
/// - **KDBX3's header hash is checked here, not by `keepass`.** KDBX3
///   authenticates its outer header only through `Meta/HeaderHash` inside
///   the encrypted payload, and `keepass` 0.15 never compares it. `open`
///   verifies it (see `verify_kdbx3_header`) before returning the database,
///   so a file whose header was altered without the key is rejected rather
///   than served with wrong protected values. That check needs the KDF to
///   run twice for a KDBX3 file (once to decrypt the payload for the hash,
///   once more inside `keepass` to get the entries), so KDBX3 unlocks cost
///   about twice as much as they did.
pub fn open(
    path: &Path,
    password: Option<&Zeroizing<String>>,
    keyfile: Option<&Path>,
) -> Result<(Database, Fingerprint), VaultError> {
    let mut file = open_file(path, VaultError::NotFound)?;
    // The whole file is read here, not inside `keepass`, so the fstat calls
    // can bracket the read. The fd is closed before key derivation.
    let before = Fingerprint::from_metadata(&file.metadata()?);
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let after = Fingerprint::from_metadata(&file.metadata()?);
    drop(file);
    if !before.matches(after) {
        return Err(VaultError::Changed);
    }

    // A fresh key per use: `DatabaseKey` is consumed by each parse, and the
    // KDBX3 check below parses the same file a second time.
    let make_key = || -> Result<DatabaseKey, VaultError> {
        let mut key = DatabaseKey::new();
        if let Some(password) = password {
            key = key.with_password(password);
        }
        if let Some(keyfile_path) = keyfile {
            let mut keyfile_handle = open_file(keyfile_path, VaultError::KeyfileNotFound)?;
            // io::Error here (e.g. a permissions error mid-read) maps to
            // VaultError::Io via the #[from] impl above.
            //
            // Upstream leak: `keepass` zeroizes its own copy of the raw keyfile,
            // but its XML keyfile parser makes about six unzeroized
            // intermediate copies of the key material, which together cover
            // the whole 32-byte key and survive a lock
            // (`docs/review-2026-09-secrets.md` finding 2). Pre-parsing the
            // keyfile here would remove most of those at the cost of
            // duplicating `keepass`'s format detection; the fix belongs
            // upstream.
            key = key.with_keyfile(&mut keyfile_handle)?;
        }
        Ok(key)
    };

    let version =
        DatabaseVersion::parse(&data).map_err(|err| VaultError::Corrupt(err.to_string()))?;
    if let DatabaseVersion::KDB3(_) = version {
        verify_kdbx3_header(&data, make_key()?)?;
    }

    // Sound because `Database::open` touches no state shared with anything
    // else — it reads `data` and consumes `key` — so nothing is left half
    // updated if it unwinds, and `DatabaseKey`'s `ZeroizeOnDrop` still runs
    // during the unwind. The panic payload is dropped rather than put in
    // the error: it's `keepass`'s text, which is never forwarded (see
    // `VaultError::Corrupt`).
    //
    // This only works while panics unwind. Setting `panic = "abort"` in a
    // Cargo profile silently turns every one of these back into a process
    // abort that takes all unlocked databases with it.
    let key = make_key()?;
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        Database::open(&mut Cursor::new(&data), key)
    }))
    .map_err(|_| VaultError::Corrupt("keepass panicked while parsing".to_string()))?
    .map(|db| (db, before))
    .map_err(VaultError::from)
}

/// Checks a KDBX3 file's `Meta/HeaderHash` against the outer header bytes as
/// they sit in the file (from offset 0 through the end-of-header entry, not
/// a re-serialization). The hash is stored inside the encrypted payload, so
/// the payload has to be decrypted first. The check is the gate: nothing
/// from the decrypted file is served unless it returns `Ok`.
fn verify_kdbx3_header(data: &[u8], key: DatabaseKey) -> Result<(), VaultError> {
    let header_len = kdbx3_outer_header_len(data)
        .ok_or_else(|| VaultError::Corrupt("KDBX3 outer header is truncated".to_string()))?;

    let xml = std::panic::catch_unwind(AssertUnwindSafe(|| {
        Database::get_xml(&mut Cursor::new(data), key)
    }))
    .map_err(|_| VaultError::Corrupt("keepass panicked while parsing".to_string()))?
    .map_err(VaultError::from)?;
    let xml = Zeroizing::new(xml);

    let stored = kdbx3_header_hash(&xml)
        .ok_or_else(|| VaultError::Corrupt("KDBX3 file has no header hash".to_string()))?;
    let actual = Sha256::digest(&data[..header_len]);
    if stored.as_slice() != actual.as_slice() {
        return Err(VaultError::Corrupt(
            "KDBX3 header hash mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Byte length of a KDBX3 outer header: the 12-byte version header, then
/// `(type: u8, len: u16 LE, data)` entries up to and including the
/// end-of-header entry (type 0). `None` if an entry runs past the end of
/// the file.
fn kdbx3_outer_header_len(data: &[u8]) -> Option<usize> {
    const VERSION_HEADER_LEN: usize = 12;
    let mut pos = VERSION_HEADER_LEN;
    loop {
        let entry_type = *data.get(pos)?;
        let entry_len = u16::from_le_bytes([*data.get(pos + 1)?, *data.get(pos + 2)?]) as usize;
        let end = pos.checked_add(3 + entry_len)?;
        if end > data.len() {
            return None;
        }
        if entry_type == 0 {
            return Some(end);
        }
        pos = end;
    }
}

/// The decoded `Meta/HeaderHash` value from a decrypted KDBX3 payload, or
/// `None` if it is absent or not valid base64. Only the first `<Meta>`
/// block is searched, so a same-named element elsewhere in the document
/// is ignored.
fn kdbx3_header_hash(xml: &[u8]) -> Option<Vec<u8>> {
    let meta = between(xml, b"<Meta>", b"</Meta>")?;
    let encoded = between(meta, b"<HeaderHash>", b"</HeaderHash>")?;
    let encoded = std::str::from_utf8(encoded).ok()?.trim();
    STANDARD.decode(encoded).ok()
}

/// The bytes strictly between the first `open` and the next `close` after
/// it.
fn between<'a>(haystack: &'a [u8], open: &[u8], close: &[u8]) -> Option<&'a [u8]> {
    let start = haystack.windows(open.len()).position(|w| w == open)? + open.len();
    let rest = &haystack[start..];
    let len = rest.windows(close.len()).position(|w| w == close)?;
    Some(&rest[..len])
}

/// `File::open` with the not-found case mapped to a caller-supplied
/// `VaultError` variant, so the same helper serves both the database path
/// and the keyfile path with different error variants.
fn open_file(
    path: &Path,
    not_found: impl FnOnce(PathBuf) -> VaultError,
) -> Result<File, VaultError> {
    File::open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            not_found(path.to_path_buf())
        } else {
            VaultError::Io(err)
        }
    })
}

/// List every entry in the database, recursing into all groups. Always
/// returns everything — no filtering — matching "kpa stays dumb and returns
/// everything" from `docs/design.md` § Protocol.
pub fn list_entries(db: &Database) -> Vec<EntrySummary> {
    let mut out = Vec::new();
    collect_entries(db, &mut out);
    out
}

/// How many entries the database holds, across every group. Walks the
/// tree the same way `collect_entries` does but copies nothing out of it —
/// `status` only needs the number, so it has no reason to make a copy of
/// every title, username and URL just to call `.len()` on them.
pub fn entry_count(db: &Database) -> usize {
    let mut count = 0;
    let mut stack = vec![db.root().id()];
    while let Some(id) = stack.pop() {
        let Some(group) = db.group(id) else {
            continue;
        };
        count += group.entries().count();
        stack.extend(group.groups().map(|child| child.id()));
    }
    count
}

/// One attachment on a current entry, borrowed from the open database:
/// outside the recycle bin, and the entry's live version, never a
/// historical one. Borrowed rather than copied, so a private key in it is
/// never left behind in a buffer nobody wipes. No `Debug`, for the same
/// reason.
#[derive(Clone, Copy)]
pub struct AttachmentView<'a> {
    pub entry_uuid: Uuid,
    /// The entry's title, under the same protectedness rule as `list`'s own
    /// `title` (`unprotected_field`) — `None` if it is absent, empty, or
    /// marked protected.
    pub entry_title: Option<&'a str>,
    /// The name under which the entry stores this attachment (KeePass's
    /// "filename").
    pub name: &'a str,
    pub data: &'a [u8],
}

/// Shows `visit` every attachment on every current entry, database-wide:
/// no history, and nothing in the recycle bin. Entries come in tree order:
/// a group's own entries in their stored order, then each of its groups in
/// turn, the same way. Used by the SSH agent's key discovery
/// (`ssh::keys::scan`), which only ever looks at what a database's
/// current entries hold (`docs/ssh-agent.md` § 6.4).
pub fn for_each_attachment(db: &Database, mut visit: impl FnMut(AttachmentView<'_>)) {
    for_each_current_entry(db, |entry| visit_attachments(entry, &mut visit));
}

/// Like [`for_each_attachment`], for the one current entry `uuid` only
/// ([`current_entry`]), without visiting any other entry. Visits nothing
/// if there is no such entry, or if it is in the recycle bin.
pub fn for_each_entry_attachment(
    db: &Database,
    uuid: Uuid,
    mut visit: impl FnMut(AttachmentView<'_>),
) {
    if let Some(entry) = current_entry(db, uuid) {
        visit_attachments(&entry, &mut visit);
    }
}

/// The entry `uuid`, looked up directly rather than by walking the tree.
/// The database's entries are its live ones only: never a historical
/// revision. Entries in the recycle bin are included.
fn entry_by_uuid(db: &Database, uuid: Uuid) -> Option<keepass::db::EntryRef<'_>> {
    db.entry(keepass::db::EntryId::from_uuid(uuid))
}

/// [`entry_by_uuid`], unless the entry is in the recycle bin: one of its
/// ancestors, walked up to the root, is the recycle bin group. Iterative,
/// and stops at a group it has already seen, so a malformed parent chain
/// can't loop.
fn current_entry(db: &Database, uuid: Uuid) -> Option<keepass::db::EntryRef<'_>> {
    let entry = entry_by_uuid(db, uuid)?;
    let Some(recycle_bin) = db.recycle_bin().map(|group| group.id()) else {
        return Some(entry);
    };
    let mut seen = std::collections::HashSet::new();
    let mut group = Some(entry.parent().id());
    while let Some(id) = group {
        if id == recycle_bin {
            return None;
        }
        if !seen.insert(id) {
            break;
        }
        group = db
            .group(id)
            .and_then(|group| group.parent().map(|parent| parent.id()));
    }
    Some(entry)
}

fn visit_attachments(
    entry: &keepass::db::EntryRef<'_>,
    visit: &mut impl FnMut(AttachmentView<'_>),
) {
    use keepass::db::fields;

    let entry_title = unprotected_field(entry, fields::TITLE).filter(|t| !t.is_empty());
    for (name, attachment) in entry.attachments_named() {
        visit(AttachmentView {
            entry_uuid: entry.id().uuid(),
            entry_title,
            name,
            data: attachment.get(),
        });
    }
}

/// Visits every entry outside the recycle bin, in tree order. An explicit
/// worklist like `collect_entries`'s, with each group's children pushed in
/// reverse so the first one is visited first. The recycle bin's subtree is
/// skipped whole rather than filtered entry by entry: a group only ever
/// has one parent, so this can't miss a path into it that isn't through
/// its own id.
fn for_each_current_entry(db: &Database, mut visit: impl FnMut(&keepass::db::EntryRef<'_>)) {
    let recycle_bin = db.recycle_bin().map(|group| group.id());
    let mut stack = vec![db.root().id()];
    while let Some(id) = stack.pop() {
        if Some(id) == recycle_bin {
            continue;
        }
        let Some(group) = db.group(id) else {
            continue;
        };
        for entry in group.entries() {
            visit(&entry);
        }
        let children: Vec<_> = group.groups().map(|child| child.id()).collect();
        stack.extend(children.into_iter().rev());
    }
}

/// A field's value, unless the user marked it protected in their KeePass
/// client — a protected field is treated as absent, not de-protected. The
/// `keepass` convenience getters (`get_title`, etc.) don't make this
/// distinction: they call through to `Value::get()`, which exposes a
/// protected value the same as an unprotected one.
fn unprotected_field<'a>(entry: &'a keepass::db::Entry, key: &str) -> Option<&'a str> {
    match entry.fields.get(key)? {
        v if v.is_protected() => None,
        v => Some(v.get().as_str()),
    }
}

/// Look up one entry by uuid and read one field's raw value off it — even
/// if the user marked that field protected in their KeePass client.
///
/// This is deliberately different from `unprotected_field`: that one exists
/// because `list` is an index dump, where "protected" has to mean "omit it"
/// or protection would be pointless. `copy` is not a dump — it's a request
/// for exactly one named field of exactly one named entry, which the caller
/// already identified by uuid. There is nothing left for protection to
/// guard against here that the request itself didn't already ask for, so
/// `copy` reads straight through `Value::get()` instead of filtering
/// through `unprotected_field`.
///
/// Returns `None` if no entry with that uuid exists. Returns `Some(None)`
/// if the entry exists but the field is absent or empty — both count as
/// nothing to copy. Same explicit-worklist traversal as
/// `collect_entries`/`entry_count`, for the same reason: a deeply nested
/// `.kdbx` must not recurse.
pub fn entry_field(db: &Database, uuid: Uuid, key: &str) -> Option<Option<Zeroizing<String>>> {
    with_entry(db, uuid, |entry| {
        entry
            .fields
            .get(key)
            .map(|v| v.get().as_str())
            .filter(|s| !s.is_empty())
            .map(|s| Zeroizing::new(s.to_string()))
    })
}

/// Whether an entry with this uuid exists, regardless of its fields.
/// `copy`'s bare `title` request needs exactly this and nothing more: it
/// never resolves to any field (`proto::copy::Field::ReservedTitle`), but
/// still has to distinguish `UnknownUuid` from `FieldEmpty`.
pub fn entry_exists(db: &Database, uuid: Uuid) -> bool {
    with_entry(db, uuid, |_| ()).is_some()
}

/// The current code for this entry's `otp` field, generated now — the
/// field itself only ever holds the seed (an `otpauth://` URL), and kpa
/// never returns that, logs it, or holds it longer than this call needs
/// to. `None` if no entry with this uuid exists; `Some(None)` if it exists
/// but has no `otp` field, the field doesn't parse as a valid `otpauth://`
/// URL, or the system clock can't be read — `copy` reports all of these
/// the same as any other field with nothing to give (`FieldEmpty`), never
/// the parse error, which could otherwise echo back raw seed bytes.
///
/// Only the de-facto-standard `otp` field (`keepass`'s `fields::OTP`) is
/// read. The legacy KeeOtp `TimeOtp-Seed`/`-Length`/`-Period` fields are
/// a different, older convention that `keepass` 0.15's `totp` feature
/// does not parse, so supporting them would mean hand-rolling that format
/// here — out of scope for what "the crate's own feature, read-only"
/// promises.
pub fn entry_totp(db: &Database, uuid: Uuid) -> Option<Option<Zeroizing<String>>> {
    with_entry(db, uuid, |entry| {
        entry
            .get_otp()
            .ok()
            .and_then(|totp| totp.value_now().ok())
            .map(|code| Zeroizing::new(code.code))
    })
}

/// The entry's title, for naming it in the operation log. `None` if there
/// is no such entry, it has no title, or the title is protected: a log line
/// must not de-protect a field the user marked protected (same rule as
/// `unprotected_field`).
pub fn entry_title(db: &Database, uuid: Uuid) -> Option<String> {
    use keepass::db::fields;

    with_entry(db, uuid, |entry| {
        unprotected_field(entry, fields::TITLE)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
    })
    .flatten()
}

/// Find the entry with `uuid` and run `read` on it. A direct lookup
/// ([`entry_by_uuid`]), so it neither walks the tree nor depends on its
/// depth. An entry in the recycle bin is found like any other, for
/// `copy` and the operation log alike.
fn with_entry<R>(
    db: &Database,
    uuid: Uuid,
    read: impl FnOnce(&keepass::db::Entry) -> R,
) -> Option<R> {
    entry_by_uuid(db, uuid).map(|entry| read(&entry))
}

fn collect_entries(db: &Database, out: &mut Vec<EntrySummary>) {
    use keepass::db::fields;

    // Explicit worklist over group ids, rather than recursion or a stack of
    // borrowed `GroupRef`s: a `.kdbx` with a deep enough group nesting can
    // otherwise overflow the stack and abort the process (verified down to
    // a 2 MiB thread stack — see `docs/review-2026-09.md` finding 5). Ids
    // rather than `GroupRef`s because `GroupRef::groups()` ties its
    // children's lifetime to the parent `GroupRef`'s own borrow, which
    // doesn't outlive one loop iteration; going back through `Database::group`
    // re-borrows from `db` itself instead. This changes traversal from
    // depth-first-preorder to pop-order, which doesn't matter today (`list`
    // is an unordered index) — if order ever matters to a client, push
    // children in reverse.
    let mut stack = vec![db.root().id()];
    while let Some(id) = stack.pop() {
        let Some(group) = db.group(id) else {
            continue;
        };

        for entry in group.entries() {
            out.push(EntrySummary {
                uuid: entry.id().uuid(),
                title: unprotected_field(&entry, fields::TITLE).map(str::to_owned),
                username: unprotected_field(&entry, fields::USERNAME).map(str::to_owned),
                url: unprotected_field(&entry, fields::URL).map(str::to_owned),
                group: group.name.clone(),
                fields: copyable_field_names(&entry),
            });
        }
        stack.extend(group.groups().map(|child| child.id()));
    }
}

/// Exact KeePass key spellings that are never "custom": the four built-ins
/// `copy` supports, `otp`, and `Title` — kpa never makes `Title` copyable
/// itself, but it is still KeePass's own reserved key, not a user-defined
/// one. Exact-case: a differently-cased key (e.g. a custom `USERNAME`) is
/// a distinct `HashMap` entry and *is* a custom field — see
/// `copyable_field_names`.
const RESERVED_ENTRY_KEYS: [&str; 6] = [
    keepass::db::fields::TITLE,
    keepass::db::fields::USERNAME,
    keepass::db::fields::PASSWORD,
    keepass::db::fields::URL,
    keepass::db::fields::NOTES,
    keepass::db::fields::OTP,
];

/// Field names `copy` can be asked for on this entry — never values.
/// Built-ins in the fixed order `docs/design.md` § Protocol documents
/// (`username`, `password`, `url`, `notes`, `totp`), each listed only when
/// present and non-empty; then this entry's custom (user-defined) string
/// fields, by their KeePass key, `custom:`-prefixed exactly when that key
/// collides case-insensitively with a built-in name or with `title`
/// (the collision rule — also implemented, independently, by
/// `proto::copy::Field`'s own encode/decode, which this must stay
/// consistent with).
///
/// `keepass`'s `Entry::fields` is an unordered `HashMap`
/// (`db/types/entry.rs`), so the database's own field order is not
/// recoverable here; custom keys are sorted instead, which is at least
/// deterministic.
///
/// Protectedness never hides a field's *name* here, unlike `list`'s own
/// `title`/`username`/`url`: this reads straight through `Value::get()`,
/// the same as `entry_field` does for `copy` — a bare name carries nothing
/// a protected value does. `totp` is listed whenever the `otp` field is
/// present and non-empty, regardless of whether it actually parses as a
/// valid `otpauth://` URL — `entry_totp` is what validates that, at copy
/// time.
fn copyable_field_names(entry: &keepass::db::Entry) -> Vec<String> {
    use keepass::db::fields;

    let has_value = |key: &str| entry.fields.get(key).is_some_and(|v| !v.get().is_empty());

    let mut names: Vec<String> = [
        ("username", fields::USERNAME),
        ("password", fields::PASSWORD),
        ("url", fields::URL),
        ("notes", fields::NOTES),
        ("totp", fields::OTP),
    ]
    .into_iter()
    .filter(|(_, key)| has_value(key))
    .map(|(name, _)| name.to_string())
    .collect();

    let mut custom: Vec<&String> = entry
        .fields
        .iter()
        .filter(|(key, value)| {
            !RESERVED_ENTRY_KEYS.contains(&key.as_str()) && !value.get().is_empty()
        })
        .map(|(key, _)| key)
        .collect();
    custom.sort();

    names.extend(custom.into_iter().map(|key| custom_field_wire_name(key)));
    names
}

/// Whether `key` collides, case-insensitively, with a name
/// `docs/design.md` § Protocol reserves on the wire — the five built-ins
/// `copyable_field_names` lists plus `title`. Kept in lockstep with
/// `proto::copy::Field`'s own `RESERVED_NAMES`: that one decides what a
/// *request* means, this one decides how a *listed* custom key is spelled,
/// and they have to agree or a name `list` prints would not be the one
/// `copy` resolves back to the same field.
fn collides_with_a_reserved_name(key: &str) -> bool {
    ["username", "password", "url", "notes", "totp", "title"]
        .iter()
        .any(|reserved| key.eq_ignore_ascii_case(reserved))
}

/// The wire name for a custom field keyed `key`: the bare key itself,
/// unless it collides case-insensitively with a reserved name, in which
/// case it is prefixed `custom:` so a bare request for that spelling still
/// means the built-in (or, for `title`, means nothing copyable at all).
fn custom_field_wire_name(key: &str) -> String {
    if collides_with_a_reserved_name(key) {
        format!("custom:{key}")
    } else {
        key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use keepass::Database;
    use keepass::db::{Value, fields};
    use uuid::Uuid;

    use super::{
        entry_count, entry_exists, entry_field, entry_title, entry_totp, for_each_attachment,
        for_each_entry_attachment, list_entries,
    };

    /// `entry_count` must agree with `list_entries` everywhere, including
    /// in nested groups and when fields are protected — it's what `status`
    /// reports, so a disagreement would show up as a wrong count.
    #[test]
    fn entry_count_matches_list_entries() {
        let mut db = Database::new();
        assert_eq!(entry_count(&db), 0);

        {
            let mut root = db.root_mut();
            root.add_entry().set_unprotected(fields::TITLE, "top");
            let mut child = root.add_group();
            child.add_entry().set_protected(fields::TITLE, "hidden");
            child
                .add_group()
                .add_entry()
                .set_unprotected(fields::TITLE, "deep");
        }

        assert_eq!(entry_count(&db), 3);
        assert_eq!(entry_count(&db), list_entries(&db).len());
    }

    /// The title that names an entry in the operation log is found at any
    /// depth, and a protected one is never returned.
    #[test]
    fn entry_title_reads_unprotected_titles_only() {
        let mut db = Database::new();
        let (open, hidden, untitled);
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "top");
            open = e.id().uuid();
            let mut child = root.add_group();
            untitled = child.add_entry().id().uuid();
            let mut deep = child.add_group();
            let mut e = deep.add_entry();
            e.set_protected(fields::TITLE, "SECRET-TITLE");
            hidden = e.id().uuid();
        }

        assert_eq!(entry_title(&db, open).as_deref(), Some("top"));
        assert_eq!(entry_title(&db, hidden), None);
        assert_eq!(entry_title(&db, untitled), None);
        assert_eq!(entry_title(&db, Uuid::new_v4()), None);
    }

    /// Regression for `docs/review-2026-09.md` finding 1: a field the user
    /// marked protected must not come back as plaintext from `list`, for
    /// any of the fields `list` surfaces, not just `Password`. Built
    /// in-process — this needs no fixture file.
    #[test]
    fn list_omits_protected_fields() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_protected(fields::TITLE, "SECRET-TITLE");
            entry.set_protected(fields::USERNAME, "SECRET-USERNAME");
            entry.set_protected(fields::URL, "SECRET-URL");
        }

        let entries = list_entries(&db);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, None);
        assert_eq!(entries[0].username, None);
        assert_eq!(entries[0].url, None);
    }

    /// Regression for `docs/review-2026-09.md` finding 5: `collect_entries`
    /// used to recurse once per group nesting level, which overflowed and
    /// aborted the process well before this depth on a 2 MiB thread stack.
    /// Built in-process — this needs no fixture file, and fails loudly
    /// (abort) rather than merely failing an assertion on regression.
    #[test]
    fn list_survives_deeply_nested_groups() {
        let mut db = Database::new();
        // Looked up by id and re-borrowed each iteration, rather than
        // reassigning a `GroupMut` cursor directly — `Database::group_mut`
        // (unlike `GroupMut::add_group`) hands back a borrow of `db`
        // itself, not of the previous iteration's temporary, so this loop
        // doesn't fight the borrow checker.
        let mut id = db.root().id();
        for _ in 0..100_000 {
            let mut group = db.group_mut(id).expect("just-created group must exist");
            id = group.add_group().id();
        }
        db.group_mut(id)
            .expect("just-created group must exist")
            .add_entry()
            .set_unprotected(fields::TITLE, "deep");

        let entries = list_entries(&db);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title.as_deref(), Some("deep"));
    }

    /// `entry_field` reads a protected field through, unlike
    /// `unprotected_field` — this is the whole reason `copy` has its own
    /// lookup rather than reusing `list`'s.
    #[test]
    fn entry_field_reads_through_protection() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.id().uuid()
        };

        assert_eq!(
            entry_field(&db, uuid, fields::PASSWORD)
                .expect("entry exists")
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
    }

    /// An unknown uuid is `None`, distinct from a known entry with an
    /// absent field — `control` maps these to different wire errors.
    #[test]
    fn entry_field_distinguishes_unknown_uuid_from_empty_field() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            root.add_entry().set_unprotected(fields::TITLE, "top");
            db.root().entries().next().expect("one entry").id().uuid()
        };

        assert_eq!(entry_field(&db, Uuid::new_v4(), fields::PASSWORD), None);
        assert_eq!(entry_field(&db, uuid, fields::PASSWORD), Some(None));
    }

    /// A field set to the empty string counts the same as absent — there is
    /// nothing to copy either way.
    #[test]
    fn entry_field_treats_an_empty_value_as_absent() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::URL, "");
            entry.id().uuid()
        };

        assert_eq!(entry_field(&db, uuid, fields::URL), Some(None));
    }

    /// Nested groups, same stack-based traversal as `collect_entries` — so
    /// this doesn't overflow on a deeply nested tree either.
    #[test]
    fn entry_field_finds_entries_in_nested_groups() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut child = root.add_group();
            let mut entry = child.add_entry();
            entry.set_unprotected(fields::NOTES, "deep notes");
            entry.id().uuid()
        };

        assert_eq!(
            entry_field(&db, uuid, fields::NOTES)
                .expect("entry exists")
                .as_deref()
                .map(String::as_str),
            Some("deep notes")
        );
    }

    /// `entry_exists` distinguishes a real uuid from a made-up one,
    /// independent of what fields that entry has.
    #[test]
    fn entry_exists_checks_only_the_uuid() {
        let mut db = Database::new();
        let uuid = db.root_mut().add_entry().id().uuid();

        assert!(entry_exists(&db, uuid));
        assert!(!entry_exists(&db, Uuid::new_v4()));
    }

    /// Built-ins appear in the fixed, documented order, and only when
    /// present and non-empty — an absent or empty one is skipped, not
    /// listed with nothing to copy.
    #[test]
    fn copyable_fields_lists_present_builtins_in_order() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::URL, "https://example.com");
            entry.set_unprotected(fields::USERNAME, "alice");
            entry.set_unprotected(fields::PASSWORD, "hunter2");
            entry.set_unprotected(fields::NOTES, "");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert_eq!(entry.fields, vec!["username", "password", "url"]);
    }

    /// A protected built-in's *name* still appears — only `list`'s own
    /// `title`/`username`/`url` values stay filtered by protection, not
    /// `fields`.
    #[test]
    fn copyable_fields_includes_protected_builtins_by_name() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert_eq!(entry.fields, vec!["password"]);
    }

    /// Custom fields are listed by their key, sorted (since `keepass`
    /// stores them in an unordered `HashMap`), after every built-in.
    #[test]
    fn copyable_fields_lists_custom_keys_sorted_after_builtins() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::USERNAME, "alice");
            entry.set_unprotected("zeta", "z");
            entry.set_unprotected("api-key", "k");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert_eq!(entry.fields, vec!["username", "api-key", "zeta"]);
    }

    /// A custom field keyed the same as a built-in, only in a different
    /// case, is a distinct, genuine field (`keepass`'s keys are
    /// exact-case) — and is listed `custom:`-prefixed, per the collision
    /// rule, so a bare `password` on the wire still means the built-in.
    #[test]
    fn a_custom_field_colliding_with_a_builtin_is_prefixed() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::PASSWORD, "hunter2");
            // Not `fields::PASSWORD` ("Password") — a differently-cased,
            // genuinely distinct key.
            entry.set_unprotected("PASSWORD", "also a secret");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert_eq!(entry.fields, vec!["password", "custom:PASSWORD"]);
    }

    /// An empty custom value is skipped, same rule as the built-ins.
    #[test]
    fn copyable_fields_skips_empty_custom_values() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected("empty", "");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert!(entry.fields.is_empty());
    }

    /// `totp` is listed as copyable only when the `otp` field is present
    /// and non-empty — `copyable_field_names` doesn't itself validate that
    /// it parses (that's `entry_totp`'s job, at copy time).
    #[test]
    fn copyable_fields_lists_totp_when_otp_is_present() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::OTP, "otpauth://totp/x?secret=ABC");
            entry.id().uuid()
        };

        let entries = list_entries(&db);
        let entry = entries.iter().find(|e| e.uuid == uuid).expect("entry");
        assert_eq!(entry.fields, vec!["totp"]);
    }

    /// `entry_totp` generates the current code from a valid `otpauth://`
    /// seed, deterministically for a fixed time — the `keepass` crate's
    /// own test vector (`db/otp.rs`), reused here against kpa's own entry
    /// lookup rather than `keepass`'s `TOTP` type directly.
    #[test]
    fn entry_totp_generates_a_code_from_a_valid_otp_field() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(
                fields::OTP,
                "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC",
            );
            entry.id().uuid()
        };

        let code = entry_totp(&db, uuid)
            .expect("entry exists")
            .expect("a valid otp field should produce a code");
        assert_eq!(code.len(), 6, "expected a 6-digit code, got {code:?}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    /// An entry with no `otp` field, or one that doesn't parse as a valid
    /// `otpauth://` URL, has nothing to copy — not an error that could
    /// echo the bad value back.
    #[test]
    fn entry_totp_is_absent_without_a_valid_otp_field() {
        let mut db = Database::new();
        let (no_field, bad_field) = {
            let mut root = db.root_mut();
            let no_field = root.add_entry().id().uuid();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::OTP, "not an otpauth url");
            (no_field, entry.id().uuid())
        };

        assert_eq!(entry_totp(&db, no_field), Some(None));
        assert_eq!(entry_totp(&db, bad_field), Some(None));
        assert_eq!(entry_totp(&db, Uuid::new_v4()), None);
    }

    /// What `for_each_attachment` shows, owned for comparing: entry uuid,
    /// entry title, attachment name and data.
    type Seen = (Uuid, Option<String>, String, Vec<u8>);

    fn attachments(db: &Database) -> Vec<Seen> {
        let mut seen = Vec::new();
        for_each_attachment(db, |a| {
            seen.push((
                a.entry_uuid,
                a.entry_title.map(str::to_owned),
                a.name.to_string(),
                a.data.to_vec(),
            ));
        });
        seen
    }

    fn names(seen: &[Seen]) -> Vec<&str> {
        seen.iter().map(|(_, _, name, _)| name.as_str()).collect()
    }

    /// The basic case: one entry, one attachment, found with its name, its
    /// data, and its entry's title.
    #[test]
    fn for_each_attachment_finds_a_current_attachment() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Example");
            entry.add_attachment("key.pub", Value::unprotected(b"ATTACHMENT".to_vec()));
            entry.id().uuid()
        };

        let seen = attachments(&db);
        assert_eq!(
            seen,
            [(
                uuid,
                Some("Example".to_string()),
                "key.pub".to_string(),
                b"ATTACHMENT".to_vec()
            )]
        );
    }

    /// Only the named entry's attachments, and nothing for an unknown uuid.
    #[test]
    fn for_each_entry_attachment_reads_one_current_entry() {
        let mut db = Database::new();
        let (wanted, other) = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "wanted");
            entry.add_attachment("a.key", Value::unprotected(b"A".to_vec()));
            entry.add_attachment("b.key", Value::unprotected(b"B".to_vec()));
            let wanted = entry.id().uuid();
            let mut other = root.add_entry();
            other.add_attachment("c.key", Value::unprotected(b"C".to_vec()));
            (wanted, other.id().uuid())
        };

        let entry_names = |uuid| {
            let mut names = Vec::new();
            for_each_entry_attachment(&db, uuid, |a| names.push(a.name.to_string()));
            names.sort();
            names
        };

        assert_eq!(entry_names(wanted), ["a.key", "b.key"]);
        assert_eq!(entry_names(other), ["c.key"]);
        assert!(entry_names(Uuid::new_v4()).is_empty());
    }

    /// An entry in the recycle bin, however deep, has no attachments to
    /// visit, though `with_entry`'s readers still find it.
    #[test]
    fn for_each_entry_attachment_skips_an_entry_in_the_recycle_bin() {
        let mut db = Database::new();
        let (entry_id, bin_id) = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            let bin_id = bin.id();
            let mut nested = bin.add_group();
            let mut entry = nested.add_entry();
            entry.set_unprotected(fields::TITLE, "recycled");
            entry.add_attachment("bin.key", Value::unprotected(b"BIN".to_vec()));
            (entry.id(), bin_id)
        };
        let mut seen = 0;
        for_each_entry_attachment(&db, entry_id.uuid(), |_| seen += 1);
        assert_eq!(seen, 1, "sanity: visited before it's the recycle bin");

        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        let mut seen = 0;
        for_each_entry_attachment(&db, entry_id.uuid(), |_| seen += 1);
        assert_eq!(seen, 0);
        assert_eq!(
            entry_title(&db, entry_id.uuid()).as_deref(),
            Some("recycled")
        );
    }

    /// Nested groups, and an entry with no title (protected or absent) —
    /// `entry_title` comes back `None` rather than panicking.
    #[test]
    fn for_each_attachment_walks_nested_groups_and_tolerates_a_titleless_entry() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut child = root.add_group();
            let mut entry = child.add_entry();
            entry.set_protected(fields::TITLE, "SECRET-TITLE");
            entry.add_attachment("deep.key", Value::unprotected(b"DEEP".to_vec()));
        }

        let seen = attachments(&db);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, None);
        assert_eq!(seen[0].2, "deep.key");
    }

    /// Entries come in tree order: a group's own entries, then each of its
    /// groups in turn, depth first, in their stored order.
    #[test]
    fn for_each_attachment_visits_in_tree_order() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.add_entry()
                .add_attachment("root", Value::unprotected(b"0".to_vec()));
            let mut first = root.add_group();
            first
                .add_entry()
                .add_attachment("first", Value::unprotected(b"1".to_vec()));
            first
                .add_group()
                .add_entry()
                .add_attachment("first/nested", Value::unprotected(b"2".to_vec()));
            root.add_group()
                .add_entry()
                .add_attachment("second", Value::unprotected(b"3".to_vec()));
        }

        assert_eq!(
            names(&attachments(&db)),
            ["root", "first", "first/nested", "second"]
        );
    }

    /// An attachment that exists only on a historical revision of an
    /// entry — never on its current one — is invisible, since only current
    /// entries are visited.
    #[test]
    fn for_each_attachment_ignores_history() {
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "historical");
            entry.add_attachment("old.key", Value::unprotected(b"OLD".to_vec()));
            entry.id()
        };

        // Snapshots the attachment into history, then removes it from the
        // live entry — the only remaining copy is historical.
        db.entry_mut(id)
            .expect("just-created entry must exist")
            .edit_tracking(|e| {
                e.as_mut().remove_attachment_by_name("old.key");
            });

        assert!(
            db.entry(id)
                .expect("entry still exists")
                .history
                .as_ref()
                .is_some_and(|h| !h.get_entries().is_empty()),
            "the attachment should have been pushed into history"
        );
        assert!(attachments(&db).is_empty());
    }

    /// An entry moved into the recycle bin is skipped, along with its
    /// attachment.
    #[test]
    fn for_each_attachment_ignores_the_recycle_bin() {
        let mut db = Database::new();
        let (entry_id, bin_id) = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "recycled");
            entry.add_attachment("bin.key", Value::unprotected(b"BIN".to_vec()));
            let entry_id = entry.id();
            let bin_id = root.add_group().id();
            (entry_id, bin_id)
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        db.entry_mut(entry_id)
            .expect("just-created entry must exist")
            .move_to(bin_id)
            .expect("the recycle bin group exists");

        assert!(attachments(&db).is_empty());
    }
}
