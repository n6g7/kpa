//! Thin wrapper around the `keepass` crate.
//!
//! Kept deliberately dumb: open a `.kdbx` given a password and/or keyfile,
//! and list or count what's in it. No caching, no freshness guard, no
//! locking — that is daemon state, and it lives in `server.rs`.
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
}

/// Open a `.kdbx` file with a password and/or a keyfile.
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
/// (`server.rs`). That covers the copies kpa holds; the ones it can't reach
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
) -> Result<Database, VaultError> {
    let mut file = open_file(path, VaultError::NotFound)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

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
            });
        }
        stack.extend(group.groups().map(|child| child.id()));
    }
}

#[cfg(test)]
mod tests {
    use keepass::Database;
    use keepass::db::fields;

    use super::{entry_count, list_entries};

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
}
