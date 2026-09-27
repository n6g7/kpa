//! Thin wrapper around the `keepass` crate.
//!
//! Kept deliberately dumb: open a `.kdbx` given a password and/or keyfile,
//! and list what's in it. No caching, no freshness guard, no locking — all
//! of that is daemon state that belongs in a later step (`vault.rs` grows a
//! `Vault` struct with that state once `server.rs` exists). For now this
//! module just proves `keepass` can actually open real databases and gives
//! `probe` something to call.
//!
//! Every field/method name below was checked against the vendored source
//! for `keepass` 0.15.0 (`~/.cargo/registry/src/*/keepass-0.15.0/src/`)
//! rather than assumed from memory: `with_password`/`with_keyfile` are
//! methods on `DatabaseKey`, not Cargo features — there is no feature flag
//! needed to unlock with a password or a keyfile, only `challenge_response`,
//! `totp`, `save_kdbx4` and `serialization` are real feature names, and v1
//! needs none of them.

use std::fs::File;
use std::path::{Path, PathBuf};

use keepass::db::DatabaseOpenError;
use keepass::error::{CryptographyError, DatabaseKeyError};
use keepass::{Database, DatabaseKey};
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
/// caller bug — `probe`'s CLI always supplies a password).
///
/// `password` is `&Zeroizing<String>` rather than `&str` so callers are
/// pushed into holding the prompt result in a wiped-on-drop buffer instead
/// of a plain `String` — `&str` alone can't carry that guarantee. This
/// only covers the copy this codebase is responsible for: `rpassword`
/// accumulates the typed password in its own internal buffer first, and
/// that buffer is not zeroized by `rpassword` 7.5.4 regardless of what we
/// do with its result.
///
/// Note: a `.kdbx` with implausible KDF parameters (a corrupted
/// `TransformRounds` or Argon2 `memory` field) can make this function hang
/// indefinitely (KDBX3, AES-KDF has no rounds ceiling) or abort the process
/// via allocation failure (KDBX4, Argon2's memory cost is applied before
/// the HMAC that would otherwise reject the file) — see
/// `docs/review-2026-09.md` finding 7. Ordinary file corruption is
/// sufficient to hit this; there is no attacker required. The fix belongs
/// upstream in `keepass` (ceilings on rounds/memory/parallelism before the
/// KDF runs); revisit a partial header pre-check here only if this is hit
/// in practice.
pub fn open(
    path: &Path,
    password: Option<&Zeroizing<String>>,
    keyfile: Option<&Path>,
) -> Result<Database, VaultError> {
    let mut file = open_file(path, VaultError::NotFound)?;

    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(keyfile_path) = keyfile {
        let mut keyfile_handle = open_file(keyfile_path, VaultError::KeyfileNotFound)?;
        // io::Error here (e.g. a permissions error mid-read) maps to
        // VaultError::Io via the #[from] impl above.
        key = key.with_keyfile(&mut keyfile_handle)?;
    }

    Ok(Database::open(&mut file, key)?)
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
    use keepass::db::fields;
    use keepass::Database;

    use super::list_entries;

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
