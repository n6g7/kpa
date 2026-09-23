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

    /// Password and/or keyfile didn't decrypt the database. `keepass`
    /// itself can't tell a wrong password from a wrong keyfile apart —
    /// both feed the same key-derivation step — so neither can we.
    #[error("wrong password or keyfile")]
    WrongCredentials,

    /// The file was readable but isn't a valid (or isn't a supported)
    /// KeePass database: truncated, garbage bytes, unsupported version,
    /// bad checksum, etc.
    #[error("database file is malformed or corrupt: {0}")]
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
/// an index, never a secret dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySummary {
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
pub fn open(
    path: &Path,
    password: Option<&str>,
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
    collect_entries(db.root(), &mut out);
    out
}

fn collect_entries(group: keepass::db::GroupRef<'_>, out: &mut Vec<EntrySummary>) {
    for entry in group.entries() {
        out.push(EntrySummary {
            uuid: entry.id().uuid(),
            title: entry.get_title().map(str::to_owned),
            username: entry.get_username().map(str::to_owned),
            url: entry.get_url().map(str::to_owned),
            group: group.name.clone(),
        });
    }

    for child in group.groups() {
        collect_entries(child, out);
    }
}
