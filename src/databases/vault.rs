//! Thin wrapper around the `keepass` crate.
//!
//! Kept deliberately dumb: open a `.kdbx` given a password and/or keyfile.
//! No caching and no locking: that is daemon state, and it lives in
//! `databases`. The freshness fingerprint is taken here, because it has to
//! bracket the read. Reading what is inside is `entry`'s.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use keepass::config::DatabaseVersion;
use keepass::db::DatabaseOpenError;
use keepass::error::{CryptographyError, DatabaseKeyError};
use keepass::{Database, DatabaseKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::kdf::{self, KdfCeiling};

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

    /// The path is something other than a regular file: a FIFO, a device, a
    /// directory. Refused before anything is read from it.
    #[error("{0} is not a regular file")]
    NotRegular(VaultFile),

    /// The file is larger than kpa reads (see [`VaultFile::limit`]). Refused
    /// as soon as that is known, so no more than the limit is ever held.
    #[error("{} is larger than {} MiB", .0, .0.limit() >> 20)]
    TooLarge(VaultFile),
    /// The header asks for more key derivation than kpa runs: AES rounds,
    /// or Argon2 memory, lanes or work above a ceiling (`kdf`). Refused
    /// before any key derivation, which no file may be able to make hang or
    /// abort the daemon.
    #[error("key derivation above kpa's ceiling: {0}")]
    KdfAboveCeiling(KdfCeiling),

    /// The file was readable but isn't a valid (or isn't a supported)
    /// KeePass database: truncated, garbage bytes, bad checksum, etc. (a
    /// format kpa doesn't read is `UnsupportedFormat`).
    ///
    /// Deliberately content-free in `Display`: `keepass`'s own error text
    /// can embed raw bytes out of the decrypted database (e.g. its
    /// `cs_bool` deserializer echoes the offending element's text
    /// verbatim). That must never cross a process boundary, and a `detail`
    /// string on a socket client's response is never derived from file
    /// contents (`docs/protocol.md`). The original message is
    /// kept for developers via `Debug` (`{err:?}`), which nothing currently
    /// prints.
    #[error("database file is malformed or corrupt")]
    Corrupt(String),

    /// The file is a KeePass format kpa doesn't read. kpa reads KDBX3 and
    /// KDBX4 and refuses every other format `keepass` parses (see `open`).
    #[error("not a KDBX3 or KDBX4 file; kpa reads only those")]
    UnsupportedFormat,

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

/// Which of the two files `open` reads: the database, or the keyfile that
/// goes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFile {
    Database,
    Keyfile,
}

impl VaultFile {
    /// The most kpa reads of the file, in bytes. A real vault is tens of MiB
    /// at most and a keyfile a few KiB, so no honest file meets these; they
    /// are small enough that a file's writer (ACT-3) can't make the daemon
    /// hold more than a few times that: unlocking a vault at the ceiling
    /// takes about six times its size in memory at its peak.
    pub const fn limit(self) -> u64 {
        match self {
            VaultFile::Database => 128 << 20,
            VaultFile::Keyfile => 16 << 20,
        }
    }
}

impl std::fmt::Display for VaultFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VaultFile::Database => "database file",
            VaultFile::Keyfile => "keyfile",
        })
    }
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
/// (the fix is upstream).
///
/// Reads KDBX3 and KDBX4 only; any other format `keepass` can parse comes
/// back as `UnsupportedFormat` before the key is used.
///
/// Reads regular files only, a database up to [`VaultFile::limit`] and a
/// keyfile up to its own: the path is opened without blocking and checked
/// before anything is read, so a FIFO, a device or an oversized file is
/// refused (`NotRegular`, `TooLarge`) without holding the caller or memory.
///
/// **Never panics.** `keepass` indexes past the end of short header fields
/// in several places and panics on them (the fix is upstream), so the parse
/// runs under `catch_unwind` and a panic comes back as `Corrupt`. See the
/// comment at that call for when this stops holding.
///
/// The key derivation the header asks for is checked first (`kdf::check`):
/// `keepass` runs whatever AES rounds or Argon2 memory, lanes and
/// iterations it finds, and an implausible one either aborts the process on
/// allocation failure (no unwind, so `catch_unwind` doesn't help, and every
/// unlocked database goes with it) or keeps a core busy, in a thread that
/// can't be cancelled, for as long as the database's unlock claim stays
/// taken. The file's descriptor is closed before then. Above the ceilings
/// the file is refused (`KdfAboveCeiling`); within them an unlock is bounded
/// at about a minute of one core.
///
/// One more gap in `keepass` 0.15.0 that `open` closes:
///
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
    let mut file = open_regular(path, VaultFile::Database, VaultError::NotFound)?;
    // The whole file is read here, not inside `keepass`, so the fstat calls
    // can bracket the read. The fd is closed before key derivation.
    let before = Fingerprint::from_metadata(&file.metadata()?);
    let data = read_bounded(&mut file, VaultFile::Database)?;
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
            let mut keyfile_handle = open_regular(
                keyfile_path,
                VaultFile::Keyfile,
                VaultError::KeyfileNotFound,
            )?;
            // `keepass` reads a keyfile to its end whatever its size, so the
            // bounded read is done here and it is handed the bytes.
            // io::Error here (e.g. a permissions error mid-read) maps to
            // VaultError::Io via the #[from] impl above.
            let keyfile_bytes = read_bounded(&mut keyfile_handle, VaultFile::Keyfile)?;
            //
            // Upstream leak: `keepass` zeroizes its own copy of the raw keyfile,
            // but its XML keyfile parser makes about six unzeroized
            // intermediate copies of the key material, which together cover
            // the whole 32-byte key and survive a lock. Pre-parsing the
            // keyfile here would remove most of those at the cost of
            // duplicating `keepass`'s format detection; the fix belongs
            // upstream.
            key = key.with_keyfile(&mut Cursor::new(&keyfile_bytes[..]))?;
        }
        Ok(key)
    };

    // Only the formats whose header kpa authenticates are read. `keepass`
    // also parses KeePass 1.x (KDB), whose header, with the group and entry
    // counts that decide how much of the payload is read, is covered by no
    // hash or MAC: whoever can write the file could drop entries and it
    // would still open. Any other version, including one a later `keepass`
    // adds, is refused here before the key is used.
    let version =
        DatabaseVersion::parse(&data).map_err(|err| VaultError::Corrupt(err.to_string()))?;
    match version {
        DatabaseVersion::KDB3(_) | DatabaseVersion::KDB4(_) => {}
        _ => return Err(VaultError::UnsupportedFormat),
    }
    // Before any key derivation, including the one `verify_kdbx3_header`
    // runs: the parameters are the file writer's, and `keepass` runs them
    // as they stand.
    kdf::check(&data, &version).map_err(VaultError::KdfAboveCeiling)?;
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

/// Opens `path` for reading, as a regular file of at most `kind`'s limit.
/// The not-found case maps to a caller-supplied `VaultError` variant, so the
/// same helper serves both the database path and the keyfile path with
/// different error variants.
///
/// The open is non-blocking, so a FIFO at the path doesn't hold the caller
/// (and the database's unlock claim with it) until some writer turns up:
/// it opens at once, and the `fstat` that follows refuses it, as it does a
/// device or a directory. `O_NOCTTY` keeps a terminal device at the path
/// from becoming the daemon's controlling terminal, whose hangup would
/// signal it. A symlink is followed.
fn open_regular(
    path: &Path,
    kind: VaultFile,
    not_found: impl FnOnce(PathBuf) -> VaultError,
) -> Result<File, VaultError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                not_found(path.to_path_buf())
            } else {
                VaultError::Io(err)
            }
        })?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(VaultError::NotRegular(kind));
    }
    if meta.len() > kind.limit() {
        return Err(VaultError::TooLarge(kind));
    }
    Ok(file)
}

/// Reads the rest of `file`, which [`open_regular`] vetted, holding no more
/// than `kind`'s limit: the read stops one byte past it, so a file that grew
/// since the `fstat`, or lies about its size, is refused instead of read to
/// its end. The buffer starts at the file's size, so a read that doesn't
/// grow the file never reallocates (and leaves no stray copy behind), and
/// it wipes itself on every exit, a failed read included: what is read can
/// be a keyfile.
fn read_bounded(file: &mut File, kind: VaultFile) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let size = usize::try_from(file.metadata()?.len().min(kind.limit())).unwrap_or(0);
    let mut data = Zeroizing::new(Vec::with_capacity(size));
    file.by_ref()
        .take(kind.limit() + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > kind.limit() {
        return Err(VaultError::TooLarge(kind));
    }
    Ok(data)
}

/// The freshness fingerprint, one field at a time. Each test changes one
/// property of a temp file and checks that the guard reacts. The contents
/// are arbitrary bytes: the fingerprint is about the file, not its KDBX
/// structure. The same checks run end to end against the daemon in
/// `tests/control.rs`.
#[cfg(test)]
mod fingerprint_tests {
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use super::{Fingerprint, is_unchanged};

    const BYTES: &[u8] = b"0123456789";

    fn set_mtime(path: &Path, time: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .expect("failed to open for set_modified")
            .set_modified(time)
            .expect("failed to set mtime");
    }

    /// File timestamps come from a coarse kernel clock, so a change made in
    /// the same tick as the previous one would not move ctime. Wait one tick.
    fn tick() {
        std::thread::sleep(Duration::from_millis(20));
    }

    fn baseline() -> (tempfile::TempDir, PathBuf, Fingerprint, SystemTime) {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let path = dir.path().join("vault.kdbx");
        fs::write(&path, BYTES).expect("failed to write file");
        let fp = Fingerprint::from_file(&path).expect("failed to stat file");
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            is_unchanged(&path, &fp),
            "a file must match its own fingerprint"
        );
        (dir, path, fp, mtime)
    }

    #[test]
    fn size_change_is_detected() {
        let (_dir, path, fp, _) = baseline();
        fs::write(&path, b"0123456789abc").unwrap();

        let now = Fingerprint::from_file(&path).unwrap();
        assert_ne!(now.size, fp.size);
        assert!(!is_unchanged(&path, &fp));
    }

    #[test]
    fn mtime_change_is_detected() {
        let (_dir, path, fp, mtime) = baseline();
        set_mtime(&path, mtime + Duration::from_secs(3600));

        let now = Fingerprint::from_file(&path).unwrap();
        assert_ne!(
            (now.mtime_sec, now.mtime_nsec),
            (fp.mtime_sec, fp.mtime_nsec)
        );
        assert!(!is_unchanged(&path, &fp));
    }

    /// Same size, same inode, and mtime restored to its exact value after a
    /// content change. Only ctime moves, which is what the ctime field is
    /// for.
    #[test]
    fn restored_mtime_is_caught_by_ctime() {
        let (_dir, path, fp, mtime) = baseline();
        tick();
        let mut changed = BYTES.to_vec();
        *changed.last_mut().unwrap() = b'X';
        fs::write(&path, &changed).unwrap();
        tick();
        set_mtime(&path, mtime);

        let now = Fingerprint::from_file(&path).unwrap();
        assert_eq!(now.dev, fp.dev);
        assert_eq!(now.ino, fp.ino);
        assert_eq!(now.size, fp.size);
        assert_eq!(
            (now.mtime_sec, now.mtime_nsec),
            (fp.mtime_sec, fp.mtime_nsec)
        );
        assert_ne!(
            (now.ctime_sec, now.ctime_nsec),
            (fp.ctime_sec, fp.ctime_nsec),
            "ctime must move even when mtime is restored"
        );
        assert!(!is_unchanged(&path, &fp));
    }

    /// A replacement file with the same size and content, and the original
    /// mtime restored. The old inode is held open so the new file cannot
    /// reuse its number.
    #[test]
    fn replaced_inode_is_detected() {
        let (dir, path, fp, mtime) = baseline();
        let _old_inode_held_open = File::open(&path).unwrap();

        let replacement = dir.path().join("vault.kdbx.new");
        fs::write(&replacement, BYTES).unwrap();
        set_mtime(&replacement, mtime);
        fs::rename(&replacement, &path).unwrap();

        let now = Fingerprint::from_file(&path).unwrap();
        assert_ne!(now.ino, fp.ino);
        assert!(!is_unchanged(&path, &fp));
    }

    #[test]
    fn a_missing_file_counts_as_changed() {
        let (_dir, path, fp, _) = baseline();
        fs::remove_file(&path).unwrap();
        assert!(!is_unchanged(&path, &fp));
    }
}
