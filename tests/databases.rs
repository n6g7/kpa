//! `Databases` against the throwaway `.kdbx` fixtures from
//! `tests/fixture.sh` (built on demand by `tests/common`): the unlock that
//! reads a file, and what the `Open` guard reads out of it. Right password
//! opens; wrong password fails cleanly; the keyfile-only fixture opens with
//! its keyfile; a corrupt file errors rather than panicking.

mod common;
#[path = "databases/kdb.rs"]
mod kdb;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kpa::config::DatabaseConfig;
use kpa::databases::{
    Begin, Ceiling, Databases, OpenError, UnlockFailure, Unlocking, VaultError, VaultFile,
};
use zeroize::Zeroizing;

/// The one database, `work`, at `path`, locked.
fn databases_at(path: &Path, keyfile: Option<PathBuf>) -> Databases {
    Databases::new(
        vec![DatabaseConfig {
            name: "work".to_string(),
            path: path.to_path_buf(),
            keyfile,
            serve_ssh_keys: false,
            ssh_keys: Vec::new(),
        }],
        Duration::from_secs(3600),
    )
}

fn databases() -> Databases {
    databases_at(&common::password_db(), None)
}

fn begin(databases: &Databases) -> Unlocking<'_> {
    match databases.begin_unlock("work") {
        Ok(Begin::Started(unlocking)) => unlocking,
        _ => panic!("expected an unlock to start"),
    }
}

/// `work` unlocked with the fixtures' password (and `keyfile`, if given).
fn unlocked_at(path: &Path, keyfile: Option<PathBuf>) -> Databases {
    let databases = databases_at(path, keyfile);
    let password = Zeroizing::new(common::PASSWORD.to_string());
    begin(&databases)
        .finish(Some(&password))
        .expect("fixture should open with its real password");
    databases
}

/// Why an unlock of the file at `path` with `password` fails.
fn vault_error(path: &Path, password: Option<&str>, keyfile: Option<PathBuf>) -> VaultError {
    let databases = databases_at(path, keyfile);
    let password = password.map(|password| Zeroizing::new(password.to_string()));
    match begin(&databases).finish(password.as_ref()) {
        Err(UnlockFailure::Vault(err)) => err,
        Err(other) => panic!("expected a vault error, got {other:?}"),
        Ok(()) => panic!("the unlock should not have succeeded"),
    }
}

#[test]
fn finish_with_the_right_password_unlocks_and_the_guard_reads() {
    let databases = databases();
    let password = Zeroizing::new(common::PASSWORD.to_string());
    begin(&databases).finish(Some(&password)).expect("unlocks");

    let open = databases.open("work").expect("unlocked");
    assert_eq!(
        open.entry_count(),
        1,
        "expected exactly the one seeded entry"
    );
    let entries = open.entries();
    assert_eq!(entries[0].title.as_deref(), Some("Example"));
    assert_eq!(entries[0].username.as_deref(), Some("alice"));
    assert_eq!(entries[0].url.as_deref(), Some("https://example.com"));
    assert_eq!(entries[0].group, "Web");
    assert_eq!(
        open.entry(entries[0].uuid).and_then(|entry| entry.title()),
        Some("Example".to_string())
    );
}

#[test]
fn finish_with_the_wrong_password_fails_and_frees_the_claim() {
    let databases = databases();
    let wrong = Zeroizing::new("not the password".to_string());
    let result = begin(&databases).finish(Some(&wrong));
    assert!(matches!(
        result,
        Err(UnlockFailure::Vault(VaultError::WrongCredentials))
    ));
    assert!(!databases.any_unlocked());
    begin(&databases);
}

#[test]
fn a_lock_during_the_key_derivation_cannot_be_undone() {
    let databases = databases();
    let unlocking = begin(&databases);
    let token = unlocking.unlock_token().clone();
    databases.lock("work").unwrap();
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let result = unlocking.finish(Some(&password));
    assert!(matches!(result, Err(UnlockFailure::LockedMeanwhile)));
    assert!(token.is_cancelled());
    assert!(!databases.any_unlocked());
}

/// A custom field colliding case-insensitively with a built-in is a
/// genuine, distinct field: `Entry::field` reads it by its own literal key,
/// separate from the real `Password`.
#[test]
fn custom_colliding_field_is_read_by_its_literal_key() {
    let databases = unlocked_at(&common::fields_db(), None);
    let open = databases.open("work").expect("unlocked");
    let entries = open.entries();
    let example = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Example"))
        .expect("Example entry");
    let entry = open.entry(example.uuid).expect("entry exists");

    assert_eq!(
        entry.field("Password").as_deref().map(String::as_str),
        Some("entrypass1")
    );
    assert_eq!(
        entry.field("PASSWORD").as_deref().map(String::as_str),
        Some("not-the-real-password")
    );
}

/// `list`'s `fields` array against a real database: built-ins in order,
/// custom fields sorted after them, and the collision rule applied to a
/// custom `PASSWORD` key that collides with the real `Password` field.
#[test]
fn copyable_fields_against_a_real_database() {
    let databases = unlocked_at(&common::fields_db(), None);
    let open = databases.open("work").expect("unlocked");

    let entries = open.entries();
    let example = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Example"))
        .expect("fixture should have an Example entry");

    // Custom keys sort by their raw key, before the collision prefix is
    // applied: "PASSWORD" sorts ahead of "api-key" (ASCII uppercase
    // precedes lowercase).
    assert_eq!(
        example.fields,
        vec![
            "username",
            "password",
            "url",
            "totp",
            "custom:PASSWORD",
            "api-key"
        ]
    );

    let no_otp = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("NoOtp"))
        .expect("fixture should have a NoOtp entry");
    assert!(!no_otp.fields.contains(&"totp".to_string()));
}

/// `Entry::totp` against the same database, end to end through the unlock
/// rather than an in-process `Database::new()`: the real decode/parse path.
#[test]
fn totp_against_a_real_database() {
    let databases = unlocked_at(&common::fields_db(), None);
    let open = databases.open("work").expect("unlocked");
    let entries = open.entries();
    let totp = |title: &str| {
        let entry = entries
            .iter()
            .find(|e| e.title.as_deref() == Some(title))
            .unwrap_or_else(|| panic!("{title} entry"));
        open.entry(entry.uuid).expect("entry exists").totp()
    };

    let code = totp("Example").expect("a valid otp field should produce a code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    assert!(totp("BadOtp").is_none());
    assert!(totp("NoOtp").is_none());
}

#[test]
fn opens_a_genuine_kdbx4_database() {
    // keepass's own docs claim KDBX3 *and* KDBX4 support, and
    // `Database::open`/`Database::parse` dispatch on the file's version
    // header rather than needing to be told the format, so this should
    // need no code change at all. This test is here to make that claim
    // load-bearing instead of assumed: the fixture is a genuine KDBX4 file
    // (built with pykeepass, since keepassxc-cli 2.7.12 can't produce one;
    // see tests/fixture.sh), and if the unlock ever regressed to only
    // handling KDBX3, this is what would catch it.
    let databases = unlocked_at(&common::kdbx4_db(), None);
    let open = databases.open("work").expect("unlocked");

    let entries = open.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title.as_deref(), Some("Example"));
    assert_eq!(entries[0].username.as_deref(), Some("alice"));
    assert_eq!(entries[0].group, "Web");
}

#[test]
fn keyfile_only_fixture_opens_via_keyfile() {
    let databases = databases_at(&common::keyfile_db(), Some(common::keyfile()));
    begin(&databases)
        .finish(None)
        .expect("keyfile-only fixture should open with just its keyfile");

    // This fixture has no groups or entries seeded: opening cleanly with
    // an empty list is the actual assertion here.
    let open = databases.open("work").expect("unlocked");
    assert!(open.entries().is_empty());
}

#[test]
fn missing_file_errors_cleanly() {
    let missing = common::password_db().with_file_name("does-not-exist.kdbx");

    match vault_error(&missing, Some(common::PASSWORD), None) {
        VaultError::NotFound(path) => assert_eq!(path, missing),
        other => panic!("expected NotFound, got a different error: {other}"),
    }
}

#[test]
fn malformed_file_errors_without_panicking() {
    let src = common::password_db();
    let truncated = src.with_file_name("fixture-truncated.kdbx");

    let bytes = fs::read(&src).expect("fixture should be readable to build the truncated copy");
    // Cut it down to a handful of header bytes: enough to pass the
    // cheap version-header check but fail well before a valid parse.
    let truncated_bytes = &bytes[..bytes.len().min(24)];
    fs::write(&truncated, truncated_bytes).expect("failed to write truncated fixture");

    match vault_error(&truncated, Some(common::PASSWORD), None) {
        VaultError::Corrupt(_) => {}
        other => panic!("expected Corrupt, got a different error: {other}"),
    }
}

/// A KDBX4 file whose outer header carries a compression field shorter
/// than the four bytes `keepass` reads from it, which indexes past the end
/// of the field and panics. The unlock must turn that into `Corrupt` rather
/// than unwinding into its caller. Generated here, so no committed fixture:
/// the 12-byte version header, then one header field of type 3 and length 0.
#[test]
fn a_panicking_parse_is_reported_as_corrupt() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");

    let mut kdbx = vec![0x03, 0xd9, 0xa2, 0x9a];
    kdbx.extend_from_slice(&0xB54B_FB67u32.to_le_bytes());
    kdbx.extend_from_slice(&1u16.to_le_bytes());
    kdbx.extend_from_slice(&4u16.to_le_bytes());
    kdbx.push(3);
    kdbx.extend_from_slice(&0u32.to_le_bytes());
    let db_path = dir.path().join("short-field.kdbx");
    fs::write(&db_path, &kdbx).expect("failed to write kdbx");

    match vault_error(&db_path, Some(common::PASSWORD), None) {
        VaultError::Corrupt(_) => {}
        other => panic!("expected Corrupt, got a different error: {other}"),
    }
}

/// `keepass` also reads KeePass 1.x (KDB) files, whose header, with the
/// group and entry counts, is authenticated by nothing: a file whose count
/// was lowered still opens, minus the entries past it. kpa reads KDBX3 and
/// KDBX4 only, so a KDB file is refused whether or not its header was
/// edited, before the password is tried.
#[test]
fn a_kdb_file_is_refused_whatever_its_header_says() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    for entries_in_header in [3, 1, 0] {
        let path = dir.path().join(format!("{entries_in_header}.kdb"));
        fs::write(
            &path,
            kdb::kdb_with_three_entries(common::PASSWORD, entries_in_header),
        )
        .expect("failed to write kdb");

        for password in [common::PASSWORD, "wrong password"] {
            match vault_error(&path, Some(password), None) {
                VaultError::UnsupportedFormat => {}
                other => panic!("expected UnsupportedFormat, got a different error: {other}"),
            }
        }
    }
}

/// The pre-release KeePass 2 format is the other version `keepass` parses
/// the header of; it has no reader, and is refused like KDB.
#[test]
fn a_pre_release_kdbx_file_is_refused() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let mut header = vec![0x03, 0xd9, 0xa2, 0x9a];
    header.extend_from_slice(&0xB54B_FB66u32.to_le_bytes());
    header.extend_from_slice(&[0; 4]);
    let path = dir.path().join("prerelease.kdbx");
    fs::write(&path, &header).expect("failed to write file");

    match vault_error(&path, Some(common::PASSWORD), None) {
        VaultError::UnsupportedFormat => {}
        other => panic!("expected UnsupportedFormat, got a different error: {other}"),
    }
}

/// `vault_error`, with a deadline: an unlock that blocks is a failure of the
/// test, not a hang of the suite (the blocked thread is left behind).
fn vault_error_at_once(
    path: &Path,
    password: Option<&str>,
    keyfile: Option<PathBuf>,
) -> VaultError {
    let (path, password) = (path.to_path_buf(), password.map(str::to_string));
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(vault_error(&path, password.as_deref(), keyfile));
    });
    receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("the unlock should have been refused at once")
}

fn fifo_at(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .expect("failed to make a fifo");
}

/// A sparse file of `len` bytes: it costs no disk, and reading it would cost
/// `len` bytes of memory.
fn sparse_file(path: &Path, len: u64) {
    fs::File::create(path)
        .and_then(|file| file.set_len(len))
        .expect("failed to make a sparse file");
}

/// A FIFO at the database path is refused at once. Opened for reading, it
/// would block until some writer turned up, holding the database's one
/// unlock for good: the database is unlockable again once the path is a
/// vault.
#[test]
fn a_fifo_at_the_database_path_is_refused_at_once_and_frees_the_claim() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().join("vault.kdbx");
    fifo_at(&path);

    let err = vault_error_at_once(&path, Some(common::PASSWORD), None);
    assert!(
        matches!(err, VaultError::NotRegular(VaultFile::Database)),
        "{err}"
    );

    fs::remove_file(&path).expect("remove the fifo");
    fs::copy(common::password_db(), &path).expect("copy a vault over it");
    let databases = unlocked_at(&path, None);
    assert!(databases.open("work").is_ok());
}

#[test]
fn a_directory_or_a_device_is_not_a_database() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let err = vault_error_at_once(dir.path(), Some(common::PASSWORD), None);
    assert!(
        matches!(err, VaultError::NotRegular(VaultFile::Database)),
        "{err}"
    );

    let err = vault_error_at_once(Path::new("/dev/zero"), Some(common::PASSWORD), None);
    assert!(
        matches!(err, VaultError::NotRegular(VaultFile::Database)),
        "{err}"
    );
}

/// A file one byte over the ceiling is refused from its size, without being
/// read; one at the ceiling is read (and found not to be a database).
#[test]
fn a_database_file_over_the_ceiling_is_refused_unread() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().join("big.kdbx");
    let limit = VaultFile::Database.limit();

    sparse_file(&path, limit + 1);
    let err = vault_error_at_once(&path, Some(common::PASSWORD), None);
    assert!(
        matches!(err, VaultError::TooLarge(VaultFile::Database)),
        "{err}"
    );

    sparse_file(&path, limit);
    match vault_error_at_once(&path, Some(common::PASSWORD), None) {
        VaultError::Corrupt(_) => {}
        other => panic!("a file at the ceiling is read, got: {other}"),
    }
}

/// The same for the keyfile, which `keepass` would read to its end.
#[test]
fn a_keyfile_that_is_not_a_regular_file_or_over_the_ceiling_is_refused() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let keyfile = dir.path().join("key");
    let db = common::keyfile_db();

    fifo_at(&keyfile);
    let err = vault_error_at_once(&db, None, Some(keyfile.clone()));
    assert!(
        matches!(err, VaultError::NotRegular(VaultFile::Keyfile)),
        "{err}"
    );
    fs::remove_file(&keyfile).expect("remove the fifo");

    sparse_file(&keyfile, VaultFile::Keyfile.limit() + 1);
    let err = vault_error_at_once(&db, None, Some(keyfile.clone()));
    assert!(
        matches!(err, VaultError::TooLarge(VaultFile::Keyfile)),
        "{err}"
    );
}

/// The version header and outer header of a vault that asks for the key
/// derivation given, and nothing else: enough for `open` to read what it
/// would run, not for it to open anything. KDBX3 has a `TransformRounds`
/// entry; KDBX4 a KDF parameter dictionary.
mod kdf_header {
    const IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
    const LATEST: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];

    pub fn kdbx3_aes(rounds: u64) -> Vec<u8> {
        let mut data = [IDENTIFIER, LATEST].concat();
        data.extend([0, 0, 3, 0]);
        data.extend([6, 8, 0]);
        data.extend(rounds.to_le_bytes());
        data.extend([0, 0, 0]);
        data
    }

    fn entry(kind: u8, key: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend((key.len() as u32).to_le_bytes());
        out.extend(key.as_bytes());
        out.extend((value.len() as u32).to_le_bytes());
        out.extend(value);
        out
    }

    fn kdbx4(entries: Vec<Vec<u8>>) -> Vec<u8> {
        let mut dictionary = 0x100u16.to_le_bytes().to_vec();
        dictionary.extend(entries.concat());
        dictionary.push(0);
        let mut data = [IDENTIFIER, LATEST].concat();
        data.extend([1, 0, 4, 0]);
        data.push(11);
        data.extend((dictionary.len() as u32).to_le_bytes());
        data.extend(dictionary);
        data.extend([0; 5]);
        data
    }

    pub fn kdbx4_aes(rounds: u64) -> Vec<u8> {
        kdbx4(vec![
            entry(
                0x42,
                "$UUID",
                &[
                    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00,
                    0x64, 0x82, 0x38,
                ],
            ),
            entry(0x05, "R", &rounds.to_le_bytes()),
        ])
    }

    pub fn kdbx4_argon2d(memory: u64, iterations: u64, lanes: u32) -> Vec<u8> {
        kdbx4(vec![
            entry(
                0x42,
                "$UUID",
                &[
                    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03,
                    0xe3, 0x0a, 0x0c,
                ],
            ),
            entry(0x05, "M", &memory.to_le_bytes()),
            entry(0x05, "I", &iterations.to_le_bytes()),
            entry(0x04, "P", &lanes.to_le_bytes()),
            entry(0x04, "V", &0x13u32.to_le_bytes()),
        ])
    }
}

/// A header that asks for more key derivation than kpa runs is refused
/// before any key derivation: at once, whatever the claim, and the database
/// can be unlocked again (a hung unlock would keep its claim for good).
/// The same header at the ceiling gets past the check and fails later, on
/// the rest of the file.
#[test]
fn a_key_derivation_above_the_ceiling_is_refused_at_once() {
    use kdf_header::*;

    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().join("vault.kdbx");
    let one_tib = 1u64 << 40;
    let cases = [
        (kdbx3_aes(u64::MAX), Ceiling::AesRounds),
        (kdbx4_aes(u64::MAX), Ceiling::AesRounds),
        (kdbx4_argon2d(one_tib, 1, 1), Ceiling::Argon2Memory),
        (
            kdbx4_argon2d(64 << 20, u64::from(u32::MAX), 2),
            Ceiling::Argon2Work,
        ),
        (
            kdbx4_argon2d(1 << 20, 1, 1 << 24),
            Ceiling::Argon2Parallelism,
        ),
    ];
    for (header, ceiling) in cases {
        fs::write(&path, &header).expect("failed to write the header");
        let start = std::time::Instant::now();
        match vault_error(&path, Some(common::PASSWORD), None) {
            VaultError::KdfAboveCeiling(found) => assert_eq!(found, ceiling),
            other => panic!("expected {ceiling:?}, got a different error: {other}"),
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{ceiling:?}");
        // The claim is free: the next unlock starts.
        let databases = databases_at(&path, None);
        assert!(matches!(
            databases.begin_unlock("work"),
            Ok(Begin::Started(_))
        ));
    }

    // At the ceilings the header is read on, and it is the rest that fails.
    for header in [
        kdbx3_aes(1 << 30),
        kdbx4_aes(1 << 30),
        kdbx4_argon2d(1 << 30, 32, 256),
    ] {
        fs::write(&path, &header).expect("failed to write the header");
        assert!(
            matches!(
                vault_error(&path, Some(common::PASSWORD), None),
                VaultError::Corrupt(_)
            ),
            "a header at the ceilings is not refused for them"
        );
    }
}

/// Copies the password fixture into `dir` with one bit flipped in the
/// outer header's ProtectedStreamKey (field 8). That field doesn't feed the
/// master key, so the file still decrypts; only the protected values are
/// decoded under the wrong keystream. The KDBX3 header has no checksum of
/// its own, so nothing else needs fixing up.
fn kdbx3_with_flipped_protected_stream_key(dir: &Path) -> PathBuf {
    let mut data = fs::read(common::password_db()).expect("fixture should be readable");
    // Outer header fields start after the 12-byte version header; each is
    // `type: u8, len: u16 LE, data`, ended by type 0.
    let mut pos = 12;
    loop {
        let ty = data[pos];
        let len = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        assert_ne!(ty, 0, "fixture has no ProtectedStreamKey field");
        if ty == 8 {
            data[pos + 3] ^= 0x01;
            break;
        }
        pos += 3 + len;
    }
    let path = dir.join("tampered.kdbx");
    fs::write(&path, &data).expect("failed to write tampered copy");
    path
}

/// A KDBX3 header altered without the key must not open: KDBX3's only
/// authentication of the outer header is `Meta/HeaderHash`, and `keepass`
/// doesn't check it, so kpa has to.
#[test]
fn tampered_kdbx3_header_is_rejected() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = kdbx3_with_flipped_protected_stream_key(dir.path());

    match vault_error(&path, Some(common::PASSWORD), None) {
        VaultError::Corrupt(_) => {}
        other => panic!("expected Corrupt, got a different error: {other}"),
    }
}

/// The fingerprint an unlock takes describes the file it read: the database
/// stays unlocked until the file changes, and not after.
#[test]
fn a_file_changed_after_the_read_locks_the_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = dir.path().join("vault.kdbx");
    fs::copy(common::password_db(), &copy).expect("copy fixture");
    let databases = unlocked_at(&copy, None);
    assert!(databases.open("work").is_ok());

    fs::OpenOptions::new()
        .append(true)
        .open(&copy)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"x"))
        .expect("append to copy");

    assert!(matches!(databases.open("work"), Err(OpenError::Stale)));
    assert!(!databases.any_unlocked());
}
