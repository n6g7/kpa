//! `Databases` against the throwaway `.kdbx` fixtures from
//! `tests/fixture.sh` (built on demand by `tests/common`): the unlock that
//! reads a file, and what the `Open` guard reads out of it. Right password
//! opens; wrong password fails cleanly; the keyfile-only fixture opens with
//! its keyfile; a corrupt file errors rather than panicking.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kpa::config::DatabaseConfig;
use kpa::databases::{Begin, Databases, OpenError, UnlockFailure, Unlocking, VaultError};
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

/// A legacy KDB file whose header parses far enough to reach `keepass`'s
/// short-field reads, which index past the end of the buffer and panic
/// (docs/review-2026-09-robustness.md finding 8). The unlock must turn
/// that into `Corrupt` rather than unwinding into its caller. Generated
/// here, so no committed fixture: a 124-byte header (KDB signatures, flags
/// = 2) plus 16 zero bytes, with a keyfile and no password.
#[test]
fn a_panicking_parse_is_reported_as_corrupt() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");

    let mut kdb = Vec::with_capacity(140);
    kdb.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    kdb.extend_from_slice(&0xB54B_FB65u32.to_le_bytes());
    kdb.extend_from_slice(&2u32.to_le_bytes());
    kdb.resize(140, 0);
    let db_path = dir.path().join("legacy.kdb");
    fs::write(&db_path, &kdb).expect("failed to write kdb");

    let keyfile = dir.path().join("key.xml");
    fs::write(
        &keyfile,
        "<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>AAAA</Data></Key></KeyFile>",
    )
    .expect("failed to write keyfile");

    match vault_error(&db_path, None, Some(keyfile)) {
        VaultError::Corrupt(_) => {}
        other => panic!("expected Corrupt, got a different error: {other}"),
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
