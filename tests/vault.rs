//! Integration tests against the throwaway fixtures from `tests/fixture.sh`
//! (built on demand by `tests/common`). These are the tests PR 1's brief
//! calls out by name: right password opens; wrong password fails cleanly;
//! the keyfile-only fixture opens via `--keyfile`; a corrupt file errors
//! rather than panicking.

mod common;

use std::fs;

use kpa::vault::{self, VaultError};
use zeroize::Zeroizing;

#[test]
fn opens_with_the_right_password() {
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) = vault::open(&common::password_db(), Some(&password), None)
        .expect("fixture should open with its real password");

    let entries = vault::list_entries(&db);
    assert_eq!(entries.len(), 1, "expected exactly the one seeded entry");

    let entry = &entries[0];
    assert_eq!(entry.title.as_deref(), Some("Example"));
    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert_eq!(entry.url.as_deref(), Some("https://example.com"));
    assert_eq!(entry.group, "Web");
}

#[test]
fn wrong_password_fails_cleanly() {
    let password = Zeroizing::new("definitely not it".to_string());
    let result = vault::open(&common::password_db(), Some(&password), None);

    match result {
        Err(VaultError::WrongCredentials) => {}
        Err(other) => panic!("expected WrongCredentials, got a different error: {other}"),
        Ok(_) => panic!("wrong password should not have opened the database"),
    }
}

/// A custom field colliding case-insensitively with a built-in is a
/// genuine, distinct field — `entry_field` reads it by its own literal
/// key, separate from the real `Password`.
#[test]
fn custom_colliding_field_is_read_by_its_literal_key() {
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) = vault::open(&common::fields_db(), Some(&password), None)
        .expect("fixture should open with its real password");
    let entries = vault::list_entries(&db);
    let example = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Example"))
        .expect("Example entry");

    assert_eq!(
        vault::entry_field(&db, example.uuid, "Password")
            .expect("entry exists")
            .as_deref()
            .map(String::as_str),
        Some("entrypass1")
    );
    assert_eq!(
        vault::entry_field(&db, example.uuid, "PASSWORD")
            .expect("entry exists")
            .as_deref()
            .map(String::as_str),
        Some("not-the-real-password")
    );
}

/// `list`'s `fields` array against a real database: built-ins in order,
/// custom fields sorted after them, and the collision rule applied to a
/// custom `PASSWORD` key that collides with the real `Password` field.
#[test]
fn copyable_fields_against_a_real_database() {
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) = vault::open(&common::fields_db(), Some(&password), None)
        .expect("fixture should open with its real password");

    let entries = vault::list_entries(&db);
    let example = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Example"))
        .expect("fixture should have an Example entry");

    // Custom keys sort by their raw key, before the collision prefix is
    // applied — "PASSWORD" sorts ahead of "api-key" (ASCII uppercase
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

/// `entry_totp` against the same database, end to end through `vault::open`
/// rather than an in-process `Database::new()` — the real decode/parse path.
#[test]
fn entry_totp_against_a_real_database() {
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) = vault::open(&common::fields_db(), Some(&password), None)
        .expect("fixture should open with its real password");
    let entries = vault::list_entries(&db);

    let example = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Example"))
        .expect("Example entry");
    let code = vault::entry_totp(&db, example.uuid)
        .expect("entry exists")
        .expect("a valid otp field should produce a code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    let bad_otp = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("BadOtp"))
        .expect("BadOtp entry");
    assert_eq!(vault::entry_totp(&db, bad_otp.uuid), Some(None));

    let no_otp = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("NoOtp"))
        .expect("NoOtp entry");
    assert_eq!(vault::entry_totp(&db, no_otp.uuid), Some(None));
}

#[test]
fn opens_a_genuine_kdbx4_database() {
    // keepass's own docs claim KDBX3 *and* KDBX4 support, and
    // `Database::open`/`Database::parse` dispatch on the file's version
    // header rather than needing to be told the format — so this should
    // need no code change at all. This test is here to make that claim
    // load-bearing instead of assumed: the fixture is a genuine KDBX4 file
    // (built with pykeepass, since keepassxc-cli 2.7.12 can't produce one —
    // see tests/fixture.sh), and if `vault::open` ever regressed to only
    // handling KDBX3, this is what would catch it.
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) = vault::open(&common::kdbx4_db(), Some(&password), None)
        .expect("a genuine KDBX4 fixture should open");

    let entries = vault::list_entries(&db);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title.as_deref(), Some("Example"));
    assert_eq!(entries[0].username.as_deref(), Some("alice"));
    assert_eq!(entries[0].group, "Web");
}

#[test]
fn keyfile_only_fixture_opens_via_keyfile() {
    let (db, _) = vault::open(&common::keyfile_db(), None, Some(&common::keyfile()))
        .expect("keyfile-only fixture should open with just its keyfile");

    // This fixture has no groups or entries seeded — opening cleanly with
    // an empty list is the actual assertion here.
    assert!(vault::list_entries(&db).is_empty());
}

#[test]
fn missing_file_errors_cleanly() {
    let missing = common::password_db().with_file_name("does-not-exist.kdbx");
    let password = Zeroizing::new(common::PASSWORD.to_string());

    match vault::open(&missing, Some(&password), None) {
        Err(VaultError::NotFound(path)) => assert_eq!(path, missing),
        Err(other) => panic!("expected NotFound, got a different error: {other}"),
        Ok(_) => panic!("a nonexistent path should never open successfully"),
    }
}

#[test]
fn malformed_file_errors_without_panicking() {
    let src = common::password_db();
    let truncated = src.with_file_name("fixture-truncated.kdbx");

    let bytes = fs::read(&src).expect("fixture should be readable to build the truncated copy");
    // Cut it down to a handful of header bytes — enough to pass the
    // cheap version-header check but fail well before a valid parse.
    let truncated_bytes = &bytes[..bytes.len().min(24)];
    fs::write(&truncated, truncated_bytes).expect("failed to write truncated fixture");

    let password = Zeroizing::new(common::PASSWORD.to_string());
    let result = vault::open(&truncated, Some(&password), None);

    match result {
        Err(VaultError::Corrupt(_)) => {}
        Err(other) => panic!("expected Corrupt, got a different error: {other}"),
        Ok(_) => panic!("a truncated file should never open successfully"),
    }
}

/// A legacy KDB file whose header parses far enough to reach `keepass`'s
/// short-field reads, which index past the end of the buffer and panic
/// (docs/review-2026-09-robustness.md finding 8). `vault::open` must turn
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

    match vault::open(&db_path, None, Some(&keyfile)) {
        Err(VaultError::Corrupt(_)) => {}
        Err(other) => panic!("expected Corrupt, got a different error: {other}"),
        Ok(_) => panic!("a 140-byte KDB should never open successfully"),
    }
}

/// Copies the password fixture into `dir` with one bit flipped in the
/// outer header's ProtectedStreamKey (field 8). That field doesn't feed the
/// master key, so the file still decrypts; only the protected values are
/// decoded under the wrong keystream. The KDBX3 header has no checksum of
/// its own, so nothing else needs fixing up.
fn kdbx3_with_flipped_protected_stream_key(dir: &std::path::Path) -> std::path::PathBuf {
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
    let password = Zeroizing::new(common::PASSWORD.to_string());

    match vault::open(&path, Some(&password), None) {
        Err(VaultError::Corrupt(_)) => {}
        Err(other) => panic!("expected Corrupt, got a different error: {other}"),
        Ok(_) => panic!("a KDBX3 file with an altered header opened"),
    }
}
