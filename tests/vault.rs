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
    let db = vault::open(&common::password_db(), Some(&password), None)
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
    let db = vault::open(&common::kdbx4_db(), Some(&password), None)
        .expect("a genuine KDBX4 fixture should open");

    let entries = vault::list_entries(&db);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title.as_deref(), Some("Example"));
    assert_eq!(entries[0].username.as_deref(), Some("alice"));
    assert_eq!(entries[0].group, "Web");
}

#[test]
fn keyfile_only_fixture_opens_via_keyfile() {
    let db = vault::open(&common::keyfile_db(), None, Some(&common::keyfile()))
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
