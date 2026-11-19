//! `Databases` against a real `.kdbx` fixture: the unlock that reads a file.

mod common;

use std::time::Duration;

use kpa::config::DatabaseConfig;
use kpa::databases::{Begin, Databases, UnlockFailure, VaultError};
use zeroize::Zeroizing;

fn databases() -> Databases {
    Databases::new(
        vec![DatabaseConfig {
            name: "work".to_string(),
            path: common::password_db(),
            keyfile: None,
            serve_ssh_keys: false,
            ssh_keys: Vec::new(),
        }],
        Duration::from_secs(3600),
    )
}

fn begin(databases: &Databases) -> kpa::databases::Unlocking<'_> {
    match databases.begin_unlock("work") {
        Ok(Begin::Started(unlocking)) => unlocking,
        _ => panic!("expected an unlock to start"),
    }
}

#[test]
fn finish_with_the_right_password_unlocks_and_the_guard_reads() {
    let databases = databases();
    let password = Zeroizing::new(common::PASSWORD.to_string());
    begin(&databases).finish(Some(&password)).expect("unlocks");

    let open = databases.open("work").expect("unlocked");
    assert_eq!(open.entry_count(), 1);
    let entries = open.entries();
    assert_eq!(entries[0].title.as_deref(), Some("Example"));
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
