//! Integration tests against `tests/fixture.sh`'s `fixture-ssh.kdbx`:
//! `ssh::keys::scan` against a real database, and `parse_private_key`
//! against each of its key types.

mod common;

use kpa::databases::Databases;
use kpa::ssh::keys::{self, SkipReason};

/// The ssh fixture, unlocked.
fn fixture() -> Databases {
    common::unlocked_fixture(&common::ssh_db())
}

/// Scanning finds exactly the three usable OpenSSH keys (Ed25519, ECDSA
/// and RSA) and reports the passphrase-protected and PEM ones as skipped —
/// the key attachments on `"Historical"` and `"Recycled"` are invisible,
/// since one lives only in history and the other only in the recycle bin.
#[test]
fn scan_finds_the_three_usable_keys_and_skips_the_encrypted_and_pem_ones() {
    let result = keys::scan(&fixture().open("fixture").expect("unlocked"));

    let mut found_names: Vec<&str> = result
        .found
        .iter()
        .map(|k| k.attachment_name.as_str())
        .collect();
    found_names.sort_unstable();
    assert_eq!(found_names, vec!["id_ecdsa", "id_ed25519", "id_rsa"]);

    let mut skipped: Vec<_> = result
        .skipped
        .iter()
        .map(|s| (s.attachment_name.as_str(), s.reason.clone()))
        .collect();
    skipped.sort_by_key(|(name, _)| *name);
    assert_eq!(
        skipped,
        vec![
            ("id_encrypted", SkipReason::Encrypted),
            ("id_rsa_pem", SkipReason::Pem),
        ]
    );

    // Neither the historical nor the recycled key attachment shows up
    // anywhere, found or skipped.
    for entry in result.found.iter().map(|k| k.entry_title.as_deref()) {
        assert_ne!(entry, Some("Historical"));
        assert_ne!(entry, Some("Recycled"));
    }
}

/// History and the recycle bin are ignored at the
/// `Open::for_each_attachment` level already — `"Historical"` and
/// `"Recycled"` contribute no attachments at all to scan.
#[test]
fn history_and_recycle_bin_attachments_are_never_visited() {
    let mut names = Vec::new();
    fixture()
        .open("fixture")
        .expect("unlocked")
        .for_each_attachment(|a| {
            if matches!(a.entry_title, Some("Historical" | "Recycled")) {
                names.push(a.name.to_string());
            }
        });
    assert!(names.is_empty(), "unexpected attachments: {names:?}");
}

/// `parse_private_key` reads every served key type, and refuses the
/// encrypted one.
#[test]
fn parse_private_key_reads_every_found_key_type() {
    let databases = fixture();
    let db = databases.open("fixture").expect("unlocked");
    let parses = |attachment_name: &str| {
        let mut parsed = None;
        db.for_each_attachment(|a| {
            if a.name == attachment_name {
                parsed = Some(keys::parse_private_key(a.data).is_some());
            }
        });
        parsed.unwrap_or_else(|| panic!("no attachment named {attachment_name}"))
    };

    for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
        assert!(parses(name), "{name}");
    }
    assert!(!parses("id_encrypted"));
}
