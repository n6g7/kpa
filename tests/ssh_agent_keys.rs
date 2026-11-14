//! Integration tests against `tests/fixture.sh`'s `fixture-ssh.kdbx`:
//! `ssh_agent::keys::scan` against a real database, and `parse_private_key`
//! against each of its key types.

mod common;

use kpa::ssh_agent::keys::{self, SkipReason};
use kpa::vault::{self, EntryAttachment};
use zeroize::Zeroizing;

fn attachments() -> Vec<EntryAttachment> {
    let password = Zeroizing::new(common::PASSWORD.to_string());
    let (db, _) =
        vault::open(&common::ssh_db(), Some(&password), None).expect("fixture should open");
    vault::list_attachments(&db)
}

/// Scanning finds exactly the three usable OpenSSH keys (Ed25519, ECDSA
/// and RSA) and reports the passphrase-protected and PEM ones as skipped —
/// the key attachments on `"Historical"` and `"Recycled"` are invisible,
/// since one lives only in history and the other only in the recycle bin.
#[test]
fn scan_finds_the_three_usable_keys_and_skips_the_encrypted_and_pem_ones() {
    let result = keys::scan(&attachments());

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

/// History and the recycle bin are ignored at the `vault::list_attachments`
/// level already — `"Historical"` and `"Recycled"` contribute no
/// attachments at all to scan.
#[test]
fn history_and_recycle_bin_attachments_are_never_listed() {
    let names: Vec<String> = attachments()
        .iter()
        .filter(|a| {
            a.entry_title.as_deref() == Some("Historical")
                || a.entry_title.as_deref() == Some("Recycled")
        })
        .map(|a| a.attachment_name.clone())
        .collect();
    assert!(names.is_empty(), "unexpected attachments: {names:?}");
}

/// `parse_private_key` reads every served key type, and refuses the
/// encrypted one.
#[test]
fn parse_private_key_reads_every_found_key_type() {
    let attachments = attachments();
    let data_for = |attachment_name: &str| {
        attachments
            .iter()
            .find(|a| a.attachment_name == attachment_name)
            .map(|a| a.data.as_slice())
            .unwrap_or_else(|| panic!("no attachment named {attachment_name}"))
    };

    for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
        assert!(keys::parse_private_key(data_for(name)).is_some(), "{name}");
    }
    assert!(keys::parse_private_key(data_for("id_encrypted")).is_none());
}
