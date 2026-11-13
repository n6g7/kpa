//! Integration tests against `tests/fixture.sh`'s `fixture-ssh.kdbx`:
//! `ssh_agent::keys::scan` against a real database, and `decrypt` against
//! each of its key types.

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

/// Scanning finds exactly the three OpenSSH keys (Ed25519, the
/// passphrase-protected one, and RSA) and reports the PEM one as skipped —
/// the key attachments on `"Historical"` and `"Recycled"` are invisible,
/// since one lives only in history and the other only in the recycle bin.
#[test]
fn scan_finds_exactly_the_three_openssh_keys_and_skips_the_pem_one() {
    let result = keys::scan(&attachments());

    let mut found_names: Vec<&str> = result
        .found
        .iter()
        .map(|k| k.attachment_name.as_str())
        .collect();
    found_names.sort_unstable();
    assert_eq!(found_names, vec!["id_ecdsa", "id_ed25519", "id_rsa"]);

    assert_eq!(result.skipped.len(), 1);
    assert_eq!(result.skipped[0].attachment_name, "id_rsa_pem");
    assert_eq!(result.skipped[0].reason, SkipReason::Pem);

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

/// `decrypt` works for all three served key types: Ed25519 and RSA are
/// unencrypted, and the Ecdsa one needs its entry's Password field as the
/// passphrase.
#[test]
fn decrypt_works_for_every_found_key_type() {
    let attachments = attachments();
    let result = keys::scan(&attachments);
    assert_eq!(result.found.len(), 3);

    let data_for = |attachment_name: &str| {
        attachments
            .iter()
            .find(|a| a.attachment_name == attachment_name)
            .map(|a| a.data.as_slice())
            .unwrap_or_else(|| panic!("no attachment named {attachment_name}"))
    };

    let irrelevant = Zeroizing::new("irrelevant".to_string());
    keys::decrypt(data_for("id_ed25519"), &irrelevant).expect("Ed25519 key decrypts");
    keys::decrypt(data_for("id_rsa"), &irrelevant).expect("RSA key decrypts");

    let right_passphrase = Zeroizing::new(common::SSH_KEY_PASSPHRASE.to_string());
    keys::decrypt(data_for("id_ecdsa"), &right_passphrase)
        .expect("Ecdsa key decrypts with its passphrase");

    let wrong_passphrase = Zeroizing::new("definitely not it".to_string());
    assert!(keys::decrypt(data_for("id_ecdsa"), &wrong_passphrase).is_err());
}
