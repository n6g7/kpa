//! Turning a served key into a signature: decoding the request's key blob,
//! reading the private key at its first use (`docs/ssh-agent.md` § 6.4),
//! and signing with the algorithm the request asked for (§ 6.5).

use std::collections::hash_map::Entry;

use keepass::Database;
use ssh_key::encoding::{Decode, Encode, Reader};
use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PrivateKey};
use uuid::Uuid;

use super::SlotView;
use super::sign::Refused;
use crate::ssh_agent::keys;
use crate::ssh_agent::wire::SignFlags;
use crate::vault;

/// Decodes a raw public-key blob off the wire (`SIGN_REQUEST`'s
/// `key_blob`), refusing trailing bytes.
pub(super) fn key_data_from_blob(blob: &[u8]) -> ssh_key::Result<KeyData> {
    let mut reader: &[u8] = blob;
    let key_data = KeyData::decode(&mut reader)?;
    reader.ensure_finished()?;
    Ok(key_data)
}

/// Whether `key` can sign a request with `flags` at all: an RSA key only
/// signs with SHA-2 (`docs/ssh-agent.md` § 6.5), so a request for SHA-1
/// `ssh-rsa` is refused before anyone is asked about it.
pub(super) fn supported(key: &KeyData, flags: SignFlags) -> bool {
    !matches!(key, KeyData::Rsa(_)) || rsa_hash(flags).is_some()
}

/// Signs `data` with the key the slot's database serves under
/// `fingerprint`, reading it from the database first if this is its first
/// signature since unlock and keeping it in the slot until lock. Whether
/// the request may be signed at all is not asked here.
///
/// The key is found in the slot's own scan: only that one knows the entry
/// it came from. Refused as [`Refused::Locked`] for a locked database,
/// [`Refused::NotServed`] for a key its scan didn't find, and
/// [`Refused::SigningFailed`] if the key's attachment is gone or doesn't
/// parse, or the signature fails.
pub(super) fn sign(
    slot: &mut SlotView<'_>,
    fingerprint: Fingerprint,
    data: &[u8],
    flags: SignFlags,
) -> Result<Vec<u8>, Refused> {
    let entry_uuid = slot.served(fingerprint)?.entry_uuid;
    let db = slot.db.ok_or(Refused::Locked)?;
    let private_key = match slot.ssh.private_keys.entry(fingerprint) {
        Entry::Occupied(cached) => cached.into_mut(),
        Entry::Vacant(vacant) => vacant
            .insert(read_private_key(db, entry_uuid, fingerprint).ok_or(Refused::SigningFailed)?),
    };
    sign_with(private_key, data, flags).ok_or(Refused::SigningFailed)
}

/// The private key on entry `entry_uuid`: the one attachment that parses to
/// a key with `fingerprint`. Each attachment is parsed once, straight from
/// the database's bytes.
fn read_private_key(
    db: &Database,
    entry_uuid: Uuid,
    fingerprint: Fingerprint,
) -> Option<PrivateKey> {
    let mut found = None;
    vault::for_each_entry_attachment(db, entry_uuid, |attachment| {
        if found.is_some() {
            return;
        }
        found = keys::parse_private_key(attachment.data)
            .filter(|key| key.public_key().fingerprint(HashAlg::Sha256) == fingerprint);
    });
    found
}

/// The hash an RSA signature uses: `rsa-sha2-512` or `rsa-sha2-256`,
/// whichever `flags` asks for, and `None` for a request asking for neither
/// (SHA-1 `ssh-rsa`).
fn rsa_hash(flags: SignFlags) -> Option<HashAlg> {
    if flags.rsa_sha2_512() {
        Some(HashAlg::Sha512)
    } else if flags.rsa_sha2_256() {
        Some(HashAlg::Sha256)
    } else {
        None
    }
}

/// The raw signature bytes `SIGN_RESPONSE` carries. An RSA key signs with
/// the SHA-2 algorithm `flags` asks for, and refuses SHA-1
/// ([`rsa_hash`]). Any other key signs with its own algorithm.
fn sign_with(key: &PrivateKey, data: &[u8], flags: SignFlags) -> Option<Vec<u8>> {
    use signature::Signer;

    let signature = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(rsa) => {
            (rsa, Some(rsa_hash(flags)?)).try_sign(data).ok()?
        }
        _ => key.try_sign(data).ok()?,
    };
    signature.encode_vec().ok()
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ssh_key::{Algorithm, Signature};

    use super::super::SshSlot;
    use super::*;
    use crate::prompt::CancelSource;
    use crate::ssh_agent::testing::{RSA_3072, database, key_database, test_key};

    /// `key`'s fingerprint, and a database serving it, scanned.
    fn scanned(key: &PrivateKey) -> (Fingerprint, Database, SshSlot) {
        let db = key_database(&[("github", key)]);
        let ssh = SshSlot::scan(&db, &database("personal", vec![]));
        (key.public_key().fingerprint(HashAlg::Sha256), db, ssh)
    }

    /// Signs as `sign` does under the host's lock, on a slot whose
    /// database is `db`.
    fn sign_on(
        db: Option<&Database>,
        ssh: &mut SshSlot,
        fingerprint: Fingerprint,
        flags: u32,
    ) -> Result<Vec<u8>, Refused> {
        let mut last_activity = Instant::now();
        let lock_signal = CancelSource::new();
        let mut backoff = None;
        let mut slot = SlotView::new(db, ssh, &mut last_activity, &lock_signal, &mut backoff);
        sign(&mut slot, fingerprint, b"data", SignFlags::new(flags))
    }

    #[test]
    fn a_signature_verifies_and_the_key_is_kept_for_the_next() {
        let key = test_key(1);
        let (fingerprint, db, mut ssh) = scanned(&key);

        let raw = sign_on(Some(&db), &mut ssh, fingerprint, 0).expect("signs");
        let signature = Signature::decode(&mut raw.as_slice()).expect("signature decodes");
        signature::Verifier::verify(key.public_key(), b"data", &signature).expect("verifies");
        assert!(ssh.private_keys.contains_key(&fingerprint));
    }

    /// An RSA key signs with the SHA-2 algorithm the request asks for, and
    /// refuses a request for neither (SHA-1 `ssh-rsa`).
    #[test]
    fn an_rsa_key_signs_with_sha2_only() {
        let key = PrivateKey::from_openssh(RSA_3072).expect("test vector");
        let (fingerprint, db, mut ssh) = scanned(&key);

        assert!(!supported(key.public_key().key_data(), SignFlags::new(0)));
        assert!(matches!(
            sign_on(Some(&db), &mut ssh, fingerprint, 0),
            Err(Refused::SigningFailed)
        ));
        for (flags, hash) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
            assert!(supported(
                key.public_key().key_data(),
                SignFlags::new(flags)
            ));
            let raw = sign_on(Some(&db), &mut ssh, fingerprint, flags).expect("signs");
            let signature = Signature::decode(&mut raw.as_slice()).expect("signature decodes");
            assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            signature::Verifier::verify(key.public_key(), b"data", &signature).expect("verifies");
        }
    }

    #[test]
    fn any_other_key_signs_whatever_the_flags() {
        assert!(supported(
            test_key(1).public_key().key_data(),
            SignFlags::new(0)
        ));
    }

    #[test]
    fn a_key_whose_entry_is_gone_does_not_sign() {
        let key = test_key(1);
        let (fingerprint, db, mut ssh) = scanned(&key);
        ssh.served[0].entry_uuid = Uuid::new_v4();

        assert!(matches!(
            sign_on(Some(&db), &mut ssh, fingerprint, 0),
            Err(Refused::SigningFailed)
        ));
    }

    /// Only a key the slot's own scan found signs, and only while its
    /// database is open.
    #[test]
    fn a_key_outside_the_scan_or_a_locked_database_does_not_sign() {
        let key = test_key(1);
        let (fingerprint, db, mut ssh) = scanned(&key);
        let other = test_key(2).public_key().fingerprint(HashAlg::Sha256);

        assert!(matches!(
            sign_on(Some(&db), &mut ssh, other, 0),
            Err(Refused::NotServed)
        ));
        assert!(matches!(
            sign_on(None, &mut ssh, fingerprint, 0),
            Err(Refused::Locked)
        ));
    }

    #[test]
    fn a_blob_with_trailing_bytes_is_refused() {
        let mut blob = test_key(1).public_key().to_bytes().expect("key encodes");
        assert!(key_data_from_blob(&blob).is_ok());
        blob.push(0);
        assert!(key_data_from_blob(&blob).is_err());
    }
}
