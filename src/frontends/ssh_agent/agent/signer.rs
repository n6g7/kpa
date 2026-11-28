//! Turning a served key into a signature: decoding the request's key blob,
//! reading the private key at its first use (`docs/ssh-agent.md` § 6.4),
//! and signing with the algorithm the request asked for (§ 6.5).

use std::collections::hash_map::Entry;

use ssh_key::encoding::{Decode, Encode, Reader};
use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PrivateKey};

use super::hold::Hold;
use super::sign::Refused;
use crate::frontends::ssh_agent::wire::SignFlags;
use crate::ssh::keys;

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

/// Signs `data` with the key the held database serves under `fingerprint`,
/// reading it from the database first if this is its first signature since
/// unlock and keeping it in the state until lock. Whether the request may be
/// signed at all is not asked here.
///
/// The key is found in the hold's own scan: only that one knows the entry it
/// came from. Refused as [`Refused::Locked`] for a locked database,
/// [`Refused::NotServed`] for a key its scan didn't find, and
/// [`Refused::SigningFailed`] if the key's attachment is gone or doesn't
/// parse, or the signature fails.
pub(super) fn sign(
    hold: &mut Hold<'_>,
    fingerprint: Fingerprint,
    data: &[u8],
    flags: SignFlags,
) -> Result<Vec<u8>, Refused> {
    let entry_uuid = hold.served(fingerprint)?.entry_uuid;
    let (open, scanned) = hold.unlocked_mut().ok_or(Refused::Locked)?;
    let private_key = match scanned.private_keys.entry(fingerprint) {
        Entry::Occupied(cached) => cached.into_mut(),
        Entry::Vacant(vacant) => vacant.insert(
            keys::read_private_key(open, entry_uuid, fingerprint).ok_or(Refused::SigningFailed)?,
        ),
    };
    sign_with(private_key, data, flags).ok_or(Refused::SigningFailed)
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
    use ssh_key::{Algorithm, Signature};
    use uuid::Uuid;

    use super::*;
    use crate::config::SshKeyConfirm;
    use crate::frontends::ssh_agent::testing::Fixture;
    use crate::ssh::testing::{RSA_3072, test_key};

    fn fingerprint(key: &PrivateKey) -> Fingerprint {
        key.public_key().fingerprint(HashAlg::Sha256)
    }

    /// Signs as the sign flow does, in one hold of `personal`.
    fn sign_in(fx: &Fixture, fingerprint: Fingerprint, flags: u32) -> Result<Vec<u8>, Refused> {
        let mut hold = fx.agent.hold("personal")?;
        sign(&mut hold, fingerprint, b"data", SignFlags::new(flags))
    }

    #[test]
    fn a_signature_verifies_and_the_key_is_kept_for_the_next() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);

        let raw = sign_in(&fx, fingerprint(&key), 0).expect("signs");
        let signature = Signature::decode(&mut raw.as_slice()).expect("signature decodes");
        signature::Verifier::verify(key.public_key(), b"data", &signature).expect("verifies");
        assert!(
            fx.state.inner().scanned["personal"]
                .private_keys
                .contains_key(&fingerprint(&key))
        );
    }

    /// An RSA key signs with the SHA-2 algorithm the request asks for, and
    /// refuses a request for neither (SHA-1 `ssh-rsa`).
    #[test]
    fn an_rsa_key_signs_with_sha2_only() {
        let key = PrivateKey::from_openssh(RSA_3072).expect("test vector");
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);

        assert!(!supported(key.public_key().key_data(), SignFlags::new(0)));
        assert!(matches!(
            sign_in(&fx, fingerprint(&key), 0),
            Err(Refused::SigningFailed)
        ));
        for (flags, hash) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
            assert!(supported(
                key.public_key().key_data(),
                SignFlags::new(flags)
            ));
            let raw = sign_in(&fx, fingerprint(&key), flags).expect("signs");
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
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        fx.state
            .inner()
            .scanned
            .get_mut("personal")
            .expect("scanned")
            .served[0]
            .entry_uuid = Uuid::new_v4();

        assert!(matches!(
            sign_in(&fx, fingerprint(&key), 0),
            Err(Refused::SigningFailed)
        ));
    }

    /// Only a key the hold's own scan found signs, and only while its
    /// database is unlocked.
    #[test]
    fn a_key_outside_the_scan_or_a_locked_database_does_not_sign() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        assert!(matches!(
            sign_in(&fx, fingerprint(&test_key(2)), 0),
            Err(Refused::NotServed)
        ));

        let locked = Fixture::locked(&key, SshKeyConfirm::Never);
        assert!(matches!(
            sign_in(&locked, fingerprint(&key), 0),
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
