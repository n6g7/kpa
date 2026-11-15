//! Test helpers shared by this subsystem's unit tests: throwaway keys,
//! real `session-bind@openssh.com` messages, and databases and configs
//! that serve keys.

use signature::Signer;
use ssh_key::encoding::Encode;
use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};

use super::wire::SessionBind;
use crate::config::{DatabaseConfig, SshKeyConfig};

/// A deterministic, non-cryptographic stand-in for `OsRng`: these tests
/// only need *a* valid keypair, the same one for the same seed.
struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl ssh_key::rand_core::TryRng for TestRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl ssh_key::rand_core::TryCryptoRng for TestRng {}

/// An Ed25519 key, the same for the same `seed`.
pub(crate) fn test_key(seed: u64) -> PrivateKey {
    PrivateKey::random(&mut TestRng(seed), Algorithm::Ed25519).expect("key generation")
}

/// A real `session-bind@openssh.com` message for `session_id`, signed by
/// `host`.
pub(super) fn signed_bind(
    host: &PrivateKey,
    session_id: &[u8],
    is_forwarding: bool,
) -> SessionBind {
    let signature: Signature = host.try_sign(session_id).expect("signing should succeed");
    SessionBind {
        hostkey: host.public_key().to_bytes().expect("key encodes"),
        session_id: session_id.to_vec(),
        signature: signature.encode_vec().expect("signature encodes"),
        is_forwarding,
    }
}

/// A database whose root holds one entry per `(title, key)`, each with the
/// key as an OpenSSH attachment, the way a KeePass client stores one.
pub(crate) fn key_database(keys: &[(&str, &PrivateKey)]) -> keepass::Database {
    use keepass::db::{Value, fields};

    let mut db = keepass::Database::new();
    {
        let mut root = db.root_mut();
        for (title, key) in keys {
            let pem = key.to_openssh(LineEnding::LF).expect("key encodes");
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, *title);
            entry.add_attachment("id_ed25519", Value::unprotected(pem.as_bytes().to_vec()));
        }
    }
    db
}

/// A `serve_ssh_keys` database named `name`, with `ssh_keys` as its
/// `[[database.ssh_key]]` overrides.
pub(super) fn database(name: &str, ssh_keys: Vec<SshKeyConfig>) -> DatabaseConfig {
    DatabaseConfig {
        name: name.to_string(),
        path: format!("/{name}.kdbx").into(),
        keyfile: None,
        serve_ssh_keys: true,
        ssh_keys,
    }
}
