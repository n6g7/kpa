//! What a `SIGN_REQUEST`'s data actually is (`docs/ssh-agent.md` § 6.3).
//!
//! kpa parses it exactly the way OpenSSH's `ssh-agent` does in
//! `parse_userauth_request` (`ssh-agent.c`): try reading it as an SSH login
//! first, then as an `SSHSIG` blob, and call it [`Purpose::Other`] if
//! neither fits. Both parses reject trailing bytes — a login or a
//! signature request is the *whole* of what was asked to be signed, never
//! a prefix of something bigger smuggled past a careless parser.
//!
//! The login parse additionally requires the request's own key blob to
//! equal the key that's actually being asked to sign: `classify` takes
//! that key as a parameter precisely so this check can happen here, once,
//! rather than being left to every caller to remember.

use ssh_key::encoding::{Decode, Reader};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, PublicKey};

/// `SSH2_MSG_USERAUTH_REQUEST`, from OpenSSH's `ssh2.h`. The byte a login's
/// signed data always starts with, right after its session identifier.
const SSH2_MSG_USERAUTH_REQUEST: u8 = 50;

const SERVICE_SSH_CONNECTION: &str = "ssh-connection";
const METHOD_PUBLICKEY: &str = "publickey";
const METHOD_PUBLICKEY_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// The `SSHSIG` preamble (`PROTOCOL.sshsig` § 3), spelled out as bytes
/// because it's matched directly rather than decoded as a `string`.
const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

/// What a `SIGN_REQUEST`'s `data` turned out to be, once [`classify`] has
/// looked at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// An SSH login: `data` is a well-formed `SSH2_MSG_USERAUTH_REQUEST`
    /// `publickey` (or `publickey-hostbound-v00@openssh.com`) signing
    /// request, naming the key [`classify`] was asked about.
    Login(LoginRequest),
    /// An `ssh-keygen -Y sign` / `ssh-keygen -Y verify` signature
    /// (`SSHSIG`). Carries the namespace (`git`, `file`, …) — the rest of
    /// the blob (the hashed message) has no policy meaning on its own.
    SshSig { namespace: String },
    /// Neither: arbitrary data the requester wants signed with no
    /// recognized structure.
    Other,
}

/// [`Purpose::Login`]'s fields: everything a login signing request carries
/// that policy or a prompt might need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    /// The exchange hash from the connection this login authenticates —
    /// compared against a connection's bindings to tell local use from
    /// forwarded (`docs/ssh-agent.md` § 6.2–6.3).
    pub session_id: Vec<u8>,
    /// The server username the login is for.
    pub user: String,
    /// Present for `publickey-hostbound-v00@openssh.com`: the destination
    /// host key the login is bound to. `None` for plain `publickey`.
    pub hostbound_hostkey: Option<KeyData>,
}

/// Classify `data` — a `SIGN_REQUEST`'s signing payload — against
/// `signing_key`, the key the request asked to sign with.
#[must_use]
pub fn classify(data: &[u8], signing_key: &PublicKey) -> Purpose {
    if let Some(login) = try_login(data, signing_key) {
        return Purpose::Login(login);
    }
    if let Some(namespace) = try_sshsig(data) {
        return Purpose::SshSig { namespace };
    }
    Purpose::Other
}

/// Decode a string-wrapped key blob (`sshkey_froms` in OpenSSH), rejecting
/// anything left over inside it once the key itself is decoded.
fn read_key_blob(reader: &mut impl Reader) -> ssh_key::Result<KeyData> {
    reader.read_prefixed(|inner| {
        let key_data = KeyData::decode(inner)?;
        inner.ensure_finished()?;
        Ok(key_data)
    })
}

/// Do `claimed` (the signing request's own algorithm name, e.g.
/// `"rsa-sha2-256"`) and `actual` (the signing key's algorithm) name the
/// same *kind* of key? Mirrors `sshkey_type_from_name(pkalg) !=
/// expected_key->type` in `parse_userauth_request`, which checks only the
/// key type (RSA, ECDSA of a given curve, Ed25519, …), not which RSA hash
/// variant was requested — that's `SignFlags`' job, not this check's.
fn same_key_type(claimed: &Algorithm, actual: &Algorithm) -> bool {
    match (claimed, actual) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }) => true,
        (Algorithm::Ecdsa { curve: a }, Algorithm::Ecdsa { curve: b }) => a == b,
        (Algorithm::Ed25519, Algorithm::Ed25519) => true,
        (Algorithm::Dsa, Algorithm::Dsa) => true,
        (Algorithm::SkEd25519, Algorithm::SkEd25519) => true,
        (Algorithm::SkEcdsaSha2NistP256, Algorithm::SkEcdsaSha2NistP256) => true,
        _ => false,
    }
}

fn try_login(data: &[u8], signing_key: &PublicKey) -> Option<LoginRequest> {
    let mut reader: &[u8] = data;

    // `sshbuf_froms(b, &sess_id)`: a non-empty `string`, read before the
    // type byte — a client on an unrelated protocol version is reported as
    // a version mismatch, not a bad signing request, by the same
    // reasoning `proto::decode_request` orders its own checks.
    let session_id = Vec::<u8>::decode(&mut reader).ok()?;
    if session_id.is_empty() {
        return None;
    }

    if u8::decode(&mut reader).ok()? != SSH2_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = String::decode(&mut reader).ok()?;
    let service = String::decode(&mut reader).ok()?;
    if service != SERVICE_SSH_CONNECTION {
        return None;
    }
    let method = String::decode(&mut reader).ok()?;
    let hostbound = match method.as_str() {
        METHOD_PUBLICKEY => false,
        METHOD_PUBLICKEY_HOSTBOUND => true,
        _ => return None,
    };
    if u8::decode(&mut reader).ok()? != 1 {
        // "sig-follows": the client always sends 1 when it's actually
        // asking for a signature, which is the only case kpa ever sees.
        return None;
    }
    let pkalg = String::decode(&mut reader).ok()?;
    let claimed_algorithm = Algorithm::new(&pkalg).ok()?;
    if !same_key_type(&claimed_algorithm, &signing_key.algorithm()) {
        return None;
    }
    let key_blob = read_key_blob(&mut reader).ok()?;
    if &key_blob != signing_key.key_data() {
        return None;
    }
    let hostbound_hostkey = if hostbound {
        Some(read_key_blob(&mut reader).ok()?)
    } else {
        None
    };
    reader.ensure_finished().ok()?;

    Some(LoginRequest {
        session_id,
        user,
        hostbound_hostkey,
    })
}

fn try_sshsig(data: &[u8]) -> Option<String> {
    let mut reader: &[u8] = data;

    let mut magic = [0u8; SSHSIG_MAGIC.len()];
    reader.read(&mut magic).ok()?;
    if &magic != SSHSIG_MAGIC {
        return None;
    }
    let namespace = String::decode(&mut reader).ok()?;
    if namespace.is_empty() {
        return None;
    }
    let _reserved = Vec::<u8>::decode(&mut reader).ok()?;
    let _hash_algorithm = String::decode(&mut reader).ok()?;
    let _hash = Vec::<u8>::decode(&mut reader).ok()?;
    reader.ensure_finished().ok()?;

    Some(namespace)
}

#[cfg(test)]
mod tests {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    use super::*;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// A deterministic, non-cryptographic stand-in for `OsRng` — these
    /// tests only need *a* valid keypair, never a secret one, and a fixed
    /// seed keeps them reproducible.
    struct TestRng(u64);

    impl TestRng {
        fn next(&mut self) -> u64 {
            // splitmix64
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
            #[allow(clippy::cast_possible_truncation)]
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

    /// A fresh seed per call, so two calls (even for the same algorithm)
    /// never produce the same keypair — several tests below need two
    /// distinct keys to tell apart.
    fn test_key(algorithm: Algorithm) -> PrivateKey {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEED: AtomicU64 = AtomicU64::new(0x5EED);
        let seed = SEED.fetch_add(1, Ordering::Relaxed);
        PrivateKey::random(&mut TestRng(seed), algorithm).expect("key generation")
    }

    /// Builds the bytes OpenSSH's `sign_and_send_pubkey` builds
    /// (`sshconnect2.c`), so these tests exercise the exact wire shape a
    /// real `ssh` produces, not a reimplementation of it. `new` gives a
    /// well-formed `publickey` login for `pkalg`/`key_blob`; tests override
    /// just the field they're exercising.
    struct LoginFields<'a> {
        session_id: &'a [u8],
        user: &'a str,
        service: &'a str,
        method: &'a str,
        sig_follows: Option<u8>,
        pkalg: &'a str,
        key_blob: &'a [u8],
        hostkey_blob: Option<&'a [u8]>,
        trailing: &'a [u8],
    }

    impl<'a> LoginFields<'a> {
        fn new(pkalg: &'a str, key_blob: &'a [u8]) -> Self {
            Self {
                session_id: b"session-id",
                user: "alice",
                service: "ssh-connection",
                method: "publickey",
                sig_follows: Some(1),
                pkalg,
                key_blob,
                hostkey_blob: None,
                trailing: &[],
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut out = string(self.session_id);
            out.push(SSH2_MSG_USERAUTH_REQUEST);
            out.extend(string(self.user.as_bytes()));
            out.extend(string(self.service.as_bytes()));
            out.extend(string(self.method.as_bytes()));
            if let Some(byte) = self.sig_follows {
                out.push(byte);
            }
            out.extend(string(self.pkalg.as_bytes()));
            out.extend(string(self.key_blob));
            if let Some(hostkey) = self.hostkey_blob {
                out.extend(string(hostkey));
            }
            out.extend_from_slice(self.trailing);
            out
        }
    }

    fn key_blob_bytes(key: &PrivateKey) -> Vec<u8> {
        key.public_key().to_bytes().expect("key encodes")
    }

    #[test]
    fn a_well_formed_publickey_login_is_recognized_for_each_key_type() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
            Algorithm::Rsa { hash: None },
        ] {
            let key = test_key(algorithm.clone());
            let public = key.public_key();
            let pkalg = match algorithm {
                Algorithm::Rsa { .. } => "rsa-sha2-256".to_string(),
                _ => algorithm.as_str().to_string(),
            };
            let data = LoginFields::new(&pkalg, &key_blob_bytes(&key)).bytes();
            let purpose = classify(&data, public);
            let Purpose::Login(login) = purpose else {
                panic!("{algorithm:?}: expected a login, got {purpose:?}");
            };
            assert_eq!(login.session_id, b"session-id");
            assert_eq!(login.user, "alice");
            assert_eq!(login.hostbound_hostkey, None);
        }
    }

    #[test]
    fn a_hostbound_login_carries_the_hostkey() {
        let key = test_key(Algorithm::Ed25519);
        let hostkey = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let hostkey_blob = key_blob_bytes(&hostkey);
        let data = LoginFields {
            user: "bob",
            method: METHOD_PUBLICKEY_HOSTBOUND,
            hostkey_blob: Some(&hostkey_blob),
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        let Purpose::Login(login) = classify(&data, key.public_key()) else {
            panic!("expected a login");
        };
        assert_eq!(
            login.hostbound_hostkey.as_ref(),
            Some(hostkey.public_key().key_data())
        );
    }

    #[test]
    fn trailing_bytes_after_a_login_are_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let data = LoginFields {
            trailing: b"trailing",
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn trailing_bytes_after_a_hostbound_login_are_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let hostkey = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let hostkey_blob = key_blob_bytes(&hostkey);
        let data = LoginFields {
            method: METHOD_PUBLICKEY_HOSTBOUND,
            hostkey_blob: Some(&hostkey_blob),
            trailing: b"x",
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn a_key_blob_that_doesnt_match_the_signing_key_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let other = test_key(Algorithm::Ed25519);
        let other_blob = key_blob_bytes(&other);
        let data = LoginFields::new("ssh-ed25519", &other_blob).bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn an_empty_session_id_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let data = LoginFields {
            session_id: b"",
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn a_non_ssh_connection_service_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let data = LoginFields {
            service: "not-ssh-connection",
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn an_unknown_method_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let data = LoginFields {
            method: "publickey-v2@example.com",
            ..LoginFields::new("ssh-ed25519", &key_blob)
        }
        .bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn sig_follows_must_be_exactly_one() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        for byte in [0u8, 2u8] {
            let data = LoginFields {
                sig_follows: Some(byte),
                ..LoginFields::new("ssh-ed25519", &key_blob)
            }
            .bytes();
            assert_eq!(classify(&data, key.public_key()), Purpose::Other);
        }
    }

    #[test]
    fn a_pkalg_naming_a_different_key_type_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let key_blob = key_blob_bytes(&key);
        let data = LoginFields::new("ecdsa-sha2-nistp256", &key_blob).bytes();
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn rsa_sha2_variants_both_match_an_rsa_key() {
        let key = test_key(Algorithm::Rsa { hash: None });
        let key_blob = key_blob_bytes(&key);
        for pkalg in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
            let data = LoginFields::new(pkalg, &key_blob).bytes();
            assert!(
                matches!(classify(&data, key.public_key()), Purpose::Login(_)),
                "{pkalg} should match an RSA key"
            );
        }
    }

    #[test]
    fn a_well_formed_sshsig_blob_yields_its_namespace() {
        let key = test_key(Algorithm::Ed25519);
        let signed = ssh_key::SshSig::sign(&key, "git", HashAlg::Sha512, b"commit contents")
            .expect("signing should succeed");
        let data =
            ssh_key::SshSig::signed_data(signed.namespace(), signed.hash_alg(), b"commit contents")
                .expect("rebuilding the signed data should succeed");

        assert_eq!(
            classify(&data, key.public_key()),
            Purpose::SshSig {
                namespace: "git".to_string()
            }
        );
    }

    #[test]
    fn trailing_bytes_after_an_sshsig_blob_are_rejected() {
        let key = test_key(Algorithm::Ed25519);
        let mut data =
            ssh_key::SshSig::signed_data("git", HashAlg::Sha256, b"hello").expect("builds");
        data.push(0xff);
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn an_empty_sshsig_namespace_is_rejected() {
        let key = test_key(Algorithm::Ed25519);
        // `signed_data` itself refuses an empty namespace, so the bytes
        // are built by hand here.
        let mut data = Vec::new();
        data.extend_from_slice(SSHSIG_MAGIC);
        data.extend(string(b"")); // namespace
        data.extend(string(b"")); // reserved
        data.extend(string(b"sha256"));
        data.extend(string(
            b"0123456789012345678901234567890123456789012345678901234567890a",
        ));
        assert_eq!(classify(&data, key.public_key()), Purpose::Other);
    }

    #[test]
    fn an_sshsig_blob_doesnt_need_the_signature_itself() {
        // Confirms this module parses the pre-signature "signed data"
        // blob (`PROTOCOL.sshsig` § 3), not the full armored `SshSig`
        // (which also carries the public key and signature): `SshSig`'s
        // own PEM round-trip is deliberately not exercised here.
        let key = test_key(Algorithm::Ed25519);
        let data = ssh_key::SshSig::signed_data("file", HashAlg::Sha256, b"doc").expect("builds");
        assert_eq!(
            classify(&data, key.public_key()),
            Purpose::SshSig {
                namespace: "file".to_string()
            }
        );
    }

    #[test]
    fn arbitrary_data_is_other() {
        let key = test_key(Algorithm::Ed25519);
        assert_eq!(
            classify(b"just some bytes", key.public_key()),
            Purpose::Other
        );
        assert_eq!(classify(&[], key.public_key()), Purpose::Other);
    }

    /// Pins that signing with a real key and verifying with `ssh-key`
    /// still lines up with `SshSig::to_pem`'s armor — a cheap sanity check
    /// that this module's understanding of the format matches the
    /// library actually used to sign and verify in later tasks.
    #[test]
    fn a_signed_sshsig_still_verifies_through_ssh_key() {
        let key = test_key(Algorithm::Ed25519);
        let sig = ssh_key::SshSig::sign(&key, "file", HashAlg::Sha256, b"contents")
            .expect("signing should succeed");
        let pem = sig.to_pem(LineEnding::LF).expect("pem encoding");
        let parsed = pem.parse::<ssh_key::SshSig>().expect("pem decoding");
        key.public_key()
            .verify("file", b"contents", &parsed)
            .expect("verification should succeed");
    }
}
