//! Values the stores' and the state's tests share.

use ssh_key::Fingerprint;
use ssh_key::public::KeyData;

use super::{RequestDetails, Scope, SignatureApproval};
use crate::ssh::keys::{self, ServedKey};
use crate::ssh::testing::{database, test_key};

pub(super) fn fingerprint(seed: u64) -> Fingerprint {
    test_key(seed)
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
}

pub(super) fn host_key(seed: u64) -> KeyData {
    test_key(seed).public_key().key_data().clone()
}

pub(super) fn approval(key: u64, destination: Option<u64>, remember: bool) -> SignatureApproval {
    SignatureApproval {
        scope: Scope::new(fingerprint(key), destination.map(host_key).as_ref()),
        remember,
    }
}

/// The key `approval(1, ..)` is for, as an open database serves it.
pub(super) fn key() -> ServedKey {
    let cfg = database("personal", vec![]);
    keys::resolve_cached(&cfg, vec![test_key(1).public_key().clone()]).remove(0)
}

pub(super) fn requested(command: &str) -> RequestDetails {
    RequestDetails {
        purpose: "login",
        user: Some("alice".to_string()),
        namespace: None,
        class: "local",
        command: Some(command.to_string()),
    }
}
