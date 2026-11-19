//! Test helpers for this subsystem's unit tests: real
//! `session-bind@openssh.com` messages.

use signature::Signer;
use ssh_key::encoding::Encode;
use ssh_key::{PrivateKey, Signature};

use super::wire::SessionBind;

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
