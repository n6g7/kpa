#![no_main]

use kpa::frontends::ssh_agent::{bind, classify, wire};
use libfuzzer_sys::fuzz_target;
use ssh_key::PublicKey;
use ssh_key::public::{Ed25519PublicKey, KeyData};

// Exercises the three pure modules under `src/frontends/ssh_agent/`, the
// same way `decode_request` exercises `src/frontends/control/proto/`: the
// property checked is that arbitrary bytes only ever produce a value or a
// refusal, never a panic and never a hang. None of `wire`, `classify` or
// `bind` does I/O or holds unbounded state, so there's nothing here that
// should be able to loop or allocate without bound either.
//
// The first byte picks which path gets the rest of the input:
//
// - `0`: `wire::next_frame` on the raw bytes — the incremental framer a
//   real connection feeds a growing buffer into.
// - `1`: `wire::decode_request` on the raw bytes directly, as a message
//   body (type byte included, no outer length).
// - `2`: the rest becomes the *body* of a real `EXTENSION
//   session-bind@openssh.com` message (the extension name itself is
//   fixed, so coverage reaches past it on every run) — hostkey, session
//   id, signature and `is_forwarding` are all attacker-controlled bytes,
//   same as a real connection. A body that happens to decode is applied
//   to a fresh `SessionBindState` twice (the second time exercises the
//   already-recorded/duplicate path) and classified.
// - `3`: the rest becomes the `data` field of a `SIGN_REQUEST` whose key
//   blob is fixed (so the message always decodes), pushed through
//   `classify` against that same fixed key.
// - anything else: the whole input is tried as a single frame, through
//   both `next_frame` and `decode_request` in sequence, the way a real
//   connection's read loop would.
fuzz_target!(|data: &[u8]| {
    match data.split_first() {
        Some((0, rest)) => {
            let _ = wire::next_frame(rest);
        }
        Some((1, rest)) => {
            let _ = wire::decode_request(rest);
        }
        Some((2, rest)) => {
            let message = session_bind_message(rest);
            if let wire::AgentRequest::SessionBind(bind_msg) = wire::decode_request(&message) {
                let mut bindings = bind::SessionBindState::new();
                let _ = bindings.apply(&bind_msg);
                let _ = bindings.apply(&bind_msg); // the duplicate-binding path
                let _ = bindings.class();
            }
        }
        Some((3, rest)) => {
            let message = sign_request_message(rest);
            if let wire::AgentRequest::SignRequest(sign) = wire::decode_request(&message) {
                let _ = classify::classify(&sign.data, &fixed_signing_key());
            }
        }
        _ => {
            if let Ok(wire::Frame::Complete { message, .. }) = wire::next_frame(data) {
                let _ = wire::decode_request(message);
            }
        }
    }
});

/// RFC 4251 §5 `string`: a `uint32` length, then the bytes.
fn string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// A fixed, arbitrary Ed25519 key — never used for real cryptography here,
/// only as a stable point of comparison for `classify` and a key blob
/// `SIGN_REQUEST` can always decode.
fn fixed_signing_key() -> PublicKey {
    PublicKey::from(KeyData::Ed25519(Ed25519PublicKey([0x42; 32])))
}

/// An `EXTENSION session-bind@openssh.com` message (type byte and
/// extension name fixed) whose body is exactly `body` — every byte past
/// the name is attacker-controlled, the same as a real connection.
fn session_bind_message(body: &[u8]) -> Vec<u8> {
    let mut message = vec![27];
    message.extend(string(b"session-bind@openssh.com"));
    message.extend_from_slice(body);
    message
}

/// A `SIGN_REQUEST` (type byte and key blob fixed, so it always decodes)
/// whose `data` field is exactly `data`.
fn sign_request_message(data: &[u8]) -> Vec<u8> {
    let key_blob = fixed_signing_key()
        .to_bytes()
        .expect("a fixed Ed25519 key always encodes");
    let mut message = vec![13];
    message.extend(string(&key_blob));
    message.extend(string(data));
    message.extend_from_slice(&0u32.to_be_bytes());
    message
}
