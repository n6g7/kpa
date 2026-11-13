//! The SSH agent wire protocol kpa speaks: [RFC 9987], plus OpenSSH's
//! `session-bind@openssh.com` extension (`PROTOCOL.agent` § 1, mirrored in
//! `docs/ssh-agent.md` § 6.1, 6.2). This module turns bytes already read off
//! the socket into an [`AgentRequest`], and an [`AgentResponse`] into the
//! bytes to write back — no I/O, and no socket of its own.
//!
//! Framing is `uint32` length, then the message ([`next_frame`]).
//! [`decode_request`] never fails: every message `§ 6.1`'s table doesn't
//! list, and every message this build recognizes the type byte of but can't
//! otherwise parse, decodes to [`AgentRequest::Unsupported`] — answered with
//! `SSH_AGENT_FAILURE` by whoever dispatches it, the same way OpenSSH's own
//! `ssh-agent` answers a request it can't make sense of (`process_message`
//! in its `ssh-agent.c`: any parse failure falls through to a generic
//! failure reply, regardless of which message type started it).
//!
//! [RFC 9987]: https://www.rfc-editor.org/rfc/rfc9987.html

use ssh_key::encoding::{Decode, Encode, Reader};

/// `AGENT_MAX_LEN` in OpenSSH's `ssh-agent.c`: the largest message this
/// agent accepts. [`next_frame`] checks a frame's declared length against
/// this before ever looking at whether the body has arrived, so a peer
/// can't make the agent wait on megabytes it was never going to accept.
pub const MAX_FRAME_LEN: usize = 256 * 1024;

/// Agent request message numbers ([RFC 9987] § 8.1).
///
/// [RFC 9987]: https://www.rfc-editor.org/rfc/rfc9987.html
mod request_type {
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const SIGN_REQUEST: u8 = 13;
    pub const EXTENSION: u8 = 27;
}

/// Agent response message numbers ([RFC 9987] § 8.1).
///
/// [RFC 9987]: https://www.rfc-editor.org/rfc/rfc9987.html
mod response_type {
    pub const FAILURE: u8 = 5;
    pub const SUCCESS: u8 = 6;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_RESPONSE: u8 = 14;
    pub const EXTENSION_FAILURE: u8 = 28;
    pub const EXTENSION_RESPONSE: u8 = 29;
}

/// The one extension name kpa verifies itself (`bind` does the actual
/// work); `query` is answered right here since its reply is fixed.
const SESSION_BIND_EXTENSION: &str = "session-bind@openssh.com";
const QUERY_EXTENSION: &str = "query";

/// One frame pulled off the front of a byte buffer that's still growing as
/// more arrives from the socket. Pure: it looks at `buf` and says what it
/// sees, and never reads a socket itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `buf` doesn't hold a whole frame yet — read more before calling
    /// [`next_frame`] again.
    Incomplete,
    /// A whole frame at the front of `buf`. `message` is its body (the
    /// bytes after the `uint32` length, type byte included); `consumed` is
    /// how much of `buf` to drop — length prefix included — before pulling
    /// the next one.
    Complete { message: &'a [u8], consumed: usize },
}

/// [`next_frame`]'s one failure: a declared length over [`MAX_FRAME_LEN`].
/// `docs/ssh-agent.md` § 6.1 says what a caller does with it: close the
/// connection. There is no resynchronizing with a peer that announced a
/// frame this large — the only bytes known about it are the four that said
/// so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oversize;

/// Pull one frame off the front of `buf`, if a whole one has arrived yet.
///
/// # Errors
/// [`Oversize`] if the declared length exceeds [`MAX_FRAME_LEN`] — checked
/// before `buf` is asked to actually hold that many bytes, so a four-byte
/// header claiming gigabytes is rejected at once rather than after however
/// much of it the caller was willing to buffer.
pub fn next_frame(buf: &[u8]) -> Result<Frame<'_>, Oversize> {
    if buf.len() < 4 {
        return Ok(Frame::Incomplete);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(Oversize);
    }
    if buf.len() < 4 + len {
        return Ok(Frame::Incomplete);
    }
    Ok(Frame::Complete {
        message: &buf[4..4 + len],
        consumed: 4 + len,
    })
}

/// Encode `message` (type byte included) with its `uint32` length prefix,
/// ready to write to the socket.
///
/// # Panics
/// If `message` is longer than [`MAX_FRAME_LEN`] — never true of anything
/// this module builds; kept as an assertion rather than silently truncating
/// or lying about a response's length.
#[must_use]
pub fn encode_frame(message: &[u8]) -> Vec<u8> {
    assert!(message.len() <= MAX_FRAME_LEN, "built an oversize frame");
    #[allow(clippy::cast_possible_truncation)] // just asserted <= MAX_FRAME_LEN
    let len = message.len() as u32;
    let mut framed = Vec::with_capacity(4 + message.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

/// `SSH_AGENTC_SIGN_REQUEST`'s flags ([RFC 9987] § 8.3). Only two bits are
/// defined, and both are meaningful for `ssh-rsa` keys only. A bit this
/// build doesn't know about is kept in [`SignFlags::raw`] but otherwise
/// ignored — an unknown flag is not by itself a reason to refuse a
/// request, the same way OpenSSH's `ssh-agent` treats one.
///
/// [RFC 9987]: https://www.rfc-editor.org/rfc/rfc9987.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignFlags(u32);

impl SignFlags {
    const RSA_SHA2_256: u32 = 0x0000_0002;
    const RSA_SHA2_512: u32 = 0x0000_0004;

    #[must_use]
    pub fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The request asked for an `rsa-sha2-256` signature rather than the
    /// legacy SHA-1 `ssh-rsa`.
    #[must_use]
    pub fn rsa_sha2_256(self) -> bool {
        self.0 & Self::RSA_SHA2_256 != 0
    }

    /// The request asked for an `rsa-sha2-512` signature.
    #[must_use]
    pub fn rsa_sha2_512(self) -> bool {
        self.0 & Self::RSA_SHA2_512 != 0
    }

    /// The flags exactly as the client sent them, unknown bits included.
    #[must_use]
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// `SSH_AGENTC_SIGN_REQUEST`'s body. `key_blob` and `data` are carried
/// unparsed: matching `key_blob` against a served key is `keys.rs`'s job,
/// and [`classify`](super::classify) says what `data` means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: SignFlags,
}

/// `session-bind@openssh.com`'s fields, read structurally — every field is
/// the raw bytes of the `string` or `bool` on the wire. Parsing `hostkey`
/// and `signature` into real key/signature types, and verifying the
/// signature, is [`bind`](super::bind)'s job: this module only has to know
/// the shape well enough to tell the extension apart from `query` and from
/// one it doesn't recognize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    pub hostkey: Vec<u8>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub is_forwarding: bool,
}

/// One identity `REQUEST_IDENTITIES` lists: a served key and its comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// One decoded agent request — the message half of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    RequestIdentities,
    SignRequest(SignRequest),
    SessionBind(SessionBind),
    /// `EXTENSION query`: which extensions this build answers for real.
    ExtensionQuery,
    /// Every message `§ 6.1`'s table doesn't list (add, remove, remove-all,
    /// smartcard, `LOCK`, `UNLOCK`, any other extension), and every message
    /// whose type byte this module recognizes but whose body doesn't parse.
    /// Always answered `SSH_AGENT_FAILURE`.
    Unsupported,
}

/// Decode one message — a [`Frame::Complete`]'s `message`, type byte
/// included. Total: never fails. Anything this build doesn't handle, or
/// can't parse, comes back as [`AgentRequest::Unsupported`] rather than an
/// error, since that's exactly the one response every unhandled case gets.
#[must_use]
pub fn decode_request(message: &[u8]) -> AgentRequest {
    try_decode(message).unwrap_or(AgentRequest::Unsupported)
}

fn try_decode(message: &[u8]) -> ssh_key::Result<AgentRequest> {
    let mut reader: &[u8] = message;
    let kind = u8::decode(&mut reader)?;
    match kind {
        request_type::REQUEST_IDENTITIES => {
            reader.ensure_finished()?;
            Ok(AgentRequest::RequestIdentities)
        }
        request_type::SIGN_REQUEST => {
            let key_blob = Vec::<u8>::decode(&mut reader)?;
            let data = Vec::<u8>::decode(&mut reader)?;
            let flags = u32::decode(&mut reader)?;
            reader.ensure_finished()?;
            Ok(AgentRequest::SignRequest(SignRequest {
                key_blob,
                data,
                flags: SignFlags(flags),
            }))
        }
        request_type::EXTENSION => decode_extension(&mut reader),
        _ => Ok(AgentRequest::Unsupported),
    }
}

fn decode_extension(reader: &mut &[u8]) -> ssh_key::Result<AgentRequest> {
    let name = String::decode(reader)?;
    match name.as_str() {
        SESSION_BIND_EXTENSION => {
            let hostkey = Vec::<u8>::decode(reader)?;
            let session_id = Vec::<u8>::decode(reader)?;
            let signature = Vec::<u8>::decode(reader)?;
            let is_forwarding = bool::decode(reader)?;
            reader.ensure_finished()?;
            Ok(AgentRequest::SessionBind(SessionBind {
                hostkey,
                session_id,
                signature,
                is_forwarding,
            }))
        }
        // `query` carries nothing else, and OpenSSH's own agent doesn't
        // check for trailing bytes after the name either — see
        // `process_ext_query` in `ssh-agent.c`.
        QUERY_EXTENSION => Ok(AgentRequest::ExtensionQuery),
        _ => Ok(AgentRequest::Unsupported),
    }
}

/// One agent response — what a decoded [`AgentRequest`] becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentResponse {
    IdentitiesAnswer(Vec<Identity>),
    /// Already in the standard SSH signature encoding (algorithm name,
    /// then its algorithm-specific blob): the caller signs with `ssh-key`
    /// and hands over `Signature::encode_vec()`'s result unchanged.
    SignResponse(Vec<u8>),
    Success,
    Failure,
    ExtensionFailure,
    /// `query`'s reply: the extensions this build answers for real.
    ExtensionResponse(Vec<String>),
}

/// Encode `response` into the bytes to write to the socket — framed, ready
/// to go straight to the connection.
#[must_use]
pub fn encode_response(response: &AgentResponse) -> Vec<u8> {
    const INFALLIBLE: &str = "encoding into a Vec<u8> never fails";

    let mut message = Vec::new();
    match response {
        AgentResponse::IdentitiesAnswer(identities) => {
            message.push(response_type::IDENTITIES_ANSWER);
            #[allow(clippy::cast_possible_truncation)] // bounded by MAX_FRAME_LEN below
            let count = identities.len() as u32;
            message.extend_from_slice(&count.to_be_bytes());
            for identity in identities {
                identity.key_blob.encode(&mut message).expect(INFALLIBLE);
                identity.comment.encode(&mut message).expect(INFALLIBLE);
            }
        }
        AgentResponse::SignResponse(signature) => {
            message.push(response_type::SIGN_RESPONSE);
            signature.encode(&mut message).expect(INFALLIBLE);
        }
        AgentResponse::Success => message.push(response_type::SUCCESS),
        AgentResponse::Failure => message.push(response_type::FAILURE),
        AgentResponse::ExtensionFailure => message.push(response_type::EXTENSION_FAILURE),
        AgentResponse::ExtensionResponse(names) => {
            message.push(response_type::EXTENSION_RESPONSE);
            QUERY_EXTENSION.encode(&mut message).expect(INFALLIBLE);
            for name in names {
                name.encode(&mut message).expect(INFALLIBLE);
            }
        }
    }
    encode_frame(&message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4251 §5 `string`: a `uint32` length, then the bytes.
    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    fn framed(message: &[u8]) -> Vec<u8> {
        encode_frame(message)
    }

    // --- Framing -----------------------------------------------------

    #[test]
    fn an_empty_buffer_is_incomplete() {
        assert_eq!(next_frame(&[]), Ok(Frame::Incomplete));
    }

    #[test]
    fn a_short_length_prefix_is_incomplete() {
        assert_eq!(next_frame(&[0, 0, 0]), Ok(Frame::Incomplete));
    }

    #[test]
    fn a_truncated_body_is_incomplete() {
        // Declares 5 bytes, only 2 are here.
        let mut buf = vec![0, 0, 0, 5];
        buf.extend_from_slice(b"he");
        assert_eq!(next_frame(&buf), Ok(Frame::Incomplete));
    }

    #[test]
    fn a_whole_frame_decodes_and_reports_its_consumed_length() {
        let mut buf = vec![0, 0, 0, 3];
        buf.extend_from_slice(b"abc");
        buf.extend_from_slice(b"next frame's bytes");
        assert_eq!(
            next_frame(&buf),
            Ok(Frame::Complete {
                message: b"abc",
                consumed: 7,
            })
        );
    }

    #[test]
    fn a_declared_length_over_the_cap_is_oversize() {
        let mut buf = vec![0, 0, 0, 0];
        let too_big = u32::try_from(MAX_FRAME_LEN + 1).expect("fits a u32");
        buf[..4].copy_from_slice(&too_big.to_be_bytes());
        assert_eq!(next_frame(&buf), Err(Oversize));
    }

    #[test]
    fn oversize_is_reported_before_the_body_has_to_arrive() {
        // Only the four-byte header is present — no body at all — yet the
        // declared length alone is enough to reject it.
        let too_big = u32::try_from(MAX_FRAME_LEN + 1).expect("fits a u32");
        assert_eq!(next_frame(&too_big.to_be_bytes()), Err(Oversize));
    }

    #[test]
    fn exactly_the_cap_is_not_oversize() {
        let mut buf = Vec::new();
        let at_cap = u32::try_from(MAX_FRAME_LEN).expect("fits a u32");
        buf.extend_from_slice(&at_cap.to_be_bytes());
        buf.extend(std::iter::repeat_n(0u8, MAX_FRAME_LEN));
        assert_eq!(
            next_frame(&buf),
            Ok(Frame::Complete {
                message: &buf[4..],
                consumed: buf.len(),
            })
        );
    }

    // --- Decoding: one case per § 6.1 table row -----------------------

    #[test]
    fn request_identities_has_no_body() {
        assert_eq!(decode_request(&[11]), AgentRequest::RequestIdentities);
    }

    #[test]
    fn a_trailing_byte_after_request_identities_is_unsupported() {
        assert_eq!(decode_request(&[11, 0]), AgentRequest::Unsupported);
    }

    #[test]
    fn sign_request_carries_the_key_blob_data_and_flags() {
        let mut message = vec![13];
        message.extend(string(b"key-blob"));
        message.extend(string(b"data-to-sign"));
        message.extend(0x0000_0006u32.to_be_bytes()); // both RSA flags

        let AgentRequest::SignRequest(request) = decode_request(&message) else {
            panic!("should decode as a sign request");
        };
        assert_eq!(request.key_blob, b"key-blob");
        assert_eq!(request.data, b"data-to-sign");
        assert!(request.flags.rsa_sha2_256());
        assert!(request.flags.rsa_sha2_512());
    }

    #[test]
    fn sign_request_with_no_flags_asks_for_neither_rsa_variant() {
        let mut message = vec![13];
        message.extend(string(b"k"));
        message.extend(string(b"d"));
        message.extend(0u32.to_be_bytes());

        let AgentRequest::SignRequest(request) = decode_request(&message) else {
            panic!("should decode as a sign request");
        };
        assert!(!request.flags.rsa_sha2_256());
        assert!(!request.flags.rsa_sha2_512());
        assert_eq!(request.flags.raw(), 0);
    }

    #[test]
    fn an_unknown_flag_bit_is_kept_but_doesnt_set_the_named_ones() {
        let mut message = vec![13];
        message.extend(string(b"k"));
        message.extend(string(b"d"));
        message.extend(0x8000_0000u32.to_be_bytes());

        let AgentRequest::SignRequest(request) = decode_request(&message) else {
            panic!("should decode as a sign request");
        };
        assert!(!request.flags.rsa_sha2_256());
        assert!(!request.flags.rsa_sha2_512());
        assert_eq!(request.flags.raw(), 0x8000_0000);
    }

    #[test]
    fn a_sign_request_missing_its_flags_is_unsupported() {
        let mut message = vec![13];
        message.extend(string(b"k"));
        message.extend(string(b"d"));
        // No flags field at all.
        assert_eq!(decode_request(&message), AgentRequest::Unsupported);
    }

    #[test]
    fn session_bind_carries_all_four_fields() {
        let mut message = vec![27];
        message.extend(string(SESSION_BIND_EXTENSION.as_bytes()));
        message.extend(string(b"hostkey-bytes"));
        message.extend(string(b"session-id-bytes"));
        message.extend(string(b"signature-bytes"));
        message.push(1); // is_forwarding

        let AgentRequest::SessionBind(bind) = decode_request(&message) else {
            panic!("should decode as a session bind");
        };
        assert_eq!(bind.hostkey, b"hostkey-bytes");
        assert_eq!(bind.session_id, b"session-id-bytes");
        assert_eq!(bind.signature, b"signature-bytes");
        assert!(bind.is_forwarding);
    }

    #[test]
    fn session_bind_is_forwarding_false() {
        let mut message = vec![27];
        message.extend(string(SESSION_BIND_EXTENSION.as_bytes()));
        message.extend(string(b"h"));
        message.extend(string(b"s"));
        message.extend(string(b"g"));
        message.push(0);

        let AgentRequest::SessionBind(bind) = decode_request(&message) else {
            panic!("should decode as a session bind");
        };
        assert!(!bind.is_forwarding);
    }

    #[test]
    fn a_session_bind_with_trailing_bytes_is_unsupported() {
        let mut message = vec![27];
        message.extend(string(SESSION_BIND_EXTENSION.as_bytes()));
        message.extend(string(b"h"));
        message.extend(string(b"s"));
        message.extend(string(b"g"));
        message.push(0);
        message.push(0xff); // trailing garbage
        assert_eq!(decode_request(&message), AgentRequest::Unsupported);
    }

    #[test]
    fn extension_query_decodes() {
        let mut message = vec![27];
        message.extend(string(QUERY_EXTENSION.as_bytes()));
        assert_eq!(decode_request(&message), AgentRequest::ExtensionQuery);
    }

    #[test]
    fn an_unrecognized_extension_is_unsupported() {
        let mut message = vec![27];
        message.extend(string(b"made-up@example.com"));
        message.extend(b"whatever contents");
        assert_eq!(decode_request(&message), AgentRequest::Unsupported);
    }

    #[test]
    fn an_extension_whose_name_doesnt_even_parse_is_unsupported() {
        // Declares a name longer than what follows.
        let mut message = vec![27];
        message.extend(100u32.to_be_bytes());
        message.extend(b"short");
        assert_eq!(decode_request(&message), AgentRequest::Unsupported);
    }

    /// Every message `§ 6.1`'s table routes to `FAILURE`: add, remove,
    /// remove-all, smartcard add/remove, `LOCK`, `UNLOCK`.
    #[test]
    fn every_unhandled_message_type_is_unsupported() {
        for kind in [17, 18, 19, 20, 21, 22, 23, 26] {
            assert_eq!(
                decode_request(&[kind]),
                AgentRequest::Unsupported,
                "message type {kind} should be unsupported"
            );
        }
    }

    #[test]
    fn an_empty_message_is_unsupported() {
        assert_eq!(decode_request(&[]), AgentRequest::Unsupported);
    }

    // --- Encoding: one case per documented response -------------------

    #[test]
    fn identities_answer_encodes_the_count_then_each_key_and_comment() {
        let response = AgentResponse::IdentitiesAnswer(vec![
            Identity {
                key_blob: b"key-one".to_vec(),
                comment: "github".to_string(),
            },
            Identity {
                key_blob: b"key-two".to_vec(),
                comment: "work".to_string(),
            },
        ]);

        let mut expected = vec![12];
        expected.extend(2u32.to_be_bytes());
        expected.extend(string(b"key-one"));
        expected.extend(string(b"github"));
        expected.extend(string(b"key-two"));
        expected.extend(string(b"work"));
        assert_eq!(encode_response(&response), framed(&expected));
    }

    #[test]
    fn an_empty_identities_answer_still_states_its_zero_count() {
        let mut expected = vec![12];
        expected.extend(0u32.to_be_bytes());
        assert_eq!(
            encode_response(&AgentResponse::IdentitiesAnswer(Vec::new())),
            framed(&expected)
        );
    }

    #[test]
    fn sign_response_carries_the_signature_bytes_as_is() {
        let mut expected = vec![14];
        expected.extend(string(b"already-encoded-signature"));
        assert_eq!(
            encode_response(&AgentResponse::SignResponse(
                b"already-encoded-signature".to_vec()
            )),
            framed(&expected)
        );
    }

    #[test]
    fn success_is_one_byte() {
        assert_eq!(encode_response(&AgentResponse::Success), framed(&[6]));
    }

    #[test]
    fn failure_is_one_byte() {
        assert_eq!(encode_response(&AgentResponse::Failure), framed(&[5]));
    }

    #[test]
    fn extension_failure_is_one_byte() {
        assert_eq!(
            encode_response(&AgentResponse::ExtensionFailure),
            framed(&[28])
        );
    }

    #[test]
    fn extension_response_names_query_and_lists_the_supported_extensions() {
        let mut expected = vec![29];
        expected.extend(string(b"query"));
        expected.extend(string(b"session-bind@openssh.com"));
        assert_eq!(
            encode_response(&AgentResponse::ExtensionResponse(vec![
                "session-bind@openssh.com".to_string()
            ])),
            framed(&expected)
        );
    }

    /// Every response is framed: a `uint32` length, then the message —
    /// not just the message on its own.
    #[test]
    fn every_response_comes_out_framed() {
        for response in [
            AgentResponse::Success,
            AgentResponse::Failure,
            AgentResponse::ExtensionFailure,
            AgentResponse::IdentitiesAnswer(Vec::new()),
            AgentResponse::SignResponse(Vec::new()),
            AgentResponse::ExtensionResponse(Vec::new()),
        ] {
            let bytes = encode_response(&response);
            assert!(bytes.len() >= 4, "{response:?} should have a length prefix");
            let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            assert_eq!(declared, bytes.len() - 4, "{response:?}'s declared length");
        }
    }
}
