//! The request half of the protocol, plus the two failures that happen
//! before a request is recognized as an op at all.
//!
//! [`ProtocolError`] is the wire-facing side of [`DecodeError`]; both live
//! here rather than in an op module because neither belongs to any op —
//! at the point they arise, which op was asked for isn't known.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::VERSION;
use super::copy::CopyRequest;
use super::error::{ErrorCode, ErrorFields};
use super::list::ListRequest;
use super::lock::LockRequest;
use super::unlock::UnlockRequest;
use crate::io::ByteCounter;

/// One request. `op` is `#[serde(flatten)]`ed so the wire shape is a single
/// flat object (`{"v":1,"op":"unlock","db":"personal"}`) rather than
/// `op` nesting its own sub-object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub v: u32,
    #[serde(flatten)]
    pub op: Op,
}

/// Which op, plus its payload. Each variant wraps the request type from
/// that op's own module, and `#[serde(tag = "op")]` flattens the wrapped
/// struct's fields into the same object — so `Op::List(ListRequest { db })`
/// goes over the wire as `{"op":"list","db":"personal"}`, unchanged.
///
/// `Status` stays a unit variant: its request carries nothing, and an
/// empty struct would be ceremony with no field to hold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Status,
    Unlock(UnlockRequest),
    Lock(LockRequest),
    List(ListRequest),
    Copy(CopyRequest),
}

/// Why `decode_request` gave up. Deliberately one bucket for every JSON/shape
/// problem: none of them give a client anything more actionable than "fix
/// the request", and (matching the policy on `vault::VaultError::Corrupt`)
/// `serde_json`'s own error text is never forwarded to the client.
#[derive(Debug)]
pub enum DecodeError {
    /// Not valid JSON, missing/non-numeric `v`, an `op` shape this build
    /// doesn't recognize, or a `password` that `Password` refuses.
    MalformedRequest,
    /// The request's own `v` didn't match `VERSION`. Carries the client's
    /// claimed version so the response can name both.
    VersionMismatch(u64),
}

/// The fields `decode_request` reads before the request is matched against
/// `Op`. Every other field is skipped without being copied.
#[derive(Deserialize)]
struct Envelope<'a> {
    v: u64,
    /// Raw JSON text, never unescaped: `serde_json` only finds where it
    /// ends.
    #[serde(borrow, default)]
    password: Option<&'a RawValue>,
}

/// Decode one request line. Two passes over `line`, both straight from the
/// text:
///
/// 1. `v` first, before the rest of the request is asked to match `Op`'s
///    shape at all — a client running a different protocol version may not
///    even have a compatible `op` shape, and the version mismatch is the
///    more useful thing to report in that case. The same pass refuses a
///    `password` with escapes in it, before anything has unescaped it into
///    a buffer kpa can't wipe (see `Password`).
/// 2. The whole request. Strings arrive as slices of `line`, so the only
///    copy of a password is the zeroizing one `Password` decodes into.
///
/// Never through a `serde_json::Value`, which would copy every string in
/// the request, the password's base64 included, into a plain `String`.
pub fn decode_request(line: &str) -> Result<Request, DecodeError> {
    let envelope: Envelope =
        serde_json::from_str(line).map_err(|_| DecodeError::MalformedRequest)?;
    if envelope.v != u64::from(VERSION) {
        return Err(DecodeError::VersionMismatch(envelope.v));
    }
    if envelope
        .password
        .is_some_and(|raw| raw.get().contains('\\'))
    {
        return Err(DecodeError::MalformedRequest);
    }

    serde_json::from_str(line).map_err(|_| DecodeError::MalformedRequest)
}

/// Serialize `request` into a newline-terminated line, for `send_request`
/// to write to the socket.
///
/// Serialized twice on purpose, the same technique `write_response` uses
/// for the daemon's replies: once into a [`ByteCounter`] to measure, once
/// into a `Zeroizing` buffer allocated at exactly that size. An `unlock`
/// carrying the master password is the one request that holds a secret
/// (as base64, inside `Password`'s `Serialize`), and a buffer that grows
/// while being filled frees an unwiped copy at each reallocation.
pub fn encode_request(request: &Request) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, request)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(counter.0 + 1));
    serde_json::to_writer(&mut *buf, request)?;
    buf.push(b'\n');
    Ok(buf)
}

/// Failures that precede dispatch. Unlike an op's error type, this one
/// names no database — there wasn't a recognized request to name one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Carries the version the client claimed, so the response can name it
    /// alongside `VERSION` (`docs/plan.md` step 2 asks for exactly that).
    VersionMismatch {
        client_v: u64,
    },
    MalformedRequest,
}

impl ProtocolError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            // The wording lives here rather than in `server.rs` because
            // this is the module that owns `VERSION` — the two have to
            // agree, and this way they can't drift.
            ProtocolError::VersionMismatch { client_v } => {
                ErrorFields::new(ErrorCode::VersionMismatch).detail(format!(
                    "client sent v{client_v}; this daemon speaks v{VERSION}"
                ))
            }
            ProtocolError::MalformedRequest => ErrorFields::new(ErrorCode::MalformedRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;
    use uuid::Uuid;

    use super::super::copy::Field;
    use super::super::unlock::{MAX_PASSWORD_LEN, Password};
    use super::*;

    /// The nil uuid, used everywhere below a request needs one — these
    /// tests are about wire shape, not about which entry.
    fn uuid() -> Uuid {
        Uuid::nil()
    }

    /// Every request shape from `docs/design.md` § Requests, and the one
    /// each `kpa` subcommand sends. Worth pinning because `Op`'s variants
    /// wrap per-op structs and it's `#[serde(tag = "op")]` that flattens
    /// them back into a single object — a change there would silently
    /// nest or rename fields.
    #[test]
    fn requests_match_the_documented_wire_shape() {
        let cases = [
            (Op::Status, json!({"v": 1, "op": "status"})),
            (
                Op::Unlock(UnlockRequest {
                    db: "personal".to_string(),
                    password: None,
                }),
                json!({"v": 1, "op": "unlock", "db": "personal"}),
            ),
            (
                Op::Lock(LockRequest {
                    db: Some("personal".to_string()),
                }),
                json!({"v": 1, "op": "lock", "db": "personal"}),
            ),
            // Omitted, not null: the doc's "db omitted = lock all".
            (
                Op::Lock(LockRequest { db: None }),
                json!({"v": 1, "op": "lock"}),
            ),
            (
                Op::List(ListRequest {
                    db: Some("personal".to_string()),
                }),
                json!({"v": 1, "op": "list", "db": "personal"}),
            ),
            (
                Op::List(ListRequest { db: None }),
                json!({"v": 1, "op": "list"}),
            ),
            (
                Op::Copy(CopyRequest {
                    db: "personal".to_string(),
                    uuid: uuid(),
                    field: Field::Password,
                }),
                json!({
                    "v": 1,
                    "op": "copy",
                    "db": "personal",
                    "uuid": uuid(),
                    "field": "password",
                }),
            ),
        ];

        for (op, expected) in cases {
            let request = Request { v: VERSION, op };
            assert_eq!(
                serde_json::to_value(&request).expect("request should serialize"),
                expected,
                "wrong wire shape for {:?}",
                request.op
            );
        }
    }

    /// The decode half. The rejection cases have their own tests below;
    /// these are the ones that have to keep working for any client to be
    /// understood at all.
    #[test]
    fn decodes_each_documented_request() {
        let cases = [
            (r#"{"v":1,"op":"status"}"#, Op::Status),
            (
                r#"{"v":1,"op":"unlock","db":"personal"}"#,
                Op::Unlock(UnlockRequest {
                    db: "personal".to_string(),
                    password: None,
                }),
            ),
            (
                r#"{"v":1,"op":"lock","db":"personal"}"#,
                Op::Lock(LockRequest {
                    db: Some("personal".to_string()),
                }),
            ),
            (r#"{"v":1,"op":"lock"}"#, Op::Lock(LockRequest { db: None })),
            // An explicit null reads the same as omitting it, so a client
            // that spells out its empty fields is still understood.
            (
                r#"{"v":1,"op":"lock","db":null}"#,
                Op::Lock(LockRequest { db: None }),
            ),
            (
                r#"{"v":1,"op":"list","db":"personal"}"#,
                Op::List(ListRequest {
                    db: Some("personal".to_string()),
                }),
            ),
            (r#"{"v":1,"op":"list"}"#, Op::List(ListRequest { db: None })),
            (
                r#"{"v":1,"op":"copy","db":"personal","uuid":"00000000-0000-0000-0000-000000000000","field":"password"}"#,
                Op::Copy(CopyRequest {
                    db: "personal".to_string(),
                    uuid: uuid(),
                    field: Field::Password,
                }),
            ),
        ];

        for (line, expected) in cases {
            let request = decode_request(line).unwrap_or_else(|err| panic!("{line}: {err:?}"));
            assert_eq!(request.v, VERSION);
            assert_eq!(request.op, expected, "wrong decode for {line}");
        }
    }

    /// What the client encodes, the daemon decodes back to the same thing.
    #[test]
    fn requests_round_trip() {
        let ops = [
            Op::Status,
            Op::Unlock(UnlockRequest {
                db: "personal".to_string(),
                password: None,
            }),
            Op::Lock(LockRequest { db: None }),
            Op::Lock(LockRequest {
                db: Some("work".to_string()),
            }),
            Op::List(ListRequest { db: None }),
            Op::List(ListRequest {
                db: Some("work".to_string()),
            }),
            Op::Copy(CopyRequest {
                db: "personal".to_string(),
                uuid: uuid(),
                field: Field::Notes,
            }),
        ];

        for op in ops {
            let request = Request { v: VERSION, op };
            let text = serde_json::to_string(&request).expect("request should serialize");
            let decoded = decode_request(&text).unwrap_or_else(|err| panic!("{text}: {err:?}"));
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn rejects_a_mismatched_version_before_the_op_shape() {
        // The `op` here isn't one this build knows; the version mismatch is
        // still what comes back, since that's the more useful thing to say.
        let err =
            decode_request(r#"{"v":2,"op":"teleport"}"#).expect_err("a v2 request must not decode");
        assert!(matches!(err, DecodeError::VersionMismatch(2)));
    }

    #[test]
    fn rejects_malformed_input() {
        for line in [
            "not json",
            "",
            "{}",
            r#"{"op":"status"}"#,                     // no `v`
            r#"{"v":"1","op":"status"}"#,             // `v` not a number
            r#"{"v":1,"op":"teleport"}"#,             // unknown op
            r#"{"v":1,"op":"unlock"}"#,               // `unlock` needs a `db`
            r#"{"v":1,"op":"copy","db":"personal"}"#, // `copy` needs a `uuid` and `field`
        ] {
            assert!(
                matches!(decode_request(line), Err(DecodeError::MalformedRequest)),
                "should have been rejected: {line:?}"
            );
        }
    }

    /// `field` is no longer a closed allow-list: any string decodes,
    /// because any string might name a real custom field on the entry
    /// `copy` is asked about — see `proto::copy::Field`'s own doc comment.
    /// A name that doesn't resolve to anything fails at `copy` time
    /// (`FieldEmpty`), not at decode time.
    #[test]
    fn an_unrecognized_field_name_still_decodes() {
        let line = r#"{"v":1,"op":"copy","db":"personal","uuid":"00000000-0000-0000-0000-000000000000","field":"notes_dump"}"#;
        let request = decode_request(line).expect("an unrecognized field name should still decode");
        assert_eq!(
            request.op,
            Op::Copy(CopyRequest {
                db: "personal".to_string(),
                uuid: uuid(),
                field: Field::Custom("notes_dump".to_string()),
            })
        );
    }

    fn unlock_with(password: &str) -> String {
        format!(r#"{{"v":1,"op":"unlock","db":"personal","password":"{password}"}}"#)
    }

    /// The decoded password only compares equal if it came through
    /// `PasswordVisitor::visit_borrowed_str`, the only path that accepts
    /// it: this also pins that `#[serde(flatten)]` and `#[serde(tag)]`
    /// hand the string over borrowed.
    #[test]
    fn decodes_an_unlock_that_carries_a_password() {
        let request = decode_request(&unlock_with("aHVudGVyMg==")).expect("should decode");
        assert_eq!(
            request.op,
            Op::Unlock(UnlockRequest {
                db: "personal".to_string(),
                password: Some(Password::new(zeroize::Zeroizing::new(
                    "hunter2".to_string()
                ))),
            })
        );

        // An explicit null reads the same as omitting it.
        let line = r#"{"v":1,"op":"unlock","db":"personal","password":null}"#;
        let request = decode_request(line).expect("should decode");
        assert_eq!(
            request.op,
            Op::Unlock(UnlockRequest {
                db: "personal".to_string(),
                password: None,
            })
        );
    }

    #[test]
    fn a_password_round_trips() {
        let request = Request {
            v: VERSION,
            op: Op::Unlock(UnlockRequest {
                db: "personal".to_string(),
                password: Some(Password::new(zeroize::Zeroizing::new(
                    "pa\"ss\\wörd\n".to_string(),
                ))),
            }),
        };
        let text = serde_json::to_string(&request).expect("request should serialize");
        assert!(!text.contains('\\'), "base64 never needs escaping: {text}");
        assert_eq!(decode_request(&text).expect("should decode"), request);
    }

    #[test]
    fn rejects_a_password_it_cannot_use() {
        let oversized = STANDARD.encode("a".repeat(MAX_PASSWORD_LEN + 1));
        for line in [
            unlock_with("not base64!"),
            unlock_with(&oversized),
            unlock_with(&STANDARD.encode(b"\xff")),
            r#"{"v":1,"op":"unlock","db":"personal","password":42}"#.to_string(),
            r#"{"v":1,"op":"unlock","db":"personal","password":["aGk="]}"#.to_string(),
        ] {
            assert!(
                matches!(decode_request(&line), Err(DecodeError::MalformedRequest)),
                "should have been rejected: {line:?}"
            );
        }
    }

    /// For building the JSON escapes below.
    const BACKSLASH: char = '\u{5c}';

    /// Each of these unescapes to valid base64 (`aHVudGVyMg==`, `aGk=`), so
    /// only the escape gets them refused.
    #[test]
    fn rejects_a_password_with_escapes() {
        let b = BACKSLASH;
        for line in [
            unlock_with(&format!("aHVudGVy{b}u004dg==")),
            unlock_with(&format!("aHVudGVyMg{b}u003d{b}u003d")),
            unlock_with(&format!("aHVu{b}/dGVyMg==")),
            // The escape check reads the raw field wherever it sits, and an
            // escaped key still names it.
            format!(r#"{{"password":"aGk{b}u003d","v":1,"op":"unlock","db":"personal"}}"#),
            format!(r#"{{"v":1,"op":"unlock","db":"personal","pass{b}u0077ord":"aGk{b}u003d"}}"#),
        ] {
            assert!(
                matches!(decode_request(&line), Err(DecodeError::MalformedRequest)),
                "should have been rejected: {line:?}"
            );
        }
    }

    /// The `v` check still comes first, so a client on another protocol
    /// version hears about that rather than about its password.
    #[test]
    fn a_mismatched_version_is_reported_before_a_bad_password() {
        let line = format!(
            r#"{{"v":2,"op":"unlock","db":"personal","password":"{}u0041"}}"#,
            BACKSLASH
        );
        assert!(matches!(
            decode_request(&line),
            Err(DecodeError::VersionMismatch(2))
        ));
    }
}
