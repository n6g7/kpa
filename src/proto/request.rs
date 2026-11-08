//! The request half of the protocol, plus the two failures that happen
//! before a request is recognized as an op at all.
//!
//! [`ProtocolError`] is the wire-facing side of [`DecodeError`]; both live
//! here rather than in an op module because neither belongs to any op —
//! at the point they arise, which op was asked for isn't known.

use serde::{Deserialize, Serialize};

use super::VERSION;
use super::copy::CopyRequest;
use super::error::{ErrorCode, ErrorFields};
use super::list::ListRequest;
use super::lock::LockRequest;
use super::unlock::UnlockRequest;

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
    /// Not valid JSON, missing/non-numeric `v`, or an `op` shape this build
    /// doesn't recognize.
    MalformedRequest,
    /// The request's own `v` didn't match `VERSION`. Carries the client's
    /// claimed version so the response can name both.
    VersionMismatch(u64),
}

/// Decode one request line. Two-stage on purpose: `v` is read out of a
/// generic `serde_json::Value` first, before the rest of the request is
/// asked to match `Op`'s shape at all — a client running a different
/// protocol version may not even have a compatible `op` shape, and the
/// version mismatch is the more useful thing to report in that case.
pub fn decode_request(line: &str) -> Result<Request, DecodeError> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|_| DecodeError::MalformedRequest)?;

    let v = value
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .ok_or(DecodeError::MalformedRequest)?;
    if v != u64::from(VERSION) {
        return Err(DecodeError::VersionMismatch(v));
    }

    serde_json::from_value(value).map_err(|_| DecodeError::MalformedRequest)
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
    use serde_json::json;
    use uuid::Uuid;

    use super::super::copy::Field;
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
}
