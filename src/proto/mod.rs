//! Wire protocol: the JSON shape exchanged over the Unix socket, per
//! `docs/design.md` § Protocol.
//!
//! One module per op, since an op's payload type and its error type belong
//! together and nothing outside that op needs either: [`status`],
//! [`unlock`], [`lock`], [`list`], [`copy`]. [`request`] holds the request
//! half plus the failures that precede dispatch, and [`error`] the wire
//! vocabulary all of them share.
//!
//! [`Response`] itself stays here rather than being split up: it's the one
//! place the whole wire shape is visible as a single match, which is worth
//! more than spreading five arms across five files.

mod copy;
mod error;
mod list;
mod lock;
mod request;
mod status;
mod unlock;

pub use copy::{CopyEntry, CopyError, CopyOutcome, CopyRequest, Field};
pub use error::ErrorCode;
pub use list::{List, ListError, ListRequest, WireEntry};
pub use lock::{Lock, LockError, LockRequest};
pub use request::{DecodeError, Op, ProtocolError, Request, decode_request};
pub use status::{DatabaseStatus, Status};
pub use unlock::{Unlock, UnlockError, UnlockRequest};

use serde::Serialize;

use error::serialize_error;

/// Protocol version this build speaks. Every `Response` carries this,
/// regardless of what the request asked for or which version it claimed —
/// see `decode_request` and `docs/design.md`'s "skew impossible to ignore"
/// rationale.
pub const VERSION: u32 = 1;

/// Everything a kpa daemon has to be able to do, as one bound. Each op's
/// trait is defined next to that op's types; this just gathers them, so
/// `dispatch` takes one bound instead of four and `server::Server` has one
/// thing to satisfy.
///
/// The blanket impl means implementing the five op traits is all it takes —
/// there is nothing extra to write.
pub trait Handler: Status + Unlock + Lock + List + CopyEntry {}

impl<T: Status + Unlock + Lock + List + CopyEntry> Handler for T {}

/// Turn one decoded request into the response for it.
///
/// This is the only place an op's outcome becomes a `Response` variant, so
/// the pairing — `Op::Lock` to `Response::Lock` to `LockError` — is stated
/// once, here, rather than being a convention each handler has to remember
/// to follow.
pub fn dispatch<H>(handler: &H, request: &Request) -> Response
where
    H: Handler + ?Sized,
{
    match &request.op {
        Op::Status => Response::Status {
            databases: handler.status(),
            version: handler.daemon_version(),
        },
        Op::Unlock(request) => Response::Unlock(handler.unlock(request)),
        Op::Lock(request) => Response::Lock(handler.lock(request)),
        Op::List(request) => Response::List(handler.list(request)),
        Op::Copy(request) => Response::Copy(handler.copy(request)),
    }
}

/// One response, one variant per `Op`. Each variant carries a `Result`
/// whose error type names *exactly* what that op can fail with: `lock` can
/// only ever hit an unknown database name, while `unlock` carries the whole
/// prompt-and-credentials surface. That's the point of the split — a
/// shared error type would say every op can return every error, which is
/// false and gives a client nothing to match on.
///
/// `Status` carries no `Result`: it reports state the daemon already holds
/// in memory, so it has no failure mode to describe.
///
/// `Serialize` only: on the wire, a successful `Unlock` and a successful
/// `Lock(Ok(Some(_)))` are genuinely indistinguishable
/// (`{"v":1,"ok":true,"db":"personal"}` either way) — the response doesn't
/// self-describe which op produced it, by design (`docs/design.md` § "which
/// response is this? answered by which socket it arrived on"). That's fine
/// for encoding, since `server.rs` always knows which variant it's building,
/// but it means decoding one generically, without already knowing the
/// request, isn't meaningful — so this type doesn't implement `Deserialize`.
/// A reader that isn't the client for its own request (a test, say) should
/// read the field it cares about out of a `serde_json::Value` instead.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    Status {
        databases: Vec<DatabaseStatus>,
        /// The daemon's own build version (`kpa::VERSION`), so `kpa version`
        /// can name a CLI/daemon mismatch after an upgrade where the old
        /// daemon is still running. Always present on this build; absent
        /// only when the peer is an older daemon that predates this field —
        /// the client reads it as an optional field for exactly that reason.
        version: String,
    },
    /// `Ok` names the database that is now unlocked.
    Unlock(Result<String, UnlockError>),
    /// `Ok` names the database that was locked; `None` means "all of them".
    Lock(Result<Option<String>, LockError>),
    /// `Ok` carries the entries of every database the request covered.
    List(Result<Vec<WireEntry>, ListError>),
    /// `Ok` names which field was copied and for how long it will stay on
    /// the clipboard — never the value itself (see `copy`'s module doc).
    Copy(Result<CopyOutcome, CopyError>),
    /// Rejected before the daemon knew which op was even being asked for,
    /// so it belongs to no op's `Result`.
    Protocol(ProtocolError),
}

impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &VERSION)?;
        match self {
            Response::Status { databases, version } => {
                map.serialize_entry("ok", &true)?;
                map.serialize_entry("databases", databases)?;
                map.serialize_entry("version", version)?;
            }
            Response::Unlock(Ok(db)) => {
                map.serialize_entry("ok", &true)?;
                map.serialize_entry("db", db)?;
            }
            Response::Unlock(Err(err)) => serialize_error(&mut map, &err.fields())?,
            Response::Lock(Ok(db)) => {
                map.serialize_entry("ok", &true)?;
                if let Some(db) = db {
                    map.serialize_entry("db", db)?;
                }
            }
            Response::Lock(Err(err)) => serialize_error(&mut map, &err.fields())?,
            Response::List(Ok(entries)) => {
                map.serialize_entry("ok", &true)?;
                map.serialize_entry("entries", entries)?;
            }
            Response::List(Err(err)) => serialize_error(&mut map, &err.fields())?,
            Response::Copy(Ok(outcome)) => {
                map.serialize_entry("ok", &true)?;
                map.serialize_entry("copied", &outcome.field)?;
                map.serialize_entry("expires_in", &outcome.expires_in)?;
            }
            Response::Copy(Err(err)) => serialize_error(&mut map, &err.fields())?,
            Response::Protocol(err) => serialize_error(&mut map, &err.fields())?,
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `Response`'s `Serialize` is hand-written, so these pin the exact wire
    /// shape of each variant against `docs/design.md` § Protocol rather than
    /// trusting a derive to keep matching it.
    #[test]
    fn success_responses_match_the_documented_wire_shape() {
        let status = Response::Status {
            databases: vec![
                DatabaseStatus {
                    name: "personal".to_string(),
                    locked: false,
                    entries: Some(341),
                },
                DatabaseStatus {
                    name: "work".to_string(),
                    locked: true,
                    entries: None,
                },
            ],
            version: "1.2.3".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&status).expect("status should serialize"),
            json!({
                "v": 1,
                "ok": true,
                "databases": [
                    {"name": "personal", "locked": false, "entries": 341},
                    {"name": "work", "locked": true},
                ],
                "version": "1.2.3",
            })
        );

        let list = Response::List(Ok(vec![WireEntry {
            db: "personal".to_string(),
            uuid: uuid::Uuid::nil(),
            title: Some("GitHub".to_string()),
            username: Some("alice".to_string()),
            url: None,
            group: "Dev".to_string(),
        }]));
        assert_eq!(
            serde_json::to_value(&list).expect("list should serialize"),
            json!({
                "v": 1,
                "ok": true,
                "entries": [{
                    "db": "personal",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "title": "GitHub",
                    "username": "alice",
                    "group": "Dev",
                }],
            })
        );

        // Locking everything names no database.
        assert_eq!(
            serde_json::to_value(Response::Lock(Ok(None))).expect("lock should serialize"),
            json!({"v": 1, "ok": true})
        );

        // `copy`'s success carries no secret and no `db` — just which field,
        // and for how long.
        let copy = Response::Copy(Ok(CopyOutcome {
            db: "personal".to_string(),
            entry: "GitHub".to_string(),
            field: Field::Password,
            expires_in: 30,
        }));
        assert_eq!(
            serde_json::to_value(&copy).expect("copy should serialize"),
            json!({"v": 1, "ok": true, "copied": "password", "expires_in": 30})
        );
    }

    /// The reason `Response` is `Serialize`-only: these two are different
    /// variants of different ops and still produce identical bytes, so
    /// there is nothing for a generic `Deserialize` to recover.
    #[test]
    fn unlock_and_lock_successes_are_wire_identical() {
        let unlocked = Response::Unlock(Ok("personal".to_string()));
        let locked = Response::Lock(Ok(Some("personal".to_string())));

        assert_eq!(
            serde_json::to_value(&unlocked).expect("unlock should serialize"),
            serde_json::to_value(&locked).expect("lock should serialize"),
        );
        assert_eq!(
            serde_json::to_value(&unlocked).expect("unlock should serialize"),
            json!({"v": 1, "ok": true, "db": "personal"})
        );
    }

    /// `list` returning nothing is an empty array, not an absent field —
    /// a client can iterate the result without special-casing.
    #[test]
    fn an_empty_listing_still_carries_an_array() {
        assert_eq!(
            serde_json::to_value(Response::List(Ok(Vec::new()))).expect("should serialize"),
            json!({"v": 1, "ok": true, "entries": []})
        );
    }

    /// A field the vault withheld (the user marked it protected) is
    /// *absent*, never `null` and never an empty string — so a client
    /// can't mistake "protected" for "set to nothing".
    #[test]
    fn entries_omit_withheld_fields_entirely() {
        let response = Response::List(Ok(vec![WireEntry {
            db: "personal".to_string(),
            uuid: uuid::Uuid::nil(),
            title: None,
            username: None,
            url: None,
            group: "Web".to_string(),
        }]));

        let value = serde_json::to_value(&response).expect("should serialize");
        let entry = &value["entries"][0];
        assert_eq!(
            entry,
            &json!({
                "db": "personal",
                "uuid": "00000000-0000-0000-0000-000000000000",
                "group": "Web",
            })
        );
        for withheld in ["title", "username", "url"] {
            assert!(entry.get(withheld).is_none(), "{withheld} should be absent");
        }
    }

    /// Every variant of every op's error type, and the code each one
    /// means on the wire — including the deliberate collapse where both
    /// `PromptFailed` and `Io` report `io`.
    ///
    /// Exhaustive as written, and a new variant wants a row here. Nothing
    /// enforces that, but nothing silently misbehaves either: each error's
    /// `fields()` matches exhaustively, so the compiler already forces a
    /// decision about what a new variant means on the wire.
    ///
    /// `ProtocolError::VersionMismatch` is the one variant left out; its
    /// detail is generated, so it has its own test below.
    #[test]
    fn every_error_variant_maps_to_its_wire_code() {
        let db = "personal";
        let owned = || db.to_string();

        // (response, expected code, expected `db`, expected `detail`)
        let cases: [(Response, &str, Option<&str>, Option<&str>); 21] = [
            (
                Response::Unlock(Err(UnlockError::InProgress { db: owned() })),
                "unlock_in_progress",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::Stale { db: owned() })),
                "stale",
                Some(db),
                Some("database changed on disk"),
            ),
            (
                Response::List(Err(ListError::Stale { db: owned() })),
                "stale",
                Some(db),
                Some("database changed on disk"),
            ),
            // Deliberately the same code as `list` on a locked database:
            // it names the state the unlock left behind.
            (
                Response::Unlock(Err(UnlockError::LockedDuringUnlock { db: owned() })),
                "locked",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::UnknownDb { db: owned() })),
                "unknown_db",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::PromptCancelled { db: owned() })),
                "prompt_cancelled",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::PromptFailed {
                    db: owned(),
                    detail: "no such file".to_string(),
                })),
                "io",
                Some(db),
                Some("no such file"),
            ),
            (
                Response::Unlock(Err(UnlockError::WrongCredentials { db: owned() })),
                "wrong_credentials",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::NotFound { db: owned() })),
                "not_found",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::Corrupt { db: owned() })),
                "corrupt",
                Some(db),
                None,
            ),
            (
                Response::Unlock(Err(UnlockError::Io { db: owned() })),
                "io",
                Some(db),
                None,
            ),
            (
                Response::Lock(Err(LockError::UnknownDb { db: owned() })),
                "unknown_db",
                Some(db),
                None,
            ),
            (
                Response::List(Err(ListError::UnknownDb { db: owned() })),
                "unknown_db",
                Some(db),
                None,
            ),
            (
                Response::List(Err(ListError::Locked { db: owned() })),
                "locked",
                Some(db),
                None,
            ),
            (
                Response::Protocol(ProtocolError::MalformedRequest),
                "malformed_request",
                None,
                None,
            ),
            (
                Response::Copy(Err(CopyError::UnknownDb { db: owned() })),
                "unknown_db",
                Some(db),
                None,
            ),
            (
                Response::Copy(Err(CopyError::Locked { db: owned() })),
                "locked",
                Some(db),
                None,
            ),
            (
                Response::Copy(Err(CopyError::Stale { db: owned() })),
                "stale",
                Some(db),
                Some("database changed on disk"),
            ),
            (
                Response::Copy(Err(CopyError::UnknownUuid { db: owned() })),
                "unknown_uuid",
                Some(db),
                None,
            ),
            (
                Response::Copy(Err(CopyError::FieldEmpty { db: owned() })),
                "field_empty",
                Some(db),
                None,
            ),
            (
                Response::Copy(Err(CopyError::Clipboard {
                    db: owned(),
                    detail: "no reachable Wayland compositor".to_string(),
                })),
                "io",
                Some(db),
                Some("no reachable Wayland compositor"),
            ),
        ];

        for (response, code, expected_db, expected_detail) in cases {
            let value = serde_json::to_value(&response).expect("response should serialize");

            assert_eq!(value["ok"], json!(false), "{response:?} should not be ok");
            assert_eq!(value["v"], json!(VERSION));
            assert_eq!(value["error"], json!(code), "wrong code for {response:?}");
            assert_eq!(
                value.get("db").and_then(serde_json::Value::as_str),
                expected_db,
                "wrong db for {response:?}"
            );
            assert_eq!(
                value.get("detail").and_then(serde_json::Value::as_str),
                expected_detail,
                "wrong detail for {response:?}"
            );
        }
    }

    /// A parser message must never ride out on `detail` — it can embed
    /// raw bytes from the decrypted database (see `vault::VaultError::Corrupt`).
    /// `Corrupt` carries only the database name, so there is nothing to leak.
    #[test]
    fn a_corrupt_database_reports_no_parser_text() {
        let response = Response::Unlock(Err(UnlockError::Corrupt {
            db: "personal".to_string(),
        }));
        assert_eq!(
            serde_json::to_value(&response).expect("should serialize"),
            json!({"v": 1, "ok": false, "error": "corrupt", "db": "personal"})
        );
    }

    /// `docs/plan.md` step 2 asks for "a clear error naming both versions",
    /// and the response's own `v` is always the daemon's, never the
    /// client's claim.
    #[test]
    fn version_mismatch_names_both_versions() {
        let response = Response::Protocol(ProtocolError::VersionMismatch { client_v: 99 });
        let value = serde_json::to_value(&response).expect("response should serialize");

        assert_eq!(value["v"], json!(VERSION));
        assert_eq!(value["error"], json!("version_mismatch"));
        let detail = value["detail"].as_str().expect("detail should be a string");
        assert!(detail.contains("99"), "should name the client's: {detail}");
        assert!(detail.contains("v1"), "should name the daemon's: {detail}");
    }
}
