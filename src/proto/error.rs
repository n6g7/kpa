//! The error vocabulary every op shares.
//!
//! Ops deliberately don't share an error *type* — `lock` can't return
//! `wrong_credentials`, and [`LockError`](super::LockError) says so — but
//! they do all collapse to the same three wire fields on the way out
//! (`error`, `db`, `detail`). That mapping lives here, once, so each op
//! module only has to say which code its variants mean.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// The `error` strings the protocol uses (`docs/design.md` § Protocol). A
/// client can match on a code it recognizes without knowing which op
/// produced it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    VersionMismatch,
    MalformedRequest,
    UnknownDb,
    Locked,
    WrongCredentials,
    /// The configured prompt command exited unsuccessfully (e.g. the user
    /// dismissed a dmenu-style prompt) rather than returning a password.
    PromptCancelled,
    NotFound,
    Corrupt,
    Io,
    /// Another unlock of the same database is already prompting.
    UnlockInProgress,
    /// The database's file changed on disk after it was unlocked (or while
    /// it was being read). The database has been dropped; unlock again.
    Stale,
}

/// What an error response puts on the wire, however it arose. Each op
/// error builds one of these in its `fields()`; `serialize_error` writes it.
pub(super) struct ErrorFields<'a> {
    code: ErrorCode,
    db: Option<&'a str>,
    detail: Option<Cow<'a, str>>,
}

impl<'a> ErrorFields<'a> {
    pub(super) fn new(code: ErrorCode) -> ErrorFields<'a> {
        ErrorFields {
            code,
            db: None,
            detail: None,
        }
    }

    /// Name the database this error is about — almost every one is about
    /// exactly one, echoing back the name the request used.
    pub(super) fn db(mut self, db: &'a str) -> ErrorFields<'a> {
        self.db = Some(db);
        self
    }

    /// Free text for a human. Never derived from file contents — see the
    /// note on `vault::VaultError::Corrupt` for why parser text must not
    /// reach a client.
    pub(super) fn detail(mut self, detail: impl Into<Cow<'a, str>>) -> ErrorFields<'a> {
        self.detail = Some(detail.into());
        self
    }
}

pub(super) fn serialize_error<M>(map: &mut M, fields: &ErrorFields<'_>) -> Result<(), M::Error>
where
    M: serde::ser::SerializeMap,
{
    map.serialize_entry("ok", &false)?;
    map.serialize_entry("error", &fields.code)?;
    if let Some(db) = fields.db {
        map.serialize_entry("db", db)?;
    }
    if let Some(detail) = &fields.detail {
        map.serialize_entry("detail", detail.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Drives `serialize_error` the way `Response`'s own `Serialize` does —
    /// into a map the caller already opened — so these tests exercise the
    /// real writer rather than a reimplementation of it.
    struct AsError<'a>(ErrorFields<'a>);

    impl Serialize for AsError<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;

            let mut map = serializer.serialize_map(None)?;
            serialize_error(&mut map, &self.0)?;
            map.end()
        }
    }

    fn wire(fields: ErrorFields<'_>) -> serde_json::Value {
        serde_json::to_value(AsError(fields)).expect("an error should serialize")
    }

    /// The protocol's whole error vocabulary, in both directions. Encoding
    /// is what the daemon emits; decoding matters because clients parse
    /// these strings back into `ErrorCode` to match on them.
    #[test]
    fn every_error_code_round_trips_as_snake_case() {
        let cases = [
            (ErrorCode::VersionMismatch, "version_mismatch"),
            (ErrorCode::MalformedRequest, "malformed_request"),
            (ErrorCode::UnknownDb, "unknown_db"),
            (ErrorCode::Locked, "locked"),
            (ErrorCode::WrongCredentials, "wrong_credentials"),
            (ErrorCode::PromptCancelled, "prompt_cancelled"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::Corrupt, "corrupt"),
            (ErrorCode::Io, "io"),
            (ErrorCode::UnlockInProgress, "unlock_in_progress"),
            (ErrorCode::Stale, "stale"),
        ];

        for (code, expected) in cases {
            assert_eq!(
                serde_json::to_value(code).expect("a code should serialize"),
                json!(expected),
                "wrong wire string for {code:?}"
            );
            let parsed: ErrorCode =
                serde_json::from_value(json!(expected)).expect("a code should parse back");
            assert_eq!(parsed, code);
        }
    }

    /// An error writes `ok` and `error` always, `db` and `detail` only
    /// when it was given them — absent, never `null`. Note there is no
    /// `v`: that belongs to the response as a whole, and `Response`'s own
    /// `Serialize` writes it before delegating here.
    #[test]
    fn only_the_fields_that_were_given_reach_the_wire() {
        assert_eq!(
            wire(ErrorFields::new(ErrorCode::MalformedRequest)),
            json!({"ok": false, "error": "malformed_request"})
        );

        assert_eq!(
            wire(ErrorFields::new(ErrorCode::Locked).db("personal")),
            json!({"ok": false, "error": "locked", "db": "personal"})
        );

        assert_eq!(
            wire(ErrorFields::new(ErrorCode::VersionMismatch).detail("client sent v99")),
            json!({
                "ok": false,
                "error": "version_mismatch",
                "detail": "client sent v99",
            })
        );

        assert_eq!(
            wire(
                ErrorFields::new(ErrorCode::Io)
                    .db("personal")
                    .detail("no such file")
            ),
            json!({
                "ok": false,
                "error": "io",
                "db": "personal",
                "detail": "no such file",
            })
        );
    }

    /// Why `detail` is a `Cow`: one field has to take both a borrow of an
    /// error's existing `String` (`UnlockError::PromptFailed`) and a
    /// freshly built one (`ProtocolError::VersionMismatch`, which
    /// `format!`s its message). Both land identically on the wire.
    #[test]
    fn detail_accepts_borrowed_and_owned_text() {
        let borrowed: &str = "no such file";
        let owned: String = format!("no such {}", "file");

        assert_eq!(
            wire(ErrorFields::new(ErrorCode::Io).detail(borrowed)),
            wire(ErrorFields::new(ErrorCode::Io).detail(owned))
        );
    }

    /// Setting a field twice keeps the last value rather than emitting the
    /// key twice — a duplicate key would be JSON a client could read
    /// either way.
    #[test]
    fn the_last_value_for_a_field_wins() {
        assert_eq!(
            wire(
                ErrorFields::new(ErrorCode::UnknownDb)
                    .db("first")
                    .db("second")
            ),
            json!({"ok": false, "error": "unknown_db", "db": "second"})
        );
    }
}
