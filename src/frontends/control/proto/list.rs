//! `list`: the index. Reads already-decrypted state held in memory, so it
//! can only fail on *which* database was asked for, never on reading one.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"list", ...}` carries. This *is* the deserialization
/// target — `Op::List` wraps it — so the payload has exactly one
/// representation rather than a wire shape and a handler shape that have
/// to be kept in step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListRequest {
    /// `None` covers every unlocked database, skipping locked ones rather
    /// than failing on them. Omitted from the wire rather than sent as
    /// `null`; an incoming explicit `null` still reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
}

/// What a successful `list` answers, as the daemon builds it and a client
/// reads it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListResponse {
    /// The entries of every database the request covered.
    pub entries: Vec<WireEntry>,
}

/// One entry of the index `list` answers, with the database it came from:
/// `list` can span every unlocked database at once (`docs/protocol.md`'s
/// example response tags each entry with `"db"`).
///
/// Carries no secret: no password, no notes, and any title, username or URL
/// the user marked protected is absent rather than de-protected, per
/// `docs/protocol.md` § What `list` returns ("`list` never returns
/// secrets"); the control front end does that filtering. `fields` is the one
/// exception to "no secret-shaped content": it carries *names* only, never
/// values, and a field's protectedness never hides its name here, because
/// only `title`/`username`/`url` above carry values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct WireEntry {
    pub db: String,
    #[zeroize(skip)]
    pub uuid: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub group: String,
    /// Field names `copy` can be asked for on this entry, exactly as `copy`
    /// takes them: the standard fields present and non-empty (`UserName`,
    /// `Password`, `URL`, `Notes`), `totp` when the entry has a seed, then
    /// every other stored key, sorted (`docs/protocol.md`). Omitted from
    /// the wire when empty, like the `Option` fields above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    UnknownDb {
        db: String,
    },
    /// Named a database that is configured but currently locked. Only
    /// reachable when the request named one: `list` across everything
    /// skips locked databases rather than failing.
    Locked {
        db: String,
    },
    /// The database's file changed on disk since it was unlocked. The
    /// database is dropped by the time this is returned.
    Stale {
        db: String,
    },
}

impl ListError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            ListError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            ListError::Locked { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            ListError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
        }
    }
}
