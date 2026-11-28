//! `copy`: hand one field of one entry to the clipboard. The secret itself
//! never rides the wire back out — the response says which field and for
//! how long, never the value (`docs/design.md` decision #4: "the daemon
//! owns the clipboard, so the secret never enters the client's address
//! space").

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ErrorCode, ErrorFields};

/// The name `copy` and `list` give the code made from an entry's TOTP seed:
/// the one name that is not a field the entry stores.
pub const TOTP: &str = "totp";

/// What `{"op":"copy", ...}` carries; `Op::Copy` wraps it. `field` is a name
/// from `list`'s `fields` array for this entry, matched exactly. Any string
/// is a valid request: one that names nothing the entry offers fails with
/// `field_empty`, the same as an empty field (there is no more specific,
/// still-honest code for "this name doesn't mean anything here" without
/// echoing vault content back).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopyRequest {
    pub db: String,
    pub uuid: Uuid,
    pub field: String,
}

/// Everything `copy` can fail with. Every variant but `NoDisplay` names the
/// database the copy was for. `NoDisplay` is about where the request came
/// from, not about any database, so it names none — same shape as
/// `UnlockError::NoPrompt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyError {
    UnknownDb {
        db: String,
    },
    /// Named a database that is configured but currently locked.
    Locked {
        db: String,
    },
    /// The database's file changed on disk since it was unlocked. The
    /// database is dropped by the time this is returned, same as `list`.
    Stale {
        db: String,
    },
    /// The uuid doesn't name an entry in this database.
    UnknownUuid {
        db: String,
    },
    /// The entry exists, but the requested field is absent or empty on it —
    /// there's nothing to copy. Empty counts the same as absent: either way
    /// there is no secret to hand to the clipboard. Also what a field name
    /// that doesn't resolve to anything on this entry reports (see
    /// [`Field`]'s doc comment).
    FieldEmpty {
        db: String,
    },
    /// The clipboard backend couldn't take the secret — no reachable Wayland
    /// compositor, a missing protocol, or similar. `detail` is the
    /// backend's own error text, which never carries the secret itself.
    Clipboard {
        db: String,
        detail: String,
    },
    /// Nobody could paste the secret where it would land: the requester
    /// isn't on the desktop, or the display session isn't active and
    /// unlocked (`docs/headless.md` § 5). The clipboard is never touched.
    NoDisplay,
}

impl CopyError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            CopyError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            CopyError::Locked { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            CopyError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
            CopyError::UnknownUuid { db } => ErrorFields::new(ErrorCode::UnknownUuid).db(db),
            CopyError::FieldEmpty { db } => ErrorFields::new(ErrorCode::FieldEmpty).db(db),
            // Collapsed to `io`, same as `UnlockError::PromptFailed`: from
            // the client's side, "the daemon couldn't reach the clipboard"
            // is an I/O failure like any other.
            CopyError::Clipboard { db, detail } => ErrorFields::new(ErrorCode::Io)
                .db(db)
                .detail(detail.as_str()),
            CopyError::NoDisplay => ErrorFields::new(ErrorCode::NoDisplay)
                .detail("no active, unlocked display session for the requester to paste into"),
        }
    }
}

/// What a successful `copy` answers on the wire, as the daemon builds it and
/// a client reads it: which field, and for how long, never its value.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CopyOutcome {
    pub copied: String,
    /// Whole seconds until the daemon drops its clipboard offer on its own.
    pub expires_in: u64,
}
