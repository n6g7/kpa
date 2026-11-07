//! `copy`: hand one field of one entry to the clipboard. The secret itself
//! never rides the wire back out — the response says which field and for
//! how long, never the value (`docs/design.md` § Clipboard: "the daemon
//! owns the clipboard, so the secret never enters the client's address
//! space").

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"copy", ...}` carries; `Op::Copy` wraps it. `field` is the
/// allow-list from `docs/design.md` § Protocol — no arbitrary
/// custom-attribute dump in v1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopyRequest {
    pub db: String,
    pub uuid: Uuid,
    pub field: Field,
}

/// The fields `copy` can be asked for. Deliberately not every field
/// `keepass` exposes: `docs/design.md` reserves custom-attribute access for
/// later (§ Deferred), so this enum, not a bare string, is what keeps that
/// promise enforced by the type rather than by convention.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Password,
    Username,
    Url,
    Notes,
}

/// Everything `copy` can fail with.
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
    /// there is no secret to hand to the clipboard.
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
        }
    }
}

/// What a successful `copy` reports. `db` and `entry` are never put on the
/// wire (the client already named both) — they're here only so
/// `server.rs`'s operation log can say which database and entry a copy
/// touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOutcome {
    pub db: String,
    /// The entry's title, or its uuid when it has no readable title.
    pub entry: String,
    pub field: Field,
    /// Whole seconds until the daemon drops its clipboard offer on its own.
    pub expires_in: u64,
}

/// Serving `copy`. Named `CopyEntry` rather than `Copy` — `std::marker::Copy`
/// is in the prelude, and `impl Copy for Server` would collide with every
/// `#[derive(Copy, ...)]` elsewhere in the crate the moment both traits are
/// in scope together. `Status`/`List`/`Lock`/`Unlock` don't have this
/// problem; this one does, so it gets a different name.
pub trait CopyEntry {
    fn copy(&self, request: &CopyRequest) -> Result<CopyOutcome, CopyError>;
}
