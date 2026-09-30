//! `lock`: drops in-memory state and touches no files, so there is exactly
//! one way for it to fail.

use serde::{Deserialize, Serialize};

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"lock", ...}` carries; `Op::Lock` wraps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockRequest {
    /// `None` locks every database. Omitted from the wire rather than
    /// sent as `null`, matching `docs/design.md`'s "db omitted = lock
    /// all"; an incoming explicit `null` still reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    UnknownDb { db: String },
}

impl LockError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        let LockError::UnknownDb { db } = self;
        ErrorFields::new(ErrorCode::UnknownDb).db(db)
    }
}

/// Serving `lock`.
pub trait Lock {
    /// `Ok` echoes back what was locked — `None` meaning "all of them".
    fn lock(&self, request: &LockRequest) -> Result<Option<String>, LockError>;
}
