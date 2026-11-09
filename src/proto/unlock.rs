//! `unlock`: the only op that reads a file and the only one that asks for
//! credentials — which is why its error type is by far the largest of the
//! four.

use serde::{Deserialize, Serialize};

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"unlock", ...}` carries; `Op::Unlock` wraps it. `db` is
/// required — there is no "unlock everything".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockRequest {
    pub db: String,
}

/// Everything `unlock` can fail with. Every variant names the database the
/// unlock was for, so the error says which request failed, even when the
/// cause isn't about the database itself (a dismissed prompt, a locked
/// screen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    UnknownDb {
        db: String,
    },
    /// The prompt command exited unsuccessfully — typically the user
    /// dismissing it.
    PromptCancelled {
        db: String,
    },
    /// The prompt command couldn't be run at all: not on `PATH`, not
    /// executable, and so on.
    PromptFailed {
        db: String,
        detail: String,
    },
    WrongCredentials {
        db: String,
    },
    /// The `.kdbx` or its keyfile isn't where the config says it is.
    NotFound {
        db: String,
    },
    Corrupt {
        db: String,
    },
    Io {
        db: String,
    },
    /// Another `unlock` of the same database is already prompting. Refused
    /// rather than queued, so one keypress can't stack up password prompts.
    InProgress {
        db: String,
    },
    /// A `lock` arrived while this unlock was prompting or deriving the
    /// key. The lock wins: the database this unlock opened is discarded.
    /// Reported as `locked`, which is the state it leaves behind.
    LockedDuringUnlock {
        db: String,
    },
    /// The database file changed while it was being read, so the read
    /// can't be trusted. Nothing was unlocked; try again.
    Stale {
        db: String,
    },
    /// The screen is known to be locked, so no prompt was raised: nobody
    /// could answer it behind the locker.
    NoDisplay {
        db: String,
    },
}

impl UnlockError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            UnlockError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            UnlockError::PromptCancelled { db } => {
                ErrorFields::new(ErrorCode::PromptCancelled).db(db)
            }
            // Reported as plain `io`: from the client's side "the daemon
            // couldn't run the prompt" is an I/O failure like any other,
            // and `detail` says which one. `prompt_cancelled` stays
            // distinct because that one is the user's own doing.
            UnlockError::PromptFailed { db, detail } => ErrorFields::new(ErrorCode::Io)
                .db(db)
                .detail(detail.as_str()),
            UnlockError::WrongCredentials { db } => {
                ErrorFields::new(ErrorCode::WrongCredentials).db(db)
            }
            UnlockError::NotFound { db } => ErrorFields::new(ErrorCode::NotFound).db(db),
            UnlockError::Corrupt { db } => ErrorFields::new(ErrorCode::Corrupt).db(db),
            UnlockError::Io { db } => ErrorFields::new(ErrorCode::Io).db(db),
            UnlockError::InProgress { db } => ErrorFields::new(ErrorCode::UnlockInProgress).db(db),
            UnlockError::LockedDuringUnlock { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            UnlockError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
            UnlockError::NoDisplay { db } => ErrorFields::new(ErrorCode::NoDisplay)
                .db(db)
                .detail("the screen is locked"),
        }
    }
}

/// Serving `unlock`. The implementor owns credential acquisition — the
/// protocol never carries a password, so nothing about *how* the
/// implementor asks for one appears in this signature.
pub trait Unlock {
    /// `Ok` names the database that is now unlocked.
    fn unlock(&self, request: &UnlockRequest) -> Result<String, UnlockError>;
}
