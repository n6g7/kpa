//! `unlock`: the only op that reads a file and the only one that asks for
//! credentials — which is why its error type is by far the largest of the
//! four.

use serde::{Deserialize, Serialize};

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"unlock", ...}` carries; `Op::Unlock` wraps it. `db` is
/// required — there is no "unlock everything".
///
/// The master password is never in a request: the daemon asks the user for
/// it, on screen or on the terminal the request passed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockRequest {
    pub db: String,
}

/// Everything `unlock` can fail with. Every variant but `NoPrompt` names
/// the database the unlock was for, even when the cause isn't about the
/// database itself (a dismissed prompt). `NoPrompt` is about where the
/// request came from, not about any database, so it names none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    UnknownDb {
        db: String,
    },
    /// The prompt ended without a password: the prompt command exited
    /// unsuccessfully, typically the user dismissing it, or the terminal it
    /// was on went away, or nothing was entered before the timeout.
    PromptCancelled {
        db: String,
    },
    /// The prompt couldn't be shown at all: the command isn't on `PATH` or
    /// isn't executable, or the terminal couldn't be written to or read.
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
    /// The file is a KeePass format kpa doesn't read (KeePass 1.x, say).
    /// Reported as `corrupt`, with a `detail` that names the cause.
    UnsupportedFormat {
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
    /// No prompt was raised, because nobody could answer it: the request
    /// can't be asked on screen (it comes from outside the desktop, or the
    /// screen is known to be locked, or it preferred the terminal) and it
    /// passed no terminal.
    NoPrompt,
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
            UnlockError::UnsupportedFormat { db } => ErrorFields::new(ErrorCode::Corrupt)
                .db(db)
                .detail("not a KDBX3 or KDBX4 file; kpa reads only those"),
            UnlockError::Io { db } => ErrorFields::new(ErrorCode::Io).db(db),
            UnlockError::InProgress { db } => ErrorFields::new(ErrorCode::UnlockInProgress).db(db),
            UnlockError::LockedDuringUnlock { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            UnlockError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
            UnlockError::NoPrompt => {
                ErrorFields::new(ErrorCode::NoPrompt).detail("no screen or terminal to prompt on")
            }
        }
    }
}
