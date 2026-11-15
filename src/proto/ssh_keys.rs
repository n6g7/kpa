//! `ssh_keys`: what a database's vault holds in the way of SSH keys
//! (`docs/ssh-agent.md` § 6.4), for `kpa ssh keys`. A scan of an unlocked
//! database, so like `list` it can only fail on *which* database was asked
//! for.

use serde::{Deserialize, Serialize};

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"ssh_keys", ...}` carries; `Op::SshKeys` wraps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshKeysRequest {
    pub db: String,
}

/// What the scan found: the keys the agent can serve and the attachments
/// it skipped. Entry titles are vault content: they reach the same-uid
/// caller of this request, who escapes them before a terminal sees them
/// (`output::escape_one_line`), and never the daemon's log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SshKeysReport {
    pub keys: Vec<WireSshKey>,
    pub skipped: Vec<WireSkippedKey>,
}

/// One key found in an attachment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSshKey {
    /// The key type as `ssh-add -l` shows it, such as `ssh-ed25519`.
    #[serde(rename = "type")]
    pub key_type: String,
    /// `SHA256:…`, the form a `[[database.ssh_key]]` names a key by.
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The attachment's file name on the entry.
    pub attachment: String,
}

/// One attachment that looked like a private key and was not read as one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSkippedKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub attachment: String,
    /// Why, in words, with what to do about it where there is something to
    /// do.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeysError {
    UnknownDb {
        db: String,
    },
    /// A locked database has nothing to scan. The request never falls back
    /// to the key cache: it exists to show what the vault holds now.
    Locked {
        db: String,
    },
    /// The database's file changed on disk since it was unlocked. The
    /// database is dropped by the time this is returned.
    Stale {
        db: String,
    },
}

impl SshKeysError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            SshKeysError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            SshKeysError::Locked { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            SshKeysError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
        }
    }
}

/// Serving `ssh_keys`.
pub trait SshKeys {
    fn ssh_keys(&self, request: &SshKeysRequest) -> Result<SshKeysReport, SshKeysError>;
}
