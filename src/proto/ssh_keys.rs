//! `ssh_keys`: what the unlocked databases hold in the way of SSH keys
//! (`docs/ssh-agent.md` § 6.4), for `kpa ssh keys`. A scan of unlocked
//! databases, so like `list` it can only fail on *which* database was asked
//! for.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ErrorCode, ErrorFields};

/// What `{"op":"ssh_keys", ...}` carries; `Op::SshKeys` wraps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshKeysRequest {
    /// `None` covers every unlocked database, listing the locked ones in
    /// the report rather than failing on them, as `list` skips them.
    /// Omitted from the wire rather than sent as `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<String>,
}

/// What the scan found: the keys the agent can serve and the attachments
/// it skipped. Entry titles are vault content: they reach the same-uid
/// caller of this request, who escapes them before a terminal sees them
/// (`output::escape_one_line`), and never the daemon's log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SshKeysReport {
    /// In config order of the databases, then entry order.
    pub keys: Vec<WireSshKey>,
    pub skipped: Vec<WireSkippedKey>,
    /// Configured databases a request for all of them could not scan.
    /// Omitted when empty, and always for a request that named one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked: Vec<String>,
}

/// One SSH key in a database: what `ssh_keys` reports for each key found,
/// and what a pending request names its key by.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSshKey {
    /// The database it was found in. A key held by two databases is
    /// reported once for each.
    pub db: String,
    /// The key type as `ssh-add -l` shows it, such as `ssh-ed25519`.
    #[serde(rename = "type")]
    pub key_type: String,
    /// `SHA256:…`, the form a `[[database.ssh_key]]` names a key by.
    pub fingerprint: String,
    /// The key's name: its `[[database.ssh_key]]` override's, else its
    /// entry's title, else `<database> <fingerprint>`.
    pub name: String,
    /// The entry's uuid.
    pub entry: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The attachment's file name on the entry.
    pub attachment: String,
}

/// One attachment that looked like a private key and was not read as one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSkippedKey {
    pub db: String,
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
    /// to the key cache: it exists to show what the vault holds now. Only
    /// a request that named the database fails on it.
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
