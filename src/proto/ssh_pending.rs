//! `ssh_pending`: the SSH requests refused for want of an approval, for
//! a client to approve one of (`docs/ssh-agent.md` § 6.8). It reads
//! state the daemon holds in memory, so like `status` it has no failure.

use serde::{Deserialize, Serialize};
use ssh_key::Fingerprint;
use uuid::Uuid;

/// One pending request. `id` is what `ssh_approve` names it by. `name`,
/// `user`, `namespace` and `command` are text from the vault or from the
/// requester: the caller escapes them before a terminal sees them
/// (`output::escape_one_line`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirePending {
    pub id: Uuid,
    pub db: String,
    /// As `ssh-add -l` prints it.
    pub key: Fingerprint,
    /// The key's name, as its identity comment gives it.
    pub name: String,
    /// `login`, `sshsig` or `other`.
    pub purpose: String,
    /// The remote user, of a login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The namespace, of an `sshsig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// How the requester's connection was classified: `local` or `local,
    /// bound`.
    pub class: String,
    /// The destination's host key, of a bound connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Fingerprint>,
    /// The requester's command name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Seconds since it was last refused.
    pub age: u64,
}

/// Serving `ssh_pending`.
pub trait SshPending {
    /// Every database's pending requests, in config order, oldest first.
    fn ssh_pending(&self) -> Vec<WirePending>;
}
