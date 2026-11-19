//! `ssh_pending`: the SSH requests refused for want of an approval, for
//! a client to approve one of (`docs/ssh-agent.md` § 6.8). It reads
//! state the daemon holds in memory, so like `status` it has no failure.

use serde::{Deserialize, Serialize};
use ssh_key::Fingerprint;
use uuid::Uuid;

use super::WireSshKey;

/// One pending request. `id` is what `ssh_approve` names it by. The key's
/// name and title come from the vault, and the request's `user`,
/// `namespace` and `command` from the requester: the caller escapes them
/// before a terminal sees them (`output::escape_one_line`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirePending {
    pub id: Uuid,
    /// When it was last refused, in Unix seconds. A client works out the age
    /// from it.
    pub refused_at: u64,
    /// What approving it grants.
    pub scope: WireScope,
    /// Whether the approval is kept until lock (`true`) or covers this one
    /// signature (`false`).
    pub remember: bool,
    /// What was refused.
    pub request: WireRequestDetails,
}

/// What an approval covers: a key, and for a bound connection the
/// destination it was bound to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireScope {
    pub key: WireSshKey,
    /// The destination's host key, of a bound connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Fingerprint>,
}

/// What a refused request was.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireRequestDetails {
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
    /// The requester's command name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// Serving `ssh_pending`.
pub trait SshPending {
    /// Every database's pending requests, in config order, oldest first.
    fn ssh_pending(&self) -> Vec<WirePending>;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const KEY: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";

    fn pending() -> WirePending {
        WirePending {
            id: Uuid::from_u128(1),
            refused_at: 1_700_000_000,
            scope: WireScope {
                key: WireSshKey {
                    db: "personal".to_string(),
                    key_type: "ssh-ed25519".to_string(),
                    fingerprint: KEY.to_string(),
                    name: "github".to_string(),
                    entry: Uuid::from_u128(2),
                    title: Some("GitHub".to_string()),
                    attachment: "id_ed25519".to_string(),
                },
                destination: Some(KEY.parse().expect("a fingerprint")),
            },
            remember: true,
            request: WireRequestDetails {
                purpose: "login".to_string(),
                user: Some("git".to_string()),
                namespace: None,
                class: "local, bound".to_string(),
                command: Some("ssh".to_string()),
            },
        }
    }

    /// A pending request is what approving it grants, the key it is for
    /// (the object `ssh_keys` reports), and what was refused.
    #[test]
    fn a_pending_request_is_a_scope_and_what_was_refused() {
        assert_eq!(
            serde_json::to_value(pending()).expect("serializes"),
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "refused_at": 1_700_000_000,
                "scope": {
                    "key": {
                        "db": "personal",
                        "type": "ssh-ed25519",
                        "fingerprint": KEY,
                        "name": "github",
                        "entry": "00000000-0000-0000-0000-000000000002",
                        "title": "GitHub",
                        "attachment": "id_ed25519",
                    },
                    "destination": KEY,
                },
                "remember": true,
                "request": {
                    "purpose": "login",
                    "user": "git",
                    "class": "local, bound",
                    "command": "ssh",
                },
            })
        );
    }

    /// What a request or a key has none of is left out, not null.
    #[test]
    fn what_a_request_has_none_of_is_left_out() {
        let bare = WirePending {
            scope: WireScope {
                key: WireSshKey {
                    title: None,
                    ..pending().scope.key
                },
                destination: None,
            },
            request: WireRequestDetails {
                user: None,
                command: None,
                ..pending().request
            },
            ..pending()
        };

        let json = serde_json::to_value(&bare).expect("serializes");

        assert!(json["scope"].get("destination").is_none());
        assert!(json["scope"]["key"].get("title").is_none());
        assert!(json["request"].get("user").is_none());
        assert!(json["request"].get("command").is_none());
        let back: WirePending = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, bare);
    }
}
