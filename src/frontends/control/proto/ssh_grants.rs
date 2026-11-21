//! `ssh_grants`: the signature approvals currently granted, for a client to
//! list (`docs/ssh-agent.md` § 6.8). It reads state the daemon holds in
//! memory, so like `status` it has no failure, and it is never logged.

use serde::{Deserialize, Serialize};

use super::WireScope;

/// One approval the user gave. The key's name and title come from the vault:
/// the caller escapes them before a terminal sees them
/// (`output::escape_one_line`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGrant {
    /// When it was given, in Unix seconds. A client works out the age from
    /// it.
    pub granted_at: u64,
    /// What it covers.
    pub scope: WireScope,
    /// Whether it is kept until lock (`true`) or covers one signature
    /// (`false`).
    pub remember: bool,
    /// For a one-signature approval, the seconds it still waits for its
    /// signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// How it was given: `on_screen` or `cli`.
    pub by: String,
    /// The signatures it has covered.
    pub uses: u64,
    /// When it last covered one, in Unix seconds. Absent if it never has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    /// The seconds before its database locks for being idle, if nothing uses
    /// it.
    pub idle_lock_in: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::frontends::control::proto::WireSshKey;

    const KEY: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";

    fn grant() -> WireGrant {
        WireGrant {
            granted_at: 1_700_000_000,
            scope: WireScope {
                key: WireSshKey {
                    db: "personal".to_string(),
                    key_type: "ssh-ed25519".to_string(),
                    fingerprint: KEY.to_string(),
                    name: "github".to_string(),
                    entry: Uuid::from_u128(2),
                    title: None,
                    attachment: "id_ed25519".to_string(),
                },
                destination: None,
                forwarding_host: None,
                forwarding_session: None,
            },
            remember: true,
            expires_in: None,
            by: "on_screen".to_string(),
            uses: 3,
            last_used_at: Some(1_700_000_030),
            idle_lock_in: 1500,
        }
    }

    /// What a grant has none of is left out, not null.
    #[test]
    fn a_grant_is_a_scope_how_long_it_lasts_and_how_it_has_been_used() {
        let mut one_signature = grant();
        one_signature.remember = false;
        one_signature.expires_in = Some(42);
        one_signature.by = "cli".to_string();
        one_signature.last_used_at = None;
        one_signature.scope.forwarding_session = Some(2);

        let kept = serde_json::to_value(grant()).expect("serializes");
        assert_eq!(kept["granted_at"], 1_700_000_000);
        assert_eq!(kept["remember"], true);
        assert!(kept.get("expires_in").is_none());
        assert_eq!(kept["by"], "on_screen");
        assert_eq!(kept["uses"], 3);
        assert_eq!(kept["last_used_at"], 1_700_000_030u64);
        assert!(kept["scope"].get("forwarding_session").is_none());
        assert_eq!(kept["idle_lock_in"], 1500);
        assert!(kept["scope"].get("destination").is_none());

        let once = serde_json::to_value(&one_signature).expect("serializes");
        assert_eq!(once["expires_in"], json!(42));
        assert!(once.get("last_used_at").is_none());
        assert_eq!(once["scope"]["forwarding_session"], 2);
        let back: WireGrant = serde_json::from_value(once).expect("deserializes");
        assert_eq!(back, one_signature);
    }
}
