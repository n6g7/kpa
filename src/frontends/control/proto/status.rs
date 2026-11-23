//! `status`: the lock state of every configured database.
//!
//! The one op with no error type. It reports state the daemon already
//! holds in memory, so there is nothing for it to fail at — which is why
//! [`Response::Status`](super::Response::Status) carries no `Result`.

use serde::{Deserialize, Serialize};

/// What a successful `status` answers, as the daemon builds it and a client
/// reads it (`docs/protocol.md` § Responses).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub databases: Vec<DatabaseStatus>,
    /// The daemon's own build version (`kpa::VERSION`), so `kpa version`
    /// can name a CLI/daemon mismatch after an upgrade where the old
    /// daemon is still running.
    pub version: String,
    /// Whether a `copy` from the requester that asked would land. Advisory:
    /// `copy` decides again. A daemon older than the client doesn't send it,
    /// and that reads as `true`: the client goes on and `copy` decides.
    #[serde(default = "copy_may_land")]
    pub can_copy: bool,
}

fn copy_may_land() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatabaseStatus {
    pub name: String,
    pub locked: bool,
    /// Omitted while locked: the daemon has no entries to count until the
    /// database is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<usize>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `entries` being *absent* is what means "locked" — so an unlocked
    /// database with nothing in it has to report `0`, not omit the field.
    /// Otherwise an empty vault would be indistinguishable from a locked
    /// one, which are very different things to show in a tray icon.
    #[test]
    fn an_empty_unlocked_database_is_not_a_locked_one() {
        let unlocked_but_empty = DatabaseStatus {
            name: "personal".to_string(),
            locked: false,
            entries: Some(0),
        };
        assert_eq!(
            serde_json::to_value(&unlocked_but_empty).expect("should serialize"),
            json!({"name": "personal", "locked": false, "entries": 0})
        );

        let locked = DatabaseStatus {
            name: "personal".to_string(),
            locked: true,
            entries: None,
        };
        assert_eq!(
            serde_json::to_value(&locked).expect("should serialize"),
            json!({"name": "personal", "locked": true})
        );
    }
}
