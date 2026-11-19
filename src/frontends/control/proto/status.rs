//! `status`: the lock state of every configured database.
//!
//! The one op with no error type. It reports state the daemon already
//! holds in memory, so there is nothing for it to fail at — which is why
//! [`Response::Status`](super::Response::Status) carries no `Result`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatabaseStatus {
    pub name: String,
    pub locked: bool,
    /// Omitted while locked: the daemon has no entries to count until the
    /// database is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<usize>,
}

/// Serving `status`. Returns a bare `Vec` rather than a `Result` — there
/// is no failure to report.
pub trait Status {
    fn status(&self) -> Vec<DatabaseStatus>;

    /// The daemon's own build version (`kpa::VERSION`), piggybacked on
    /// `status` rather than given its own op: `kpa version` needs exactly
    /// one thing from the daemon, and `status` is already the "what's the
    /// daemon's state" round trip every client makes to find out. A default
    /// impl, since every `Handler` means the same build talking about
    /// itself — there is nothing for an implementor to override.
    fn daemon_version(&self) -> String {
        crate::VERSION.to_string()
    }
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

    /// `daemon_version`'s default impl is what every real `Handler` gets
    /// for free; pin it against `crate::VERSION` so a change to one can't
    /// silently drift from the other.
    #[test]
    fn daemon_version_defaults_to_the_crate_version() {
        struct Fake;
        impl Status for Fake {
            fn status(&self) -> Vec<DatabaseStatus> {
                Vec::new()
            }
        }
        assert_eq!(Fake.daemon_version(), crate::VERSION);
    }
}
