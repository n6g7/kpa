//! What `kpa ssh grants` prints (`docs/ssh-agent.md` § 6.8): the signature
//! approvals currently granted, one per line.
//!
//! Pure: the grants and the time now in, text out. Cells go through
//! `output::Table`, which escapes them (`docs/threat-model.md` T-13): key
//! names come from the vault. The key is shown by its name, as `kpa ssh
//! pending` shows it.

use std::time::SystemTime;

use serde::Deserialize;

use super::ssh_requests_report::{age, span};
use crate::frontends::control::proto::WireGrant;
use crate::output::Table;

/// What `ssh_grants` answers: the approvals, grouped by database in config
/// order and oldest first within each.
#[derive(Deserialize)]
pub struct Grants {
    grants: Vec<WireGrant>,
}

/// A cell with nothing to say.
const NONE: &str = "-";

/// The table of `answer`, with each approval's age at `now`.
pub fn render(answer: &Grants, now: SystemTime) -> String {
    if answer.grants.is_empty() {
        return "No SSH approval is granted.\n".to_string();
    }
    let mut table = Table::new([
        "KEY",
        "DATABASE",
        "DESTINATION",
        "FORWARDING HOST",
        "LASTS",
        "AGE",
        "GRANTED BY",
        "USES",
        "IDLE LOCK",
    ]);
    for grant in &answer.grants {
        table.row([
            &grant.scope.key.name,
            &grant.scope.key.db,
            &grant
                .scope
                .destination
                .map_or_else(|| NONE.to_string(), |destination| destination.to_string()),
            &grant
                .scope
                .forwarding_host
                .map_or_else(|| NONE.to_string(), |host| host.to_string()),
            &lasts(grant),
            &age(now, grant.granted_at),
            match grant.by.as_str() {
                "on_screen" => "screen",
                by => by,
            },
            &grant.uses.to_string(),
            &format!("in {}", span(grant.idle_lock_in)),
        ]);
    }
    format!(
        "{}\n`kpa lock <database>` drops a database's approvals. IDLE LOCK is when \
         the database locks if nothing uses it.\n",
        table.render()
    )
}

/// How long the approval covers: until its database locks, or one signature
/// for as long as it still waits for it.
fn lasts(grant: &WireGrant) -> String {
    match grant.expires_in {
        Some(left) if !grant.remember => format!("1 signature, {} left", span(left)),
        _ => "until lock".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use uuid::Uuid;

    use super::*;
    use crate::frontends::control::proto::{WireScope, WireSshKey};

    const KEY: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";
    const DESTINATION: &str = "SHA256:BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /// The clock the report is rendered at.
    const NOW: u64 = 1_700_000_000;

    fn grant(name: &str) -> WireGrant {
        WireGrant {
            granted_at: NOW - 75,
            scope: WireScope {
                key: WireSshKey {
                    db: "personal".to_string(),
                    key_type: "ssh-ed25519".to_string(),
                    fingerprint: KEY.to_string(),
                    name: name.to_string(),
                    entry: Uuid::from_u128(9),
                    title: None,
                    attachment: "id_ed25519".to_string(),
                },
                destination: Some(DESTINATION.parse().expect("a fingerprint")),
                forwarding_host: None,
            },
            remember: true,
            expires_in: None,
            by: "on_screen".to_string(),
            uses: 3,
            idle_lock_in: 29 * 60 + 12,
        }
    }

    fn at_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW)
    }

    #[test]
    fn approvals_are_listed_in_aligned_columns() {
        let mut once = grant("deploy-key");
        once.scope.destination = None;
        once.scope.forwarding_host = Some(KEY.parse().expect("a fingerprint"));
        once.remember = false;
        once.expires_in = Some(42);
        once.by = "cli".to_string();
        once.uses = 0;
        once.granted_at = NOW - 4;

        let text = render(
            &Grants {
                grants: vec![grant("github"), once],
            },
            at_now(),
        );

        assert_eq!(
            text,
            format!(
                "\
KEY         DATABASE  DESTINATION                                         FORWARDING HOST                                     LASTS                  AGE  GRANTED BY  USES  IDLE LOCK
github      personal  {DESTINATION}  -                                                   until lock             1m   screen      3     in 29m
deploy-key  personal  -                                                   {KEY}  1 signature, 42s left  4s   cli         0     in 29m

`kpa lock <database>` drops a database's approvals. IDLE LOCK is when the database locks if nothing uses it.
"
            )
        );
    }

    #[test]
    fn nothing_granted_says_so() {
        assert_eq!(
            render(&Grants { grants: vec![] }, at_now()),
            "No SSH approval is granted.\n"
        );
    }
}
