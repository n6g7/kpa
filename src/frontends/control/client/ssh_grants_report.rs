//! What `kpa ssh grants` prints (`docs/ssh-agent.md` § 6.8): the signature
//! approvals currently granted, one per line.
//!
//! Pure: the grants and the time now in, text out. Cells go through
//! `output::Table`, which escapes them (`docs/threat-model.md` T-13): key
//! names come from the vault. The key is shown by its name, as `kpa ssh
//! pending` shows it.

use std::time::SystemTime;

use serde::Deserialize;

use super::ssh_requests_report::{age, host, session, span};
use crate::frontends::control::proto::WireGrant;
use crate::output::Table;
use crate::ssh::known_hosts::HostNames;

/// What `ssh_grants` answers: the approvals, grouped by database in config
/// order and oldest first within each.
#[derive(Deserialize)]
pub struct Grants {
    grants: Vec<WireGrant>,
}

/// A cell with nothing to say.
const NONE: &str = "-";

/// Every column, in order, and the ones shown without `--full`.
const HEADER: [&str; 11] = [
    "KEY",
    "DATABASE",
    "DESTINATION",
    "FORWARDING HOST",
    "SESSION",
    "LASTS",
    "AGE",
    "GRANTED BY",
    "USES",
    "LAST USED",
    "IDLE LOCK",
];
const BRIEF: [usize; 5] = [0, 2, 3, 5, 8];

/// The table of `answer`, with each approval's age at `now` and its hosts by
/// the name `names` gives them. Without `full` it keeps to the columns that
/// say what is approved.
pub fn render(answer: &Grants, now: SystemTime, names: &HostNames, full: bool) -> String {
    if answer.grants.is_empty() {
        return "No SSH approval is granted.\n".to_string();
    }
    let rows: Vec<[String; 11]> = answer
        .grants
        .iter()
        .map(|grant| cells(grant, now, names))
        .collect();
    let (table, footer) = if full {
        let mut table = Table::new(HEADER);
        for row in &rows {
            table.row(row.each_ref().map(String::as_str));
        }
        (
            table.render(),
            "`kpa lock <database>` drops a database's approvals. IDLE LOCK is when the database \
             locks if nothing uses it.",
        )
    } else {
        let mut table = Table::new(BRIEF.map(|column| HEADER[column]));
        for row in &rows {
            table.row(BRIEF.map(|column| row[column].as_str()));
        }
        (
            table.render(),
            "`kpa lock <database>` drops a database's approvals. `--full` shows more columns.",
        )
    };
    format!("{table}\n{footer}\n")
}

/// One approval's cells, one per [`HEADER`] column.
fn cells(grant: &WireGrant, now: SystemTime, names: &HostNames) -> [String; 11] {
    [
        grant.scope.key.name.clone(),
        grant.scope.key.db.clone(),
        host(grant.scope.destination.as_ref(), names),
        host(grant.scope.forwarding_host.as_ref(), names),
        session(&grant.scope),
        lasts(grant),
        age(now, grant.granted_at),
        match grant.by.as_str() {
            "on_screen" => "screen",
            by => by,
        }
        .to_string(),
        grant.uses.to_string(),
        grant
            .last_used_at
            .map_or_else(|| NONE.to_string(), |at| age(now, at)),
        format!("in {}", span(grant.idle_lock_in)),
    ]
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
    use crate::ssh::testing::test_key;

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
                forwarding_session: None,
            },
            remember: true,
            expires_in: None,
            by: "on_screen".to_string(),
            uses: 3,
            last_used_at: Some(NOW - 30),
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
        once.scope.forwarding_session = Some(2);
        once.last_used_at = None;
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
            &HostNames::default(),
            true,
        );

        assert_eq!(
            text,
            format!(
                "\
KEY         DATABASE  DESTINATION                                         FORWARDING HOST                                     SESSION  LASTS                  AGE  GRANTED BY  USES  LAST USED  IDLE LOCK
github      personal  {DESTINATION}  -                                                   -        until lock             1m   screen      3     30s        in 29m
deploy-key  personal  -                                                   {KEY}  2        1 signature, 42s left  4s   cli         0     -          in 29m

`kpa lock <database>` drops a database's approvals. IDLE LOCK is when the database locks if nothing uses it.
"
            )
        );
    }

    #[test]
    fn nothing_granted_says_so() {
        assert_eq!(
            render(
                &Grants { grants: vec![] },
                at_now(),
                &HostNames::default(),
                false
            ),
            "No SSH approval is granted.\n"
        );
    }

    /// Without `--full` the table says what is approved and nothing else.
    #[test]
    fn the_default_table_keeps_to_what_is_approved() {
        let mut once = grant("deploy-key");
        once.remember = false;
        once.expires_in = Some(42);
        once.uses = 0;

        let text = render(
            &Grants {
                grants: vec![grant("github"), once],
            },
            at_now(),
            &HostNames::default(),
            false,
        );

        assert_eq!(
            text,
            format!(
                "\
KEY         DESTINATION                                         FORWARDING HOST  LASTS                  USES
github      {DESTINATION}  -                until lock             3
deploy-key  {DESTINATION}  -                1 signature, 42s left  0

`kpa lock <database>` drops a database's approvals. `--full` shows more columns.
"
            )
        );
    }

    /// A host `known_hosts` names is shown by its name, any other by its
    /// fingerprint.
    #[test]
    fn a_host_known_by_name_is_shown_by_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let known = test_key(2).public_key().clone();
        std::fs::write(
            &path,
            format!("github.com {}\n", known.to_openssh().expect("encodes")),
        )
        .expect("write known_hosts");
        let mut forwarded = grant("github");
        forwarded.scope.destination = Some(known.fingerprint(ssh_key::HashAlg::Sha256));

        let text = render(
            &Grants {
                grants: vec![forwarded],
            },
            at_now(),
            &HostNames::read(Some(&path)),
            false,
        );

        assert!(text.contains("github.com"), "{text}");
        assert!(!text.contains(&known.fingerprint(ssh_key::HashAlg::Sha256).to_string()));
    }
}
