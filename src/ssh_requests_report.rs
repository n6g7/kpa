//! What `kpa ssh pending` and `kpa ssh approve` print (`docs/ssh-agent.md`
//! § 6.8): the SSH requests refused for want of an approval, one per line,
//! each with the id `kpa ssh approve` takes, and the line that says one was
//! approved.
//!
//! Pure: the requests in, text out. Cells go through `output::Table`, which
//! escapes them (`docs/threat-model.md` T-13): key names come from the
//! vault, and users and command names from the requester.

use std::time::Duration;

use kpa::output::Table;
use kpa::proto::WirePending;
use kpa::ssh_agent::approve::PENDING_TTL;
use serde::Deserialize;
use uuid::Uuid;

/// What `ssh_pending` answers: the requests, oldest first.
#[derive(Deserialize)]
pub(super) struct Pending {
    pending: Vec<WirePending>,
}

/// What `ssh_approve` answers when it approved: nothing.
#[derive(Deserialize)]
pub(super) struct Approved {}

/// The line `kpa ssh approve` prints once `id` is approved.
pub(super) fn approved(id: Uuid, _: &Approved) -> String {
    format!("Approved {id}. Retry the command that was refused.\n")
}

/// A cell with nothing to say.
const NONE: &str = "-";

pub(super) fn render(answer: &Pending) -> String {
    if answer.pending.is_empty() {
        return "No SSH request is pending.\n".to_string();
    }
    let mut table = Table::new([
        "ID",
        "KEY",
        "DATABASE",
        "REQUEST",
        "FROM",
        "AGE",
        "DESTINATION",
    ]);
    for request in &answer.pending {
        table.row([
            &request.id.to_string(),
            &request.name,
            &request.db,
            &what(request),
            request.command.as_deref().unwrap_or(NONE),
            &age(Duration::from_secs(request.age)),
            &request
                .destination
                .map_or_else(|| NONE.to_string(), |destination| destination.to_string()),
        ]);
    }
    format!(
        "{}\nApprove one with `kpa ssh approve <id>`. A request left alone expires after {} \
         minutes, and nothing is blocked meanwhile.\n",
        table.render(),
        PENDING_TTL.as_secs() / 60,
    )
}

/// What the requester asked for, unescaped: the table does that.
fn what(request: &WirePending) -> String {
    match (request.purpose.as_str(), &request.user, &request.namespace) {
        ("login", Some(user), _) => format!("login as {user}"),
        ("login", None, _) => "login".to_string(),
        ("sshsig", _, Some(namespace)) => format!("sign ({namespace})"),
        ("sshsig", _, None) => "sign".to_string(),
        _ => "other".to_string(),
    }
}

fn age(age: Duration) -> String {
    match age.as_secs() {
        secs if secs < 60 => format!("{secs}s"),
        secs => format!("{}m", secs / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `SHA256:…` fingerprints, `ssh_key`'s own doc example and one
    /// that differs from it.
    const KEY: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";
    const DESTINATION: &str = "SHA256:BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn request() -> WirePending {
        WirePending {
            id: Uuid::from_u128(1),
            db: "personal".to_string(),
            key: KEY.parse().expect("a fingerprint"),
            name: "github".to_string(),
            purpose: "login".to_string(),
            user: Some("alice".to_string()),
            namespace: None,
            class: "local, bound".to_string(),
            destination: Some(DESTINATION.parse().expect("a fingerprint")),
            command: Some("ssh".to_string()),
            age: 75,
        }
    }

    fn pending(pending: Vec<WirePending>) -> Pending {
        Pending { pending }
    }

    #[test]
    fn requests_are_listed_in_aligned_columns_with_their_ids() {
        let signing = WirePending {
            id: Uuid::from_u128(2),
            name: "deploy-key".to_string(),
            purpose: "sshsig".to_string(),
            user: None,
            namespace: Some("git".to_string()),
            destination: None,
            command: None,
            age: 4,
            ..request()
        };

        let text = render(&pending(vec![request(), signing]));

        assert_eq!(
            text,
            format!(
                "\
ID                                    KEY         DATABASE  REQUEST         FROM  AGE  DESTINATION
00000000-0000-0000-0000-000000000001  github      personal  login as alice  ssh   1m   {DESTINATION}
00000000-0000-0000-0000-000000000002  deploy-key  personal  sign (git)      -     4s   -

Approve one with `kpa ssh approve <id>`. A request left alone expires after 5 minutes, and nothing is blocked meanwhile.
"
            )
        );
    }

    #[test]
    fn an_approval_names_the_request_and_says_to_retry() {
        assert_eq!(
            approved(Uuid::from_u128(1), &Approved {}),
            "Approved 00000000-0000-0000-0000-000000000001. Retry the command that was refused.\n"
        );
    }

    #[test]
    fn nothing_pending_says_so() {
        assert_eq!(render(&pending(Vec::new())), "No SSH request is pending.\n");
    }

    /// Text the requester or the vault chose can't drive the terminal or
    /// break a line: a key name, user and command made of control
    /// characters come out escaped.
    #[test]
    fn hostile_text_is_escaped() {
        let hostile = WirePending {
            user: Some("evil\u{1b}[2J\n".to_string()),
            command: Some("a\u{9b}b".to_string()),
            name: "n\u{7}ame".to_string(),
            ..request()
        };

        let text = render(&pending(vec![hostile]));

        assert!(!text.contains(['\u{1b}', '\u{9b}', '\u{7}']), "{text:?}");
        assert!(text.contains("evil\\u001b[2J\\u000a"), "{text}");
        assert_eq!(text.lines().count(), 4, "{text}");
    }
}
