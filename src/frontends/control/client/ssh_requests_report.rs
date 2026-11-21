//! What `kpa ssh pending` and `kpa ssh approve` print (`docs/ssh-agent.md`
//! § 6.8): the SSH requests refused for want of an approval, one per line,
//! each with the id `kpa ssh approve` takes, and the line that says one was
//! approved.
//!
//! Pure: the requests and the time now in, text out. Cells go through `output::Table`, which
//! escapes them (`docs/threat-model.md` T-13): key names come from the
//! vault, and users and command names from the requester. The key is shown
//! by its name, which is its entry's title unless the config names it
//! otherwise; the entry's title and the attachment's name would say no more
//! about which key it is.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::frontends::control::proto::{WirePending, WireScope};
use crate::output::Table;
use crate::ssh::approvals::PENDING_TTL;
use serde::Deserialize;
use uuid::Uuid;

/// What `ssh_pending` answers: the requests, oldest first.
#[derive(Deserialize)]
pub struct Pending {
    pending: Vec<WirePending>,
}

/// What `ssh_approve` answers when it approved: nothing.
#[derive(Deserialize)]
pub struct Approved {}

/// The line `kpa ssh approve` prints once `id` is approved.
pub fn approved(id: Uuid, _: &Approved) -> String {
    format!("Approved {id}. Retry the command that was refused.\n")
}

/// A cell with nothing to say.
const NONE: &str = "-";

/// The table of `answer`, with each request's age at `now`.
pub fn render(answer: &Pending, now: SystemTime) -> String {
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
        "FORWARDING HOST",
        "SESSION",
    ]);
    for request in &answer.pending {
        table.row([
            &request.id.to_string(),
            &request.scope.key.name,
            &request.scope.key.db,
            &what(request),
            request.request.command.as_deref().unwrap_or(NONE),
            &age(now, request.refused_at),
            &request
                .scope
                .destination
                .map_or_else(|| NONE.to_string(), |destination| destination.to_string()),
            &request
                .scope
                .forwarding_host
                .map_or_else(|| NONE.to_string(), |host| host.to_string()),
            &session(&request.scope),
        ]);
    }
    format!(
        "{}\nApprove one with `kpa ssh approve <id>`. A request left alone expires after {} \
         minutes, and nothing is blocked meanwhile.\n",
        table.render(),
        PENDING_TTL.as_secs() / 60,
    )
}

/// The number of the forwarding session a forwarded request comes from.
pub(super) fn session(scope: &WireScope) -> String {
    scope
        .forwarding_session
        .map_or_else(|| NONE.to_string(), |session| session.to_string())
}

/// What the requester asked for, unescaped: the table does that.
fn what(request: &WirePending) -> String {
    let request = &request.request;
    match (request.purpose.as_str(), &request.user, &request.namespace) {
        ("login", Some(user), _) => format!("login as {user}"),
        ("login", None, _) => "login".to_string(),
        ("sshsig", _, Some(namespace)) => format!("sign ({namespace})"),
        ("sshsig", _, None) => "sign".to_string(),
        _ => "other".to_string(),
    }
}

/// How long before `now` a request was refused. A request dated in the future
/// is just refused.
pub(super) fn age(now: SystemTime, refused_at: u64) -> String {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    span(
        now.saturating_sub(Duration::from_secs(refused_at))
            .as_secs(),
    )
}

/// `secs` seconds as the tables show a span: seconds below a minute, whole
/// minutes after.
pub(super) fn span(secs: u64) -> String {
    match secs {
        secs if secs < 60 => format!("{secs}s"),
        secs => format!("{}m", secs / 60),
    }
}

#[cfg(test)]
mod tests {
    use crate::frontends::control::proto::{WireRequestDetails, WireScope, WireSshKey};

    use super::*;

    /// Real `SHA256:…` fingerprints, `ssh_key`'s own doc example and one
    /// that differs from it.
    const KEY: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";
    /// The clock the reports are rendered at.
    const NOW: u64 = 1_700_000_000;
    const DESTINATION: &str = "SHA256:BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn request() -> WirePending {
        WirePending {
            id: Uuid::from_u128(1),
            refused_at: NOW - 75,
            scope: WireScope {
                key: WireSshKey {
                    db: "personal".to_string(),
                    key_type: "ssh-ed25519".to_string(),
                    fingerprint: KEY.to_string(),
                    name: "github".to_string(),
                    entry: Uuid::from_u128(9),
                    title: Some("GitHub".to_string()),
                    attachment: "id_ed25519".to_string(),
                },
                destination: Some(DESTINATION.parse().expect("a fingerprint")),
                forwarding_host: None,
                forwarding_session: None,
            },
            remember: true,
            request: WireRequestDetails {
                purpose: "login".to_string(),
                user: Some("alice".to_string()),
                namespace: None,
                class: "local, bound".to_string(),
                command: Some("ssh".to_string()),
            },
        }
    }

    /// `request()`, with its key named `name`.
    fn named(name: &str) -> WirePending {
        let mut named = request();
        named.scope.key.name = name.to_string();
        named
    }

    fn at_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW)
    }

    fn pending(pending: Vec<WirePending>) -> Pending {
        Pending { pending }
    }

    #[test]
    fn requests_are_listed_in_aligned_columns_with_their_ids() {
        let signing = {
            let mut signing = named("deploy-key");
            signing.id = Uuid::from_u128(2);
            signing.refused_at = NOW - 4;
            signing.scope.destination = None;
            signing.scope.forwarding_host = Some(KEY.parse().expect("a fingerprint"));
            signing.scope.forwarding_session = Some(2);
            signing.request = WireRequestDetails {
                purpose: "sshsig".to_string(),
                user: None,
                namespace: Some("git".to_string()),
                class: "local".to_string(),
                command: None,
            };
            signing
        };

        let text = render(&pending(vec![request(), signing]), at_now());

        assert_eq!(
            text,
            format!(
                "\
ID                                    KEY         DATABASE  REQUEST         FROM  AGE  DESTINATION                                         FORWARDING HOST                                     SESSION
00000000-0000-0000-0000-000000000001  github      personal  login as alice  ssh   1m   {DESTINATION}  -                                                   -
00000000-0000-0000-0000-000000000002  deploy-key  personal  sign (git)      -     4s   -                                                   {KEY}  2

Approve one with `kpa ssh approve <id>`. A request left alone expires after 5 minutes, and nothing is blocked meanwhile.
"
            )
        );
    }

    #[test]
    fn a_request_from_the_future_is_just_refused() {
        let mut ahead = request();
        ahead.refused_at = NOW + 30;

        assert!(render(&pending(vec![ahead]), at_now()).contains("  0s  "));
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
        assert_eq!(
            render(&pending(Vec::new()), at_now()),
            "No SSH request is pending.\n"
        );
    }

    /// Text the requester or the vault chose can't drive the terminal or
    /// break a line: a key name, user and command made of control
    /// characters come out escaped.
    #[test]
    fn hostile_text_is_escaped() {
        let mut hostile = named("n\u{7}ame");
        hostile.request.user = Some("evil\u{1b}[2J\n".to_string());
        hostile.request.command = Some("a\u{9b}b".to_string());

        let text = render(&pending(vec![hostile]), at_now());

        assert!(!text.contains(['\u{1b}', '\u{9b}', '\u{7}']), "{text:?}");
        assert!(text.contains("evil\\u001b[2J\\u000a"), "{text}");
        assert_eq!(text.lines().count(), 4, "{text}");
    }
}
