//! What the unlock and confirm prompts say (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the key, what it is for and where the signature goes, as one
//! question, and the pieces it is made of, for a prompt program that wants
//! them (`KPA_PROMPT_DATA`, `docs/design.md`).
//!
//! Each prompt's [`PromptData`] is filled first, with every piece escaped and
//! cut to its budget, and the message is formatted from that data and
//! nothing else, so the two can't disagree.

use ssh_key::HashAlg;
use ssh_key::public::KeyData;

use crate::frontends::ssh_agent::classify::Purpose;
use crate::output::escape_one_line;
use crate::prompt::{HostData, PromptData, PromptKind, Question};
use crate::ssh::keys::ServedKey;

/// The most bytes (escaped) each piece of a message may take. The message
/// is one line the prompt caps at 320 bytes, and the destination comes last,
/// so every variable piece is cut well short of that: the worst message,
/// an unlock prompt for a login forwarded through a host `known_hosts`
/// doesn't name to one it doesn't name either, is 291 bytes
/// (`the_worst_message_fits_the_prompt_cap`), and the destination is always
/// whole.
const MAX_DATABASE_LEN: usize = 24;
const MAX_KEY_NAME_LEN: usize = 64;
/// The login user or `SSHSIG` namespace, from the request.
const MAX_REQUESTED_LEN: usize = 32;
/// A host name from `known_hosts`.
const MAX_HOST_NAME_LEN: usize = 56;

/// A host a message names: its host key, and the name `known_hosts` gives
/// it, if it has one.
pub(super) struct Host<'a> {
    pub(super) key: &'a KeyData,
    pub(super) name: Option<String>,
}

impl Host<'_> {
    /// The host as the data names it: its name, escaped and cut, and its
    /// host key's fingerprint.
    fn data(&self) -> HostData {
        HostData {
            name: self
                .name
                .as_deref()
                .map(|name| escape_one_line(name, MAX_HOST_NAME_LEN)),
            fingerprint: self.key.fingerprint(HashAlg::Sha256).to_string(),
        }
    }
}

/// The confirm prompt's question, which the user answers yes or no to:
/// "Approve use of key "github" to log in to git@github.com?". The key is
/// shown by its name, quoted. What follows says what it is for and, for a
/// connection bound to a `destination`, where: the host name `known_hosts`
/// gives its host key if it has one, else the host key's fingerprint. A
/// forwarded connection says which host it comes through too: "Approve use
/// of key "github" on build-box to log in to git@github.com?". Every piece
/// that comes from outside kpa's own text is escaped and cut to its own
/// budget, so none can hide the destination.
pub(super) fn approval(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&Host<'_>>,
    forwarding: Option<&Host<'_>>,
) -> Question {
    let data = data(
        PromptKind::Confirm,
        served,
        purpose,
        destination,
        forwarding,
    );
    let message = message(&format!("Approve use of {}", key(&data)), &data);
    Question { message, data }
}

/// The unlock prompt's question, about unlocking, which says what for:
/// "Unlock database personal to use key "github" to log in as git?". It
/// doesn't ask to approve the key; the confirm prompt does.
pub(super) fn unlock(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&Host<'_>>,
    forwarding: Option<&Host<'_>>,
) -> Question {
    let data = data(PromptKind::Unlock, served, purpose, destination, forwarding);
    let lead = format!(
        "Unlock database {} to use {}",
        data.database.as_deref().unwrap_or_default(),
        key(&data)
    );
    let message = message(&lead, &data);
    Question { message, data }
}

/// The pieces of a prompt about `served` and a request for `purpose`, each
/// escaped and cut to its budget.
fn data(
    kind: PromptKind,
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&Host<'_>>,
    forwarding: Option<&Host<'_>>,
) -> PromptData {
    let mut data = PromptData::new(kind);
    data.database = Some(escape_one_line(&served.database, MAX_DATABASE_LEN));
    data.key = Some(crate::prompt::KeyData {
        name: escape_one_line(&served.name, MAX_KEY_NAME_LEN),
        fingerprint: served.fingerprint.to_string(),
        key_type: served.public_key.algorithm().to_string(),
    });
    data.purpose = Some(purpose.label().to_string());
    match purpose {
        Purpose::Login(login) => {
            data.user = Some(escape_one_line(&login.user, MAX_REQUESTED_LEN));
        }
        Purpose::SshSig { namespace } => {
            data.namespace = Some(escape_one_line(namespace, MAX_REQUESTED_LEN));
        }
        Purpose::Other => {}
    }
    data.destination = destination.map(Host::data);
    data.forwarding_host = forwarding.map(Host::data);
    data
}

/// `key "github"`, the key's name quoted.
fn key(data: &PromptData) -> String {
    let name = data.key.as_ref().map_or("", |key| key.name.as_str());
    format!("key \"{}\"", quoted(name))
}

/// `lead`, then which host the request is forwarded through, then what the
/// key is for and where, as a question.
fn message(lead: &str, data: &PromptData) -> String {
    let through = on(data.forwarding_host.as_ref());
    let user = data.user.as_deref().unwrap_or_default();
    let what = match (data.purpose.as_deref(), data.destination.as_ref()) {
        (Some("login"), Some(dest)) => match &dest.name {
            Some(_) => format!(" to log in to {user}@{}", shown(dest)),
            None => format!(" to log in as {user} to {}", shown(dest)),
        },
        (Some("login"), None) => format!(" to log in as {user}"),
        (Some("sshsig"), destination) => format!(
            " to sign for namespace {}{}",
            data.namespace.as_deref().unwrap_or_default(),
            on(destination)
        ),
        (_, destination) => on(destination),
    };
    format!("{lead}{through}{what}?")
}

/// The host's name, else its host key's fingerprint.
fn shown(host: &HostData) -> String {
    match &host.name {
        Some(name) => name.clone(),
        None => format!("host key {}", host.fingerprint),
    }
}

/// " on <host>" for a host, nothing without one.
fn on(host: Option<&HostData>) -> String {
    host.map(|host| format!(" on {}", shown(host)))
        .unwrap_or_default()
}

/// A key's name for the message, with its quotes escaped, so it can't end
/// its own quotation and continue the sentence. The name is cut again to its
/// budget after, between whole characters and whole escapes, so quoting
/// can't push the message's other pieces out.
fn quoted(name: &str) -> String {
    let mut quoted = String::new();
    let mut rest = name;
    while let Some(next) = rest.chars().next() {
        let len = escape_len(rest).unwrap_or(next.len_utf8());
        let piece = if next == '"' { "\\\"" } else { &rest[..len] };
        if quoted.len() + piece.len() > MAX_KEY_NAME_LEN {
            break;
        }
        quoted.push_str(piece);
        rest = &rest[len..];
    }
    quoted
}

/// The length of the `\uXXXX` escape `text` starts with, if it does.
fn escape_len(text: &str) -> Option<usize> {
    let escape = text.strip_prefix("\\u")?.get(..4)?;
    escape.chars().all(|c| c.is_ascii_hexdigit()).then_some(6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SshKeyConfirm;
    use crate::frontends::ssh_agent::classify::LoginRequest;
    use crate::ssh::testing::test_key;

    fn served(name: &str) -> ServedKey {
        let key = test_key(1);
        let public_key = key.public_key().clone();
        ServedKey {
            database: "personal".to_string(),
            fingerprint: public_key.fingerprint(HashAlg::Sha256),
            public_key,
            name: name.to_string(),
            entry_uuid: uuid::Uuid::nil(),
            title: None,
            attachment: None,
            confirm: SshKeyConfirm::Once,
            forwarded: true,
        }
    }

    fn login(user: &str) -> Purpose {
        Purpose::Login(LoginRequest {
            session_id: vec![1],
            user: user.to_string(),
            hostbound_hostkey: None,
        })
    }

    fn sshsig(namespace: &str) -> Purpose {
        Purpose::SshSig {
            namespace: namespace.to_string(),
        }
    }

    fn dest() -> KeyData {
        test_key(2).public_key().key_data().clone()
    }

    fn fingerprint() -> String {
        dest().fingerprint(HashAlg::Sha256).to_string()
    }

    fn via() -> KeyData {
        test_key(3).public_key().key_data().clone()
    }

    fn via_fingerprint() -> String {
        via().fingerprint(HashAlg::Sha256).to_string()
    }

    fn host<'a>(key: Option<&'a KeyData>, name: Option<&str>) -> Option<Host<'a>> {
        key.map(|key| Host {
            key,
            name: name.map(str::to_string),
        })
    }

    fn approved(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        approval(&served("github"), purpose, host(dest, name).as_ref(), None).message
    }

    fn unlocked(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        unlock(&served("github"), purpose, host(dest, name).as_ref(), None).message
    }

    /// The same questions for a login forwarded through `via`, named
    /// `via_name`, to `dest`, named `dest_name`.
    fn forwarded(
        message: fn(&ServedKey, &Purpose, Option<&Host<'_>>, Option<&Host<'_>>) -> Question,
        via_name: Option<&str>,
        dest_name: Option<&str>,
    ) -> String {
        let (dest, via) = (dest(), via());
        message(
            &served("github"),
            &login("git"),
            host(Some(&dest), dest_name).as_ref(),
            host(Some(&via), via_name).as_ref(),
        )
        .message
    }

    /// A forwarded login says which host it comes through, and where it
    /// goes.
    #[test]
    fn a_forwarded_login_names_the_forwarding_host_and_the_destination() {
        let (fingerprint, via) = (fingerprint(), via_fingerprint());

        assert_eq!(
            forwarded(approval, Some("build-box"), Some("github.com")),
            "Approve use of key \"github\" on build-box to log in to git@github.com?"
        );
        assert_eq!(
            forwarded(unlock, Some("build-box"), Some("github.com")),
            "Unlock database personal to use key \"github\" on build-box \
             to log in to git@github.com?"
        );
        assert_eq!(
            forwarded(approval, None, None),
            format!(
                "Approve use of key \"github\" on host key {via} \
                 to log in as git to host key {fingerprint}?"
            )
        );
    }

    /// Every purpose and destination, as an approval question.
    #[test]
    fn an_approval_asks_about_the_key_its_purpose_and_destination() {
        let (dest, fingerprint) = (dest(), fingerprint());

        assert_eq!(
            approved(&login("git"), None, None),
            "Approve use of key \"github\" to log in as git?"
        );
        assert_eq!(
            approved(&login("git"), Some(&dest), Some("github.com")),
            "Approve use of key \"github\" to log in to git@github.com?"
        );
        assert_eq!(
            approved(&login("git"), Some(&dest), None),
            format!("Approve use of key \"github\" to log in as git to host key {fingerprint}?")
        );
        assert_eq!(
            approved(&sshsig("git"), None, None),
            "Approve use of key \"github\" to sign for namespace git?"
        );
        assert_eq!(
            approved(&sshsig("git"), Some(&dest), Some("github.com")),
            "Approve use of key \"github\" to sign for namespace git on github.com?"
        );
        assert_eq!(
            approved(&Purpose::Other, None, None),
            "Approve use of key \"github\"?"
        );
        assert_eq!(
            approved(&Purpose::Other, Some(&dest), None),
            format!("Approve use of key \"github\" on host key {fingerprint}?")
        );
    }

    /// The unlock question says what the key is for as the approval question
    /// does, led by the database it unlocks.
    #[test]
    fn an_unlock_asks_the_same_question_led_by_its_database() {
        let (dest, fingerprint) = (dest(), fingerprint());

        assert_eq!(
            unlocked(&login("git"), None, None),
            "Unlock database personal to use key \"github\" to log in as git?"
        );
        assert_eq!(
            unlocked(&login("git"), Some(&dest), Some("github.com")),
            "Unlock database personal to use key \"github\" to log in to git@github.com?"
        );
        assert_eq!(
            unlocked(&login("git"), Some(&dest), None),
            format!(
                "Unlock database personal to use key \"github\" \
                 to log in as git to host key {fingerprint}?"
            )
        );
        assert_eq!(
            unlocked(&sshsig("git"), None, None),
            "Unlock database personal to use key \"github\" to sign for namespace git?"
        );
        assert_eq!(
            unlocked(&Purpose::Other, Some(&dest), None),
            format!("Unlock database personal to use key \"github\" on host key {fingerprint}?")
        );
    }

    /// Whatever the key, user, namespace, database and host name are, the
    /// whole message, destination included, fits the prompt's cap, and the
    /// destination is its end: each piece is cut on its own.
    #[test]
    fn the_worst_message_fits_the_prompt_cap() {
        let (dest, fingerprint) = (dest(), fingerprint());
        let long = "w".repeat(1000);
        let mut key = served(&long);
        key.database = long.clone();
        let via = via();
        let mut longest = 0;

        for message in [approval, unlock] {
            // Only a login is forwarded.
            for (purpose, forwarded) in [
                (login(&long), true),
                (login(&long), false),
                (sshsig(&long), false),
                (Purpose::Other, false),
            ] {
                for name in [None, Some(long.as_str())] {
                    for via_name in [None, Some(long.as_str())] {
                        let via = host(Some(&via), via_name).filter(|_| forwarded);
                        let text = message(
                            &key,
                            &purpose,
                            host(Some(&dest), name).as_ref(),
                            via.as_ref(),
                        )
                        .message;
                        assert!(text.len() <= 320, "{} bytes: {text}", text.len());
                        longest = longest.max(text.len());
                        let end = match name {
                            Some(_) => format!("{}?", "w".repeat(MAX_HOST_NAME_LEN)),
                            None => format!("host key {fingerprint}?"),
                        };
                        assert!(text.ends_with(&end), "{text}");
                    }
                }
            }
        }
        assert_eq!(longest, 291);
    }

    /// A key name can't close its quotes and carry on the sentence, nor
    /// hold a newline or a bidi override.
    #[test]
    fn a_hostile_key_name_stays_inside_its_quotes() {
        let question = approval(
            &served("x\" to log in as root\n\u{202e}"),
            &Purpose::Other,
            None,
            None,
        );
        assert_eq!(
            question.message,
            "Approve use of key \"x\\\" to log in as root\\u000a\\u202e\"?"
        );
    }

    /// The data holds the name escaped for display and not quoted for the
    /// sentence: a `"` is a `"`, as JSON holds it.
    #[test]
    fn the_data_escapes_a_key_name_without_quoting_it() {
        let question = approval(&served("say \"hi\"\n\u{202e}"), &Purpose::Other, None, None);

        let key = question.data.key.expect("a key");
        assert_eq!(key.name, "say \"hi\"\\u000a\\u202e");
        assert!(question.message.contains("say \\\"hi\\\""));
    }

    /// Quoting a name can't push it past its budget, nor cut a `\uXXXX`
    /// escape or leave a `\` that would escape the closing quote.
    #[test]
    fn quoting_keeps_a_key_name_within_its_budget_between_whole_pieces() {
        for name in ["\"".repeat(100), "\u{202e}\"".repeat(100)] {
            let question = approval(&served(&name), &Purpose::Other, None, None);

            let quoted = question
                .message
                .strip_prefix("Approve use of key \"")
                .and_then(|rest| rest.strip_suffix("\"?"))
                .expect("a quoted key");
            assert!(quoted.len() <= MAX_KEY_NAME_LEN, "{quoted}");
            assert!(
                !quoted.ends_with('\\') || quoted.ends_with("\\\\"),
                "{quoted}"
            );
            assert!(!quoted.rsplit('\\').next().is_some_and(|tail| {
                tail.starts_with('u')
                    && tail.len() < 5
                    && tail.chars().all(|c| c.is_ascii_hexdigit() || c == 'u')
            }));
        }
    }

    /// The data names every piece the message does, and the message is made
    /// of the data: they agree on a forwarded login.
    #[test]
    fn the_data_has_the_pieces_the_message_names() {
        let (dest, via) = (dest(), via());
        let question = approval(
            &served("github"),
            &login("git"),
            host(Some(&dest), Some("github.com")).as_ref(),
            host(Some(&via), None).as_ref(),
        );

        assert_eq!(
            serde_json::to_value(&question.data).expect("serializes"),
            serde_json::json!({
                "v": 1,
                "kind": "confirm",
                "database": "personal",
                "key": {
                    "name": "github",
                    "fingerprint": served("github").fingerprint.to_string(),
                    "type": "ssh-ed25519",
                },
                "purpose": "login",
                "user": "git",
                "destination": {
                    "name": "github.com",
                    "fingerprint": fingerprint(),
                },
                "forwarding_host": {"fingerprint": via_fingerprint()},
            })
        );
        assert_eq!(
            question.message,
            format!(
                "Approve use of key \"github\" on host key {} to log in to git@github.com?",
                via_fingerprint()
            )
        );
    }

    /// An unlock on demand is the confirm's data with the kind of an unlock;
    /// an `SSHSIG` carries its namespace and no user.
    #[test]
    fn the_unlock_and_sshsig_data_say_what_they_are() {
        let unlocked = unlock(&served("github"), &sshsig("git"), None, None);

        assert_eq!(unlocked.data.kind, PromptKind::Unlock);
        assert_eq!(unlocked.data.purpose.as_deref(), Some("sshsig"));
        assert_eq!(unlocked.data.namespace.as_deref(), Some("git"));
        assert_eq!(unlocked.data.user, None);
        assert_eq!(unlocked.data.destination, None);
    }
}
