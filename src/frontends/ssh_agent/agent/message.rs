//! What the unlock and confirm prompts say (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the key, what it is for and where the signature goes, as one
//! question, and the pieces it is made of, for a prompt program that wants
//! them (`KPA_PROMPT_DATA`, `docs/design.md`).
//!
//! Each prompt's [`Pieces`] are filled first, with every piece escaped and
//! cut to its budget, and the message is formatted from that data and
//! nothing else, so the two can't disagree.

use serde_json::{Map, Value, json};
use ssh_key::HashAlg;

use super::request::NamedHost;
use crate::frontends::ssh_agent::classify::Purpose;
use crate::output::escape_one_line;
use crate::prompt::Question;
use crate::ssh::keys::ServedKey;

/// The most bytes (escaped) each piece of a message may take. The message
/// is one line the prompt caps at 320 bytes, and the destination comes last,
/// so every variable piece is cut well short of that: the worst message,
/// an unlock prompt for a login forwarded through three hosts, the first
/// one `known_hosts` doesn't name, to a destination it doesn't name either,
/// is 319 bytes (`the_worst_message_fits_the_prompt_cap`), and the
/// destination is always whole.
const MAX_DATABASE_LEN: usize = 16;
const MAX_KEY_NAME_LEN: usize = 64;
/// The login user or `SSHSIG` namespace, from the request.
const MAX_REQUESTED_LEN: usize = 32;
/// A host name from `known_hosts`.
const MAX_HOST_NAME_LEN: usize = 56;
/// A forwarding host after the first, as the message shows it: its name, or
/// the start of its fingerprint, with `…` if either is cut. The data has it
/// whole.
const MAX_HOP_LEN: usize = 13;
/// How many forwarding hosts the message shows. A longer chain shows the
/// first, `…` and the last.
const MAX_HOPS_SHOWN: usize = 3;
const ELLIPSIS: &str = "…";

/// The host as the data names it: its name, escaped and cut, and its host
/// key's fingerprint.
fn piece(host: &NamedHost) -> HostPiece {
    HostPiece {
        name: host
            .name
            .as_deref()
            .map(|name| escape_one_line(name, MAX_HOST_NAME_LEN)),
        fingerprint: host.key.fingerprint(HashAlg::Sha256).to_string(),
    }
}

/// A host, as a prompt names it.
struct HostPiece {
    /// The name `known_hosts` gives its host key, if it does.
    name: Option<String>,
    fingerprint: String,
}

impl HostPiece {
    fn value(&self) -> Value {
        let mut fields = Map::new();
        if let Some(name) = &self.name {
            fields.insert("name".to_string(), name.clone().into());
        }
        fields.insert("fingerprint".to_string(), self.fingerprint.clone().into());
        Value::Object(fields)
    }
}

/// The pieces of a prompt about a key and a request for it, each escaped and
/// cut to its budget. The message is formatted from them, and they are the
/// data a prompt program gets.
struct Pieces {
    database: String,
    key_name: String,
    key_fingerprint: String,
    key_type: String,
    /// What the key is for: `login`, `sshsig` or `other`.
    purpose: &'static str,
    /// The remote user of a login.
    user: Option<String>,
    /// The namespace of an `SSHSIG` request.
    namespace: Option<String>,
    destination: Option<HostPiece>,
    /// The hosts the agent was forwarded through, in order, the forwarding
    /// host first.
    forwarding_chain: Vec<HostPiece>,
}

impl Pieces {
    /// The pieces of a prompt about `served` and a request for `purpose`.
    fn new(
        served: &ServedKey,
        purpose: &Purpose,
        destination: Option<&NamedHost>,
        forwarding: &[NamedHost],
    ) -> Pieces {
        let (user, namespace) = match purpose {
            Purpose::Login(login) => (Some(escape_one_line(&login.user, MAX_REQUESTED_LEN)), None),
            Purpose::SshSig { namespace } => {
                (None, Some(escape_one_line(namespace, MAX_REQUESTED_LEN)))
            }
            Purpose::Other => (None, None),
        };
        Pieces {
            database: escape_one_line(&served.database, MAX_DATABASE_LEN),
            key_name: escape_one_line(&served.name, MAX_KEY_NAME_LEN),
            key_fingerprint: served.fingerprint.to_string(),
            key_type: served.public_key.algorithm().to_string(),
            purpose: purpose.label(),
            user,
            namespace,
            destination: destination.map(piece),
            forwarding_chain: forwarding.iter().map(piece).collect(),
        }
    }

    /// The question that says `message`, with these pieces as its data.
    fn question(&self, message: String) -> Question {
        let mut question = Question::new(message)
            .with("database", self.database.as_str())
            .with(
                "key",
                json!({
                    "name": self.key_name,
                    "fingerprint": self.key_fingerprint,
                    "type": self.key_type,
                }),
            )
            .with("purpose", self.purpose);
        if let Some(user) = &self.user {
            question = question.with("user", user.as_str());
        }
        if let Some(namespace) = &self.namespace {
            question = question.with("namespace", namespace.as_str());
        }
        if let Some(destination) = &self.destination {
            question = question.with("destination", destination.value());
        }
        if let Some(forwarding) = self.forwarding_chain.first() {
            question = question.with("forwarding_host", forwarding.value()).with(
                "forwarding_chain",
                Value::Array(self.forwarding_chain.iter().map(HostPiece::value).collect()),
            );
        }
        question
    }
}

/// The confirm prompt's question, which the user answers yes or no to:
/// "Approve use of key "github" to log in to git@github.com?". The key is
/// shown by its name, quoted. What follows says what it is for and, for a
/// connection bound to a `destination`, where: the host name `known_hosts`
/// gives its host key if it has one, else the host key's fingerprint. A
/// forwarded connection says which host it comes through too: "Approve use
/// of key "github" on build-box to log in to git@github.com?", and one that
/// was relayed on says the hosts it went through: "on build-box → jump-2".
/// Every piece
/// that comes from outside kpa's own text is escaped and cut to its own
/// budget, so none can hide the destination.
pub(super) fn approval(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&NamedHost>,
    forwarding: &[NamedHost],
) -> Question {
    let pieces = Pieces::new(served, purpose, destination, forwarding);
    let message = message(&format!("Approve use of {}", key(&pieces)), &pieces);
    pieces.question(message)
}

/// The unlock prompt's question, about unlocking, which says what for:
/// "Unlock database personal to use key "github" to log in as git?". It
/// doesn't ask to approve the key; the confirm prompt does.
pub(super) fn unlock(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&NamedHost>,
    forwarding: &[NamedHost],
) -> Question {
    let pieces = Pieces::new(served, purpose, destination, forwarding);
    let lead = format!(
        "Unlock database {} to use {}",
        pieces.database,
        key(&pieces)
    );
    let message = message(&lead, &pieces);
    pieces.question(message)
}

/// `key "github"`, the key's name quoted.
fn key(pieces: &Pieces) -> String {
    format!("key \"{}\"", quoted(&pieces.key_name))
}

/// `lead`, then which host the request is forwarded through, then what the
/// key is for and where, as a question.
fn message(lead: &str, pieces: &Pieces) -> String {
    let through = through(&pieces.forwarding_chain);
    let user = pieces.user.as_deref().unwrap_or_default();
    let what = match (pieces.purpose, pieces.destination.as_ref()) {
        ("login", Some(dest)) => match &dest.name {
            Some(_) => format!(" to log in to {user}@{}", shown(dest)),
            None => format!(" to log in as {user} to {}", shown(dest)),
        },
        ("login", None) => format!(" to log in as {user}"),
        ("sshsig", destination) => format!(
            " to sign for namespace {}{}",
            pieces.namespace.as_deref().unwrap_or_default(),
            on(destination)
        ),
        (_, destination) => on(destination),
    };
    format!("{lead}{through}{what}?")
}

/// The host's name, else its host key's fingerprint.
fn shown(host: &HostPiece) -> String {
    match &host.name {
        Some(name) => name.clone(),
        None => format!("host key {}", host.fingerprint),
    }
}

/// The hosts a forwarded connection comes through, as " on build-box": the
/// forwarding host as `on` shows it, and each host after it in the short form
/// ("build-box → jump-2 → jump-3"). A chain longer than [`MAX_HOPS_SHOWN`]
/// shows the first, `…` and the last. Nothing for a connection that isn't
/// forwarded.
fn through(chain: &[HostPiece]) -> String {
    let Some((first, onward)) = chain.split_first() else {
        return String::new();
    };
    let mut hosts = vec![shown(first)];
    match onward {
        [] => {}
        [.., last] if chain.len() > MAX_HOPS_SHOWN => {
            hosts.push(ELLIPSIS.to_string());
            hosts.push(brief(last));
        }
        _ => hosts.extend(onward.iter().map(brief)),
    }
    format!(" on {}", hosts.join(" → "))
}

/// A host after the first as the message shows it, in at most
/// [`MAX_HOP_LEN`] bytes: its name, else the start of its fingerprint, with
/// `…` when it is cut.
fn brief(host: &HostPiece) -> String {
    let (text, name) = match &host.name {
        Some(name) => (name.as_str(), true),
        None => (host.fingerprint.as_str(), false),
    };
    if name && text.len() <= MAX_HOP_LEN {
        return text.to_string();
    }
    format!("{}{ELLIPSIS}", cut(text, MAX_HOP_LEN - ELLIPSIS.len()))
}

/// `text` cut to at most `max_len` bytes, between whole characters and whole
/// `\uXXXX` escapes.
fn cut(text: &str, max_len: usize) -> &str {
    let mut end = 0;
    while let Some(next) = text[end..].chars().next() {
        let len = escape_len(&text[end..]).unwrap_or(next.len_utf8());
        if end + len > max_len {
            break;
        }
        end += len;
    }
    &text[..end]
}

/// " on <host>" for a host, nothing without one.
fn on(host: Option<&HostPiece>) -> String {
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
    use ssh_key::public::KeyData;

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

    fn host(key: Option<&KeyData>, name: Option<&str>) -> Option<NamedHost> {
        key.map(|key| NamedHost {
            key: key.clone(),
            name: name.map(str::to_string),
        })
    }

    fn approved(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        approval(&served("github"), purpose, host(dest, name).as_ref(), &[]).message
    }

    fn unlocked(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        unlock(&served("github"), purpose, host(dest, name).as_ref(), &[]).message
    }

    /// The same questions for a login forwarded through `via`, named
    /// `via_name`, to `dest`, named `dest_name`.
    fn forwarded(
        message: fn(&ServedKey, &Purpose, Option<&NamedHost>, &[NamedHost]) -> Question,
        via_name: Option<&str>,
        dest_name: Option<&str>,
    ) -> String {
        let (dest, via) = (dest(), via());
        message(
            &served("github"),
            &login("git"),
            host(Some(&dest), dest_name).as_ref(),
            &chain(&[(via, via_name)]),
        )
        .message
    }

    /// Hosts, each a key and the name it is given, if any.
    fn chain(hosts: &[(KeyData, Option<&str>)]) -> Vec<NamedHost> {
        hosts
            .iter()
            .map(|(key, name)| host(Some(key), *name).expect("a host"))
            .collect()
    }

    /// The message of an approval for a login to `dest` forwarded through
    /// hosts seeded 3, 4, …, one for each of `names`.
    fn through(names: &[Option<&str>]) -> String {
        forwarded_through(names).message
    }

    fn forwarded_through(names: &[Option<&str>]) -> Question {
        let hosts: Vec<_> = (3..)
            .zip(names)
            .map(|(seed, name)| (test_key(seed).public_key().key_data().clone(), *name))
            .collect();
        approval(
            &served("github"),
            &login("git"),
            host(Some(&dest()), Some("github.com")).as_ref(),
            &chain(&hosts),
        )
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

    /// Whatever the key, user, namespace, database and host names are, and
    /// however long the chain of forwarding hosts, the whole message,
    /// destination included, fits the prompt's cap, and the destination is
    /// its end: each piece is cut on its own.
    #[test]
    fn the_worst_message_fits_the_prompt_cap() {
        let (dest, fingerprint) = (dest(), fingerprint());
        let long = "w".repeat(1000);
        let mut key = served(&long);
        key.database = long.clone();
        let mut longest = 0;

        for message in [approval, unlock] {
            // Only a login is forwarded.
            for (purpose, most_hops) in [(login(&long), 5), (sshsig(&long), 0), (Purpose::Other, 0)]
            {
                for hops in 0..=most_hops {
                    for name in [None, Some(long.as_str())] {
                        for via_name in [None, Some(long.as_str())] {
                            let via: Vec<_> = (3..)
                                .take(hops)
                                .map(|seed| {
                                    (test_key(seed).public_key().key_data().clone(), via_name)
                                })
                                .collect();
                            let text = message(
                                &key,
                                &purpose,
                                host(Some(&dest), name).as_ref(),
                                &chain(&via),
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
        }
        assert_eq!(longest, 319);
    }

    /// A key name can't close its quotes and carry on the sentence, nor
    /// hold a newline or a bidi override.
    #[test]
    fn a_hostile_key_name_stays_inside_its_quotes() {
        let question = approval(
            &served("x\" to log in as root\n\u{202e}"),
            &Purpose::Other,
            None,
            &[],
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
        let question = approval(&served("say \"hi\"\n\u{202e}"), &Purpose::Other, None, &[]);

        assert_eq!(question.data["key"]["name"], "say \"hi\"\\u000a\\u202e");
        assert!(question.message.contains("say \\\"hi\\\""));
    }

    /// Quoting a name can't push it past its budget, nor cut a `\uXXXX`
    /// escape or leave a `\` that would escape the closing quote.
    #[test]
    fn quoting_keeps_a_key_name_within_its_budget_between_whole_pieces() {
        for name in ["\"".repeat(100), "\u{202e}\"".repeat(100)] {
            let question = approval(&served(&name), &Purpose::Other, None, &[]);

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
            &chain(&[(via, None)]),
        );

        assert_eq!(
            serde_json::Value::Object(question.data),
            serde_json::json!({
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
                "forwarding_chain": [{"fingerprint": via_fingerprint()}],
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

    /// An unlock on demand has the confirm's data; an `SSHSIG` carries its
    /// namespace and no user, and a connection bound to nothing has no
    /// destination.
    #[test]
    fn the_unlock_and_sshsig_data_say_what_they_are() {
        let unlocked = unlock(&served("github"), &sshsig("git"), None, &[]);

        assert_eq!(unlocked.data["purpose"], "sshsig");
        assert_eq!(unlocked.data["namespace"], "git");
        assert_eq!(unlocked.data["database"], "personal");
        assert!(!unlocked.data.contains_key("user"));
        assert!(!unlocked.data.contains_key("destination"));
        assert!(!unlocked.data.contains_key("forwarding_host"));
        assert!(!unlocked.data.contains_key("forwarding_chain"));
        assert_eq!(
            unlocked.message,
            "Unlock database personal to use key \"github\" to sign for namespace git?"
        );
    }

    /// The start of host key `seed`'s fingerprint, as a hop shows it.
    fn short_fingerprint(seed: u64) -> String {
        let fingerprint = test_key(seed)
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        format!("{}…", &fingerprint[..10])
    }

    /// A message says which hosts a forwarded login went through, in order,
    /// up to three in full, and past that the first, `…` and the last.
    #[test]
    fn a_chain_of_hops_is_shown_in_order_and_shortened_past_three() {
        let to = " to log in to git@github.com?";
        let lead = "Approve use of key \"github\"";

        assert_eq!(
            through(&[Some("build-box")]),
            format!("{lead} on build-box{to}")
        );
        assert_eq!(
            through(&[Some("build-box"), Some("jump-2")]),
            format!("{lead} on build-box → jump-2{to}")
        );
        assert_eq!(
            through(&[Some("build-box"), Some("jump-2"), Some("jump-3")]),
            format!("{lead} on build-box → jump-2 → jump-3{to}")
        );
        assert_eq!(
            through(&[
                Some("build-box"),
                Some("jump-2"),
                Some("jump-3"),
                Some("jump-4")
            ]),
            format!("{lead} on build-box → … → jump-4{to}")
        );
        assert_eq!(
            through(&[
                Some("build-box"),
                Some("jump-2"),
                Some("jump-3"),
                Some("jump-4"),
                Some("jump-5")
            ]),
            format!("{lead} on build-box → … → jump-5{to}")
        );
    }

    /// The first host is shown as a single forwarding host is, and each host
    /// after it by its name, else the start of its fingerprint, cut with `…`.
    #[test]
    fn a_hop_after_the_first_is_shown_short() {
        let first = via_fingerprint();

        assert_eq!(
            through(&[None, None]),
            format!(
                "Approve use of key \"github\" on host key {first} → {} \
                 to log in to git@github.com?",
                short_fingerprint(4)
            )
        );
        assert_eq!(
            through(&[Some("build-box"), Some("a-jump-host.example.org")]),
            "Approve use of key \"github\" on build-box → a-jump-hos… \
             to log in to git@github.com?"
        );
        // A cut never falls inside an escape.
        let escaped = format!("{}\u{202e}", "a".repeat(8));
        let text = through(&[Some("build-box"), Some(&escaped)]);
        assert!(text.contains(" → aaaaaaaa… to log in"), "{text}");
        // One that fits whole is not cut.
        let fits = format!("{}\u{202e}", "a".repeat(7));
        let text = through(&[Some("build-box"), Some(&fits)]);
        assert!(text.contains(" → aaaaaaa\\u202e to log in"), "{text}");
    }

    /// The data has the whole chain, the forwarding host first, each host
    /// whole however the message shortens it, and the chain is there for a
    /// single hop too.
    #[test]
    fn the_data_has_every_host_of_the_chain_whole() {
        let question = forwarded_through(&[
            Some("build-box"),
            None,
            Some("jump-3"),
            Some("a-jump-host.example.org"),
        ]);

        let fingerprint = |seed: u64| {
            test_key(seed)
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
        };
        assert_eq!(
            question.data["forwarding_chain"],
            serde_json::json!([
                {"name": "build-box", "fingerprint": fingerprint(3)},
                {"fingerprint": fingerprint(4)},
                {"name": "jump-3", "fingerprint": fingerprint(5)},
                {"name": "a-jump-host.example.org", "fingerprint": fingerprint(6)},
            ])
        );
        assert_eq!(
            question.data["forwarding_host"],
            question.data["forwarding_chain"][0]
        );
        assert!(
            question
                .message
                .contains(" on build-box → … → a-jump-hos… to "),
            "{}",
            question.message
        );
        assert_eq!(
            forwarded_through(&[Some("build-box")]).data["forwarding_chain"],
            serde_json::json!([{"name": "build-box", "fingerprint": fingerprint(3)}])
        );
    }
}
