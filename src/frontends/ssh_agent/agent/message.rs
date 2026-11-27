//! What the unlock and confirm prompts say (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the key, what it is for and where the signature goes, as one
//! question, and the pieces it is made of, for a prompt program that wants
//! them (`KPA_PROMPT_DATA`, `docs/design.md`).
//!
//! Each prompt's [`Pieces`] are filled first, with every piece escaped and
//! cut to its budget, and the message is formatted from those pieces and
//! nothing else, so the two can't disagree. The pieces that come from outside
//! kpa (the key's name, a login's user, a signature's namespace) are quoted
//! in the message.

use serde_json::{Map, Value, json};
use ssh_key::HashAlg;

use super::request::NamedHost;
use crate::frontends::ssh_agent::classify::Purpose;
use crate::output::escape_one_line;
use crate::prompt::{MAX_PROMPT_MESSAGE_LEN, Question};
use crate::ssh::keys::ServedKey;

/// The most bytes (escaped, and quoted where the message quotes it, but not
/// counting the quote marks) each piece of a message may take. The message
/// is one line the prompt caps at 320 bytes, and the destination comes last,
/// so every variable piece is cut well short of that: the worst message,
/// an unlock prompt for a login forwarded through a host `known_hosts`
/// doesn't name to one it doesn't name either, is 293 bytes
/// (`the_worst_message_fits_the_prompt_cap`), and the destination is always
/// whole. The hosts after the forwarding host have no budget of their own:
/// they are shown whole in what room that leaves, else not (see
/// [`onward`]).
const MAX_DATABASE_LEN: usize = 24;
const MAX_KEY_NAME_LEN: usize = 64;
/// The login user or `SSHSIG` namespace, from the request, in the data and
/// between the quotes of the message.
const MAX_REQUESTED_LEN: usize = 32;
/// A host name from `known_hosts`.
const MAX_HOST_NAME_LEN: usize = 56;
/// How many forwarding hosts the message names when it has room: the
/// forwarding host and the hosts after it. A longer chain names the first and
/// the last.
const MAX_HOPS_SHOWN: usize = 3;

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
    /// The key's name, the user and the namespace as the message writes them
    /// between its quotes.
    quoted: Quoted,
    destination: Option<HostPiece>,
    /// The hosts the agent was forwarded through, in order, the forwarding
    /// host first.
    forwarding_chain: Vec<HostPiece>,
}

/// The text of a message between a pair of quotes: [`quoted`] of the raw
/// text, which can't end the quotation or carry on the sentence.
struct Quoted {
    key_name: String,
    user: Option<String>,
    namespace: Option<String>,
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
            Purpose::Login(login) => (Some(login.user.as_str()), None),
            Purpose::SshSig { namespace } => (None, Some(namespace.as_str())),
            Purpose::Other => (None, None),
        };
        let escaped = |text: &str| escape_one_line(text, MAX_REQUESTED_LEN);
        let quote = |text: &str| quoted(text, MAX_REQUESTED_LEN);
        Pieces {
            database: escape_one_line(&served.database, MAX_DATABASE_LEN),
            key_name: escape_one_line(&served.name, MAX_KEY_NAME_LEN),
            key_fingerprint: served.fingerprint.to_string(),
            key_type: served.public_key.algorithm().to_string(),
            purpose: purpose.label(),
            user: user.map(escaped),
            namespace: namespace.map(escaped),
            quoted: Quoted {
                key_name: quoted(&served.name, MAX_KEY_NAME_LEN),
                user: user.map(quote),
                namespace: namespace.map(quote),
            },
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
/// "Approve use of key "github" to log in to \"git\"@github.com?". The key is
/// shown by its name, quoted. What follows says what it is for and, for a
/// connection bound to a `destination`, where: the host name `known_hosts`
/// gives its host key if it has one, else the host key's fingerprint. A
/// forwarded connection says which host it comes through too: "Approve use
/// of key "github" on build-box to log in to \"git\"@github.com?", and one that
/// was relayed on says the hosts it went through: "on build-box → jump-2".
/// Every piece
/// that comes from outside kpa's own text is escaped, quoted and cut to its
/// own budget, so none can hide the destination or carry on the sentence.
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
/// "Unlock database personal to use key "github" to log in as \"git\"?". It
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
    format!("key \"{}\"", pieces.quoted.key_name)
}

/// `lead`, then which host the request is forwarded through, then what the
/// key is for and where, as a question. The hosts after the forwarding host
/// go where the room under the prompt's cap is left once the rest of the
/// message is written, so they can't push the destination out.
fn message(lead: &str, pieces: &Pieces) -> String {
    let (through, further) = match pieces.forwarding_chain.split_first() {
        Some((first, further)) => (on(Some(first)), further),
        None => (String::new(), &[][..]),
    };
    let user = pieces.quoted.user.as_deref().unwrap_or_default();
    let what = match (pieces.purpose, pieces.destination.as_ref()) {
        ("login", Some(dest)) => match &dest.name {
            Some(_) => format!(" to log in to \"{user}\"@{}", shown(dest)),
            None => format!(" to log in as \"{user}\" to {}", shown(dest)),
        },
        ("login", None) => format!(" to log in as \"{user}\""),
        ("sshsig", destination) => format!(
            " to sign for namespace \"{}\"{}",
            pieces.quoted.namespace.as_deref().unwrap_or_default(),
            on(destination)
        ),
        (_, destination) => on(destination),
    };
    let room = MAX_PROMPT_MESSAGE_LEN.saturating_sub(lead.len() + through.len() + what.len() + 1);
    let onward = onward(further, room);
    format!("{lead}{through}{onward}{what}?")
}

/// The host's name, else its host key's fingerprint.
fn shown(host: &HostPiece) -> String {
    match &host.name {
        Some(name) => name.clone(),
        None => format!("host key {}", host.fingerprint),
    }
}

/// The hosts after the forwarding host, written after it (" → jump-2 →
/// jump-3") in at most `room` bytes. A host is shown whole, by its name, else
/// by its fingerprint, or not at all. The most is shown that fits, in this
/// order:
///
/// 1. every one, if there are fewer than [`MAX_HOPS_SHOWN`] of them;
/// 2. `…` and the last (" → … → jump-4"), if there are two or more;
/// 3. `…` alone (" → …"), which says there are more and is short enough to
///    fit whatever the other pieces are cut to.
///
/// Nothing for a connection that was relayed no further.
fn onward(further: &[HostPiece], room: usize) -> String {
    let Some(last) = further.last() else {
        return String::new();
    };
    let hop = |host: &HostPiece| {
        host.name
            .clone()
            .unwrap_or_else(|| host.fingerprint.clone())
    };
    let all = (further.len() < MAX_HOPS_SHOWN).then(|| {
        further
            .iter()
            .map(|host| format!(" → {}", hop(host)))
            .collect::<String>()
    });
    let last = (further.len() >= 2).then(|| format!(" → … → {}", hop(last)));
    [all, last, Some(" → …".to_string())]
        .into_iter()
        .flatten()
        .find(|text| text.len() <= room)
        .unwrap_or_default()
}

/// " on <host>" for a host, nothing without one.
fn on(host: Option<&HostPiece>) -> String {
    host.map(|host| format!(" on {}", shown(host)))
        .unwrap_or_default()
}

/// `text` for the message between a pair of quotes, at most `max_len` bytes
/// of it: escaped as [`escape_one_line`] does, with a `"` written as `\"` and
/// a `\` as `\\`, so the text can't end its own quotation, nor make the
/// closing quote look escaped, and carry on the sentence. It works from the
/// raw text, not from what [`escape_one_line`] made of it, where a `\` of the
/// text and the one that begins a `\uXXXX` escape can't be told apart. The cut
/// falls between whole characters and whole escapes, after quoting, so
/// quoting can't push the message's other pieces out.
fn quoted(text: &str, max_len: usize) -> String {
    let mut quoted = String::new();
    for c in text.chars() {
        let piece = match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            c => escape_one_line(c.encode_utf8(&mut [0; 4]), "\\u0000".len()),
        };
        if quoted.len() + piece.len() > max_len {
            break;
        }
        quoted.push_str(&piece);
    }
    quoted
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
            "Approve use of key \"github\" on build-box to log in to \"git\"@github.com?"
        );
        assert_eq!(
            forwarded(unlock, Some("build-box"), Some("github.com")),
            "Unlock database personal to use key \"github\" on build-box \
             to log in to \"git\"@github.com?"
        );
        assert_eq!(
            forwarded(approval, None, None),
            format!(
                "Approve use of key \"github\" on host key {via} \
                 to log in as \"git\" to host key {fingerprint}?"
            )
        );
    }

    /// Every purpose and destination, as an approval question.
    #[test]
    fn an_approval_asks_about_the_key_its_purpose_and_destination() {
        let (dest, fingerprint) = (dest(), fingerprint());

        assert_eq!(
            approved(&login("git"), None, None),
            "Approve use of key \"github\" to log in as \"git\"?"
        );
        assert_eq!(
            approved(&login("git"), Some(&dest), Some("github.com")),
            "Approve use of key \"github\" to log in to \"git\"@github.com?"
        );
        assert_eq!(
            approved(&login("git"), Some(&dest), None),
            format!(
                "Approve use of key \"github\" to log in as \"git\" to host key {fingerprint}?"
            )
        );
        assert_eq!(
            approved(&sshsig("git"), None, None),
            "Approve use of key \"github\" to sign for namespace \"git\"?"
        );
        assert_eq!(
            approved(&sshsig("git"), Some(&dest), Some("github.com")),
            "Approve use of key \"github\" to sign for namespace \"git\" on github.com?"
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
            "Unlock database personal to use key \"github\" to log in as \"git\"?"
        );
        assert_eq!(
            unlocked(&login("git"), Some(&dest), Some("github.com")),
            "Unlock database personal to use key \"github\" to log in to \"git\"@github.com?"
        );
        assert_eq!(
            unlocked(&login("git"), Some(&dest), None),
            format!(
                "Unlock database personal to use key \"github\" \
                 to log in as \"git\" to host key {fingerprint}?"
            )
        );
        assert_eq!(
            unlocked(&sshsig("git"), None, None),
            "Unlock database personal to use key \"github\" to sign for namespace \"git\"?"
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
                            assert!(
                                text.len() <= MAX_PROMPT_MESSAGE_LEN,
                                "{} bytes: {text}",
                                text.len()
                            );
                            if hops <= 1 {
                                longest = longest.max(text.len());
                            } else {
                                // The hops are left out before the
                                // destination is cut: at the very least `…`.
                                assert!(text.contains(" → "), "{text}");
                            }
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
        // The hosts after the forwarding host fill what is left of the cap.
        assert_eq!(longest, 293);
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

    /// A message read as a person reads it: its text outside quotes with
    /// each quoted span left empty (`""`), and each span's text as the
    /// quotes hold it, unescaped. Panics on a `\` that doesn't begin `\"`,
    /// `\\` or `\uXXXX`, and on a quote left open.
    fn read(message: &str) -> (String, Vec<String>) {
        let (mut outside, mut spans) = (String::new(), Vec::new());
        let mut chars = message.chars();
        while let Some(c) = chars.next() {
            outside.push(c);
            if c != '"' {
                continue;
            }
            let mut span = String::new();
            loop {
                match chars.next().expect("a closing quote") {
                    '"' => break,
                    '\\' => match chars.next().expect("an escape") {
                        c @ ('"' | '\\') => span.push(c),
                        'u' => {
                            let hex: String = chars.by_ref().take(4).collect();
                            let c = u32::from_str_radix(&hex, 16).expect("four hex digits");
                            span.push(char::from_u32(c).expect("a character"));
                        }
                        other => panic!("`\\{other}` in {message}"),
                    },
                    c => span.push(c),
                }
            }
            outside.push('"');
            spans.push(span);
        }
        (outside, spans)
    }

    /// A key name that closes its quotes (audit finding F-06), whether it
    /// ends in `\"` or in a lone `\`, stays whole inside them.
    #[test]
    fn a_backslash_in_a_key_name_cannot_end_its_quotation() {
        let name = "x\\\" to log in to a@b? #";
        let question = approval(&served(name), &sshsig("file"), None, &[]);

        assert_eq!(
            question.message,
            "Approve use of key \"x\\\\\\\" to log in to a@b? #\" \
             to sign for namespace \"file\"?"
        );
        assert_eq!(
            read(&question.message),
            (
                "Approve use of key \"\" to sign for namespace \"\"?".to_string(),
                vec![name.to_string(), "file".to_string()]
            )
        );

        let question = approval(&served("trailing\\"), &Purpose::Other, None, &[]);
        assert_eq!(question.message, "Approve use of key \"trailing\\\\\"?");
    }

    /// The escapes `escape_one_line` writes are kept as they are, and a
    /// `\u000a` the name spells out is a `\` and text, not a newline.
    #[test]
    fn a_backslash_is_doubled_and_the_escapes_of_the_name_are_not() {
        let question = approval(&served("a\nb\\u000ac"), &Purpose::Other, None, &[]);

        assert_eq!(
            question.message,
            "Approve use of key \"a\\u000ab\\\\u000ac\"?"
        );
    }

    /// The user of a login and the namespace of a signature, which the
    /// request writes (audit finding F-07), are quoted like the key's name:
    /// nothing of them reads outside the quotes, and a bound login still ends
    /// with its destination.
    #[test]
    fn a_requested_user_or_namespace_stays_inside_its_quotes() {
        let (dest, fingerprint) = (dest(), fingerprint());
        for user in [
            "a\" to log in to b@c? #",
            "a\\\" to log in to b@c? #",
            "root on trusted.example",
            "root\\",
        ] {
            for (destination, name, skeleton) in [
                (None, None, "to log in as \"\"?".to_string()),
                (
                    Some(&dest),
                    Some("real.example"),
                    "to log in to \"\"@real.example?".to_string(),
                ),
                (
                    Some(&dest),
                    None,
                    format!("to log in as \"\" to host key {fingerprint}?"),
                ),
            ] {
                let question = approval(
                    &served("github"),
                    &login(user),
                    host(destination, name).as_ref(),
                    &[],
                );

                assert_eq!(
                    read(&question.message),
                    (
                        format!("Approve use of key \"\" {skeleton}"),
                        vec!["github".to_string(), user.to_string()]
                    ),
                    "{}",
                    question.message
                );
            }
        }

        for namespace in ["f? x", "f\" on trusted.example? #"] {
            let question = unlock(
                &served("github"),
                &sshsig(namespace),
                host(Some(&dest), Some("real.example")).as_ref(),
                &[],
            );

            assert_eq!(
                read(&question.message),
                (
                    "Unlock database personal to use key \"\" \
                     to sign for namespace \"\" on real.example?"
                        .to_string(),
                    vec!["github".to_string(), namespace.to_string()]
                )
            );
        }
    }

    /// The message and the data agree: what the quotes hold is the piece
    /// the data names, whatever the piece has in it.
    #[test]
    fn the_quotes_hold_what_the_data_names() {
        let name = "k\"e\\y\\\"";
        let user = "u\"\\s\\\\er\"";
        let question = approval(&served(name), &login(user), None, &[]);

        assert_eq!(read(&question.message).1, [name, user].map(str::to_string));
        assert_eq!(question.data["key"]["name"], name);
        assert_eq!(question.data["user"], user);

        let question = approval(&served("k"), &sshsig(user), None, &[]);
        assert_eq!(read(&question.message).1[1], user);
        assert_eq!(question.data["namespace"], user);
    }

    /// Quoting a piece can't push it past its budget, nor cut a `\uXXXX`
    /// escape or a `\\` or `\"` pair: what is left is a whole prefix of the
    /// text, as long as the budget allows.
    #[test]
    fn quoting_keeps_each_piece_within_its_budget_between_whole_pieces() {
        for text in [
            "\"".repeat(100),
            "\\".repeat(100),
            "\u{202e}\"".repeat(100),
            "\u{202e}\\".repeat(100),
            "\\\"".repeat(100),
        ] {
            for budget in [MAX_KEY_NAME_LEN, MAX_REQUESTED_LEN] {
                let body = quoted(&text, budget);
                let (_, spans) = read(&format!("\"{body}\""));

                assert!(text.starts_with(&spans[0]), "{body}");
                assert!(body.len() <= budget, "{body}");
                // The next piece, at most a `\uXXXX`, would not have fit.
                assert!(body.len() + 6 > budget, "{body}");
            }
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
                "Approve use of key \"github\" on host key {} to log in to \"git\"@github.com?",
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
            "Unlock database personal to use key \"github\" to sign for namespace \"git\"?"
        );
    }

    /// A message says which hosts a forwarded login went through, in order:
    /// all of them up to three, and past that the first, `…` and the last.
    #[test]
    fn a_chain_of_hops_is_shown_in_order_and_shortened_past_three() {
        let to = " to log in to \"git\"@github.com?";
        let lead = "Approve use of key \"github\"";
        let names = [
            Some("build-box"),
            Some("jump-2"),
            Some("jump-3"),
            Some("jump-4"),
            Some("jump-5"),
        ];

        assert_eq!(through(&names[..1]), format!("{lead} on build-box{to}"));
        assert_eq!(
            through(&names[..2]),
            format!("{lead} on build-box → jump-2{to}")
        );
        assert_eq!(
            through(&names[..3]),
            format!("{lead} on build-box → jump-2 → jump-3{to}")
        );
        assert_eq!(
            through(&names[..4]),
            format!("{lead} on build-box → … → jump-4{to}")
        );
        assert_eq!(
            through(&names[..5]),
            format!("{lead} on build-box → … → jump-5{to}")
        );
    }

    /// The first host is shown as a single forwarding host is, and a host
    /// after it that has no name by its whole fingerprint.
    #[test]
    fn a_hop_without_a_name_is_shown_by_its_fingerprint() {
        let (first, second) = (via_fingerprint(), {
            let key = test_key(4).public_key().clone();
            key.fingerprint(HashAlg::Sha256).to_string()
        });

        assert_eq!(
            through(&[None, None]),
            format!(
                "Approve use of key \"github\" on host key {first} → {second} \
                 to log in to \"git\"@github.com?"
            )
        );
    }

    /// The hosts after the first are shown whole or not at all, in the room
    /// left: every one, else `…` and the last, else `…`.
    #[test]
    fn the_hops_that_fit_are_shown_whole_and_the_rest_are_left_out() {
        let hop = |name: &str| HostPiece {
            name: Some(name.to_string()),
            fingerprint: "SHA256:x".to_string(),
        };
        let (two, three) = (
            [hop(&"a".repeat(20)), hop(&"b".repeat(20))],
            [hop("a"), hop("b"), hop(&"c".repeat(20))],
        );
        let both = format!(" → {} → {}", "a".repeat(20), "b".repeat(20));
        let last = format!(" → … → {}", "b".repeat(20));

        assert_eq!(onward(&two, both.len()), both);
        assert_eq!(onward(&two, both.len() - 1), last);
        assert_eq!(onward(&two, last.len()), last);
        assert_eq!(onward(&two, last.len() - 1), " → …");
        assert_eq!(onward(&two, 8), " → …");
        assert_eq!(onward(&two, 7), "");
        // Three hops are more than are named in full, whatever the room.
        assert_eq!(onward(&three, 1000), format!(" → … → {}", "c".repeat(20)));
        assert_eq!(onward(&three, 8), " → …");
        assert_eq!(onward(&[], 0), "");
        // One hop that doesn't fit is `…`: there is no last to name apart
        // from it.
        assert_eq!(onward(&two[..1], 8), " → …");
    }

    /// With names as long as can be, the hops give way to what the rest of
    /// the message needs, and the destination stays whole.
    #[test]
    fn long_hop_names_leave_the_message_its_destination() {
        let long = "w".repeat(1000);
        let hops = vec![
            (
                test_key(3).public_key().key_data().clone(),
                Some(long.as_str()),
            ),
            (
                test_key(4).public_key().key_data().clone(),
                Some(long.as_str()),
            ),
            (
                test_key(5).public_key().key_data().clone(),
                Some(long.as_str()),
            ),
        ];
        let mut key = served(&long);
        key.database = long.clone();

        let text = unlock(
            &key,
            &login(&long),
            host(Some(&dest()), Some(&long)).as_ref(),
            &chain(&hops),
        )
        .message;

        assert!(text.len() <= MAX_PROMPT_MESSAGE_LEN, "{text}");
        assert!(text.contains(&format!(" on {} → …", "w".repeat(MAX_HOST_NAME_LEN))));
        assert!(text.ends_with(&format!("{}?", "w".repeat(MAX_HOST_NAME_LEN))));
    }

    /// A database name of the longest length is named whole in the unlock
    /// prompt, and a longer one is cut.
    #[test]
    fn the_unlock_names_a_database_of_24_bytes_whole() {
        let ask = |name: &str| {
            let mut key = served("github");
            key.database = name.to_string();
            unlock(&key, &Purpose::Other, None, &[]).message
        };

        assert_eq!(
            ask(&"d".repeat(24)),
            format!("Unlock database {} to use key \"github\"?", "d".repeat(24))
        );
        assert_eq!(
            ask(&"d".repeat(25)),
            format!("Unlock database {} to use key \"github\"?", "d".repeat(24))
        );
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
                .contains(" on build-box → … → a-jump-host.example.org to "),
            "{}",
            question.message
        );
        assert_eq!(
            forwarded_through(&[Some("build-box")]).data["forwarding_chain"],
            serde_json::json!([{"name": "build-box", "fingerprint": fingerprint(3)}])
        );
    }
}
