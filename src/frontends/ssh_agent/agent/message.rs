//! What the unlock and confirm prompts say (`docs/ssh-agent.md` § 6.6,
//! § 6.7): the key, what it is for and where the signature goes, as one
//! question.

use std::path::Path;

use ssh_key::HashAlg;
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::public::KeyData;

use crate::frontends::ssh_agent::classify::Purpose;
use crate::output::escape_one_line;
use crate::ssh::keys::ServedKey;

/// The most bytes (escaped) each piece of a message may take. The message
/// is one line the prompt caps at 256 bytes, and the destination comes last,
/// so every variable piece is cut well short of that: the worst message,
/// an unlock prompt for a login forwarded through a host `known_hosts`
/// doesn't name to one it doesn't name either, is 251 bytes
/// (`the_worst_message_fits_the_prompt_cap`), and the destination is always
/// whole.
const MAX_DATABASE_LEN: usize = 16;
const MAX_KEY_NAME_LEN: usize = 40;
/// The login user or `SSHSIG` namespace, from the request.
const MAX_REQUESTED_LEN: usize = 24;
/// A host name from `known_hosts`.
const MAX_HOST_NAME_LEN: usize = 48;

/// A host a message names: its host key, and the name `known_hosts` gives
/// it, if it has one.
pub(super) struct Host<'a> {
    pub(super) key: &'a KeyData,
    pub(super) name: Option<String>,
}

impl Host<'_> {
    /// The host's name, escaped and cut, else its host key's fingerprint.
    fn shown(&self) -> String {
        match &self.name {
            Some(name) => escape_one_line(name, MAX_HOST_NAME_LEN),
            None => format!("host key {}", self.key.fingerprint(HashAlg::Sha256)),
        }
    }
}

/// The confirm prompt's message, a question the user answers yes or no to:
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
) -> String {
    let lead = format!("Approve use of {}", key(served));
    question(&lead, purpose, destination, forwarding)
}

/// The unlock prompt's message, a question about unlocking that says what
/// for: "Unlock database personal to use key "github" to log in as git?". It
/// doesn't ask to approve the key; the confirm prompt does.
pub(super) fn unlock(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&Host<'_>>,
    forwarding: Option<&Host<'_>>,
) -> String {
    let lead = format!(
        "Unlock database {} to use {}",
        escape_one_line(&served.database, MAX_DATABASE_LEN),
        key(served)
    );
    question(&lead, purpose, destination, forwarding)
}

/// `key "github"`, the key's name quoted.
fn key(served: &ServedKey) -> String {
    format!("key \"{}\"", quoted(&served.name))
}

/// `lead`, then which host the request is forwarded through, then what the
/// key is for and where, as a question.
fn question(
    lead: &str,
    purpose: &Purpose,
    destination: Option<&Host<'_>>,
    forwarding: Option<&Host<'_>>,
) -> String {
    let through = on(forwarding);
    let what = match (purpose, destination) {
        (Purpose::Login(login), Some(dest)) => {
            let user = escape_one_line(&login.user, MAX_REQUESTED_LEN);
            match &dest.name {
                Some(_) => format!(" to log in to {user}@{}", dest.shown()),
                None => format!(" to log in as {user} to {}", dest.shown()),
            }
        }
        (Purpose::Login(login), None) => {
            format!(
                " to log in as {}",
                escape_one_line(&login.user, MAX_REQUESTED_LEN)
            )
        }
        (Purpose::SshSig { namespace }, destination) => format!(
            " to sign for namespace {}{}",
            escape_one_line(namespace, MAX_REQUESTED_LEN),
            on(destination)
        ),
        (Purpose::Other, destination) => on(destination),
    };
    format!("{lead}{through}{what}?")
}

/// " on <host>" for a host, nothing without one.
fn on(host: Option<&Host<'_>>) -> String {
    host.map(|host| format!(" on {}", host.shown()))
        .unwrap_or_default()
}

/// A key's name for the message: escaped, cut, and with its quotes
/// escaped, so it can't end its own quotation and continue the sentence.
fn quoted(name: &str) -> String {
    escape_one_line(&name.replace('"', "\\\""), MAX_KEY_NAME_LEN)
}

/// The first plain host name a `known_hosts` entry for `dest` gives. A
/// hashed entry can't be reversed without the name that produced it, an
/// `@revoked` or `@cert-authority` one doesn't vouch for `dest` as this
/// host's key, and a negated or wildcard pattern doesn't name one host, so
/// all of those are skipped rather than shown. `None` if the file can't
/// be read.
pub(super) fn known_hosts_name(path: &Path, dest: &KeyData) -> Option<String> {
    KnownHosts::read_file(path)
        .ok()?
        .into_iter()
        .filter(|entry| entry.marker().is_none() && entry.public_key().key_data() == dest)
        .find_map(|entry| match entry.host_patterns() {
            HostPatterns::Patterns(patterns) => patterns
                .iter()
                .find(|pattern| !pattern.starts_with('!') && !pattern.contains(['*', '?']))
                .cloned(),
            HostPatterns::HashedName { .. } => None,
        })
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
        approval(&served("github"), purpose, host(dest, name).as_ref(), None)
    }

    fn unlocked(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        unlock(&served("github"), purpose, host(dest, name).as_ref(), None)
    }

    /// The same questions for a login forwarded through `via`, named
    /// `via_name`, to `dest`, named `dest_name`.
    fn forwarded(
        message: fn(&ServedKey, &Purpose, Option<&Host<'_>>, Option<&Host<'_>>) -> String,
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
                        );
                        assert!(text.len() <= 256, "{} bytes: {text}", text.len());
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
        assert_eq!(longest, 251);
    }

    /// A key name can't close its quotes and carry on the sentence, nor
    /// hold a newline or a bidi override.
    #[test]
    fn a_hostile_key_name_stays_inside_its_quotes() {
        let message = approval(
            &served("x\" to log in as root\n\u{202e}"),
            &Purpose::Other,
            None,
            None,
        );
        assert_eq!(
            message,
            "Approve use of key \"x\\\" to log in as root\\u000a\\u202e\"?"
        );
    }

    /// Only a plain host name on a plain entry names a destination: not a
    /// revoked or certificate-authority entry, nor a negated or wildcard
    /// pattern.
    #[test]
    fn known_hosts_skips_markers_and_patterns_that_name_no_one_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let revoked = test_key(5).public_key().clone();
        let authority = test_key(6).public_key().clone();
        let patterned = test_key(7).public_key().clone();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "@revoked evil.example {}\n\
                 @cert-authority *.example {}\n\
                 !bad.example,*.example,good.example {}\n",
                revoked.to_openssh().expect("encodes"),
                authority.to_openssh().expect("encodes"),
                patterned.to_openssh().expect("encodes"),
            ),
        )
        .expect("write known_hosts");

        assert_eq!(known_hosts_name(&path, revoked.key_data()), None);
        assert_eq!(known_hosts_name(&path, authority.key_data()), None);
        assert_eq!(
            known_hosts_name(&path, patterned.key_data()).as_deref(),
            Some("good.example")
        );
    }

    #[test]
    fn known_hosts_names_an_unhashed_entry_and_skips_a_hashed_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let named = test_key(2).public_key().clone();
        let hashed = test_key(3).public_key().clone();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "github.com,140.82.121.4 {}\n\
                 |1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {}\n",
                named.to_openssh().expect("encodes"),
                hashed.to_openssh().expect("encodes"),
            ),
        )
        .expect("write known_hosts");

        assert_eq!(
            known_hosts_name(&path, named.key_data()).as_deref(),
            Some("github.com")
        );
        assert_eq!(known_hosts_name(&path, hashed.key_data()), None);
        assert_eq!(
            known_hosts_name(&path, test_key(4).public_key().key_data()),
            None
        );
        assert_eq!(
            known_hosts_name(&dir.path().join("missing"), named.key_data()),
            None
        );
    }
}
