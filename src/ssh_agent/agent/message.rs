//! What the confirm prompt says (`docs/ssh-agent.md` § 6.7): the key, what
//! it is for and where the signature goes, as one question.

use std::path::Path;

use ssh_key::HashAlg;
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::public::KeyData;

use crate::output::escape_one_line;
use crate::ssh_agent::classify::Purpose;
use crate::ssh_agent::keys::ServedKey;

/// The most bytes (escaped) each piece of a message may take. The message
/// is one line the prompt caps at 256 bytes, and the destination comes last,
/// so every variable piece is cut well short of that: the worst message, an
/// `SSHSIG` on a host `known_hosts` doesn't name, is 204 bytes
/// (`the_worst_message_fits_the_prompt_cap`), and the destination is always
/// whole.
const MAX_KEY_NAME_LEN: usize = 64;
/// The login user or `SSHSIG` namespace, from the request.
const MAX_REQUESTED_LEN: usize = 32;
/// A host name from `known_hosts`.
const MAX_HOST_NAME_LEN: usize = 56;

/// The confirm prompt's message, a question the user answers yes or no to:
/// "Approve use of key "github" to log in to git@github.com?". The key is
/// shown by its name, quoted. What follows says what it is for and, for a
/// connection bound to a destination, where: the host name `known_hosts`
/// gives its host key if it has one, else the host key's fingerprint. Every
/// piece that comes from outside kpa's own text is escaped and cut to its
/// own budget, so none can hide the destination.
pub(super) fn approval(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&KeyData>,
    known_hosts_name: Option<&str>,
) -> String {
    let lead = format!("Approve use of {}", key(served));
    question(&lead, purpose, destination, known_hosts_name)
}

/// `key "github"`, the key's name quoted.
fn key(served: &ServedKey) -> String {
    format!("key \"{}\"", quoted(&served.name))
}

/// `lead`, then what the key is for and where, as a question.
fn question(
    lead: &str,
    purpose: &Purpose,
    destination: Option<&KeyData>,
    known_hosts_name: Option<&str>,
) -> String {
    let name = known_hosts_name.map(|name| escape_one_line(name, MAX_HOST_NAME_LEN));
    let host = |dest: &KeyData| match &name {
        Some(name) => name.clone(),
        None => format!("host key {}", dest.fingerprint(HashAlg::Sha256)),
    };
    let what = match (purpose, destination) {
        (Purpose::Login(login), Some(dest)) => {
            let user = escape_one_line(&login.user, MAX_REQUESTED_LEN);
            match &name {
                Some(name) => format!(" to log in to {user}@{name}"),
                None => format!(" to log in as {user} to {}", host(dest)),
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
            on(destination.map(host))
        ),
        (Purpose::Other, destination) => on(destination.map(host)),
    };
    format!("{lead}{what}?")
}

/// " on <host>" for a destination, nothing without one.
fn on(host: Option<String>) -> String {
    host.map(|host| format!(" on {host}")).unwrap_or_default()
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
    use crate::ssh_agent::classify::LoginRequest;
    use crate::ssh_agent::testing::test_key;

    fn served(name: &str) -> ServedKey {
        let key = test_key(1);
        let public_key = key.public_key().clone();
        ServedKey {
            database: "personal".to_string(),
            fingerprint: public_key.fingerprint(HashAlg::Sha256),
            public_key,
            name: name.to_string(),
            entry_uuid: uuid::Uuid::nil(),
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

    fn approved(purpose: &Purpose, dest: Option<&KeyData>, name: Option<&str>) -> String {
        approval(&served("github"), purpose, dest, name)
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

    /// Whatever the key, user, namespace and host name are, the
    /// whole message, destination included, fits the prompt's cap, and the
    /// destination is its end: each piece is cut on its own.
    #[test]
    fn the_worst_message_fits_the_prompt_cap() {
        let (dest, fingerprint) = (dest(), fingerprint());
        let long = "w".repeat(1000);
        let key = served(&long);
        let purposes = [login(&long), sshsig(&long), Purpose::Other];
        let mut longest = 0;

        for message in [approval] {
            for purpose in &purposes {
                for name in [None, Some(long.as_str())] {
                    let text = message(&key, purpose, Some(&dest), name);
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
        assert_eq!(longest, 204);
    }

    /// A key name can't close its quotes and carry on the sentence, nor
    /// hold a newline or a bidi override.
    #[test]
    fn a_hostile_key_name_stays_inside_its_quotes() {
        let message = approval(
            &served("x\" to log in to root@bank.example\n\u{202e}"),
            &Purpose::Other,
            None,
            None,
        );
        assert_eq!(
            message,
            "Approve use of key \"x\\\" to log in to root@bank.example\\u000a\\u202e\"?"
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
