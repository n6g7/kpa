//! What the confirm prompt says (`docs/ssh-agent.md` § 6.7): the key, what
//! it is for and where the signature goes.

use std::path::Path;

use ssh_key::HashAlg;
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::public::KeyData;

use crate::ssh_agent::classify::Purpose;
use crate::ssh_agent::keys::ServedKey;

/// The longest login user or `SSHSIG` namespace a confirm prompt's
/// message carries. Both come from the request, so a long one is cut
/// rather than allowed to crowd the rest of the message out.
const MAX_REQUESTED_LEN: usize = 64;

/// The confirm prompt's message, plain text (`docs/ssh-agent.md` § 6.7).
/// The destination comes first, so the prompt's length cap can never hide
/// where the signature goes: for a connection bound to one, its host-key
/// fingerprint, with the host name `known_hosts` gives it if it has one.
/// Then the key's name and purpose, with the remote user for a login.
pub(super) fn message(
    served: &ServedKey,
    purpose: &Purpose,
    destination: Option<&KeyData>,
    known_hosts_name: Option<&str>,
) -> String {
    let what = match purpose {
        Purpose::Login(login) => format!(
            "{} for {}",
            served.name,
            capped(&login.user, MAX_REQUESTED_LEN)
        ),
        Purpose::SshSig { namespace } => format!(
            "{} to sign ({})",
            served.name,
            capped(namespace, MAX_REQUESTED_LEN)
        ),
        Purpose::Other => served.name.clone(),
    };
    let Some(dest) = destination else {
        return format!("Approve {what}");
    };
    let fingerprint = dest.fingerprint(HashAlg::Sha256);
    match known_hosts_name {
        Some(name) => format!("On {name} ({fingerprint}): approve {what}"),
        None => format!("On {fingerprint}: approve {what}"),
    }
}

/// `text` cut to at most `max_len` bytes, on a character boundary.
fn capped(text: &str, max_len: usize) -> &str {
    let mut end = text.len().min(max_len);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
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

    #[test]
    fn the_message_names_the_key_purpose_and_destination() {
        let dest = test_key(2).public_key().key_data().clone();
        let fingerprint = dest.fingerprint(HashAlg::Sha256);

        assert_eq!(
            message(&served("github"), &login("git"), None, None),
            "Approve github for git"
        );
        assert_eq!(
            message(
                &served("github"),
                &Purpose::SshSig {
                    namespace: "git".to_string()
                },
                None,
                None
            ),
            "Approve github to sign (git)"
        );
        assert_eq!(
            message(&served("github"), &Purpose::Other, Some(&dest), None),
            format!("On {fingerprint}: approve github")
        );
        assert_eq!(
            message(
                &served("github"),
                &login("git"),
                Some(&dest),
                Some("github.com")
            ),
            format!("On github.com ({fingerprint}): approve github for git")
        );
    }

    /// A long login user can't push the destination out of the prompt's
    /// capped message: the destination comes first, and the user is cut.
    #[test]
    fn a_long_login_user_comes_after_the_destination_and_is_cut() {
        let dest = test_key(2).public_key().key_data().clone();
        let fingerprint = dest.fingerprint(HashAlg::Sha256).to_string();
        let user = "u".repeat(1000);

        let message = message(&served("github"), &login(&user), Some(&dest), None);
        assert!(
            message.starts_with(&format!("On {fingerprint}: ")),
            "{message}"
        );
        assert!(
            message.ends_with(&"u".repeat(MAX_REQUESTED_LEN)),
            "{message}"
        );
        assert!(!message.contains(&"u".repeat(MAX_REQUESTED_LEN + 1)));
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
