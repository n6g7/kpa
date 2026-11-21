//! The host names OpenSSH's `known_hosts` gives host keys, for showing a host
//! by its name instead of its fingerprint: in the prompts, and in `kpa ssh
//! grants` and `kpa ssh pending` (`docs/ssh-agent.md` § 6.7, § 6.8).

use std::path::Path;

use ssh_key::Fingerprint;
use ssh_key::HashAlg;
use ssh_key::known_hosts::{HostPatterns, KnownHosts};

/// The plain host names a `known_hosts` file gives its host keys, read once.
///
/// A key is named by the first plain host name of an entry for it. A hashed
/// entry can't be reversed without the name that produced it, an `@revoked`
/// or `@cert-authority` one doesn't vouch for the key as that host's, and a
/// negated or wildcard pattern doesn't name one host, so all of those give no
/// name rather than a wrong one.
#[derive(Debug, Default)]
pub struct HostNames {
    named: Vec<(Fingerprint, String)>,
}

impl HostNames {
    /// The names `path` gives. A missing path or a file that can't be read
    /// gives none. A line that doesn't parse (a key type this build doesn't
    /// know, say) is skipped: the other lines still give theirs.
    pub fn read(path: Option<&Path>) -> HostNames {
        let Some(input) = path.and_then(|path| std::fs::read_to_string(path).ok()) else {
            return HostNames::default();
        };
        let named = KnownHosts::new(&input)
            .filter_map(Result::ok)
            .filter(|entry| entry.marker().is_none())
            .filter_map(|entry| {
                let name = match entry.host_patterns() {
                    HostPatterns::Patterns(patterns) => patterns
                        .iter()
                        .find(|pattern| !pattern.starts_with('!') && !pattern.contains(['*', '?']))
                        .cloned(),
                    HostPatterns::HashedName { .. } => None,
                }?;
                Some((entry.public_key().fingerprint(HashAlg::Sha256), name))
            })
            .collect();
        HostNames { named }
    }

    /// The name the file gives the host key with `fingerprint`, if it does.
    pub fn name(&self, fingerprint: &Fingerprint) -> Option<&str> {
        self.named
            .iter()
            .find(|(known, _)| known == fingerprint)
            .map(|(_, name)| name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::testing::test_key;

    fn fingerprint(seed: u64) -> Fingerprint {
        test_key(seed).public_key().fingerprint(HashAlg::Sha256)
    }

    /// Only a plain host name on a plain entry names a host: not a revoked
    /// or certificate-authority entry, nor a negated or wildcard pattern.
    #[test]
    fn it_skips_markers_and_patterns_that_name_no_one_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (revoked, authority, patterned) = (
            test_key(5).public_key().clone(),
            test_key(6).public_key().clone(),
            test_key(7).public_key().clone(),
        );
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

        let names = HostNames::read(Some(&path));

        assert_eq!(names.name(&fingerprint(5)), None);
        assert_eq!(names.name(&fingerprint(6)), None);
        assert_eq!(names.name(&fingerprint(7)), Some("good.example"));
    }

    #[test]
    fn it_names_an_unhashed_entry_and_skips_a_hashed_one() {
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

        let names = HostNames::read(Some(&path));

        assert_eq!(names.name(&fingerprint(2)), Some("github.com"));
        assert_eq!(names.name(&fingerprint(3)), None);
        assert_eq!(names.name(&fingerprint(4)), None);
    }

    /// One line the parser can't read doesn't take the rest of the file's
    /// names with it.
    #[test]
    fn a_line_that_does_not_parse_leaves_the_other_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "first.example {}\n\
                 odd.example ssh-unknown AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                 not a known_hosts line at all\n\
                 second.example {}\n",
                test_key(2).public_key().to_openssh().expect("encodes"),
                test_key(3).public_key().to_openssh().expect("encodes"),
            ),
        )
        .expect("write known_hosts");

        let names = HostNames::read(Some(&path));

        assert_eq!(names.name(&fingerprint(2)), Some("first.example"));
        assert_eq!(names.name(&fingerprint(3)), Some("second.example"));
    }

    #[test]
    fn a_missing_path_or_file_gives_no_names() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert_eq!(HostNames::read(None).name(&fingerprint(2)), None);
        assert_eq!(
            HostNames::read(Some(&dir.path().join("missing"))).name(&fingerprint(2)),
            None
        );
    }
}
