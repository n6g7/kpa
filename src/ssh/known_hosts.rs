//! The host names OpenSSH's `known_hosts` gives host keys, for showing a host
//! by its name instead of its fingerprint: in the prompts, the log, and `kpa
//! ssh grants` and `kpa ssh pending` (`docs/ssh-agent.md` § 6.2, § 6.7,
//! § 6.8).

use std::path::PathBuf;

use ssh_key::certificate::CertType;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use ssh_key::public::KeyData;
use ssh_key::{Certificate, Fingerprint, HashAlg};

/// What a `known_hosts` file says about naming host keys, read once.
///
/// A key is named by the first plain host name of an entry for it. A hashed
/// entry can't be reversed without the name that produced it, so it names
/// nothing, and neither does a negated or wildcard pattern, which doesn't
/// name one host. A host key that presents a certificate is named by a
/// principal of the certificate when a CA the file trusts for that name
/// signed it ([`HostNames::name_of`]). A key the file revokes is named by
/// nothing.
#[derive(Debug, Default)]
pub struct HostNames {
    named: Vec<(Fingerprint, String)>,
    authorities: Vec<Authority>,
    revoked: Vec<Fingerprint>,
}

/// An `@cert-authority` line: the CA's key, and the host patterns it is
/// trusted for.
#[derive(Debug)]
struct Authority {
    key: Fingerprint,
    patterns: Vec<String>,
}

impl HostNames {
    /// What `files` say, read in order, as `ssh` reads them. A file that is
    /// missing or can't be read says nothing, and the files after it still
    /// count. A plain entry names a key in the first file that has one for
    /// it. `@cert-authority` and `@revoked` lines count from every file, so a
    /// key one file revokes is revoked. A line that doesn't parse (a key type
    /// this build doesn't know, say) is skipped: the other lines still count.
    /// A hashed `@cert-authority` line names nothing: `ssh-keygen -H` never
    /// writes one, and kpa doesn't match hashes for it.
    pub fn read(files: &[PathBuf]) -> HostNames {
        let mut names = HostNames::default();
        for file in files {
            if let Ok(input) = std::fs::read_to_string(file) {
                names.add(&input);
            }
        }
        names
    }

    /// Adds what `input`, one file, says.
    fn add(&mut self, input: &str) {
        for entry in KnownHosts::new(input).filter_map(Result::ok) {
            let key = entry.public_key().fingerprint(HashAlg::Sha256);
            match (entry.marker(), entry.host_patterns()) {
                (Some(Marker::Revoked), _) => self.revoked.push(key),
                (Some(Marker::CertAuthority), HostPatterns::Patterns(patterns)) => {
                    self.authorities.push(Authority {
                        key,
                        patterns: patterns.clone(),
                    });
                }
                (Some(Marker::CertAuthority), HostPatterns::HashedName { .. }) => {}
                (None, HostPatterns::Patterns(patterns)) => {
                    let plain = patterns
                        .iter()
                        .find(|pattern| !pattern.starts_with('!') && !pattern.contains(['*', '?']));
                    // A key a line before this one, in this file or an earlier
                    // one, named keeps that name.
                    if let Some(name) = plain
                        && !self.named.iter().any(|(named, _)| *named == key)
                    {
                        self.named.push((key, name.clone()));
                    }
                }
                (None, HostPatterns::HashedName { .. }) => {}
            }
        }
    }

    /// The name a plain entry gives the host key with `fingerprint`, if one
    /// does and the file doesn't revoke the key.
    pub fn name(&self, fingerprint: &Fingerprint) -> Option<&str> {
        if self.revoked.contains(fingerprint) {
            return None;
        }
        self.named
            .iter()
            .find(|(known, _)| known == fingerprint)
            .map(|(_, name)| name.as_str())
    }

    /// The name for the host whose key is `key`, which presented
    /// `certificate` if it did, as of the Unix time `now`: a principal of the
    /// certificate if a trusted CA signed it for that name, else the name a
    /// plain entry gives the key, else none.
    ///
    /// A certificate names its host when all of these hold:
    /// - an `@cert-authority` line for the CA's key has a pattern that
    ///   matches one of the certificate's principals, which is the name (the
    ///   first one that does);
    /// - the CA's signature on the certificate verifies;
    /// - it is a host certificate, valid at `now`, with no critical options;
    /// - neither the key nor the CA is revoked.
    ///
    /// A key the file revokes is named by nothing, and a revoked CA only
    /// takes the certificate route away. The certificate's own claims prove
    /// nothing without the CA line: anyone can mint a certificate that names
    /// whatever it likes.
    pub fn name_of(
        &self,
        key: &KeyData,
        certificate: Option<&Certificate>,
        now: u64,
    ) -> Option<String> {
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        if self.revoked.contains(&fingerprint) {
            return None;
        }
        certificate
            .and_then(|certificate| self.principal(certificate, now))
            .or_else(|| self.name(&fingerprint).map(str::to_string))
    }

    /// The principal of `certificate` a trusted CA named, if one did.
    fn principal(&self, certificate: &Certificate, now: u64) -> Option<String> {
        let authority = certificate.signature_key().fingerprint(HashAlg::Sha256);
        if certificate.cert_type() != CertType::Host
            || !certificate.critical_options().is_empty()
            || self.revoked.contains(&authority)
        {
            return None;
        }
        let principal = certificate.valid_principals().iter().find(|principal| {
            self.authorities
                .iter()
                .filter(|line| line.key == authority)
                .any(|line| matches(&line.patterns, principal))
        })?;
        // The CA line only says which names the CA may give. That it signed
        // this certificate, which is still valid, is what has to be shown.
        certificate.validate_at(now, [&authority]).ok()?;
        Some(principal.clone())
    }
}

/// Whether `name`, a host name without a port, matches a comma list of
/// `known_hosts` patterns as OpenSSH matches one: `*` and `?` stand for any
/// run of characters and any one, case doesn't matter, and a `!` pattern that
/// matches rules the name out whatever else matches. A pattern in
/// `[host]:port` form is for a name with a port, and never matches one
/// without.
fn matches(patterns: &[String], name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let mut positive = false;
    for pattern in patterns {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, pattern.as_str()),
        };
        if pattern.starts_with('[') || !glob(&pattern.to_ascii_lowercase(), &name) {
            continue;
        }
        if negated {
            return false;
        }
        positive = true;
    }
    positive
}

/// Whether `text` matches `pattern`, in which `*` is any run of characters
/// and `?` any one.
fn glob(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some(p);
                resume = t;
                p += 1;
            }
            Some(c) if *c == '?' || *c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some(s) => {
                    p = s + 1;
                    resume += 1;
                    t = resume;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::certificate::Builder;

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

        let names = HostNames::read(&[path]);

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

        let names = HostNames::read(&[path]);

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

        let names = HostNames::read(&[path]);

        assert_eq!(names.name(&fingerprint(2)), Some("first.example"));
        assert_eq!(names.name(&fingerprint(3)), Some("second.example"));
    }

    #[test]
    fn a_missing_path_or_file_gives_no_names() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert_eq!(HostNames::read(&[]).name(&fingerprint(2)), None);
        assert_eq!(
            HostNames::read(&[dir.path().join("missing")]).name(&fingerprint(2)),
            None
        );
    }

    /// A key's `known_hosts` form: `ssh-ed25519 AAAA…`.
    fn line_key(seed: u64) -> String {
        test_key(seed).public_key().to_openssh().expect("encodes")
    }

    fn names_from(lines: &str) -> HostNames {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, lines).expect("write known_hosts");
        HostNames::read(&[path])
    }

    const NOW: u64 = 1_000_000;

    /// A certificate for `test_key(host)` made by `test_key(ca)`.
    fn certificate(host: u64, ca: u64, principals: &[&str]) -> Certificate {
        built(host, ca, principals, CertType::Host, (0, NOW * 2), false)
    }

    fn built(
        host: u64,
        ca: u64,
        principals: &[&str],
        cert_type: CertType,
        (after, before): (u64, u64),
        critical: bool,
    ) -> Certificate {
        let mut builder = Builder::new(
            vec![7; 16],
            test_key(host).public_key().key_data().clone(),
            after,
            before,
        )
        .expect("a valid window");
        builder.cert_type(cert_type).expect("a type");
        builder.key_id("build-box-id").expect("a key id");
        if principals.is_empty() {
            builder.all_principals_valid().expect("any principal");
        }
        for principal in principals {
            builder.valid_principal(*principal).expect("a principal");
        }
        if critical {
            builder
                .critical_option("force-command", "true")
                .expect("an option");
        }
        builder.sign(&test_key(ca)).expect("the CA signs")
    }

    fn host(seed: u64) -> KeyData {
        test_key(seed).public_key().key_data().clone()
    }

    /// The line a user trusts CA `ca` with, for the hosts `patterns` names.
    fn ca_line(ca: u64, patterns: &str) -> String {
        format!("@cert-authority {patterns} {}\n", line_key(ca))
    }

    /// A certificate a trusted CA signed names its host by its principal,
    /// whatever the plain entries say.
    #[test]
    fn a_trusted_cas_certificate_names_its_host_by_a_principal() {
        let names = names_from(&format!(
            "{}plain.example {}\n",
            ca_line(2, "*.example"),
            line_key(1)
        ));

        let certificate = certificate(1, 2, &["build-box.example"]);

        assert_eq!(
            names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
            Some("build-box.example")
        );
    }

    /// The first principal a pattern matches is the name.
    #[test]
    fn the_first_principal_that_matches_is_the_name() {
        let names = names_from(&ca_line(2, "*.example"));

        let certificate = certificate(1, 2, &["10.0.0.1", "second.example", "third.example"]);

        assert_eq!(
            names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
            Some("second.example")
        );
    }

    /// Everything the rule needs, one condition at a time: without it the
    /// certificate names nothing, and the host falls back to its plain entry
    /// and then to no name.
    #[test]
    fn a_certificate_that_fails_a_condition_names_nothing() {
        let fallback = format!("plain.example {}\n", line_key(1));
        let trusting = |ca: u64, patterns: &str| format!("{}{fallback}", ca_line(ca, patterns));
        let tampered = {
            let mut bytes = certificate(1, 2, &["build-box.example"])
                .to_bytes()
                .expect("encodes");
            let at = bytes
                .windows(12)
                .position(|window| window == b"build-box-id")
                .expect("the key id is in the blob");
            bytes[at] ^= 1;
            Certificate::from_bytes(&bytes).expect("still parses")
        };
        let cases: Vec<(&str, String, Certificate)> = vec![
            (
                "another CA signed it",
                trusting(3, "*.example"),
                certificate(1, 2, &["build-box.example"]),
            ),
            (
                "its signature doesn't verify",
                trusting(2, "*.example"),
                tampered,
            ),
            (
                "it is expired",
                trusting(2, "*.example"),
                built(1, 2, &["a.example"], CertType::Host, (0, NOW), false),
            ),
            (
                "it is not valid yet",
                trusting(2, "*.example"),
                built(
                    1,
                    2,
                    &["a.example"],
                    CertType::Host,
                    (NOW + 1, NOW * 2),
                    false,
                ),
            ),
            (
                "it is a user certificate",
                trusting(2, "*.example"),
                built(1, 2, &["a.example"], CertType::User, (0, NOW * 2), false),
            ),
            (
                "it has a critical option",
                trusting(2, "*.example"),
                built(1, 2, &["a.example"], CertType::Host, (0, NOW * 2), true),
            ),
            (
                "no principal matches the CA's patterns",
                trusting(2, "*.example"),
                certificate(1, 2, &["build-box.test"]),
            ),
            (
                "a negated pattern rules the principal out",
                trusting(2, "*.example,!build-box.example"),
                certificate(1, 2, &["build-box.example"]),
            ),
            (
                "the CA line is hashed",
                format!(
                    "@cert-authority |1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {}\n{fallback}",
                    line_key(2)
                ),
                certificate(1, 2, &["build-box.example"]),
            ),
            (
                "the CA line is for a host with a port",
                trusting(2, "[build-box.example]:22"),
                certificate(1, 2, &["build-box.example"]),
            ),
            (
                "the CA is revoked",
                format!("@revoked * {}\n{}", line_key(2), trusting(2, "*.example")),
                certificate(1, 2, &["build-box.example"]),
            ),
            (
                "the certificate has no principals, which means any",
                trusting(2, "*"),
                certificate(1, 2, &[]),
            ),
        ];

        for (why, lines, certificate) in cases {
            let names = names_from(&lines);
            // The CA route fails, so only the plain entry names the host:
            // the CA's say never reaches a host through a certificate it
            // didn't sign for that name.
            assert_eq!(
                names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
                names.name(&fingerprint(1)),
                "{why}"
            );
            assert_ne!(
                names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
                Some("build-box.example"),
                "{why}"
            );
        }
    }

    /// With no CA line a certificate proves nothing: its principals are
    /// whatever its maker typed, and only a plain entry can name the key.
    #[test]
    fn a_certificate_with_no_ca_line_names_nothing_by_itself() {
        let names = names_from(&format!("plain.example {}\n", line_key(1)));
        let certificate = certificate(1, 2, &["claimed.example"]);

        assert_eq!(
            names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
            Some("plain.example")
        );
        assert_eq!(
            names_from("").name_of(&host(1), Some(&certificate), NOW),
            None
        );
    }

    /// A key the file revokes is named by nothing, a plain entry or a
    /// certificate included.
    #[test]
    fn a_revoked_key_has_no_name() {
        let names = names_from(&format!(
            "{}plain.example {}\n@revoked * {}\n",
            ca_line(2, "*.example"),
            line_key(1),
            line_key(1)
        ));
        let certificate = certificate(1, 2, &["build-box.example"]);

        assert_eq!(names.name_of(&host(1), Some(&certificate), NOW), None);
        assert_eq!(names.name_of(&host(1), None, NOW), None);
        assert_eq!(names.name(&fingerprint(1)), None);
    }

    /// A host without a certificate is named by its plain entry.
    #[test]
    fn a_host_without_a_certificate_is_named_by_its_plain_entry() {
        let names = names_from(&format!("plain.example {}\n", line_key(1)));

        assert_eq!(
            names.name_of(&host(1), None, NOW).as_deref(),
            Some("plain.example")
        );
        assert_eq!(names.name_of(&host(4), None, NOW), None);
    }

    /// Several files, read as `ssh` reads them. `files[i]` is the text of
    /// the i-th.
    fn names_from_files(files: &[&str]) -> HostNames {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths: Vec<PathBuf> = files
            .iter()
            .enumerate()
            .map(|(i, text)| {
                let path = dir.path().join(format!("known_hosts-{i}"));
                std::fs::write(&path, text).expect("write known_hosts");
                path
            })
            .collect();
        HostNames::read(&paths)
    }

    /// A plain entry names a key in the first file that has one for it.
    #[test]
    fn the_first_file_that_names_a_key_wins() {
        let names = names_from_files(&[
            &format!("first.example {}\n", line_key(1)),
            &format!(
                "second.example {}\nonly-second.example {}\n",
                line_key(1),
                line_key(2)
            ),
        ]);

        assert_eq!(names.name(&fingerprint(1)), Some("first.example"));
        assert_eq!(names.name(&fingerprint(2)), Some("only-second.example"));
    }

    /// A CA line in one file trusts the CA for a certificate whatever file
    /// names the key, and a revocation in any file revokes.
    #[test]
    fn ca_and_revoked_lines_count_from_every_file() {
        let certificate = certificate(1, 2, &["build-box.example"]);
        let trusting = ca_line(2, "*.example");
        let revoking = format!("@revoked * {}\n", line_key(1));

        let names = names_from_files(&["", &trusting]);
        assert_eq!(
            names.name_of(&host(1), Some(&certificate), NOW).as_deref(),
            Some("build-box.example")
        );

        let names = names_from_files(&[&revoking, &trusting]);
        assert_eq!(names.name_of(&host(1), Some(&certificate), NOW), None);

        let names = names_from_files(&[&trusting, &revoking]);
        assert_eq!(names.name_of(&host(1), Some(&certificate), NOW), None);
    }

    /// A file that is missing or can't be read is skipped, and the files
    /// after it still count. No files name nothing.
    #[test]
    fn a_missing_file_is_skipped_and_no_files_name_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("known_hosts");
        std::fs::write(&present, format!("plain.example {}\n", line_key(1))).expect("write");
        let unreadable = dir.path().join("a-directory");
        std::fs::create_dir(&unreadable).expect("mkdir");

        let names = HostNames::read(&[dir.path().join("missing"), unreadable, present]);

        assert_eq!(names.name(&fingerprint(1)), Some("plain.example"));
        assert_eq!(HostNames::read(&[]).name(&fingerprint(1)), None);
    }

    /// Patterns are OpenSSH's: lists, globs, case, negation and ports.
    #[test]
    fn patterns_match_as_openssh_matches_them() {
        let list =
            |patterns: &str| -> Vec<String> { patterns.split(',').map(str::to_string).collect() };
        assert!(matches(&list("*.example"), "a.example"));
        assert!(matches(&list("a.example,b.example"), "B.EXAMPLE"));
        assert!(matches(&list("a?.example"), "ab.example"));
        assert!(!matches(&list("a?.example"), "a.example"));
        assert!(matches(&list("*"), "anything"));
        assert!(matches(&list("*.example,!bad.example"), "good.example"));
        assert!(!matches(&list("*.example,!bad.example"), "bad.example"));
        assert!(!matches(&list("!bad.example,*.example"), "bad.example"));
        assert!(!matches(&list("!only.example"), "other.example"));
        assert!(!matches(&list("[a.example]:22"), "a.example"));
        assert!(!matches(&list("a.example"), "b.example"));
    }
}
