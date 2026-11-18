//! Which SSH keys kpa serves (`docs/ssh-agent.md` § 6.4): scanning a
//! database's current-entry attachments for OpenSSH private keys, applying
//! config overrides, naming, and the public-key cache that lists a locked
//! database's keys.
//!
//! Pure: nothing here touches a mutex or an epoch. Callers run `scan` at
//! unlock and `parse_private_key` at a key's first signature, under their
//! own locking.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, Fingerprint, HashAlg, PrivateKey, PublicKey};
use uuid::Uuid;

use crate::config::{DatabaseConfig, SshKeyConfirm};
use crate::paths::Paths;
use crate::vault::{self, AttachmentView};

/// Marks the one private-key format kpa reads (`docs/ssh-agent.md` § 6.4).
const OPENSSH_MARKER: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

/// PEM markers for the formats kpa recognizes but refuses: PKCS#1 (classic
/// `ssh-keygen`'s old `-m PEM` output for RSA/DSA/ECDSA) and PKCS#8.
const PEM_MARKERS: [&[u8]; 2] = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
];

/// RSA keys under this many bits are refused (`docs/ssh-agent.md` § 6.5).
const MIN_RSA_BITS: u32 = 2048;

/// One OpenSSH private key found among a database's current-entry
/// attachments: its public half only. `scan` parses the whole key file to
/// learn its type and public key, then drops the parsed private key;
/// `parse_private_key` reads it again at the key's first signature.
#[derive(Debug, Clone)]
pub struct FoundKey {
    pub public_key: PublicKey,
    pub fingerprint: Fingerprint,
    pub entry_uuid: Uuid,
    pub entry_title: Option<String>,
    pub attachment_name: String,
}

/// Why an attachment that looked like a private key was not read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// PEM PKCS#1 or PKCS#8 — `ssh-keygen -p -f <file>` rewrites it to the
    /// OpenSSH format kpa reads.
    Pem,
    /// Started with the OpenSSH marker but didn't parse as one.
    Unparseable,
    /// A recognized but unsupported algorithm (`sk-*`, DSA, …), named the
    /// way the wire protocol and `ssh-add -l` would.
    UnsupportedType(String),
    /// An RSA key under `MIN_RSA_BITS`.
    RsaTooSmall(u32),
    /// Protected by a passphrase, which kpa has no way to ask for.
    Encrypted,
    /// An `ecdsa-sha2-nistp256` key whose private scalar is encoded in 31
    /// bytes, which `ssh-key` 0.7.0-rc.12 can't read
    /// (`docs/ssh-agent.md` § 6.5). Regenerating the key fixes it.
    ShortEcdsaScalar,
}

/// What a log line says about a skipped attachment: the reason, and what
/// to do about it where there is something to do.
impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::Pem => write!(
                f,
                "PEM format; `ssh-keygen -p -f <file>` rewrites it in OpenSSH format"
            ),
            SkipReason::Unparseable => write!(f, "not a readable OpenSSH private key"),
            SkipReason::UnsupportedType(algorithm) => {
                write!(f, "unsupported key type {algorithm}")
            }
            SkipReason::RsaTooSmall(bits) => {
                write!(f, "RSA key of {bits} bits, under {MIN_RSA_BITS}")
            }
            SkipReason::Encrypted => write!(f, "protected by a passphrase"),
            SkipReason::ShortEcdsaScalar => write!(
                f,
                "a P-256 key this build can't read (its private scalar is 31 bytes); \
                 regenerate the key"
            ),
        }
    }
}

/// One attachment `scan` didn't read as a served key, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAttachment {
    pub entry_uuid: Uuid,
    pub entry_title: Option<String>,
    pub attachment_name: String,
    pub reason: SkipReason,
}

/// The outcome of scanning one database's attachments.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub found: Vec<FoundKey>,
    pub skipped: Vec<SkippedAttachment>,
}

/// Scans `db`'s current-entry attachments, in tree order
/// (`vault::for_each_attachment`), for OpenSSH private keys, per
/// `docs/ssh-agent.md` § 6.4. Each is parsed straight from the database's
/// own bytes, never copied. An attachment that doesn't start with either
/// the OpenSSH or a PEM marker isn't a key at all and is silently ignored,
/// rather than reported skipped — most attachments in a vault are not SSH
/// keys.
pub fn scan(db: &keepass::Database) -> ScanResult {
    let mut result = ScanResult::default();
    vault::for_each_attachment(db, |attachment| classify(attachment, &mut result));
    result
}

fn classify(attachment: AttachmentView<'_>, result: &mut ScanResult) {
    let data = attachment.data;
    if !data.starts_with(OPENSSH_MARKER) {
        if PEM_MARKERS.iter().any(|marker| data.starts_with(marker)) {
            result.skipped.push(skipped(attachment, SkipReason::Pem));
        }
        return;
    }

    let private_key = match PrivateKey::from_openssh(data) {
        Ok(key) => key,
        Err(err) => {
            let reason = if is_short_p256_scalar(data, &err) {
                SkipReason::ShortEcdsaScalar
            } else {
                SkipReason::Unparseable
            };
            result.skipped.push(skipped(attachment, reason));
            return;
        }
    };

    if private_key.is_encrypted() {
        result
            .skipped
            .push(skipped(attachment, SkipReason::Encrypted));
        return;
    }

    let public_key = private_key.public_key();
    if let Some(reason) = unsupported(private_key.algorithm(), public_key.key_data()) {
        result.skipped.push(skipped(attachment, reason));
        return;
    }

    let public_key = public_key.clone();
    let fingerprint = public_key.fingerprint(HashAlg::Sha256);
    result.found.push(FoundKey {
        public_key,
        fingerprint,
        entry_uuid: attachment.entry_uuid,
        entry_title: attachment.entry_title.map(str::to_owned),
        attachment_name: attachment.name.to_string(),
    });
}

fn skipped(attachment: AttachmentView<'_>, reason: SkipReason) -> SkippedAttachment {
    SkippedAttachment {
        entry_uuid: attachment.entry_uuid,
        entry_title: attachment.entry_title.map(str::to_owned),
        attachment_name: attachment.name.to_string(),
        reason,
    }
}

/// Whether `err`, from parsing the OpenSSH key file `data`, is `ssh-key`
/// 0.7.0-rc.12 refusing a P-256 private scalar encoded in 31 bytes: a
/// length error on a file whose unencrypted header holds a P-256 public
/// key (`docs/ssh-agent.md` § 6.5).
fn is_short_p256_scalar(data: &[u8], err: &ssh_key::Error) -> bool {
    matches!(
        err,
        ssh_key::Error::Encoding(ssh_key::encoding::Error::Length)
    ) && matches!(
        header_public_key(data),
        Some(KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP256(_)))
    )
}

/// The public key in an OpenSSH private key file's header, read without
/// touching the private section (`PROTOCOL.key`: the magic, cipher, KDF,
/// KDF options, key count, then the first public key). The decoded file
/// holds the private section too, so it is zeroized when dropped.
fn header_public_key(data: &[u8]) -> Option<KeyData> {
    use base64::Engine as _;
    use ssh_key::encoding::Decode;
    use zeroize::Zeroizing;

    let text = std::str::from_utf8(data).ok()?;
    let body: Zeroizing<String> = Zeroizing::new(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("-----"))
            .collect(),
    );
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .ok()?,
    );
    let mut reader = decoded.strip_prefix(b"openssh-key-v1\0")?;
    for _ in 0..3 {
        // cipher name, KDF name, KDF options
        Vec::<u8>::decode(&mut reader).ok()?;
    }
    u32::decode(&mut reader).ok()?;
    let public_key = Vec::<u8>::decode(&mut reader).ok()?;
    KeyData::decode(&mut public_key.as_slice()).ok()
}

/// `None` for `docs/ssh-agent.md` § 6.5's supported set — Ed25519,
/// `ecdsa-sha2-nistp256`/`384`, and RSA at `MIN_RSA_BITS` or more — a
/// reason otherwise.
fn unsupported(algorithm: Algorithm, key_data: &KeyData) -> Option<SkipReason> {
    match algorithm {
        Algorithm::Ed25519 => None,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384,
        } => None,
        Algorithm::Rsa { .. } => match key_data {
            KeyData::Rsa(rsa) if rsa.key_size() >= MIN_RSA_BITS => None,
            KeyData::Rsa(rsa) => Some(SkipReason::RsaTooSmall(rsa.key_size())),
            _ => Some(SkipReason::UnsupportedType(algorithm.to_string())),
        },
        _ => Some(SkipReason::UnsupportedType(algorithm.to_string())),
    }
}

/// A key kpa serves: survived its database's `serve = false` overrides,
/// with the name and policy settings its config gives it.
#[derive(Debug, Clone)]
pub struct ServedKey {
    pub database: String,
    pub public_key: PublicKey,
    pub fingerprint: Fingerprint,
    pub name: String,
    pub entry_uuid: Uuid,
    /// Local approval policy (`docs/ssh-agent.md` § 6.7), from the
    /// key's settings.
    pub confirm: SshKeyConfirm,
    /// Usable through `ssh -A`, from the key's settings.
    pub forwarded: bool,
}

/// Resolves which of a database's found keys get served, applying its
/// `[[database.ssh_key]]` settings (`DatabaseConfig::ssh_key_settings`):
/// drops anything a `serve = false` override names, names the rest with
/// [`key_name`], and carries each one's `confirm`/`forwarded` policy for
/// [`super::authz::authorize_sign`].
pub fn resolve(cfg: &DatabaseConfig, found: &[FoundKey]) -> Vec<ServedKey> {
    found
        .iter()
        .filter_map(|key| {
            served(
                cfg,
                key.public_key.clone(),
                key.entry_uuid,
                key.entry_title.as_deref(),
            )
        })
        .collect()
}

/// [`resolve`] for the keys a locked database's cache lists
/// ([`read_cache`]). The cache holds no titles and no entries, so a key
/// without a `name` override is named `<database> <fingerprint>`, and its
/// `entry_uuid` is nil.
pub fn resolve_cached(cfg: &DatabaseConfig, cached: Vec<PublicKey>) -> Vec<ServedKey> {
    cached
        .into_iter()
        .filter_map(|public_key| served(cfg, public_key, Uuid::nil(), None))
        .collect()
}

/// One key as `cfg` serves it, or `None` if a `serve = false` override
/// hides it: the one place the settings are applied, for scanned and
/// cached keys alike.
fn served(
    cfg: &DatabaseConfig,
    public_key: PublicKey,
    entry_uuid: Uuid,
    entry_title: Option<&str>,
) -> Option<ServedKey> {
    let fingerprint = public_key.fingerprint(HashAlg::Sha256);
    let settings = cfg.ssh_key_settings(fingerprint);
    if !settings.serve {
        return None;
    }
    Some(ServedKey {
        database: cfg.name.clone(),
        public_key,
        fingerprint,
        name: key_name(
            &cfg.name,
            fingerprint,
            settings.name.as_deref(),
            entry_title,
        ),
        entry_uuid,
        confirm: settings.confirm,
        forwarded: settings.forwarded,
    })
}

/// A key's display name (`docs/ssh-agent.md` § 6.4 "Names"): the override's
/// `name` if set, else `entry_title` if given, else `<database>
/// <fingerprint>`. Pass `entry_title: None` when naming a key listed from
/// the cache while its database is locked — the cache holds no titles.
pub fn key_name(
    database: &str,
    fingerprint: Fingerprint,
    override_name: Option<&str>,
    entry_title: Option<&str>,
) -> String {
    if let Some(name) = override_name {
        name.to_string()
    } else if let Some(title) = entry_title {
        title.to_string()
    } else {
        format!("{database} {fingerprint}")
    }
}

/// Drops a key already served by an earlier database — "served from the
/// first one in config order" (`docs/ssh-agent.md` § 6.4). `per_database`
/// must already be ordered the way config lists its databases.
pub fn dedupe_by_config_order(per_database: Vec<Vec<ServedKey>>) -> Vec<ServedKey> {
    let mut seen = HashSet::new();
    per_database
        .into_iter()
        .flatten()
        .filter(|key| seen.insert(key.fingerprint))
        .collect()
}

/// The private key in an OpenSSH attachment `scan` found, read at its first
/// signature. `None` if it doesn't parse or is encrypted. The key material
/// zeroizes when the returned key drops.
pub fn parse_private_key(attachment: &[u8]) -> Option<PrivateKey> {
    PrivateKey::from_openssh(attachment)
        .ok()
        .filter(|key| !key.is_encrypted())
}

/// Where the public-key cache lives: `kpa/ssh-keys` under `paths`' cache
/// directory. `None` without one.
pub fn cache_dir(paths: &Paths) -> Option<PathBuf> {
    paths.cache_dir.as_ref().map(|dir| dir.join("kpa/ssh-keys"))
}

/// Writes `database`'s served public keys to `<dir>/<database>`, creating
/// `dir` if needed, mode 0600. Atomic: writes a sibling temp file and
/// renames it over the target, so a reader never sees a partial write.
///
/// Holds public keys only — no titles, no comments — which is why this
/// takes `&[PublicKey]` rather than `&[ServedKey]`: a comment on `key` is
/// dropped before it's written, so `docs/threat-model.md` G-4 holds even if
/// a caller's `PublicKey` carries one.
pub fn write_cache(dir: &Path, database: &str, keys: &[PublicKey]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let mut body = String::new();
    for key in keys {
        let bare = PublicKey::new(key.key_data().clone(), "");
        let line = bare
            .to_openssh()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        body.push_str(&line);
        body.push('\n');
    }

    let tmp_path = dir.join(format!(".{database}.tmp"));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, dir.join(database))?;
    Ok(())
}

/// Reads back what `write_cache` wrote for `database`. Tolerant: a missing
/// or unreadable file, or a line that fails to parse, is dropped rather
/// than failing the read — "nothing listed, never a crash"
/// (`docs/ssh-agent.md` § 6.4).
pub fn read_cache(dir: &Path, database: &str) -> Vec<PublicKey> {
    let Ok(text) = std::fs::read_to_string(dir.join(database)) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| PublicKey::from_openssh(line).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use uuid::Uuid;

    use super::*;
    use crate::config::SshKeyConfig;
    use crate::ssh_agent::testing::RSA_3072;

    /// `ssh-key`'s own test vector (`tests/examples/id_ed25519`):
    /// unencrypted Ed25519.
    const ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

    /// Same key as `ED25519`, encrypted under aes256-ctr (`ssh-key`'s own
    /// `tests/examples/id_ed25519.aes256-ctr.enc`).
    const ED25519_ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBKH96ujW
umB6/WnTNPjTeaAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoFzvbvyFMhAiwBOXF0mhUUacPUCMZXivG2up2c
hEnAw1b6BLRPyWbY5cC2n9ggD4ivJ1zSts6sBgjyiXQAReyrP35myYvT/OIB/NpwZM/xIJ
N7MHSUzlkX4adBrga3f7GS4uv4ChOoxC4XsE5HsxtGsq1X8jzqLlZTmOcxkcEneYQexrUc
bQP0o+gL5aKK8cQgiIlXeDbRjqhc4+h4EF6lY=
-----END OPENSSH PRIVATE KEY-----
";

    /// `ssh-key`'s own test vector (`tests/examples/id_dsa_1024`):
    /// unencrypted DSA — an unsupported algorithm.
    const DSA_1024: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQDcPYklDtlGIRTLLI1IFuOlEar/Gwaw4B3hfBywTlgbyrlxdkcdif18oYF+PEji
zLr9IXD2no5ci2q2m5xfRdleHZKT6WUifu5bh5sRIzccIbHbYPFLXlwFpHgs60OjL0SWR3
AwY2Ieeihr7JWxZybBi15SOD0AspemsDSJsGBopQAAABUAiRgVN4WX/kLT/SYf523zZYRb
u4cAAACARzmzkIqEFUZtx7FW+5jstxVSoXC6Czt6qBvYE5HeCnrnobRQAt/q3JIl+8Ugpx
P+QQSnS+1T/VkV2nNjZa/T8Jd3u8z7rfesKwh7f02V+r5H1ypG6VCI+c0qn78ja1immCZH
88AEMK1zUtR6Jeu+lHfwwxJ9qGrXRIZEt23lh1wAAACAYEKms/2GE0TLIczM2HGeJaoL4J
gOecur9Id/XvBx9gOXcDUurD1MNo8p2vpXtHXHjUSYnxZXdSflmDNL5qrkq9dQw2r4BInT
kml8HzLzzzyai5m83bU9ejfhoo/VPUk0Exz0HEN8ZzTR4EAErc2SW4SzlWwww6OQTuyzFA
Cw30gAAAHo9I0p/vSNKf4AAAAHc3NoLWRzcwAAAIEA3D2JJQ7ZRiEUyyyNSBbjpRGq/xsG
sOAd4XwcsE5YG8q5cXZHHYn9fKGBfjxI4sy6/SFw9p6OXItqtpucX0XZXh2Sk+llIn7uW4
ebESM3HCGx22DxS15cBaR4LOtDoy9ElkdwMGNiHnooa+yVsWcmwYteUjg9ALKXprA0ibBg
aKUAAAAVAIkYFTeFl/5C0/0mH+dt82WEW7uHAAAAgEc5s5CKhBVGbcexVvuY7LcVUqFwug
s7eqgb2BOR3gp656G0UALf6tySJfvFIKcT/kEEp0vtU/1ZFdpzY2Wv0/CXd7vM+633rCsI
e39Nlfq+R9cqRulQiPnNKp+/I2tYppgmR/PABDCtc1LUeiXrvpR38MMSfahq10SGRLdt5Y
dcAAAAgGBCprP9hhNEyyHMzNhxniWqC+CYDnnLq/SHf17wcfYDl3A1Lqw9TDaPKdr6V7R1
x41EmJ8WV3Un5ZgzS+aq5KvXUMNq+ASJ05JpfB8y8888mouZvN21PXo34aKP1T1JNBMc9B
xDfGc00eBABK3NkluEs5VsMMOjkE7ssxQAsN9IAAAAFAw3esRJ53DYmjVXdDy9BQOWEUti
AAAAEHVzZXJAZXhhbXBsZS5jb20BAgM=
-----END OPENSSH PRIVATE KEY-----
";

    /// Generated once with `ssh-keygen -t rsa -b 1024`: unencrypted RSA
    /// under `MIN_RSA_BITS`.
    const RSA_1024: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAvSbr4Eb3ibYzFzxghwfVYJi25iMXFQmdWVDjtqbG4Xg/9TNhOx9Z
bwxI9Vrqn6DLlt+NuSxxrI4TSy87Ai8/gnMC8QqdFNfYvF2CWqsb+/dN81WS1Qp2Jx4BsD
Lyf2gjEdR3qm46s5lXM6M2lKlcoGQqbaG/4AsNAkFOBiCEG2UAAAH4VmBUclZgVHIAAAAH
c3NoLXJzYQAAAIEAvSbr4Eb3ibYzFzxghwfVYJi25iMXFQmdWVDjtqbG4Xg/9TNhOx9Zbw
xI9Vrqn6DLlt+NuSxxrI4TSy87Ai8/gnMC8QqdFNfYvF2CWqsb+/dN81WS1Qp2Jx4BsDLy
f2gjEdR3qm46s5lXM6M2lKlcoGQqbaG/4AsNAkFOBiCEG2UAAAADAQABAAAAgGLMDJIVnz
/f2em+EJEXB12wBoBIPcswPW6kcHw7uk+UVpvFXXjbFASLvyPgfAIqo4xHcigRTcKaZvtz
TPgEI8Ah/zyjILPKBS+e4a/5dQvbcFgMtdqg9Q6CkRk7aYapmqPUzXfa67zOPdTQyYwRod
PLYakm28y+RHplQa9QqMW1AAAAQQC4FqEsL4cK9o/3X/WSgr/uNixp29vdg02N9dlzFxWn
oFIYy6MvnhShpKaMYyiN9s0Hm97MJBaDjwTj7E8gGqlIAAAAQQDpDGsA79cbe7J5zEKGOD
OoAMhrdJtKoHh0nYCzvlxLVnp49oilRru5c1RRksl3gBcTw2MiIAw+AMewTWPU+wo3AAAA
QQDPx8rj+2aQRRCeps8jDMUz2JKVHfQtZgfeh5z46Yey3rk9Wx7s3F4qwtiuRkhJufl91O
Pj3iwEnp4QT2MH74lDAAAAAAEC
-----END OPENSSH PRIVATE KEY-----
";

    /// One attachment, owned, for building a scan by hand.
    struct TestAttachment {
        entry_uuid: Uuid,
        entry_title: String,
        name: String,
        data: Vec<u8>,
    }

    fn attachment(name: &str, data: &str) -> TestAttachment {
        TestAttachment {
            entry_uuid: Uuid::new_v4(),
            entry_title: name.to_string(),
            name: format!("{name}.key"),
            data: data.as_bytes().to_vec(),
        }
    }

    /// `super::scan`'s classification, over hand-built attachments.
    fn scan(attachments: &[TestAttachment]) -> ScanResult {
        let mut result = ScanResult::default();
        for attachment in attachments {
            classify(
                AttachmentView {
                    entry_uuid: attachment.entry_uuid,
                    entry_title: Some(&attachment.entry_title),
                    name: &attachment.name,
                    data: &attachment.data,
                },
                &mut result,
            );
        }
        result
    }

    #[test]
    fn scan_finds_ed25519_and_rsa_keys() {
        let attachments = [attachment("ed25519", ED25519), attachment("rsa", RSA_3072)];
        let result = scan(&attachments);
        assert!(result.skipped.is_empty());
        assert_eq!(result.found.len(), 2);
        assert_eq!(result.found[0].public_key.algorithm(), Algorithm::Ed25519);
        assert_eq!(
            result.found[1].public_key.algorithm(),
            Algorithm::Rsa { hash: None }
        );
    }

    #[test]
    fn scan_skips_pem_without_trying_to_parse_it() {
        let attachments = [attachment(
            "pem",
            "-----BEGIN RSA PRIVATE KEY-----\nnotarealkey\n-----END RSA PRIVATE KEY-----\n",
        )];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].reason, SkipReason::Pem);
        assert_eq!(result.skipped[0].attachment_name, "pem.key");
    }

    #[test]
    fn scan_skips_openssh_garbage_as_unparseable() {
        let attachments = [attachment(
            "garbage",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        )];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert_eq!(result.skipped[0].reason, SkipReason::Unparseable);
    }

    /// A throwaway P-256 public key, for building key files by hand.
    const P256_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAtn2zrH1k1g0t0P6NGtQP8xzOSu+FhsxU4sOqL6vXYEcMqCgcdlAmUZUlhF6CTkL93+eiXpYaslDIJzZPfT/Aw=";

    /// An unencrypted OpenSSH key file (`PROTOCOL.key`) for `P256_PUB`
    /// whose private scalar is `scalar`, encoded as given, the way OpenSSH
    /// writes a scalar with a leading zero byte.
    fn p256_key_file(scalar: &[u8]) -> String {
        use base64::Engine as _;
        use ssh_key::encoding::Encode;

        let public = PublicKey::from_openssh(P256_PUB).expect("test key");
        let KeyData::Ecdsa(point) = public.key_data() else {
            panic!("not an ECDSA key");
        };
        let mut private = Vec::new();
        0x0102_0304_u32.encode(&mut private).expect("encode");
        0x0102_0304_u32.encode(&mut private).expect("encode");
        "ecdsa-sha2-nistp256".encode(&mut private).expect("encode");
        "nistp256".encode(&mut private).expect("encode");
        point.as_sec1_bytes().encode(&mut private).expect("encode");
        scalar.encode(&mut private).expect("encode");
        "".encode(&mut private).expect("encode");
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }

        let mut file = b"openssh-key-v1\0".to_vec();
        "none".encode(&mut file).expect("encode");
        "none".encode(&mut file).expect("encode");
        "".encode(&mut file).expect("encode");
        1u32.encode(&mut file).expect("encode");
        public
            .key_data()
            .encode_vec()
            .expect("encode")
            .as_slice()
            .encode(&mut file)
            .expect("encode");
        private.as_slice().encode(&mut file).expect("encode");

        let body = base64::engine::general_purpose::STANDARD.encode(file);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(70)
            .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
            .collect();
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }

    /// `ssh-key` 0.7.0-rc.12 can't read a P-256 key whose scalar OpenSSH
    /// wrote in 31 bytes: the scan names that case, so its log line can
    /// give the remedy, rather than calling the key unparseable.
    #[test]
    fn scan_names_a_p256_key_with_a_31_byte_scalar() {
        let result = scan(&[attachment("id_ecdsa", &p256_key_file(&[0x11; 31]))]);
        assert!(result.found.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].reason, SkipReason::ShortEcdsaScalar);
        assert!(
            SkipReason::ShortEcdsaScalar
                .to_string()
                .contains("regenerate the key")
        );
    }

    #[test]
    fn scan_skips_dsa_as_unsupported() {
        let attachments = [attachment("dsa", DSA_1024)];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert_eq!(
            result.skipped[0].reason,
            SkipReason::UnsupportedType("ssh-dss".to_string())
        );
    }

    #[test]
    fn scan_skips_rsa_under_the_minimum_size() {
        let attachments = [attachment("small-rsa", RSA_1024)];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert_eq!(result.skipped[0].reason, SkipReason::RsaTooSmall(1024));
    }

    /// Most attachments in a vault are not SSH keys at all — unlike PEM or
    /// unparseable OpenSSH data, these are never reported.
    #[test]
    fn scan_silently_ignores_attachments_that_are_not_key_shaped() {
        let attachments = [attachment("readme", "just some file contents")];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert!(result.skipped.is_empty());
    }

    /// `sk-ssh-ed25519@openssh.com` has no private-key test vector to
    /// parse (it's hardware-backed), so this checks the classification
    /// directly rather than through `scan`.
    #[test]
    fn unsupported_rejects_sk_keys() {
        let ed25519 = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("valid test public key");
        assert_eq!(
            unsupported(Algorithm::SkEd25519, ed25519.key_data()),
            Some(SkipReason::UnsupportedType(
                "sk-ssh-ed25519@openssh.com".to_string()
            ))
        );
    }

    #[test]
    fn scan_skips_encrypted_keys() {
        let attachments = [attachment("encrypted", ED25519_ENCRYPTED)];
        let result = scan(&attachments);
        assert!(result.found.is_empty());
        assert_eq!(result.skipped[0].reason, SkipReason::Encrypted);
    }

    #[test]
    fn parse_private_key_reads_unencrypted_keys_only() {
        let key = parse_private_key(ED25519.as_bytes()).expect("unencrypted key parses");
        assert!(!key.is_encrypted());
        assert!(parse_private_key(RSA_3072.as_bytes()).is_some());
        assert!(parse_private_key(ED25519_ENCRYPTED.as_bytes()).is_none());
        assert!(parse_private_key(b"garbage").is_none());
    }

    fn test_public_key() -> PublicKey {
        PrivateKey::from_openssh(ED25519)
            .expect("plaintext test vector")
            .public_key()
            .clone()
    }

    #[test]
    fn key_name_prefers_override_then_title_then_fallback() {
        let fingerprint = test_public_key().fingerprint(HashAlg::Sha256);
        assert_eq!(
            key_name("personal", fingerprint, Some("prod-root"), Some("title")),
            "prod-root"
        );
        assert_eq!(
            key_name("personal", fingerprint, None, Some("title")),
            "title"
        );
        assert_eq!(
            key_name("personal", fingerprint, None, None),
            format!("personal {fingerprint}")
        );
    }

    #[test]
    fn resolve_drops_keys_marked_serve_false_and_applies_overrides() {
        let key = FoundKey {
            public_key: test_public_key(),
            fingerprint: test_public_key().fingerprint(HashAlg::Sha256),
            entry_uuid: Uuid::new_v4(),
            entry_title: Some("github".to_string()),
            attachment_name: "id_ed25519".to_string(),
        };
        let fingerprint = key.fingerprint;
        let database = |ssh_keys: Vec<SshKeyConfig>| DatabaseConfig {
            name: "personal".to_string(),
            path: "/v.kdbx".into(),
            keyfile: None,
            serve_ssh_keys: true,
            ssh_keys,
        };

        let served = resolve(&database(vec![]), std::slice::from_ref(&key));
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].name, "github");
        assert_eq!(served[0].database, "personal");
        assert_eq!(served[0].confirm, SshKeyConfirm::Once);
        assert!(served[0].forwarded);

        let not_served = SshKeyConfig {
            fingerprint,
            name: None,
            confirm: SshKeyConfirm::Once,
            forwarded: true,
            serve: false,
        };
        let cfg = database(vec![not_served]);
        assert!(resolve(&cfg, std::slice::from_ref(&key)).is_empty());

        let renamed = SshKeyConfig {
            fingerprint,
            name: Some("prod-root".to_string()),
            confirm: SshKeyConfirm::Always,
            forwarded: true,
            serve: true,
        };
        let cfg = database(vec![renamed]);
        let served = resolve(&cfg, std::slice::from_ref(&key));
        assert_eq!(served[0].name, "prod-root");
        assert_eq!(served[0].confirm, SshKeyConfirm::Always);
    }

    #[test]
    fn dedupe_by_config_order_keeps_the_earliest_database() {
        let public_key = test_public_key();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        let make = |database: &str| ServedKey {
            database: database.to_string(),
            public_key: public_key.clone(),
            fingerprint,
            name: database.to_string(),
            entry_uuid: Uuid::new_v4(),
            confirm: SshKeyConfirm::Once,
            forwarded: true,
        };

        let deduped = dedupe_by_config_order(vec![vec![make("personal")], vec![make("work")]]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].database, "personal");
    }

    #[test]
    fn write_cache_then_read_cache_round_trips_and_holds_no_comment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let commented = PublicKey::new(test_public_key().key_data().clone(), "has-a-comment");

        write_cache(dir.path(), "personal", std::slice::from_ref(&commented)).expect("write_cache");
        let read_back = read_cache(dir.path(), "personal");

        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].key_data(), commented.key_data());
        assert_eq!(read_back[0].comment().as_str_lossy(), "");

        let on_disk = std::fs::read_to_string(dir.path().join("personal")).expect("cache file");
        assert!(
            !on_disk.contains("has-a-comment"),
            "the cache must hold no comments: {on_disk:?}"
        );

        let mode = std::fs::metadata(dir.path().join("personal"))
            .expect("stat cache file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn the_cache_lives_under_the_cache_directory() {
        let paths = Paths {
            cache_dir: Some(PathBuf::from("/home/me/.cache")),
            ..Paths::default()
        };
        assert_eq!(
            cache_dir(&paths),
            Some(PathBuf::from("/home/me/.cache/kpa/ssh-keys"))
        );
        assert_eq!(cache_dir(&Paths::default()), None);
    }

    #[test]
    fn read_cache_is_tolerant_of_a_missing_or_garbage_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_cache(dir.path(), "nonexistent"), Vec::new());

        std::fs::write(dir.path().join("garbage"), b"not a public key\n").expect("write");
        assert_eq!(read_cache(dir.path(), "garbage"), Vec::new());
    }

    #[test]
    fn write_cache_overwrites_a_previous_version_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rsa_key = PrivateKey::from_openssh(RSA_3072)
            .expect("rsa test vector")
            .public_key()
            .clone();

        write_cache(dir.path(), "personal", &[test_public_key()]).expect("first write");
        write_cache(dir.path(), "personal", std::slice::from_ref(&rsa_key)).expect("second write");

        let read_back = read_cache(dir.path(), "personal");
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].key_data(), rsa_key.key_data());
    }
}
