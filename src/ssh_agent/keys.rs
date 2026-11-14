//! Which SSH keys kpa serves (`docs/ssh-agent.md` § 6.4): scanning a
//! database's current-entry attachments for OpenSSH private keys, applying
//! config overrides, naming, and the public-key cache that lists a locked
//! database's keys.
//!
//! Pure: nothing here touches a mutex or an epoch. `serve.rs` calls `scan`
//! on unlock and `decrypt` at first signature, under its own locking.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, Fingerprint, HashAlg, PrivateKey, PublicKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::SshKeyConfig;
use crate::paths::Paths;
use crate::vault::EntryAttachment;

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
/// attachments: its public half only, read from the attachment's
/// unencrypted header. `decrypt` reads the private half later, lazily, and
/// only once the key is actually used.
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

/// Scans `attachments` — meant to be `vault::list_attachments`'s output for
/// one database — for OpenSSH private keys, per `docs/ssh-agent.md` § 6.4:
/// an attachment that doesn't start with either the OpenSSH or a PEM marker
/// isn't a key at all and is silently ignored, rather than reported
/// skipped — most attachments in a vault are not SSH keys.
pub fn scan(attachments: &[EntryAttachment]) -> ScanResult {
    let mut result = ScanResult::default();
    for attachment in attachments {
        classify(attachment, &mut result);
    }
    result
}

fn classify(attachment: &EntryAttachment, result: &mut ScanResult) {
    let data = &attachment.data;
    if !data.starts_with(OPENSSH_MARKER) {
        if PEM_MARKERS.iter().any(|marker| data.starts_with(marker)) {
            result.skipped.push(skipped(attachment, SkipReason::Pem));
        }
        return;
    }

    let private_key = match PrivateKey::from_openssh(data) {
        Ok(key) => key,
        Err(_) => {
            result
                .skipped
                .push(skipped(attachment, SkipReason::Unparseable));
            return;
        }
    };

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
        entry_title: attachment.entry_title.clone(),
        attachment_name: attachment.attachment_name.clone(),
    });
}

fn skipped(attachment: &EntryAttachment, reason: SkipReason) -> SkippedAttachment {
    SkippedAttachment {
        entry_uuid: attachment.entry_uuid,
        entry_title: attachment.entry_title.clone(),
        attachment_name: attachment.attachment_name.clone(),
        reason,
    }
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

/// A key kpa serves: survived its database's `serve = false` overrides, and
/// named per config.
#[derive(Debug, Clone)]
pub struct ServedKey {
    pub database: String,
    pub public_key: PublicKey,
    pub fingerprint: Fingerprint,
    pub name: String,
    pub entry_uuid: Uuid,
}

/// Resolves which of a database's found keys get served, applying its own
/// `[[database.ssh_key]]` overrides (matched by fingerprint): drops
/// anything a `serve = false` override names, and names the rest with
/// [`key_name`].
pub fn resolve(database: &str, found: &[FoundKey], overrides: &[SshKeyConfig]) -> Vec<ServedKey> {
    found
        .iter()
        .filter_map(|key| {
            let fingerprint = key.fingerprint.to_string();
            let over = overrides.iter().find(|o| o.fingerprint == fingerprint);
            if over.is_some_and(|o| !o.serve) {
                return None;
            }
            Some(ServedKey {
                database: database.to_string(),
                public_key: key.public_key.clone(),
                fingerprint: key.fingerprint,
                name: key_name(
                    database,
                    key.fingerprint,
                    over.and_then(|o| o.name.as_deref()),
                    key.entry_title.as_deref(),
                ),
                entry_uuid: key.entry_uuid,
            })
        })
        .collect()
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

/// A private key decrypted from an attachment's bytes. Dropping it zeroizes
/// the key material: `ssh_key`'s own leaf private-key types zeroize on
/// drop, and this holds nothing beyond the `PrivateKey` itself.
#[derive(Debug)]
pub struct DecryptedKey(PrivateKey);

impl DecryptedKey {
    pub fn private_key(&self) -> &PrivateKey {
        &self.0
    }
}

/// Why `decrypt` failed.
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("not a valid OpenSSH private key")]
    Parse(#[source] ssh_key::Error),
    #[error("wrong passphrase, or the key is corrupt")]
    WrongPassphrase,
}

/// Decrypts an OpenSSH private-key attachment with `passphrase` — the
/// entry's Password field, the convention KeePass clients already use
/// (`docs/ssh-agent.md` § 6.4). A key that isn't encrypted ignores
/// `passphrase` and succeeds regardless of it. Pure, and potentially slow
/// (bcrypt-pbkdf): `serve.rs` runs this outside the vault mutex, under the
/// same epoch check as unlock.
pub fn decrypt(
    attachment: &[u8],
    passphrase: &Zeroizing<String>,
) -> Result<DecryptedKey, DecryptError> {
    let key = PrivateKey::from_openssh(attachment).map_err(DecryptError::Parse)?;
    if !key.is_encrypted() {
        return Ok(DecryptedKey(key));
    }
    let decrypted = key
        .decrypt(passphrase.as_bytes())
        .map_err(|_| DecryptError::WrongPassphrase)?;
    Ok(DecryptedKey(decrypted))
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
    use zeroize::Zeroizing;

    use super::*;
    use crate::config::{SshKeyConfig, SshKeyConfirm};
    use crate::vault::EntryAttachment;

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

    /// Same key as `ED25519`, encrypted under aes256-ctr with the
    /// passphrase `hunter42` (`ssh-key`'s own
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
    const ED25519_ENCRYPTED_PASSPHRASE: &str = "hunter42";

    /// `ssh-key`'s own test vector (`tests/examples/id_rsa_3072`):
    /// unencrypted RSA, 3072 bits.
    const RSA_3072: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApo5HjJvJNyZDa39enm+aRuG3O+wejLd1TeLGpbbEVfLwEqclmvz5
QYHWnpXTmjSeTStIKlNysolDcx23XHPOe9nuyFAQyUv65WlgEYki+GqLNlWzV9JOemec2K
fZv26uZvf5pW/j0JDQYyIYpoKWDYqtk8AYmHgOrS2+/XD7RwNHF+QS5P2uaFKS7IkeJCP3
/kPfL1QymrCl11YeWC5C6G667gwenq9gPXznCFBdDuCQkS4fw3NetYBN30K2EzEHp26aWc
38a2X0PGMCz7yo56pvl0V/qW07Wibo9BIE0s1CvhGcaEsPAjcImaca48HnEzFUPMP7K0Jo
eAARrk6pNMD/B3CO4YPn6Qb+5Ino4eV/znocbfj7rvObvRlV29WtGr/74Sb1AgXLiErwgP
89cFSdMXS4W9f2Ykw3U88jW2UNDkIo8yvntUpZDYaft3hlWbt6TWb506acCF798IOpFdR6
HZFhoIdWsmOwbnOdmfKJA2KryWreQszo+TmkDa/5AAAFiD9lruM/Za7jAAAAB3NzaC1yc2
EAAAGBAKaOR4ybyTcmQ2t/Xp5vmkbhtzvsHoy3dU3ixqW2xFXy8BKnJZr8+UGB1p6V05o0
nk0rSCpTcrKJQ3Mdt1xzznvZ7shQEMlL+uVpYBGJIvhqizZVs1fSTnpnnNin2b9urmb3+a
Vv49CQ0GMiGKaClg2KrZPAGJh4Dq0tvv1w+0cDRxfkEuT9rmhSkuyJHiQj9/5D3y9UMpqw
pddWHlguQuhuuu4MHp6vYD185whQXQ7gkJEuH8NzXrWATd9CthMxB6dumlnN/Gtl9DxjAs
+8qOeqb5dFf6ltO1om6PQSBNLNQr4RnGhLDwI3CJmnGuPB5xMxVDzD+ytCaHgAEa5OqTTA
/wdwjuGD5+kG/uSJ6OHlf856HG34+67zm70ZVdvVrRq/++Em9QIFy4hK8ID/PXBUnTF0uF
vX9mJMN1PPI1tlDQ5CKPMr57VKWQ2Gn7d4ZVm7ek1m+dOmnAhe/fCDqRXUeh2RYaCHVrJj
sG5znZnyiQNiq8lq3kLM6Pk5pA2v+QAAAAMBAAEAAAGAa2MLEMaVCsDZ8WJzEDYmw5LewH
zyCYpz0J7ps4jOuBfl4DDy1yZKU4kyZpd1klRgyKKiad/Z8PD9kyhSxAJK3KHcCj1NRWx+
vRGfBk9kQ8T2Mzc4ZeRMAzHw9+PpSjtDqVIzHQ6yVRQ5t+ERAbLqqpqCZeQSN6QY2mHHZc
NF0Dh1yxqbcBd8Lvkmj+msjGLAj6kVKn/gDMrecqOs9vAE5bYXQkqAJ5ItvBdfIoYmKeRy
cZjKlAs7wkySaOOrX15ZZbg4fhRwZ5s+poCWX4FZPLFBMQ1MQVaeJbN2otxO2S+RSbdelw
6CJHMJRswg81H4EVsbv8uzj2vQbGIEcrdtZB01gCre8VIgq5sqV+NZGP4n4TgRnMpWqYzP
PA/Gg6GfJyGodm7N2cV2d2YmVvPT4FMl8/s3MmYj277GOz2YSDCy3Se+u2vS7VNF3/8Y3x
gGrevO2phFgElokwaBrD5SMTjFIWyxNZl+PhQ6eBasw9h0HqzsfhX1PaDwgQaRcI2dAAAA
wFRAWqZjrp4IADWnEAL0w1HX0ALDUgByXm3A/22QGjBLEDouoBZQeZbTGTWLW+pP60CY9T
BSjxK5jFDH3fyF/Er5JXuvmqcjXN9GdzSbd+UqQKXi9EEi0YzkCUGRTpkWnEi3CImNKYaW
VmB7fi62NUHgu9Vo5Pd0vsMTfQKlkcjHey4Yjdb3Lu9c/xknzeVzpMoNQ8K2xqlXIURRIu
HPaqXwW2XLnIYST595+inwXj8G87g+3KmUH1cWUOD7RoquTAAAAMEA0R564khkDTsgKTaR
iGVEzf4HeamqtWyPlia/HmZIv9mIvbCsfRGnPjQFYzbUrTkA/3GE7kBLhLrrEaKjAvmC2U
7vt1cDDsbXfZEV6u+Aq1dJoPW1kLKZ/96U+ZMN7bqyrzMwlbCKUEubMPERLc5R837QDQQz
Q9Qg0uL7iL1/iBt8iZDki5P9HShPzIwcB/vvwE0CklsvFZqan1Zwc+HJT9xuRy9IljvhbF
xUU4Vq0r95FuQsNudaUBiRDY2tA41zAAAAwQDL5Q5+zfXiyG52ypS+iwwFsJBB0rzd7rRn
LnEg6syDgOXWt3yFWDxQj47o1VfKvLbfroxyOF8PaTRevBWl3+yUnAdw0C15Rd01klYtpz
iGYuBTxUVNJpDeKmPMVV4aAQ4toK4wfRwR+FKpx1aOAvk9SbKo+Se3mUOykgytMhqiCEEJ
0TbQhcHQXDn0w2z4n9w8ZqdV5j9EbhYwKxNZlADwqDMhoua5FT3wLwPeMY6gkDkoKFPyAR
4JBdEVdmfK8eMAAAAQdXNlckBleGFtcGxlLmNvbQECAw==
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

    fn attachment(name: &str, data: &str) -> EntryAttachment {
        EntryAttachment {
            entry_uuid: Uuid::new_v4(),
            entry_title: Some(name.to_string()),
            attachment_name: format!("{name}.key"),
            data: data.as_bytes().to_vec(),
        }
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
    fn decrypt_passes_through_an_unencrypted_key() {
        let passphrase = Zeroizing::new("irrelevant".to_string());
        let decrypted = decrypt(ED25519.as_bytes(), &passphrase).expect("unencrypted key decrypts");
        assert!(!decrypted.private_key().is_encrypted());
    }

    #[test]
    fn decrypt_opens_an_encrypted_key_with_its_passphrase() {
        let passphrase = Zeroizing::new(ED25519_ENCRYPTED_PASSPHRASE.to_string());
        let decrypted = decrypt(ED25519_ENCRYPTED.as_bytes(), &passphrase)
            .expect("the right passphrase should decrypt it");
        assert!(!decrypted.private_key().is_encrypted());
        assert_eq!(
            decrypted.private_key().public_key(),
            PrivateKey::from_openssh(ED25519)
                .expect("plaintext test vector")
                .public_key()
        );
    }

    #[test]
    fn decrypt_fails_with_the_wrong_passphrase() {
        let passphrase = Zeroizing::new("definitely not it".to_string());
        match decrypt(ED25519_ENCRYPTED.as_bytes(), &passphrase) {
            Err(DecryptError::WrongPassphrase) => {}
            other => panic!("expected WrongPassphrase, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_also_works_for_rsa() {
        let passphrase = Zeroizing::new("irrelevant".to_string());
        let decrypted = decrypt(RSA_3072.as_bytes(), &passphrase).expect("unencrypted RSA key");
        assert_eq!(
            decrypted.private_key().algorithm(),
            Algorithm::Rsa { hash: None }
        );
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
        let fingerprint = key.fingerprint.to_string();

        let served = resolve("personal", std::slice::from_ref(&key), &[]);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].name, "github");
        assert_eq!(served[0].database, "personal");

        let not_served = SshKeyConfig {
            fingerprint: fingerprint.clone(),
            name: None,
            confirm: SshKeyConfirm::Once,
            forwarded: true,
            serve: false,
        };
        assert!(resolve("personal", std::slice::from_ref(&key), &[not_served]).is_empty());

        let renamed = SshKeyConfig {
            fingerprint,
            name: Some("prod-root".to_string()),
            confirm: SshKeyConfirm::Always,
            forwarded: true,
            serve: true,
        };
        let served = resolve("personal", std::slice::from_ref(&key), &[renamed]);
        assert_eq!(served[0].name, "prod-root");
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
