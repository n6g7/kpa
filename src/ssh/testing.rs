//! Test helpers shared by the unit tests of this subsystem and of the front
//! ends that use it: throwaway keys, and databases and configs that serve
//! keys.

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Fingerprint, LineEnding, PrivateKey};

use crate::config::{DatabaseConfig, SshKeyConfig};
use crate::databases::testing::TestEntry;
use crate::ssh::approvals::{RequestDetails, Scope, SignatureApproval};
use crate::ssh::keys::{self, ServedKey};

/// A deterministic, non-cryptographic stand-in for `OsRng`: these tests
/// only need *a* valid keypair, the same one for the same seed.
struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl ssh_key::rand_core::TryRng for TestRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

impl ssh_key::rand_core::TryCryptoRng for TestRng {}

/// An Ed25519 key, the same for the same `seed`.
pub(crate) fn test_key(seed: u64) -> PrivateKey {
    PrivateKey::random(&mut TestRng(seed), Algorithm::Ed25519).expect("key generation")
}

/// An entry titled `title` holding `key` as an OpenSSH attachment, the way a
/// KeePass client stores one.
pub(crate) fn key_entry(title: &str, key: &PrivateKey) -> TestEntry {
    let pem = key.to_openssh(LineEnding::LF).expect("key encodes");
    TestEntry::new(title).attachment("id_ed25519", pem.as_bytes().to_vec())
}

/// A `serve_ssh_keys` database named `name`, with `ssh_keys` as its
/// `[[database.ssh_key]]` overrides.
pub(crate) fn database(name: &str, ssh_keys: Vec<SshKeyConfig>) -> DatabaseConfig {
    DatabaseConfig {
        name: name.to_string(),
        path: format!("/{name}.kdbx").into(),
        keyfile: None,
        serve_ssh_keys: true,
        ssh_keys,
    }
}

/// `ssh-key`'s own test vector (`tests/examples/id_rsa_3072`): unencrypted
/// RSA, 3072 bits. A fixed one, since generating an RSA key in a test is
/// slow.
pub(crate) const RSA_3072: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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

pub(crate) fn fingerprint(seed: u64) -> Fingerprint {
    test_key(seed)
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
}

pub(crate) fn host_key(seed: u64) -> KeyData {
    test_key(seed).public_key().key_data().clone()
}

pub(crate) fn approval(key: u64, destination: Option<u64>, remember: bool) -> SignatureApproval {
    SignatureApproval {
        scope: Scope::new(fingerprint(key), destination.map(host_key).as_ref()),
        remember,
    }
}

/// The key `approval(1, ..)` is for, as an open database serves it.
pub(crate) fn key() -> ServedKey {
    let cfg = database("personal", vec![]);
    keys::resolve_cached(&cfg, vec![test_key(1).public_key().clone()]).remove(0)
}

pub(crate) fn requested(command: &str) -> RequestDetails {
    RequestDetails {
        purpose: "login",
        user: Some("alice".to_string()),
        namespace: None,
        class: "local",
        command: Some(command.to_string()),
    }
}
