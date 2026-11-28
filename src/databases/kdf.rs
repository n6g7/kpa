//! The key-derivation settings a vault's header asks for, checked against
//! ceilings before any key derivation runs.
//!
//! The settings sit in the outer header, which whoever can write the file
//! controls (ACT-3): nothing authenticates them until the KDF has run (KDBX3
//! never does, KDBX4's HMAC needs its output). `keepass` runs the KDF on
//! whatever they say, so a crafted header can make it allocate more than
//! the machine has, which aborts the process and every database it holds
//! unlocked, or spin for hours in a thread that can't be cancelled while the
//! database's unlock claim stays taken.
//!
//! This reads the same header fields `keepass` does, by the same rules, so
//! the values checked are the ones it would run. Anything it can't read it
//! lets pass: `keepass` fails on the same bytes, and does so while it parses
//! the header, before it derives anything.

use std::collections::HashMap;

use keepass::config::DatabaseVersion;

/// Most AES-KDF rounds a header may ask for. Real vaults set the rounds so
/// that an unlock takes about a second (a few million to a few tens of
/// millions on current hardware), and some set it to ten; this is a thousand
/// times the first.
const MAX_AES_ROUNDS: u64 = 1 << 30;

/// Most memory Argon2 may be asked for, in bytes. A vault that needs more
/// is for a machine with more than this to spare, and an allocation that
/// fails aborts the daemon.
const MAX_ARGON2_MEMORY: u64 = 1 << 30;

/// Most lanes (parallelism) Argon2 may be asked for. Each runs on a thread
/// of its own.
const MAX_ARGON2_PARALLELISM: u32 = 256;

/// Most Argon2 work, in bytes of memory processed: the memory times the
/// iterations, since every iteration passes over all of it. The time is
/// proportional to this, so it bounds how long an unlock can keep its core
/// and its claim (roughly a second per GiB and lane).
const MAX_ARGON2_WORK: u64 = 32 << 30;

/// Which ceiling a header is above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceiling {
    AesRounds,
    Argon2Memory,
    Argon2Parallelism,
    Argon2Work,
}

impl std::fmt::Display for Ceiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ceiling::AesRounds => write!(f, "more than {MAX_AES_ROUNDS} AES rounds"),
            Ceiling::Argon2Memory => {
                write!(
                    f,
                    "more than {} MiB of Argon2 memory",
                    MAX_ARGON2_MEMORY >> 20
                )
            }
            Ceiling::Argon2Parallelism => {
                write!(f, "more than {MAX_ARGON2_PARALLELISM} Argon2 lanes")
            }
            Ceiling::Argon2Work => write!(
                f,
                "more than {} GiB of Argon2 memory passes (memory times iterations)",
                MAX_ARGON2_WORK >> 30
            ),
        }
    }
}

/// Fails if the header of `data`, a vault of `version`, asks for key
/// derivation above a ceiling.
pub(super) fn check(data: &[u8], version: &DatabaseVersion) -> Result<(), Ceiling> {
    match version {
        DatabaseVersion::KDB3(_) => {
            for (kind, value) in header_entries(data, 2) {
                if kind == KDBX3_TRANSFORM_ROUNDS {
                    check_aes_rounds(le_u64(value))?;
                }
            }
        }
        DatabaseVersion::KDB4(_) => {
            for (kind, value) in header_entries(data, 4) {
                if kind == KDBX4_KDF_PARAMETERS {
                    check_dictionary(value)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

const KDBX3_TRANSFORM_ROUNDS: u8 = 6;
const KDBX4_KDF_PARAMETERS: u8 = 11;

/// The version header's length: the identifier, the version, the minor and
/// the major version.
const VERSION_HEADER_LEN: usize = 12;

const KDF_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];
const KDF_AES_KDBX3: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const KDF_AES_KDBX4: [u8; 16] = [
    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38,
];

/// The outer header's entries after the version header, as
/// `(type, bytes)`: each is a type byte, a little-endian length of
/// `length_size` bytes, then that many bytes, up to and including the end
/// entry (type 0). It stops where the header does, or where it is cut off.
fn header_entries(data: &[u8], length_size: usize) -> Vec<(u8, &[u8])> {
    let mut entries = Vec::new();
    let mut pos = VERSION_HEADER_LEN;
    while let Some(&kind) = data.get(pos) {
        let Some(length) = data.get(pos + 1..pos + 1 + length_size) else {
            break;
        };
        let length = length
            .iter()
            .rev()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        let start = pos + 1 + length_size;
        let Some(value) = start
            .checked_add(length)
            .and_then(|end| data.get(start..end))
        else {
            break;
        };
        entries.push((kind, value));
        pos = start + length;
        if kind == 0 {
            break;
        }
    }
    entries
}

fn le_u64(value: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(value.get(..8)?.try_into().ok()?))
}

fn le_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(value.get(..4)?.try_into().ok()?))
}

fn check_aes_rounds(rounds: Option<u64>) -> Result<(), Ceiling> {
    match rounds {
        Some(rounds) if rounds > MAX_AES_ROUNDS => Err(Ceiling::AesRounds),
        _ => Ok(()),
    }
}

/// A KDBX4 KDF parameter dictionary: a version, then entries of a value
/// type byte, a key and a value (each with a 32-bit length), and a final
/// zero type byte. A key given twice keeps its last value.
fn check_dictionary(buffer: &[u8]) -> Result<(), Ceiling> {
    const U32: u8 = 0x04;
    const U64: u8 = 0x05;
    const BYTES: u8 = 0x42;

    let Some(entries) = dictionary(buffer) else {
        return Ok(());
    };
    let typed = |key: &str, kind: u8| {
        entries
            .get(key)
            .filter(|(found, _)| *found == kind)
            .map(|(_, value)| *value)
    };

    let Some(id) = typed("$UUID", BYTES) else {
        return Ok(());
    };
    if id == KDF_AES_KDBX3 || id == KDF_AES_KDBX4 {
        check_aes_rounds(typed("R", U64).and_then(le_u64))
    } else if id == KDF_ARGON2D || id == KDF_ARGON2ID {
        let memory = typed("M", U64).and_then(le_u64);
        let iterations = typed("I", U64).and_then(le_u64);
        let lanes = typed("P", U32).and_then(le_u32);
        if memory.is_some_and(|memory| memory > MAX_ARGON2_MEMORY) {
            return Err(Ceiling::Argon2Memory);
        }
        if lanes.is_some_and(|lanes| lanes > MAX_ARGON2_PARALLELISM) {
            return Err(Ceiling::Argon2Parallelism);
        }
        match (memory, iterations) {
            (Some(memory), Some(iterations))
                if memory.saturating_mul(iterations) > MAX_ARGON2_WORK =>
            {
                Err(Ceiling::Argon2Work)
            }
            _ => Ok(()),
        }
    } else {
        Ok(())
    }
}

/// The entries of a variant dictionary, read as `keepass` reads them, as
/// `key -> (value type, value bytes)`. `None` where it can't be read.
fn dictionary(buffer: &[u8]) -> Option<HashMap<String, (u8, &[u8])>> {
    const VERSION: u16 = 0x100;
    const KNOWN_TYPES: [u8; 7] = [0x04, 0x05, 0x08, 0x0c, 0x0d, 0x18, 0x42];

    if u16::from_le_bytes(buffer.get(..2)?.try_into().ok()?) != VERSION {
        return None;
    }
    let mut entries = HashMap::new();
    let mut pos = 2usize;
    while pos + 9 < buffer.len() {
        let kind = buffer[pos];
        pos += 1;
        let key_length = le_u32(buffer.get(pos..)?)? as usize;
        pos += 4;
        let key = buffer.get(pos..pos.checked_add(key_length)?)?;
        pos += key_length;
        let value_length = le_u32(buffer.get(pos..)?)? as usize;
        pos += 4;
        let value = buffer.get(pos..pos.checked_add(value_length)?)?;
        pos += value_length;
        if !KNOWN_TYPES.contains(&kind) {
            return None;
        }
        entries.insert(String::from_utf8_lossy(key).to_string(), (kind, value));
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION_HEADER_3: [u8; 12] = [3, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0, 0, 3, 0];
    const VERSION_HEADER_4: [u8; 12] = [3, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0];

    fn kdbx3(rounds: u64) -> Vec<u8> {
        let mut data = VERSION_HEADER_3.to_vec();
        data.extend([6, 8, 0]);
        data.extend(rounds.to_le_bytes());
        data.extend([0, 0, 0]);
        data
    }

    fn entry(kind: u8, key: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend((key.len() as u32).to_le_bytes());
        out.extend(key.as_bytes());
        out.extend((value.len() as u32).to_le_bytes());
        out.extend(value);
        out
    }

    fn kdbx4(parameters: &[Vec<u8>]) -> Vec<u8> {
        let mut dictionary = 0x100u16.to_le_bytes().to_vec();
        for parameter in parameters {
            dictionary.extend(parameter);
        }
        dictionary.push(0);
        let mut data = VERSION_HEADER_4.to_vec();
        data.push(11);
        data.extend((dictionary.len() as u32).to_le_bytes());
        data.extend(dictionary);
        data.extend([0, 0, 0, 0, 0]);
        data
    }

    fn argon2(memory: u64, iterations: u64, lanes: u32) -> Vec<u8> {
        kdbx4(&[
            entry(0x42, "$UUID", &KDF_ARGON2D),
            entry(0x05, "M", &memory.to_le_bytes()),
            entry(0x05, "I", &iterations.to_le_bytes()),
            entry(0x04, "P", &lanes.to_le_bytes()),
            entry(0x04, "V", &0x13u32.to_le_bytes()),
        ])
    }

    fn aes4(rounds: u64) -> Vec<u8> {
        kdbx4(&[
            entry(0x42, "$UUID", &KDF_AES_KDBX4),
            entry(0x05, "R", &rounds.to_le_bytes()),
        ])
    }

    fn check3(data: &[u8]) -> Result<(), Ceiling> {
        check(data, &DatabaseVersion::KDB3(0))
    }

    fn check4(data: &[u8]) -> Result<(), Ceiling> {
        check(data, &DatabaseVersion::KDB4(1))
    }

    #[test]
    fn aes_rounds_are_capped() {
        assert_eq!(check3(&kdbx3(1_000_000)), Ok(()));
        assert_eq!(check3(&kdbx3(MAX_AES_ROUNDS)), Ok(()));
        assert_eq!(check3(&kdbx3(MAX_AES_ROUNDS + 1)), Err(Ceiling::AesRounds));
        assert_eq!(check3(&kdbx3(u64::MAX)), Err(Ceiling::AesRounds));

        assert_eq!(check4(&aes4(MAX_AES_ROUNDS)), Ok(()));
        assert_eq!(check4(&aes4(u64::MAX)), Err(Ceiling::AesRounds));
    }

    #[test]
    fn argon2_memory_lanes_and_work_are_capped() {
        assert_eq!(check4(&argon2(64 << 20, 14, 2)), Ok(()));
        assert_eq!(check4(&argon2(MAX_ARGON2_MEMORY, 1, 1)), Ok(()));
        assert_eq!(check4(&argon2(1 << 40, 1, 1)), Err(Ceiling::Argon2Memory));
        assert_eq!(
            check4(&argon2(MAX_ARGON2_MEMORY + 1, 1, 1)),
            Err(Ceiling::Argon2Memory)
        );
        assert_eq!(
            check4(&argon2(1 << 20, 1, MAX_ARGON2_PARALLELISM + 1)),
            Err(Ceiling::Argon2Parallelism)
        );
        assert_eq!(
            check4(&argon2(1 << 20, 1, 1 << 24)),
            Err(Ceiling::Argon2Parallelism)
        );
        assert_eq!(
            check4(&argon2(64 << 20, u64::from(u32::MAX), 2)),
            Err(Ceiling::Argon2Work)
        );
        assert_eq!(
            check4(&argon2(1 << 20, u64::MAX, 2)),
            Err(Ceiling::Argon2Work)
        );
        // A small memory with many iterations is as long as a large one with
        // few: the work is what is capped.
        assert_eq!(check4(&argon2(1 << 20, 1000, 4)), Ok(()));
        assert_eq!(
            check4(&argon2(1 << 20, (MAX_ARGON2_WORK >> 20) + 1, 4)),
            Err(Ceiling::Argon2Work)
        );
    }

    /// What can't be read is left to `keepass`, which fails on it before it
    /// derives a key: nothing here refuses or panics.
    #[test]
    fn a_header_that_cannot_be_read_passes() {
        let whole = argon2(1 << 40, 1, 1);
        for len in 0..whole.len() {
            let _ = check4(&whole[..len]);
        }
        assert_eq!(
            check4(&whole[..whole.len() - 5]),
            Err(Ceiling::Argon2Memory)
        );
        assert_eq!(check4(&[]), Ok(()));
        assert_eq!(check3(&[1, 2, 3]), Ok(()));
        assert_eq!(check3(&kdbx3(u64::MAX)[..14]), Ok(()));
        // A wrong value type is `keepass`'s to refuse.
        let wrong_type = kdbx4(&[
            entry(0x42, "$UUID", &KDF_ARGON2D),
            entry(0x04, "M", &u32::MAX.to_le_bytes()),
        ]);
        assert_eq!(check4(&wrong_type), Ok(()));
    }

    /// The last of a key given twice is the one `keepass` keeps, and the one
    /// checked.
    #[test]
    fn a_repeated_key_is_checked_by_its_last_value() {
        let data = kdbx4(&[
            entry(0x42, "$UUID", &KDF_AES_KDBX4),
            entry(0x05, "R", &u64::MAX.to_le_bytes()),
            entry(0x05, "R", &1u64.to_le_bytes()),
        ]);
        assert_eq!(check4(&data), Ok(()));
        let data = kdbx4(&[
            entry(0x42, "$UUID", &KDF_AES_KDBX4),
            entry(0x05, "R", &1u64.to_le_bytes()),
            entry(0x05, "R", &u64::MAX.to_le_bytes()),
        ]);
        assert_eq!(check4(&data), Err(Ceiling::AesRounds));
    }
}
