//! A KeePass 1.x (KDB) file builder. `keepass` reads the format but has no
//! writer for it, and kpa refuses it, so the tests that check the refusal
//! build their own: a 124-byte plain header, then the AES-256-CBC encrypted
//! payload of group and entry records.

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockCipherEncrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use sha2::{Digest, Sha256};

const MASTER_SEED: [u8; 16] = [b'S'; 16];
const IV: [u8; 16] = [b'I'; 16];
const TRANSFORM_SEED: [u8; 32] = [b'T'; 32];
const ROUNDS: u32 = 10;
const AES_FLAG: u32 = 2;

/// One KDB field: `type: u16 LE, size: u32 LE, value`.
fn field(field_type: u16, value: &[u8]) -> Vec<u8> {
    let mut out = field_type.to_le_bytes().to_vec();
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    out
}

fn group(id: u32, name: &str) -> Vec<u8> {
    let mut out = field(1, &id.to_le_bytes());
    out.extend(field(2, format!("{name}\0").as_bytes()));
    out.extend(field(8, &0u16.to_le_bytes()));
    out.extend(field(0xffff, b""));
    out
}

fn entry(tag: u8, group_id: u32, title: &str) -> Vec<u8> {
    let mut out = field(1, &[tag; 16]);
    out.extend(field(2, &group_id.to_le_bytes()));
    out.extend(field(4, format!("{title}\0").as_bytes()));
    out.extend(field(7, b"pw\0"));
    out.extend(field(0xffff, b""));
    out
}

/// A KDB file with one group and three entries, encrypted under `password`.
/// `entries_in_header` is the entry count the unauthenticated header
/// claims: `3` is the file as written, a lower number is the file after
/// someone edited that one field.
pub fn kdb_with_three_entries(password: &str, entries_in_header: u32) -> Vec<u8> {
    let mut payload = group(1, "Web");
    payload.extend(entry(1, 1, "First"));
    payload.extend(entry(2, 1, "Second"));
    payload.extend(entry(3, 1, "Third"));

    // Composite key: SHA-256 of the password. Transform: AES-ECB with the
    // transform seed as key, `ROUNDS` times over each half, then SHA-256.
    let composite = Sha256::digest(password.as_bytes());
    let cipher = Aes256::new(&TRANSFORM_SEED.into());
    let mut halves = [[0u8; 16]; 2];
    halves[0].copy_from_slice(&composite[..16]);
    halves[1].copy_from_slice(&composite[16..]);
    for _ in 0..ROUNDS {
        for half in &mut halves {
            cipher.encrypt_block(half.into());
        }
    }
    let transformed = Sha256::digest([halves[0], halves[1]].concat());
    let master_key = Sha256::digest([&MASTER_SEED[..], &transformed[..]].concat());

    let encrypted = cbc::Encryptor::<Aes256>::new(&master_key, &IV.into())
        .encrypt_padded_vec::<Pkcs7>(&payload);

    let mut file = vec![0x03, 0xd9, 0xa2, 0x9a];
    file.extend_from_slice(&0xb54b_fb65u32.to_le_bytes());
    file.extend_from_slice(&AES_FLAG.to_le_bytes());
    file.extend_from_slice(&0x0003_0002u32.to_le_bytes());
    file.extend_from_slice(&MASTER_SEED);
    file.extend_from_slice(&IV);
    file.extend_from_slice(&1u32.to_le_bytes());
    file.extend_from_slice(&entries_in_header.to_le_bytes());
    file.extend_from_slice(&Sha256::digest(&payload));
    file.extend_from_slice(&TRANSFORM_SEED);
    file.extend_from_slice(&ROUNDS.to_le_bytes());
    file.extend_from_slice(&encrypted);
    file
}
