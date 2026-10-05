//! The freshness fingerprint, one field at a time. Each test changes one
//! property of a temp file and checks that the guard reacts. The contents
//! are arbitrary bytes: the fingerprint is about the file, not its KDBX
//! structure. The same checks run end to end against the daemon in
//! `tests/server.rs`.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kpa::vault::{self, Fingerprint, is_unchanged};
use zeroize::Zeroizing;

mod common;

const BYTES: &[u8] = b"0123456789";

/// The fingerprint `vault::open` returns describes the file it read: it
/// matches until the file changes, and not after.
#[test]
fn open_returns_the_fingerprint_of_the_file_it_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = dir.path().join("vault.kdbx");
    std::fs::copy(common::password_db(), &copy).expect("copy fixture");
    let password = Zeroizing::new(common::PASSWORD.to_string());

    let (_db, fp) = vault::open(&copy, Some(&password), None).expect("copy should open");
    assert!(is_unchanged(&copy, &fp));

    std::fs::OpenOptions::new()
        .append(true)
        .open(&copy)
        .and_then(|mut file| std::io::Write::write_all(&mut file, b"x"))
        .expect("append to copy");
    assert!(!is_unchanged(&copy, &fp));
}

fn set_mtime(path: &Path, time: SystemTime) {
    File::options()
        .write(true)
        .open(path)
        .expect("failed to open for set_modified")
        .set_modified(time)
        .expect("failed to set mtime");
}

/// File timestamps come from a coarse kernel clock, so a change made in the
/// same tick as the previous one would not move ctime. Wait one tick.
fn tick() {
    std::thread::sleep(Duration::from_millis(20));
}

fn baseline() -> (tempfile::TempDir, PathBuf, Fingerprint, SystemTime) {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().join("vault.kdbx");
    fs::write(&path, BYTES).expect("failed to write file");
    let fp = Fingerprint::from_file(&path).expect("failed to stat file");
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    assert!(
        is_unchanged(&path, &fp),
        "a file must match its own fingerprint"
    );
    (dir, path, fp, mtime)
}

#[test]
fn size_change_is_detected() {
    let (_dir, path, fp, _) = baseline();
    fs::write(&path, b"0123456789abc").unwrap();

    let now = Fingerprint::from_file(&path).unwrap();
    assert_ne!(now.size, fp.size);
    assert!(!is_unchanged(&path, &fp));
}

#[test]
fn mtime_change_is_detected() {
    let (_dir, path, fp, mtime) = baseline();
    set_mtime(&path, mtime + Duration::from_secs(3600));

    let now = Fingerprint::from_file(&path).unwrap();
    assert_ne!(
        (now.mtime_sec, now.mtime_nsec),
        (fp.mtime_sec, fp.mtime_nsec)
    );
    assert!(!is_unchanged(&path, &fp));
}

/// Same size, same inode, and mtime restored to its exact value after a
/// content change. Only ctime moves, which is what the ctime field is for.
#[test]
fn restored_mtime_is_caught_by_ctime() {
    let (_dir, path, fp, mtime) = baseline();
    tick();
    let mut changed = BYTES.to_vec();
    *changed.last_mut().unwrap() = b'X';
    fs::write(&path, &changed).unwrap();
    tick();
    set_mtime(&path, mtime);

    let now = Fingerprint::from_file(&path).unwrap();
    assert_eq!(now.dev, fp.dev);
    assert_eq!(now.ino, fp.ino);
    assert_eq!(now.size, fp.size);
    assert_eq!(
        (now.mtime_sec, now.mtime_nsec),
        (fp.mtime_sec, fp.mtime_nsec)
    );
    assert_ne!(
        (now.ctime_sec, now.ctime_nsec),
        (fp.ctime_sec, fp.ctime_nsec),
        "ctime must move even when mtime is restored"
    );
    assert!(!is_unchanged(&path, &fp));
}

/// A replacement file with the same size and content, and the original
/// mtime restored. The old inode is held open so the new file cannot reuse
/// its number.
#[test]
fn replaced_inode_is_detected() {
    let (dir, path, fp, mtime) = baseline();
    let _old_inode_held_open = File::open(&path).unwrap();

    let replacement = dir.path().join("vault.kdbx.new");
    fs::write(&replacement, BYTES).unwrap();
    set_mtime(&replacement, mtime);
    fs::rename(&replacement, &path).unwrap();

    let now = Fingerprint::from_file(&path).unwrap();
    assert_ne!(now.ino, fp.ino);
    assert!(!is_unchanged(&path, &fp));
}

#[test]
fn a_missing_file_counts_as_changed() {
    let (_dir, path, fp, _) = baseline();
    fs::remove_file(&path).unwrap();
    assert!(!is_unchanged(&path, &fp));
}
