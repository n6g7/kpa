//! Tests for `bind_socket`, kept out of the library's unit tests on purpose.
//!
//! `bind_socket` changes the process umask while it binds, and the umask is
//! shared by every thread. Inside this test binary, every test takes `SERIAL`
//! for its whole body, so no two of them ever run at once. Cargo runs test
//! binaries one after another, so nothing else in another binary overlaps
//! either.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;

use kpa::server::bind_socket;
use rustix::fs::Mode;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn set_umask(mask: u32) -> Mode {
    rustix::process::umask(Mode::from_raw_mode(mask))
}

fn current_umask() -> u32 {
    let mask = set_umask(0o022);
    set_umask(mask.as_raw_mode());
    mask.as_raw_mode()
}

/// Restores a umask saved earlier when dropped, so a failing assertion can't
/// leave later tests under a wide-open umask.
struct UmaskRestore(Mode);

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

fn mode_of(path: &std::path::Path) -> u32 {
    fs::symlink_metadata(path).expect("stat").mode() & 0o777
}

#[test]
fn bind_refuses_to_replace_a_regular_file() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sock");
    fs::write(&path, "precious").expect("write");

    assert!(bind_socket(&path).is_err());
    assert_eq!(fs::read_to_string(&path).expect("read"), "precious");
}

#[test]
fn bind_leaves_an_existing_parent_directory_alone() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");

    let _listener = bind_socket(&dir.path().join("sock")).expect("bind");

    assert_eq!(mode_of(dir.path()), 0o755);
}

#[test]
fn bind_creates_a_missing_parent_private() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("kpa");

    let _listener = bind_socket(&parent.join("sock")).expect("bind");

    assert_eq!(mode_of(&parent), 0o700);
}

#[test]
fn bind_replaces_a_stale_socket() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sock");
    drop(UnixListener::bind(&path).expect("first bind"));

    if let Err(err) = bind_socket(&path) {
        panic!("bind_socket failed: {err:?}");
    }
}

#[test]
fn bind_refuses_a_parent_others_can_write_to() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).expect("chmod");

    assert!(bind_socket(&dir.path().join("sock")).is_err());
}

#[test]
fn bind_refuses_a_parent_that_is_a_symlink() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real");
    fs::create_dir(&real).expect("mkdir");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert!(bind_socket(&link.join("sock")).is_err());
}

#[test]
fn bind_restores_the_umask_on_success_and_on_error() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let _restore = UmaskRestore(set_umask(0o022));

    let _listener = bind_socket(&dir.path().join("sock")).expect("bind");
    assert_eq!(current_umask(), 0o022, "umask after a successful bind");

    fs::write(dir.path().join("plain"), "x").expect("write");
    assert!(bind_socket(&dir.path().join("plain")).is_err());
    assert_eq!(current_umask(), 0o022, "umask after a failed bind");
}

/// Reproduces the window: with the umask at its widest, the socket must never
/// be visible with any group or other bits, not even between `bind` and the
/// explicit `chmod`. The watcher samples the path as tightly as it can while
/// `bind_socket` runs.
#[test]
fn socket_is_never_visible_with_wider_than_owner_mode() {
    let _serial = serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let _restore = UmaskRestore(set_umask(0));

    for trial in 0..200 {
        let path = dir.path().join(format!("sock{trial}"));
        let stop = AtomicBool::new(false);
        let modes = thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                let mut seen = std::collections::BTreeSet::new();
                while !stop.load(Ordering::SeqCst) {
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        seen.insert(meta.mode() & 0o777);
                    }
                }
                seen
            });
            let _listener = bind_socket(&path).expect("bind");
            stop.store(true, Ordering::SeqCst);
            watcher.join().expect("watcher")
        });
        assert!(
            modes.iter().all(|mode| mode & 0o077 == 0),
            "trial {trial}: socket visible with modes {modes:?}"
        );
    }
}
