//! Filesystem and socket helpers for the daemon's Unix socket: the
//! process-wide umask guard, the owner-only bind, the socket directory
//! check. Split out of `server` so that
//! everything that touches permissions lives in one place.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rustix::fs::Mode;

/// The umask is process-wide. Every change goes through this lock, so two
/// threads that overlap can't restore each other's values in the wrong order.
static UMASK_LOCK: Mutex<()> = Mutex::new(());

fn lock_umask() -> MutexGuard<'static, ()> {
    UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sets the process umask, and puts the previous one back when dropped, so
/// the restore happens on every path out of the scope, errors included.
struct UmaskGuard {
    previous: Mode,
    _lock: MutexGuard<'static, ()>,
}

impl UmaskGuard {
    fn set(mask: u32) -> UmaskGuard {
        let lock = lock_umask();
        let previous = rustix::process::umask(Mode::from_raw_mode(mask));
        UmaskGuard {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.previous);
    }
}

/// Check that `dir` is a directory this user owns and that nobody else
/// can write to; create it with mode `0700` if it is missing. Anything else
/// — a symlink, a file, a directory another user controls or one that
/// group or others can write to — is an error and is left untouched.
fn ensure_socket_dir(dir: &Path) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            // The mode above is masked by the umask; set it outright.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let owner = crate::authn::process_uid();
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a directory owned by you, not a symlink, and not writable by others",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Bind `path` so that only its owner can ever connect to it. The socket is
/// created under umask `0177`, so it is never connectable by anyone else,
/// not even for the moment before the explicit `chmod` that backs it up.
fn bind_owner_only(path: &Path) -> std::io::Result<UnixListener> {
    let _umask = UmaskGuard::set(0o177);
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Bind the daemon's Unix socket at `path`, mode `0600` (`docs/design.md`
/// § Protocol).
///
/// The parent directory is checked by `ensure_socket_dir`: it is created with
/// mode `0700` if missing, and an existing one is never changed. So
/// `--socket ~/kpa.sock` leaves a home directory's permissions alone, and
/// `--socket /tmp/kpa.sock` is refused, since `/tmp` is writable by others.
///
/// Handles the stale-socket case: a previous `kpa serve` that didn't shut
/// down cleanly leaves its socket behind, and `bind` fails on an existing
/// path whether or not anything still listens there. Only a *socket* that
/// refuses connections is removed; anything else at the path — a live
/// daemon, a regular file — is an error, never silently deleted.
pub fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    ensure_socket_dir(dir)?;

    match bind_owner_only(path) {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            if !fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(err);
            }
            fs::remove_file(path)?;
            bind_owner_only(path)
        }
        Err(err) => Err(err),
    }
}
