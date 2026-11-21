//! Filesystem and socket helpers for the daemon's Unix socket: the
//! process-wide umask guard, the owner-only bind, the socket directory
//! check, and sending and receiving a request with a file descriptor
//! attached. Everything that touches the socket's permissions lives here,
//! in one place.

use std::fs;
use std::io::{self, IoSlice, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rustix::fs::Mode;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

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

/// Sends `bytes` on `stream`, with `fd` attached to them if there is one,
/// so the receiver gets the descriptor together with the first of the bytes.
pub fn send_with_fd(
    mut stream: &UnixStream,
    bytes: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let fds;
    if let Some(fd) = fd {
        fds = [fd];
        ancillary.push(SendAncillaryMessage::ScmRights(&fds));
    }
    let sent = sendmsg(
        stream,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    stream.write_all(&bytes[sent..])
}

/// What one [`recv_with_fd`] brought.
#[derive(Debug)]
pub enum Received {
    /// `len` bytes (none at end of file), and the descriptor that came with
    /// them if one did.
    Data { len: usize, fd: Option<OwnedFd> },
    /// More than one descriptor came with the bytes. None was kept.
    TooManyFds,
}

/// Reads what has arrived on `stream` into `buf`, taking at most one
/// descriptor that came with it. The descriptor is close-on-exec, so a
/// program the daemon starts later doesn't inherit it.
pub fn recv_with_fd(stream: &UnixStream, buf: &mut [u8]) -> io::Result<Received> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        stream,
        &mut [IoSliceMut::new(buf)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut fds = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    // The control buffer is padded past one descriptor, so a second one can
    // fit in it: count them. A client sending more than the padding holds
    // gets the rest closed by the kernel, which only the truncation flag shows.
    if fds.len() > 1 || received.flags.contains(ReturnFlags::CTRUNC) {
        return Ok(Received::TooManyFds);
    }
    Ok(Received::Data {
        len: received.bytes,
        fd: fds.pop(),
    })
}

/// Sends `bytes` with every one of `fds` attached, which [`send_with_fd`]
/// never does: for tests of what the receiving end refuses.
#[cfg(test)]
pub(crate) fn send_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    ancillary.push(SendAncillaryMessage::ScmRights(fds));
    sendmsg(
        stream,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .expect("send");
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use rustix::io::{FdFlags, fcntl_getfd};

    use super::*;

    /// What `recv_with_fd` finds when `send` has put something on a socket
    /// pair.
    fn received(send: impl FnOnce(UnixStream)) -> Received {
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        send(ours);
        let mut buf = [0u8; 64];
        recv_with_fd(&theirs, &mut buf).expect("recv")
    }

    #[test]
    fn a_descriptor_arrives_with_the_bytes_it_was_sent_with() {
        let (spare, _other) = UnixStream::pair().expect("a descriptor to send");
        let Received::Data { len, fd } = received(|stream| {
            send_with_fd(&stream, b"hello\n", Some(spare.as_fd())).expect("send");
        }) else {
            panic!("expected data");
        };
        assert_eq!(len, 6);
        let fd = fd.expect("the descriptor");
        // Close-on-exec: a program the daemon starts later doesn't inherit it.
        assert!(fcntl_getfd(&fd).expect("flags").contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn bytes_without_a_descriptor_arrive_without_one() {
        let Received::Data { len, fd } = received(|stream| {
            send_with_fd(&stream, b"hello\n", None).expect("send");
        }) else {
            panic!("expected data");
        };
        assert_eq!(len, 6);
        assert!(fd.is_none());
    }

    #[test]
    fn end_of_file_is_no_bytes() {
        let Received::Data { len, fd } = received(drop) else {
            panic!("expected data");
        };
        assert_eq!(len, 0);
        assert!(fd.is_none());
    }

    /// The receive buffer has room for two descriptors, so a second one is
    /// refused by counting, and any beyond that by the truncation the
    /// kernel reports.
    #[test]
    fn more_than_one_descriptor_is_refused() {
        let (a, _a) = UnixStream::pair().expect("descriptors to send");
        let (b, _b) = UnixStream::pair().expect("descriptors to send");
        let (c, _c) = UnixStream::pair().expect("descriptors to send");
        let (d, _d) = UnixStream::pair().expect("descriptors to send");

        for fds in [
            vec![a.as_fd(), b.as_fd()],
            vec![a.as_fd(), b.as_fd(), c.as_fd(), d.as_fd()],
        ] {
            let outcome = received(|stream| send_with_fds(&stream, b"hello\n", &fds));
            assert!(
                matches!(outcome, Received::TooManyFds),
                "{} descriptors: {outcome:?}",
                fds.len()
            );
        }
    }
}
