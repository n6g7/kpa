//! Where a request comes from: the desktop, or outside it
//! (`docs/headless.md` § 3).
//!
//! The peer's pid comes from the socket, as a pidfd (`SO_PEERPIDFD`) where
//! the kernel has it and as a bare pid (`SO_PEERCRED`) otherwise. Its
//! cgroup, read from `/proc/<pid>/cgroup`, says whether it runs under the
//! user's service manager or the display session's scope, which is where
//! the compositor and everything it spawns live.
//!
//! This decides where to ask, not who may ask: a same-uid process can move
//! work into another cgroup. So every failure, from a peer that already
//! exited to a cgroup file that doesn't parse, counts as [`Origin::Outside`].

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

/// Longest `/proc/<pid>/cgroup` accepted. A unified hierarchy has one line;
/// a hybrid one adds a line per v1 controller, still well under this.
const MAX_CGROUP_LEN: u64 = 16 * 1024;

/// Where a connected peer runs, relative to the user's display session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Under `user@<uid>.service` or in the display session's scope, while
    /// a display session exists.
    Desktop,
    /// Anywhere else: an SSH login's scope, a system service, no display
    /// session at all, or a peer kpa couldn't classify.
    Outside,
}

/// Classify the peer on `stream`. `uid` is the peer's (already checked to
/// be the daemon's own), `session` the id of the user's display session,
/// `None` when there is none.
pub fn of_peer(stream: &UnixStream, uid: u32, session: Option<&str>) -> Origin {
    if session.is_none() {
        return Origin::Outside;
    }
    match peer_cgroup(stream) {
        Ok(cgroup) => classify(&cgroup, uid, session),
        Err(err) => {
            crate::log::debug(format_args!("could not read the peer's cgroup: {err}"));
            Origin::Outside
        }
    }
}

/// Classify the contents of a `/proc/<pid>/cgroup` file. Pure, so it can be
/// tested on any input.
///
/// Only the unified hierarchy's line (`0::<path>`) is read. The peer is on
/// the desktop when that path is under `/user.slice/user-<uid>.slice/`,
/// in either `user@<uid>.service` or `session-<session>.scope`.
pub fn classify(cgroup: &str, uid: u32, session: Option<&str>) -> Origin {
    let Some(session) = session.filter(|id| !id.is_empty()) else {
        return Origin::Outside;
    };
    let Some(path) = unified_path(cgroup) else {
        return Origin::Outside;
    };
    let Some(rest) = path.strip_prefix(&format!("/user.slice/user-{uid}.slice/")) else {
        return Origin::Outside;
    };
    let unit = rest.split('/').next().unwrap_or_default();
    if unit == format!("user@{uid}.service") || unit == format!("session-{session}.scope") {
        Origin::Desktop
    } else {
        Origin::Outside
    }
}

/// The path on the file's one `0::` line. `None` if there is no such line,
/// more than one, or its path isn't absolute (a cgroup namespace shows a
/// path outside it as `/..`, which fails the prefix check anyway).
fn unified_path(cgroup: &str) -> Option<&str> {
    let mut lines = cgroup.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = lines.next()?;
    if lines.next().is_some() || !path.starts_with('/') {
        return None;
    }
    Some(path)
}

/// The contents of the peer's `/proc/<pid>/cgroup`.
///
/// With a pidfd, the pid is read from the pidfd's `fdinfo`, and read again
/// after the cgroup: a pid can only be reused once its process is reaped,
/// and a reaped process's pidfd reports pid `-1`. So an unchanged pid means
/// the cgroup read was the peer's. Without one, the `SO_PEERCRED` pid is
/// used as is, and a peer that exited in between can have its pid reused.
pub fn peer_cgroup(stream: &UnixStream) -> io::Result<String> {
    match peer_pidfd(stream) {
        Ok(pidfd) => {
            let pid = pidfd_pid(&pidfd)?;
            let cgroup = read_cgroup(pid)?;
            if pidfd_pid(&pidfd)? != pid {
                return Err(io::Error::new(ErrorKind::NotFound, "the peer exited"));
            }
            Ok(cgroup)
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOPROTOOPT) => peer_cgroup_by_pid(stream),
        Err(err) => Err(err),
    }
}

/// `peer_cgroup` for a kernel without `SO_PEERPIDFD`.
fn peer_cgroup_by_pid(stream: &UnixStream) -> io::Result<String> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    read_cgroup(cred.pid.as_raw_nonzero().get())
}

/// `SO_PEERPIDFD`: a pidfd for the process that connected. Linux 6.5 and
/// later; older kernels fail with `ENOPROTOOPT`.
fn peer_pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` and `len` are live locals of the size passed in `len`,
    // and the kernel writes at most that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if fd < 0 || len as usize != size_of::<libc::c_int>() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "SO_PEERPIDFD returned no descriptor",
        ));
    }
    // SAFETY: the kernel just installed `fd` (close-on-exec, as every pidfd
    // is) for this call alone, so nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The pid a pidfd refers to, from its `Pid:` line in `fdinfo`. Fails if
/// the process is gone (`-1`) or outside this pid namespace (`0`).
fn pidfd_pid(pidfd: &OwnedFd) -> io::Result<i32> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let info = read_bounded(&path)?;
    let pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|pid| pid.trim().parse::<i32>().ok())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "no Pid in the pidfd's fdinfo"))?;
    if pid <= 0 {
        return Err(io::Error::new(ErrorKind::NotFound, "the peer exited"));
    }
    Ok(pid)
}

fn read_cgroup(pid: i32) -> io::Result<String> {
    read_bounded(&format!("/proc/{pid}/cgroup"))
}

/// Read a small text file whole, refusing one over `MAX_CGROUP_LEN`.
fn read_bounded(path: &str) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_CGROUP_LEN + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CGROUP_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{path} exceeds {MAX_CGROUP_LEN} bytes"),
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 1000;
    const SESSION: &str = "3";

    fn origin(cgroup: &str) -> Origin {
        classify(cgroup, UID, Some(SESSION))
    }

    #[test]
    fn the_desktop_is_the_service_manager_and_the_display_session() {
        let desktop = [
            // A compositor child: an app the compositor or launcher spawned.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot-1234.scope\n",
            // The compositor itself, run as a user service.
            "0::/user.slice/user-1000.slice/user@1000.service/session.slice/compositor.service\n",
            // The service manager's own cgroup.
            "0::/user.slice/user-1000.slice/user@1000.service\n",
            // The display session's scope: a compositor started from a
            // login shell, and everything it spawns.
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            // A hybrid hierarchy: only the `0::` line counts.
            "12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice/user-1000.slice/session-3.scope\n",
        ];
        for cgroup in desktop {
            assert_eq!(origin(cgroup), Origin::Desktop, "{cgroup:?}");
        }
    }

    #[test]
    fn everything_else_is_outside() {
        let outside = [
            // An SSH login, or any other session that isn't the display one.
            "0::/user.slice/user-1000.slice/session-5.scope\n",
            // A session id that only starts with the display session's.
            "0::/user.slice/user-1000.slice/session-31.scope\n",
            // A system service: a cron job, or a terminal server's shell,
            // even one used at the desk.
            "0::/system.slice/cron.service\n",
            "0::/system.slice/terminal-server.service/shell-7.scope\n",
            // A terminal server registered as a logind session: each
            // connection is its own remote session under the user's slice,
            // with a scope that isn't the display session's.
            "0::/user.slice/user-1000.slice/session-12.scope/shell.scope\n",
            // Another user's service manager and session.
            "0::/user.slice/user-1001.slice/user@1001.service/app.slice/a.scope\n",
            "0::/user.slice/user-1001.slice/session-3.scope\n",
            // Names that only start like the desktop's units.
            "0::/user.slice/user-1000.slice/user@1000.service-x/a.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope.d\n",
            // The user slice itself, and the root.
            "0::/user.slice/user-1000.slice\n",
            "0::/\n",
        ];
        for cgroup in outside {
            assert_eq!(origin(cgroup), Origin::Outside, "{cgroup:?}");
        }
    }

    #[test]
    fn malformed_input_is_outside() {
        let malformed = [
            "",
            "\n",
            "garbage",
            // No unified line: a v1-only hierarchy.
            "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
            // A relative path, and a path outside a cgroup namespace.
            "0::user.slice/user-1000.slice/session-3.scope\n",
            "0::/../../user.slice/user-1000.slice/session-3.scope\n",
            // Two unified lines.
            "0::/user.slice/user-1000.slice/session-3.scope\n0::/system.slice/x.service\n",
            "0::/system.slice/x.service\n0::/user.slice/user-1000.slice/session-3.scope\n",
            // The prefix without its separator.
            "0::/user.slice/user-1000.sliceuser@1000.service\n",
        ];
        for cgroup in malformed {
            assert_eq!(origin(cgroup), Origin::Outside, "{cgroup:?}");
        }
    }

    #[test]
    fn nothing_is_the_desktop_without_a_display_session() {
        let cgroups = [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot-1234.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/user.slice/user-1000.slice/session-.scope\n",
        ];
        for cgroup in cgroups {
            assert_eq!(classify(cgroup, UID, None), Origin::Outside, "{cgroup:?}");
            assert_eq!(
                classify(cgroup, UID, Some("")),
                Origin::Outside,
                "{cgroup:?}"
            );
        }
    }

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let own = std::fs::read_to_string("/proc/self/cgroup").expect("own cgroup");
        assert_eq!(peer_cgroup(&ours).expect("peer cgroup"), own);
        assert_eq!(peer_cgroup_by_pid(&ours).expect("peer cgroup"), own);
    }
}
