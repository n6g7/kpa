//! Who is on the other end of a connection: plain facts about the caller,
//! read from its socket and `/proc` (`docs/headless.md` § 3). What those
//! facts allow is not decided here: that is [`authz`](crate::authz), asked
//! when a request is answered.
//!
//! The peer's pid comes from the socket, as a pidfd (`SO_PEERPIDFD`) where
//! the kernel has it and as a bare pid (`SO_PEERCRED`) otherwise. Its
//! cgroup, read from `/proc/<pid>/cgroup` when it connects, says whether it
//! runs under the user's service manager or the display session's scope.
//! Which session is the display session is not the peer's to say, so a
//! [`Requester`] only keeps the cgroup.
//!
//! A peer can also pass a terminal along with its request, for the daemon to
//! ask on when it can't ask on screen ([`Terminal`]).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};

/// Longest `/proc/<pid>/` file accepted. A unified hierarchy's `cgroup` has
/// one line; a hybrid one adds a line per v1 controller, still well under
/// this. `comm` is at most 16 bytes.
const MAX_PROC_FILE_LEN: u64 = 16 * 1024;

/// The cgroup that every connection to a listening socket is taken to
/// have, in place of its peer's own, keyed by the socket's path. Empty
/// outside tests: [`Requester::of`] makes one lookup per connection.
static ASSUMED_CGROUPS: LazyLock<Mutex<HashMap<PathBuf, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Takes every connection to the listening socket at `socket_path` to come
/// from a peer in `cgroup`, for tests that run the daemon in-process and
/// drive it with the real CLI. Test-only: nothing in the daemon calls it, and
/// no CLI flag, environment variable, config key or request field reaches
/// it. Keyed by socket, so tests running in parallel, each with a socket of
/// its own, don't affect one another.
#[doc(hidden)]
pub fn assume_cgroup(socket_path: &Path, cgroup: &str) {
    ASSUMED_CGROUPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(socket_path.to_path_buf(), cgroup.to_string());
}

/// The cgroup `assume_cgroup` set for the socket `stream` was accepted on,
/// if it did.
fn assumed_cgroup(stream: &UnixStream) -> Option<String> {
    let address = stream.local_addr().ok()?;
    let path = address.as_pathname()?;
    ASSUMED_CGROUPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(path)
        .cloned()
}

/// The uid this process acts as (its effective uid): the one every
/// same-user check compares against and the one kpa looks the user up by.
pub fn process_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The uid of the process on the other end of `stream`, from `SO_PEERCRED`.
/// Fails if the kernel can't say, and the caller must treat that as a
/// refusal, not as a match.
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|cred| cred.uid.as_raw())
        .map_err(std::io::Error::from)
}

/// Who is on the other end of a connection: plain facts about the caller,
/// read once when the connection is accepted ([`Requester::of`]) and handed
/// to everything that answers its requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester {
    /// The caller's uid.
    pub uid: u32,
    /// The caller's `/proc/<pid>/cgroup`, as it was when it connected.
    /// `None` where it couldn't be read.
    pub cgroup: Option<String>,
    /// The caller's command name, for naming it to the user who may approve
    /// what it asked for (`docs/ssh-agent.md` § 6.8). `None` where it can't
    /// be read.
    pub command: Option<String>,
    /// A terminal the peer passed with its request. The daemon uses it only
    /// if it has to ask the user something and can't ask on screen.
    pub terminal: Option<Terminal>,
}

/// A terminal the peer passed along with its request, and the connection it
/// came on: the daemon asks on the terminal, and stops asking once the peer
/// closes the connection.
///
/// Cloned freely: a clone is the same terminal.
#[derive(Debug, Clone)]
pub struct Terminal {
    fd: Arc<OwnedFd>,
    connection: Arc<UnixStream>,
}

impl Terminal {
    /// `fd`, as passed on `connection`. Refused unless it is a terminal: the
    /// daemon writes a prompt to it and switches its echo off, which it must
    /// not do to a file or a socket the peer picked.
    pub fn new(fd: OwnedFd, connection: &UnixStream) -> io::Result<Terminal> {
        if !rustix::termios::isatty(&fd) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "the descriptor passed is not a terminal",
            ));
        }
        Ok(Terminal {
            fd: Arc::new(fd),
            connection: Arc::new(connection.try_clone()?),
        })
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// The connection the terminal came on, for noticing that the peer left.
    pub fn connection(&self) -> &UnixStream {
        &self.connection
    }
}

/// Two terminals are equal when one is a clone of the other, so a
/// [`Requester`] can be compared.
impl PartialEq for Terminal {
    fn eq(&self, other: &Terminal) -> bool {
        Arc::ptr_eq(&self.fd, &other.fd)
    }
}

impl Eq for Terminal {}

impl Requester {
    /// The peer on `stream`: its uid from the socket, and its cgroup and
    /// command name where they can be read.
    pub fn of(stream: &UnixStream) -> io::Result<Requester> {
        let uid = peer_uid(stream)?;
        let cgroup = assumed_cgroup(stream).or_else(|| {
            peer_cgroup(stream)
                .inspect_err(|err| {
                    crate::log::debug(format_args!("could not read the peer's cgroup: {err}"));
                })
                .ok()
        });
        Ok(Requester {
            uid,
            cgroup,
            command: peer_command(stream),
            terminal: None,
        })
    }

    /// This process as a requester: what the tray's menu acts as, since a
    /// click has no peer. Its uid is [`process_uid`], its cgroup this
    /// process's own, its command `kpa`.
    pub fn of_this_process() -> Requester {
        let cgroup = read_bounded("/proc/self/cgroup")
            .inspect_err(|err| {
                crate::log::debug(format_args!("could not read the daemon's cgroup: {err}"));
            })
            .ok();
        Requester {
            uid: process_uid(),
            cgroup,
            command: Some("kpa".to_string()),
            terminal: None,
        }
    }
}

/// The contents of the peer's `/proc/<pid>/cgroup`: see [`peer_proc_file`].
fn peer_cgroup(stream: &UnixStream) -> io::Result<String> {
    peer_proc_file(stream, "cgroup")
}

/// The peer's command name, as the kernel records it (`/proc/<pid>/comm`,
/// at most 15 bytes): what to call the requester in front of the user. It
/// is whatever the process chose to call itself, so it names a requester
/// for display and decides nothing. `None` where it can't be read.
fn peer_command(stream: &UnixStream) -> Option<String> {
    let comm = peer_proc_file(stream, "comm").ok()?;
    Some(comm.trim_end_matches('\n').to_string()).filter(|comm| !comm.is_empty())
}

/// The contents of `/proc/<pid>/<file>` for the peer's pid.
///
/// With a pidfd, the pid is read from the pidfd's `fdinfo`, and read again
/// after the file: a pid can only be reused once its process is reaped,
/// and a reaped process's pidfd reports pid `-1`. So an unchanged pid means
/// the read was the peer's. Without one, the `SO_PEERCRED` pid is used as
/// is, and a peer that exited in between can have its pid reused.
fn peer_proc_file(stream: &UnixStream, file: &str) -> io::Result<String> {
    match peer_pidfd(stream) {
        Ok(pidfd) => {
            let pid = pidfd_pid(&pidfd)?;
            let contents = read_proc_file(pid, file)?;
            if pidfd_pid(&pidfd)? != pid {
                return Err(io::Error::new(ErrorKind::NotFound, "the peer exited"));
            }
            Ok(contents)
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            peer_proc_file_by_pid(stream, file)
        }
        Err(err) => Err(err),
    }
}

/// `peer_proc_file` for a kernel without `SO_PEERPIDFD`.
fn peer_proc_file_by_pid(stream: &UnixStream, file: &str) -> io::Result<String> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    read_proc_file(cred.pid.as_raw_nonzero().get(), file)
}

/// `SO_PEERPIDFD`: a pidfd for the process that connected. Linux 6.5 and
/// later; older kernels fail with `ENOPROTOOPT`.
fn peer_pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // TODO: once https://github.com/bytecodealliance/rustix/pull/1474 ships,
    // rustix's `socket_peerpidfd` replaces this `unsafe`, and the direct
    // `libc` dependency can go if nothing else uses it.
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

fn read_proc_file(pid: i32, file: &str) -> io::Result<String> {
    read_bounded(&format!("/proc/{pid}/{file}"))
}

/// Read a small text file whole, refusing one over `MAX_PROC_FILE_LEN`.
fn read_bounded(path: &str) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_PROC_FILE_LEN + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_PROC_FILE_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{path} exceeds {MAX_PROC_FILE_LEN} bytes"),
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let own = std::fs::read_to_string("/proc/self/cgroup").expect("own cgroup");
        assert_eq!(peer_cgroup(&ours).expect("peer cgroup"), own);
        assert_eq!(
            peer_proc_file_by_pid(&ours, "cgroup").expect("peer cgroup"),
            own
        );
    }

    #[test]
    fn the_peer_of_a_socket_pair_has_this_process_command_name() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let own = std::fs::read_to_string("/proc/self/comm").expect("own comm");
        assert_eq!(peer_command(&ours), Some(own.trim_end().to_string()));
    }

    #[test]
    fn the_requester_of_a_socket_pair_is_this_process() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");

        let requester = Requester::of(&ours).expect("peer credentials");

        assert_eq!(requester.uid, process_uid());
        assert_eq!(
            requester.cgroup.as_deref(),
            Some(
                std::fs::read_to_string("/proc/self/cgroup")
                    .expect("own cgroup")
                    .as_str()
            )
        );
        let own = std::fs::read_to_string("/proc/self/comm").expect("own comm");
        assert_eq!(requester.command.as_deref(), Some(own.trim_end()));
    }

    #[test]
    fn this_process_as_a_requester_has_its_own_uid_cgroup_and_the_name_kpa() {
        let requester = Requester::of_this_process();

        assert_eq!(requester.uid, process_uid());
        assert_eq!(
            requester.cgroup,
            Some(std::fs::read_to_string("/proc/self/cgroup").expect("own cgroup"))
        );
        assert_eq!(requester.command.as_deref(), Some("kpa"));
    }

    #[test]
    fn a_connection_to_a_socket_with_an_assumed_cgroup_has_that_cgroup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (assumed, untouched) = (dir.path().join("assumed"), dir.path().join("untouched"));
        let accepted = |path: &Path| {
            let listener = std::os::unix::net::UnixListener::bind(path).expect("bind");
            let _client = UnixStream::connect(path).expect("connect");
            listener.accept().expect("accept").0
        };
        assume_cgroup(&assumed, "0::/system.slice/cron.service\n");

        let forced = Requester::of(&accepted(&assumed)).expect("peer credentials");
        let own = Requester::of(&accepted(&untouched)).expect("peer credentials");

        assert_eq!(
            forced.cgroup.as_deref(),
            Some("0::/system.slice/cron.service\n")
        );
        assert_eq!(forced.uid, own.uid);
        assert_eq!(forced.command, own.command);
        assert_eq!(
            own.cgroup.as_deref(),
            Some(
                std::fs::read_to_string("/proc/self/cgroup")
                    .expect("own cgroup")
                    .as_str()
            )
        );
    }
}

/// What tests of the code that asks on a requester's terminal share.
#[cfg(test)]
pub(crate) mod testing {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::time::{Duration, Instant};

    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::{Mode, OFlags, open};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{LocalModes, tcgetattr};

    /// A pseudo-terminal: the master end stands for the user's keyboard and
    /// screen, the slave end for what a client's `/dev/tty` opens to.
    pub(crate) fn pty() -> (File, OwnedFd) {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let name = ptsname(&master, Vec::new()).expect("ptsname");
        let slave = open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open the slave");
        (File::from(master), slave)
    }

    /// Whether the terminal echoes what is typed, as its master end sees it.
    pub(crate) fn echoing(master: &File) -> bool {
        tcgetattr(master)
            .expect("tcgetattr")
            .local_modes
            .contains(LocalModes::ECHO)
    }

    /// Whether the user's screen has anything on it to read now.
    pub(crate) fn shows_anything(master: &File) -> bool {
        let mut fds = [PollFd::new(master, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut fds, Some(&now)).expect("poll");
        // Not just any event: the master hangs up once every slave is closed.
        fds[0].revents().contains(PollFlags::IN)
    }

    /// Reads from the user's screen until `needle` shows up, and returns
    /// everything read. Panics after a few seconds instead of hanging.
    pub(crate) fn read_until(master: &mut File, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = String::new();
        let mut buf = [0u8; 256];
        while !seen.contains(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timed out waiting for {needle:?}; the screen showed {seen:?}"
            );
            let mut fds = [PollFd::new(&*master, PollFlags::IN)];
            let timeout = Timespec {
                tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: left.subsec_nanos().into(),
            };
            if poll(&mut fds, Some(&timeout)).is_err() || fds[0].revents().is_empty() {
                continue;
            }
            let read = master.read(&mut buf).expect("read the screen");
            seen.push_str(&String::from_utf8_lossy(&buf[..read]));
        }
        seen
    }
}
