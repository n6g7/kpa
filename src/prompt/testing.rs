//! What tests of the code that asks on a terminal share.

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
