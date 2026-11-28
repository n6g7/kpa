//! Socket I/O that ends by a deadline, not after each wait.
//!
//! A socket's own send and receive timeouts restart with every byte that
//! moves, so a client that sends or reads one byte just inside them holds
//! its connection as long as it likes. These wait for readiness against one
//! deadline taken up front, so the whole exchange has a bound
//! (`docs/threat-model.md` G-11), and never block past it: what follows a
//! wait is a receive that has data, or a send that doesn't wait.

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{SendFlags, send};

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the exchange took too long")
}

/// Waits until `stream` is ready for `events`, or `deadline` passes.
fn wait_until(stream: &UnixStream, events: PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timed_out());
        }
        let timeout = Timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(stream, events)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => {}
            Ok(_) => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
}

/// Waits until a receive on `stream` would not block, or `deadline` passes.
/// A connection the peer closed counts as ready: the receive says so.
pub fn readable_by(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    wait_until(stream, PollFlags::IN, deadline)
}

/// Writes all of `data` to `stream` before `deadline`, in as many sends as
/// the peer's draining takes.
pub fn write_all_by(stream: &UnixStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    while !data.is_empty() {
        wait_until(stream, PollFlags::OUT, deadline)?;
        match send(stream, data, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(sent) => data = &data[sent..],
            Err(Errno::AGAIN | Errno::INTR) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn soon(millis: u64) -> Instant {
        Instant::now() + Duration::from_millis(millis)
    }

    #[test]
    fn a_silent_peer_times_out_at_the_deadline() {
        let (_peer, ours) = UnixStream::pair().expect("socket pair");

        let started = Instant::now();
        let err = readable_by(&ours, soon(100)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn data_or_a_closed_peer_is_readable() {
        let (peer, ours) = UnixStream::pair().expect("socket pair");
        (&peer).write_all(b"x").expect("write");
        readable_by(&ours, soon(1000)).expect("data is waiting");

        let (peer, ours) = UnixStream::pair().expect("socket pair");
        drop(peer);
        readable_by(&ours, soon(1000)).expect("end of file is waiting");
    }

    #[test]
    fn everything_is_written_to_a_reader_that_keeps_up() {
        let (ours, mut peer) = UnixStream::pair().expect("socket pair");
        let data = vec![7u8; 4 * 1024 * 1024];
        let reader = thread::spawn(move || {
            let mut got = Vec::new();
            peer.read_to_end(&mut got).expect("read");
            got.len()
        });

        write_all_by(&ours, &data, soon(10_000)).expect("written");
        drop(ours);

        assert_eq!(reader.join().expect("reader"), data.len());
    }

    #[test]
    fn a_reader_that_never_reads_cannot_hold_a_write_past_the_deadline() {
        let (ours, _peer) = UnixStream::pair().expect("socket pair");
        let data = vec![7u8; 64 * 1024 * 1024];

        let started = Instant::now();
        let err = write_all_by(&ours, &data, soon(200)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_closed_reader_is_an_error_not_a_hang() {
        let (ours, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);

        assert!(write_all_by(&ours, b"hunter2", soon(1000)).is_err());
    }
}
