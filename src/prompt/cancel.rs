//! How a lock ends a prompt it no longer wants answered: [`cancel_pair`]
//! makes a [`PromptCancel`], which the lock side keeps, and a
//! [`CancelWatch`], which the prompt watches. Dropping the `PromptCancel`
//! ends the prompt: killed if it's on screen, never shown if it's still
//! queued.
//!
//! A socket pair underneath: dropping one end hangs up the other, which a
//! prompt notices in the same `poll` that waits for its answer. Neither end
//! is exposed as a socket outside this module.

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

/// The lock side's end. Dropping it ends the prompt watching the matching
/// [`CancelWatch`].
pub struct PromptCancel {
    /// Never read: closing it, on drop, is its whole job.
    _end: UnixStream,
}

/// The prompt side's end, passed to [`run_prompt`](super::run_prompt) and
/// [`run_approval_prompt`](super::run_approval_prompt).
pub struct CancelWatch {
    end: UnixStream,
}

/// A new cancel channel: the lock side's [`PromptCancel`] and the prompt
/// side's [`CancelWatch`].
pub fn cancel_pair() -> std::io::Result<(PromptCancel, CancelWatch)> {
    let (cancel, watch) = UnixStream::pair()?;
    Ok((PromptCancel { _end: cancel }, CancelWatch { end: watch }))
}

impl CancelWatch {
    /// What a prompt polls: readable, or hung up, once the `PromptCancel`
    /// is dropped. Nothing is ever written to it.
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.end.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    use super::*;

    fn cancelled(watch: &CancelWatch) -> bool {
        let mut fds = [PollFd::from_borrowed_fd(watch.fd(), PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut fds, Some(&now)).expect("poll");
        !fds[0].revents().is_empty()
    }

    #[test]
    fn dropping_the_cancel_end_is_what_the_watch_sees() {
        let (cancel, watch) = cancel_pair().expect("cancel pair");
        assert!(!cancelled(&watch));
        drop(cancel);
        assert!(cancelled(&watch));
    }
}
