//! How a lock ends a prompt it no longer wants answered: [`cancel_pair`]
//! makes a [`PromptCancel`], which the lock side keeps, and a
//! [`CancelWatch`], which the prompt watches. [`PromptCancel::cancel`], or
//! dropping the `PromptCancel`, ends the prompt: killed if it's on screen,
//! never shown if it's still queued.
//!
//! A socket pair underneath: dropping one end hangs up the other, which a
//! prompt notices in the same `poll` that waits for its answer. Neither end
//! is exposed as a socket outside this module, and the watch's fd only
//! within `prompt`, for the backends that wait on it alongside their own.

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;

/// The lock side's end. [`cancel`](Self::cancel), or dropping it, ends the
/// prompt watching the matching [`CancelWatch`].
pub struct PromptCancel {
    /// Never read: closing it, on drop, is its whole job.
    _end: UnixStream,
}

/// The prompt side's end, passed to [`run_prompt`](super::run_prompt).
pub struct CancelWatch {
    end: UnixStream,
}

/// A new cancel channel: the lock side's [`PromptCancel`] and the prompt
/// side's [`CancelWatch`].
pub fn cancel_pair() -> std::io::Result<(PromptCancel, CancelWatch)> {
    let (cancel, watch) = UnixStream::pair()?;
    Ok((PromptCancel { _end: cancel }, CancelWatch { end: watch }))
}

impl PromptCancel {
    /// Ends the prompt watching the matching [`CancelWatch`], as dropping
    /// it does.
    pub fn cancel(self) {
        drop(self);
    }
}

impl CancelWatch {
    /// What a prompt polls: readable, or hung up, once the `PromptCancel`
    /// is gone. Nothing is ever written to it. A backend waits on it and
    /// on its own fd (a prompt program's output, the queue's wake socket)
    /// in one `poll`, which is why `prompt` exposes this fd rather than a
    /// standalone check or a blocking wait.
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.end.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    use super::*;

    /// Whether `watch`'s `PromptCancel` is gone, without blocking.
    fn is_cancelled(watch: &CancelWatch) -> bool {
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
        assert!(!is_cancelled(&watch));
        drop(cancel);
        assert!(is_cancelled(&watch));
    }

    #[test]
    fn cancelling_is_what_the_watch_sees() {
        let (cancel, watch) = cancel_pair().expect("cancel pair");
        assert!(!is_cancelled(&watch));
        cancel.cancel();
        assert!(is_cancelled(&watch));
    }
}
