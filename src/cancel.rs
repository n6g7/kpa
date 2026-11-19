//! How a lock ends the prompts it no longer wants answered. A
//! [`CancelSource`] belongs to what can lock, one per database, and hands
//! out [`CancelToken`]s; every prompt raised for that database holds one.
//! Dropping the source cancels all of its tokens at once, for good: a
//! prompt on screen is killed, one still queued is never shown, and
//! [`CancelToken::is_cancelled`] tells a caller whose prompt has already
//! answered that a lock came in since.
//!
//! Underneath, a flag and a socket pair, made the first time a prompt
//! waits on the token, so a source no prompt ever waits on costs no file
//! descriptor. A cancel sets the flag, then shuts the pair's write end
//! down: the read end, which a waiting prompt polls next to its own fd,
//! reaches end of file. A shutdown rather than a close, because a close
//! doesn't reach the read end while a prompt program forked at that moment
//! still holds a copy of the write end.

use std::fmt;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The lock side. Dropping it cancels every [`CancelToken`] it handed out.
pub struct CancelSource {
    shared: Arc<Shared>,
}

/// The prompt side: cloned freely, cancelled only by its
/// [`CancelSource`].
#[derive(Clone)]
pub struct CancelToken {
    shared: Arc<Shared>,
}

struct Shared {
    cancelled: AtomicBool,
    wake: Mutex<Wake>,
}

enum Wake {
    /// No prompt has waited on the token yet.
    Idle,
    /// What a cancel shuts down, and what a waiting prompt polls.
    Armed {
        write: UnixStream,
        read: Arc<UnixStream>,
    },
    Cancelled,
}

impl CancelSource {
    pub fn new() -> CancelSource {
        CancelSource {
            shared: Arc::new(Shared {
                cancelled: AtomicBool::new(false),
                wake: Mutex::new(Wake::Idle),
            }),
        }
    }

    /// A token this source cancels when it drops.
    pub fn token(&self) -> CancelToken {
        CancelToken {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Two tokens are equal when the same source handed them out.
impl PartialEq for CancelToken {
    fn eq(&self, other: &CancelToken) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
}

impl Eq for CancelToken {}

impl Drop for CancelSource {
    /// Sets the flag before the wake-up, so a prompt the wake-up reaches
    /// sees it set.
    fn drop(&mut self) {
        self.shared.cancelled.store(true, Ordering::SeqCst);
        let mut wake = self.shared.wake.lock().unwrap_or_else(|e| e.into_inner());
        if let Wake::Armed { write, .. } = std::mem::replace(&mut *wake, Wake::Cancelled) {
            let _ = write.shutdown(Shutdown::Write);
        }
    }
}

impl CancelToken {
    /// Whether the source has dropped. Read under the same lock the source
    /// is dropped under, it is exact: nothing has locked since the token
    /// was taken if this says `false`.
    pub fn is_cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::SeqCst)
    }

    /// What a prompt polls next to its own fd: it reaches end of file once
    /// the source drops. `None` if it already has. Made on the first call,
    /// and shared by every later one.
    pub(super) fn watch(&self) -> io::Result<Option<Arc<UnixStream>>> {
        let mut wake = self.shared.wake.lock().unwrap_or_else(|e| e.into_inner());
        match &*wake {
            Wake::Cancelled => Ok(None),
            Wake::Armed { read, .. } => Ok(Some(Arc::clone(read))),
            Wake::Idle => {
                let (write, read) = UnixStream::pair()?;
                let read = Arc::new(read);
                *wake = Wake::Armed {
                    write,
                    read: Arc::clone(&read),
                };
                Ok(Some(read))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    use super::*;

    /// Whether `watch` has reached end of file, without blocking.
    fn woken(watch: &UnixStream) -> bool {
        let mut fds = [PollFd::new(watch, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut fds, Some(&now)).expect("poll");
        !fds[0].revents().is_empty()
    }

    #[test]
    fn tokens_from_one_source_are_equal_and_from_two_sources_are_not() {
        let first = CancelSource::new();
        let second = CancelSource::new();
        assert_eq!(first.token(), first.token().clone());
        assert_ne!(first.token(), second.token());
    }

    #[test]
    fn dropping_the_source_cancels_every_token() {
        let source = CancelSource::new();
        let (first, second) = (source.token(), source.token());
        assert!(!first.is_cancelled());
        drop(source);
        assert!(first.is_cancelled());
        assert!(second.clone().is_cancelled());
    }

    /// Every watch on a token wakes, the ones taken before the cancel by
    /// end of file, and a later one finds it cancelled already.
    #[test]
    fn a_cancel_wakes_every_prompt_waiting_on_the_token() {
        let source = CancelSource::new();
        let token = source.token();
        let first = token.watch().expect("watch").expect("not cancelled");
        let second = token.watch().expect("watch").expect("not cancelled");
        assert!(!woken(&first));

        drop(source);

        assert!(woken(&first));
        assert!(woken(&second));
        assert!(token.watch().expect("watch").is_none());
    }

    /// A token nobody waits on never makes its socket pair.
    #[test]
    fn a_token_nobody_waits_on_opens_nothing() {
        let source = CancelSource::new();
        let _token = source.token();
        let wake = source.shared.wake.lock().expect("wake");
        assert!(matches!(*wake, Wake::Idle));
    }
}
