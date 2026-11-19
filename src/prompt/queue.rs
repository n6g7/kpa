//! [`PromptQueue`]: one prompt on screen at a time, across every database
//! and every kind of prompt (`docs/ssh-agent.md` § 6.7).

use std::collections::VecDeque;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use crate::cancel::CancelToken;

#[derive(Default)]
struct PromptQueueState {
    /// Something is running, or has just been released to run next.
    /// `false` means the next `enter` runs immediately.
    busy: bool,
    /// Ticket numbers handed out by `enter`, used only so a cancelling
    /// waiter can find and remove its own entry below.
    next_ticket: u64,
    /// FIFO of waiters behind whoever is running, each with the write end
    /// `release` closes to wake it: its `enter` poll sees the read end
    /// hang up.
    waiting: VecDeque<(u64, UnixStream)>,
}

/// Serializes every prompt the daemon raises, across every database and
/// every kind of [`Prompt`](super::Prompt), so only one is ever on screen
/// (`docs/ssh-agent.md` § 6.7's "only one prompt is on screen at a time").
/// Built once at startup and shared by every `Prompt`.
pub struct PromptQueue {
    state: Mutex<PromptQueueState>,
}

impl PromptQueue {
    pub fn new() -> PromptQueue {
        PromptQueue {
            state: Mutex::new(PromptQueueState::default()),
        }
    }

    /// Blocks until either this call's turn comes up (`Ok(Some(turn))`,
    /// released by dropping it) or `cancel` is cancelled first: a lock
    /// ending a prompt that was still queued, or that had just been given
    /// its turn (`Ok(None)`). Either way it never reaches the backend.
    ///
    /// A ticket that wins the queue-empty race in `release` (it already
    /// popped this entry just as `cancel` also fired) still takes its
    /// turn: once `release` has committed to treating a ticket as the
    /// next to run, something must eventually call `release` again on its
    /// behalf, which only a `PromptTurn` does. Resolving that only under
    /// `state`'s lock — the same lock `release` pops under — is what keeps
    /// the two from disagreeing about which ticket is still queued.
    pub(super) fn enter(&self, cancel: &CancelToken) -> io::Result<Option<PromptTurn<'_>>> {
        // The busy check and, if it's already taken, joining the queue
        // happen under one lock hold: splitting them would let a release
        // between the two find the queue empty and clear `busy` before
        // this ticket ever gets into it, stranding it forever.
        let queued = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.busy {
                let Some(cancel_watch) = cancel.watch()? else {
                    return Ok(None);
                };
                let (writer, watch) = UnixStream::pair()?;
                let ticket = state.next_ticket;
                state.next_ticket = state.next_ticket.wrapping_add(1);
                state.waiting.push_back((ticket, writer));
                Some((ticket, watch, cancel_watch))
            } else {
                state.busy = true;
                None
            }
        };
        if let Some((ticket, watch, cancel_watch)) = queued
            && let Wake::Cancel = wait_for_wake(&watch, &cancel_watch)?
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(pos) = state.waiting.iter().position(|(t, _)| *t == ticket) {
                state.waiting.remove(pos);
                return Ok(None);
            }
            // `release` already popped this ticket — see the doc
            // comment above.
        }
        let turn = PromptTurn { queue: self };
        // A lock that came in just before the turn did: give the turn
        // straight back rather than start a prompt the lock would kill.
        if cancel.is_cancelled() {
            return Ok(None);
        }
        Ok(Some(turn))
    }

    /// Wakes the next waiter, or marks the queue idle once none are left.
    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.waiting.pop_front() {
            None => state.busy = false,
            Some((_ticket, notify)) => drop(notify), // closing it wakes the waiter; `busy` stays set
        }
    }
}

/// Holds `PromptQueue`'s one running slot; releases it on drop, so every
/// way out of a prompt — an answer, a timeout, an interruption, or an I/O
/// error — lets the next queued prompt proceed.
pub(super) struct PromptTurn<'a> {
    queue: &'a PromptQueue,
}

impl Drop for PromptTurn<'_> {
    fn drop(&mut self) {
        self.queue.release();
    }
}

enum Wake {
    /// `watch`'s write end closed: `release` has handed this ticket the
    /// turn.
    Turn,
    /// The cancel token's watch reached end of file before `watch` did.
    Cancel,
}

/// Blocks until `watch` or `cancel` wakes, whichever comes first.
fn wait_for_wake(watch: &UnixStream, cancel: &UnixStream) -> io::Result<Wake> {
    use rustix::event::{PollFd, PollFlags, poll};

    loop {
        let mut fds = [
            PollFd::new(watch, PollFlags::IN),
            PollFd::new(cancel, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
        if !fds[0].revents().is_empty() {
            return Ok(Wake::Turn);
        }
        if !fds[1].revents().is_empty() {
            return Ok(Wake::Cancel);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::cancel::CancelSource;

    /// Waits until `n` prompts are queued behind the one on screen.
    fn wait_queued(queue: &PromptQueue, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while queue.state.lock().expect("state").waiting.len() < n {
            assert!(Instant::now() < deadline, "the prompt never queued");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn an_idle_queue_lets_the_first_prompt_straight_in() {
        let queue = PromptQueue::new();
        let source = CancelSource::new();
        assert!(queue.enter(&source.token()).expect("enter").is_some());
    }

    /// The second `enter` waits for the first turn to drop, then gets its
    /// own.
    #[test]
    fn a_second_prompt_waits_for_the_first_to_finish() {
        let queue = PromptQueue::new();
        let (a, b) = (CancelSource::new(), CancelSource::new());
        let first = queue.enter(&a.token()).expect("enter").expect("a turn");

        std::thread::scope(|scope| {
            let second = scope.spawn(|| {
                let turn = queue.enter(&b.token()).expect("enter");
                (turn.is_some(), Instant::now())
            });
            wait_queued(&queue, 1);
            let released_at = Instant::now();
            drop(first);
            let (got_turn, entered_at) = second.join().expect("second thread panicked");
            assert!(got_turn);
            assert!(entered_at >= released_at, "the second prompt didn't wait");
        });
    }

    /// A queued prompt whose token is cancelled leaves the queue without a
    /// turn, and without holding up the prompts behind it.
    #[test]
    fn a_queued_prompt_is_cancelled_without_a_turn() {
        let queue = PromptQueue::new();
        let (a, b) = (CancelSource::new(), CancelSource::new());
        let first = queue.enter(&a.token()).expect("enter").expect("a turn");

        let token = b.token();
        std::thread::scope(|scope| {
            let second = scope.spawn(|| queue.enter(&token).expect("enter").is_some());
            wait_queued(&queue, 1);
            drop(b);
            assert!(!second.join().expect("second thread panicked"));
        });

        drop(first);
        let c = CancelSource::new();
        assert!(queue.enter(&c.token()).expect("enter").is_some());
    }
}
