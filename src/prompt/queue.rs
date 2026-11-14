//! [`PromptQueue`]: one prompt on screen at a time, across every database
//! and both kinds of prompt (`docs/ssh-agent.md` § 6.7).

use std::collections::VecDeque;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use super::CancelWatch;

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

/// Serializes every prompt across every database, so only one is ever on
/// screen (`docs/ssh-agent.md` § 6.7's "only one prompt is on screen at a
/// time"). Every prompt shares one.
pub struct PromptQueue {
    state: Mutex<PromptQueueState>,
}

impl Default for PromptQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptQueue {
    pub fn new() -> PromptQueue {
        PromptQueue {
            state: Mutex::new(PromptQueueState::default()),
        }
    }

    /// Blocks until either this call's turn comes up (`Ok(Some(turn))`,
    /// released by dropping it) or `cancel` sees its `PromptCancel` dropped
    /// first — a lock ending a prompt that was still queued, never shown
    /// (`Ok(None)`).
    ///
    /// A ticket that wins the queue-empty race in `release` (it already
    /// popped this entry just as `cancel` also hung up) still comes back
    /// `Some`: once `release` has committed to treating a ticket as the
    /// next to run, something must eventually call `release` again on its
    /// behalf, which only a `PromptTurn` does. Resolving that only under
    /// `state`'s lock — the same lock `release` pops under — is what keeps
    /// the two from disagreeing about which ticket is still queued.
    pub(super) fn enter(&self, cancel: &CancelWatch) -> std::io::Result<Option<PromptTurn<'_>>> {
        // The busy check and, if it's already taken, joining the queue
        // happen under one lock hold: splitting them would let a release
        // between the two find the queue empty and clear `busy` before
        // this ticket ever gets into it, stranding it forever.
        let (ticket, watch) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.busy {
                state.busy = true;
                return Ok(Some(PromptTurn { queue: self }));
            }
            let (writer, watch) = UnixStream::pair()?;
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state.waiting.push_back((ticket, writer));
            (ticket, watch)
        };
        match wait_for_wake(&watch, cancel)? {
            Wake::Turn => Ok(Some(PromptTurn { queue: self })),
            Wake::Cancel => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(pos) = state.waiting.iter().position(|(t, _)| *t == ticket) {
                    state.waiting.remove(pos);
                    return Ok(None);
                }
                // `release` already popped this ticket — see the doc
                // comment above.
                Ok(Some(PromptTurn { queue: self }))
            }
        }
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
    /// `cancel` hung up before `watch` did.
    Cancel,
}

/// Blocks until `watch` or `cancel` hangs up, whichever comes first.
fn wait_for_wake(watch: &UnixStream, cancel: &CancelWatch) -> std::io::Result<Wake> {
    use rustix::event::{PollFd, PollFlags, poll};

    loop {
        let mut fds = [
            PollFd::new(watch, PollFlags::IN),
            PollFd::from_borrowed_fd(cancel.fd(), PollFlags::IN),
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

    use super::super::cancel_pair;
    use super::*;

    #[test]
    fn an_idle_queue_lets_the_first_prompt_straight_in() {
        let queue = PromptQueue::new();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        assert!(queue.enter(&watch).expect("enter").is_some());
    }

    /// The second `enter` waits for the first turn to drop, then gets its
    /// own.
    #[test]
    fn a_second_prompt_waits_for_the_first_to_finish() {
        let queue = PromptQueue::new();
        let (_cancel_a, watch_a) = cancel_pair().expect("cancel pair");
        let (_cancel_b, watch_b) = cancel_pair().expect("cancel pair");
        let first = queue.enter(&watch_a).expect("enter").expect("a turn");

        std::thread::scope(|scope| {
            let second = scope.spawn(|| {
                let turn = queue.enter(&watch_b).expect("enter");
                (turn.is_some(), Instant::now())
            });
            std::thread::sleep(Duration::from_millis(100));
            let released_at = Instant::now();
            drop(first);
            let (got_turn, entered_at) = second.join().expect("second thread panicked");
            assert!(got_turn);
            assert!(entered_at >= released_at, "the second prompt didn't wait");
        });
    }

    /// A queued prompt whose cancel end is dropped leaves the queue without
    /// a turn, and without holding up the prompts behind it.
    #[test]
    fn a_queued_prompt_is_cancelled_without_a_turn() {
        let queue = PromptQueue::new();
        let (_cancel_a, watch_a) = cancel_pair().expect("cancel pair");
        let (cancel_b, watch_b) = cancel_pair().expect("cancel pair");
        let first = queue.enter(&watch_a).expect("enter").expect("a turn");

        std::thread::scope(|scope| {
            let second = scope.spawn(|| queue.enter(&watch_b).expect("enter").is_some());
            std::thread::sleep(Duration::from_millis(100));
            drop(cancel_b);
            assert!(!second.join().expect("second thread panicked"));
        });

        drop(first);
        let (_cancel_c, watch_c) = cancel_pair().expect("cancel pair");
        assert!(queue.enter(&watch_c).expect("enter").is_some());
    }
}
