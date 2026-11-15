//! What a prompt comes back with: [`PromptOutcome`], generic over the
//! answer.

use zeroize::Zeroizing;

/// How a prompt ended. `T` is what an answered prompt yields: by default
/// what the user typed, as [`PromptQueue::secret`](super::PromptQueue::secret)
/// returns it.
pub enum PromptOutcome<T = Zeroizing<String>> {
    /// The user dismissed the prompt rather than answering it — for a
    /// prompt program, an unsuccessful exit.
    Cancelled,
    /// Nothing was entered within the prompt's timeout; the prompt was
    /// killed.
    TimedOut,
    /// Its [`CancelToken`](super::CancelToken) was cancelled — a lock
    /// ended the prompt. It was killed, or, if it was still queued, never
    /// shown at all.
    Interrupted,
    Answer(T),
}

/// Redacts the answer, same reasoning as `UnlockRequest`'s own `Debug`
/// (`docs/headless.md` § 9): this is cheap insurance against it ending up
/// in a test failure message or a future `{:?}` log line.
impl<T> std::fmt::Debug for PromptOutcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptOutcome::Cancelled => write!(f, "Cancelled"),
            PromptOutcome::TimedOut => write!(f, "TimedOut"),
            PromptOutcome::Interrupted => write!(f, "Interrupted"),
            PromptOutcome::Answer(_) => write!(f, "Answer(_)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_answer() {
        let outcome: PromptOutcome = PromptOutcome::Answer(Zeroizing::new("hunter2".into()));
        assert_eq!(format!("{outcome:?}"), "Answer(_)");
    }
}
