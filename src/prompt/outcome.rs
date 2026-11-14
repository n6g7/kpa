//! What a prompt comes back with: [`PromptOutcome`], generic over the
//! answer, and [`Approval`], the answer an approval prompt gives.

use zeroize::Zeroizing;

/// How a prompt ended. `T` is what an answered prompt yields: by default
/// what the program printed, as [`run_prompt`](super::run_prompt) returns
/// it.
pub enum PromptOutcome<T = Zeroizing<String>> {
    /// The user dismissed the prompt rather than answering it — for a
    /// prompt program, an unsuccessful exit.
    Cancelled,
    /// Nothing was entered within the prompt's timeout; the prompt was
    /// killed.
    TimedOut,
    /// Its [`PromptCancel`](super::PromptCancel) was dropped — a lock
    /// ended the prompt. It was killed, or, if it was still queued, never
    /// shown at all.
    Interrupted,
    Answer(T),
}

impl<T> PromptOutcome<T> {
    /// Interprets an answer, leaving the other outcomes as they are.
    pub(super) fn map<U>(self, f: impl FnOnce(T) -> U) -> PromptOutcome<U> {
        match self {
            PromptOutcome::Cancelled => PromptOutcome::Cancelled,
            PromptOutcome::TimedOut => PromptOutcome::TimedOut,
            PromptOutcome::Interrupted => PromptOutcome::Interrupted,
            PromptOutcome::Answer(answer) => PromptOutcome::Answer(f(answer)),
        }
    }
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

/// The answer to an approval prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_interprets_only_an_answer() {
        let answer = PromptOutcome::Answer("Allow").map(|a| a == "Allow");
        assert!(matches!(answer, PromptOutcome::Answer(true)));
        assert!(matches!(
            PromptOutcome::<&str>::TimedOut.map(|a| a == "Allow"),
            PromptOutcome::TimedOut
        ));
        assert!(matches!(
            PromptOutcome::<&str>::Interrupted.map(|a| a == "Allow"),
            PromptOutcome::Interrupted
        ));
        assert!(matches!(
            PromptOutcome::<&str>::Cancelled.map(|a| a == "Allow"),
            PromptOutcome::Cancelled
        ));
    }

    #[test]
    fn debug_never_shows_the_answer() {
        let outcome: PromptOutcome = PromptOutcome::Answer(Zeroizing::new("hunter2".into()));
        assert_eq!(format!("{outcome:?}"), "Answer(_)");
    }
}
