//! What a prompt comes back with: [`PromptOutcome`], generic over the
//! answer; [`ConfirmAnswer`], the answer a confirm prompt gives; and
//! [`Declined`], how a confirm prompt ended when it didn't allow.

use std::io;

use zeroize::Zeroizing;

/// How a prompt ended. `T` is what an answered prompt yields: by default
/// what the user typed, as [`PromptQueue::secret`](super::PromptQueue::secret)
/// returns it.
pub enum PromptOutcome<T = Zeroizing<String>> {
    /// The user dismissed the prompt rather than answering it — for a
    /// prompt program, an unsuccessful exit; for a terminal, its hang-up or
    /// the requester that passed it leaving.
    Cancelled,
    /// Nothing was entered within the prompt's timeout; the prompt was
    /// killed.
    TimedOut,
    /// Its [`CancelToken`](crate::cancel::CancelToken) was cancelled — a lock
    /// ended the prompt. It was killed, or, if it was still queued, never
    /// shown at all.
    Interrupted,
    Answer(T),
}

impl PromptOutcome {
    /// The answer a prompt's raw output makes: its trailing line ending
    /// stripped, and what is left read as UTF-8. It is copied into a buffer
    /// of exactly its size, so nothing reallocates and the wipe on drop
    /// covers all of it.
    pub(super) fn from_output(output: &[u8]) -> io::Result<PromptOutcome> {
        let mut end = output.len();
        while end > 0 && matches!(output[end - 1], b'\n' | b'\r') {
            end -= 1;
        }
        let text = std::str::from_utf8(&output[..end]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "prompt output is not valid UTF-8",
            )
        })?;
        let mut answer = Zeroizing::new(String::with_capacity(text.len()));
        answer.push_str(text);
        Ok(PromptOutcome::Answer(answer))
    }
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

/// The answer to a confirm prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAnswer {
    Allow,
    Deny,
}

/// How a confirm prompt ended without allowing, as a log line says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Declined {
    #[error("denied")]
    Denied,
    #[error("cancelled")]
    Cancelled,
    #[error("timed out")]
    TimedOut,
    #[error("interrupted by a lock")]
    Interrupted,
}

impl PromptOutcome<ConfirmAnswer> {
    /// `Ok` for an `Allow`, and how the prompt declined otherwise.
    pub fn allowed(self) -> Result<(), Declined> {
        match self {
            PromptOutcome::Answer(ConfirmAnswer::Allow) => Ok(()),
            PromptOutcome::Answer(ConfirmAnswer::Deny) => Err(Declined::Denied),
            PromptOutcome::Cancelled => Err(Declined::Cancelled),
            PromptOutcome::TimedOut => Err(Declined::TimedOut),
            PromptOutcome::Interrupted => Err(Declined::Interrupted),
        }
    }
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
    fn only_an_allow_is_allowed() {
        assert_eq!(
            PromptOutcome::Answer(ConfirmAnswer::Allow).allowed(),
            Ok(())
        );
        for (outcome, declined) in [
            (PromptOutcome::Answer(ConfirmAnswer::Deny), Declined::Denied),
            (PromptOutcome::Cancelled, Declined::Cancelled),
            (PromptOutcome::TimedOut, Declined::TimedOut),
            (PromptOutcome::Interrupted, Declined::Interrupted),
        ] {
            assert_eq!(outcome.allowed(), Err(declined));
        }
    }

    #[test]
    fn debug_never_shows_the_answer() {
        let outcome: PromptOutcome = PromptOutcome::Answer(Zeroizing::new("hunter2".into()));
        assert_eq!(format!("{outcome:?}"), "Answer(_)");
    }
}
