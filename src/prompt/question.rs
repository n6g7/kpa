//! [`Prompt`]: one kind of question, with its own backend and timeout,
//! asked through the shared [`PromptQueue`].

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::message::sanitize_message;
use super::{Backend, PromptOutcome, PromptQueue, Question};
use crate::cancel::CancelToken;

/// One kind of question whose answer is a `T`: `unlock`'s password, say.
/// Each kind has its own [`Backend`] and timeout, and every kind that takes
/// the screen waits its turn in the same [`PromptQueue`], so only one prompt
/// is on screen at a time. A kind whose backend asks elsewhere
/// ([`Backend::is_queued`]) doesn't wait.
pub struct Prompt<T> {
    queue: Arc<PromptQueue>,
    backend: Box<dyn Backend<T>>,
    timeout: Duration,
}

impl<T> Prompt<T> {
    pub fn new(
        queue: Arc<PromptQueue>,
        backend: impl Backend<T> + 'static,
        timeout: Duration,
    ) -> Prompt<T> {
        Prompt {
            queue,
            backend: Box::new(backend),
            timeout,
        }
    }

    /// Shows `question` and brings back the answer. Its message, plain text,
    /// is sanitized for display (`message`); its data is shown as it is, its
    /// builder having made it display-safe. The prompt gets `timeout` from
    /// the moment its turn comes. It ends as
    /// [`PromptOutcome::Interrupted`] once `cancel` is cancelled: killed if
    /// it is on screen, never shown if it is still queued.
    pub fn ask(&self, question: &Question, cancel: &CancelToken) -> io::Result<PromptOutcome<T>> {
        let question = Question {
            message: sanitize_message(&question.message),
            data: question.data.clone(),
        };
        let _turn = if self.backend.is_queued() {
            let Some(turn) = self.queue.enter(cancel)? else {
                return Ok(PromptOutcome::Interrupted);
            };
            Some(turn)
        } else {
            None
        };
        // `None` for a timeout too large to add: a deadline that never
        // arrives.
        let deadline = Instant::now().checked_add(self.timeout);
        self.backend.show(&question, deadline, cancel)
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::super::{Scripted, Step};
    use super::*;
    use crate::cancel::CancelSource;
    use crate::prompt::testing::question;

    fn prompt() -> (Prompt<Zeroizing<String>>, Scripted<Zeroizing<String>>) {
        let prompts = Scripted::new();
        let prompt = Prompt::new(
            Arc::new(PromptQueue::new()),
            prompts.clone(),
            Duration::from_secs(60),
        );
        (prompt, prompts)
    }

    /// The backend sees the message sanitized, and its answer is the
    /// caller's.
    #[test]
    fn a_prompt_shows_its_message_sanitized() {
        let (prompt, prompts) = prompt();
        prompts.push(Step::new(PromptOutcome::Answer(Zeroizing::new(
            "hunter2".to_string(),
        ))));
        let source = CancelSource::new();

        let outcome = prompt.ask(&question("Unlock personal\u{202e}evil"), &source.token());

        assert!(matches!(outcome, Ok(PromptOutcome::Answer(a)) if a.as_str() == "hunter2"));
        assert_eq!(prompts.shown(), ["Unlock personal\\u202eevil"]);
    }

    /// A token cancelled before the prompt's turn comes never reaches the
    /// backend.
    #[test]
    fn a_prompt_cancelled_before_its_turn_is_never_shown() {
        let (prompt, prompts) = prompt();
        let token = CancelSource::new().token();

        assert!(matches!(
            prompt.ask(&question("Unlock personal"), &token),
            Ok(PromptOutcome::Interrupted)
        ));
        assert!(prompts.shown().is_empty());
    }

    /// Two kinds of prompt with their own backends share one queue: the
    /// second waits for the first to finish, then shows through its own
    /// backend.
    #[test]
    fn two_kinds_of_prompt_take_turns_in_one_queue() {
        let queue = Arc::new(PromptQueue::new());
        let (first, second) = (Scripted::<Zeroizing<String>>::new(), Scripted::new());
        let unlock = Prompt::new(Arc::clone(&queue), first.clone(), Duration::from_secs(60));
        let other: Prompt<bool> =
            Prompt::new(Arc::clone(&queue), second.clone(), Duration::from_secs(60));
        let source = CancelSource::new();
        let token = source.token();
        let turn = queue.enter(&token).expect("enter").expect("a turn");

        first.push(Step::new(PromptOutcome::Cancelled));
        second.push(Step::new(PromptOutcome::Answer(true)));
        std::thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock.ask(&question("Unlock personal"), &token));
            let asking = scope.spawn(|| other.ask(&question("Something else"), &token));
            std::thread::sleep(Duration::from_millis(50));
            assert!(first.shown().is_empty() && second.shown().is_empty());
            drop(turn);
            assert!(matches!(
                unlocking.join().expect("unlock thread"),
                Ok(PromptOutcome::Cancelled)
            ));
            assert!(matches!(
                asking.join().expect("other thread"),
                Ok(PromptOutcome::Answer(true))
            ));
        });
        assert_eq!(first.shown(), ["Unlock personal"]);
        assert_eq!(second.shown(), ["Something else"]);
    }
}
