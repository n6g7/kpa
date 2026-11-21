//! [`Scripted`], a [`Backend`] for tests: each prompt it is shown takes the
//! next [`Step`] a test queued, records its message and answers as the step
//! says, without running a program. A step's hooks run on the prompting
//! thread, so a test can lock while a prompt is up, or once its answer is
//! in, without threads or timing.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::{Backend, ConfirmAnswer, PromptOutcome, Question};
use crate::cancel::CancelToken;

type Hook = Box<dyn FnOnce() + Send>;

/// One prompt, as a test scripts it.
pub(crate) struct Step<T> {
    reply: io::Result<PromptOutcome<T>>,
    while_up: Option<Hook>,
    then: Option<Hook>,
}

impl<T> Step<T> {
    /// A prompt that ends as `outcome`, unless its token is cancelled
    /// while it is up.
    pub(crate) fn new(outcome: PromptOutcome<T>) -> Step<T> {
        Step {
            reply: Ok(outcome),
            while_up: None,
            then: None,
        }
    }

    /// A prompt that fails to show, with an I/O error, as one whose program
    /// doesn't run.
    pub(crate) fn fails() -> Step<T> {
        Step {
            reply: Err(io::Error::other("the scripted prompt failed")),
            while_up: None,
            then: None,
        }
    }

    /// Runs `f` while the prompt is on screen, before it answers: a lock
    /// here ends it as `Interrupted`, as it ends a real one.
    pub(crate) fn while_up(mut self, f: impl FnOnce() + Send + 'static) -> Step<T> {
        self.while_up = Some(Box::new(f));
        self
    }

    /// Runs `f` once the prompt has answered, before its caller sees the
    /// answer.
    pub(crate) fn then(mut self, f: impl FnOnce() + Send + 'static) -> Step<T> {
        self.then = Some(Box::new(f));
        self
    }
}

impl Step<ConfirmAnswer> {
    /// A confirm prompt answered `Allow`.
    pub(crate) fn allow() -> Step<ConfirmAnswer> {
        Step::new(PromptOutcome::Answer(ConfirmAnswer::Allow))
    }
}

/// Clones share one script: hand one to a [`Prompt`](super::Prompt) and
/// keep one to drive it.
pub(crate) struct Scripted<T>(Arc<Script<T>>);

struct Script<T> {
    steps: Mutex<VecDeque<Step<T>>>,
    shown: Mutex<Vec<Question>>,
}

impl<T> Clone for Scripted<T> {
    fn clone(&self) -> Scripted<T> {
        Scripted(Arc::clone(&self.0))
    }
}

impl<T> Scripted<T> {
    pub(crate) fn new() -> Scripted<T> {
        Scripted(Arc::new(Script {
            steps: Mutex::new(VecDeque::new()),
            shown: Mutex::new(Vec::new()),
        }))
    }

    /// Queues the step the next prompt takes. A prompt with no step queued
    /// panics.
    pub(crate) fn push(&self, step: Step<T>) {
        self.0.steps.lock().expect("steps").push_back(step);
    }

    /// Every message shown so far, in order.
    pub(crate) fn shown(&self) -> Vec<String> {
        self.shown_questions()
            .into_iter()
            .map(|question| question.message)
            .collect()
    }

    /// Every question shown so far, in order.
    pub(crate) fn shown_questions(&self) -> Vec<Question> {
        self.0.shown.lock().expect("shown").clone()
    }
}

impl<T: Send> Backend<T> for Scripted<T> {
    fn is_queued(&self) -> bool {
        true
    }

    fn show(
        &self,
        question: &Question,
        _deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome<T>> {
        let step = self
            .0
            .steps
            .lock()
            .expect("steps")
            .pop_front()
            .unwrap_or_else(|| panic!("a prompt nobody scripted: {:?}", question.message));
        self.0.shown.lock().expect("shown").push(question.clone());
        if let Some(while_up) = step.while_up {
            while_up();
        }
        // A cancel ends a prompt that is up, whatever it would answer.
        if cancel.is_cancelled() {
            return Ok(PromptOutcome::Interrupted);
        }
        if let Some(then) = step.then {
            then();
        }
        step.reply
    }
}
