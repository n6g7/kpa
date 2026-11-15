//! [`Scripted`], a [`Backend`] for tests: each prompt it is shown takes the
//! next [`Step`] a test queued, records its message and answers as the step
//! says, without running a program. A step's hook runs on the prompting
//! thread, so a test can lock while a prompt is up without threads or
//! timing.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::{Backend, CancelToken, PromptOutcome};

type Hook = Box<dyn FnOnce() + Send>;

/// One prompt, as a test scripts it.
pub(crate) struct Step {
    outcome: PromptOutcome,
    while_up: Option<Hook>,
}

impl Step {
    /// A secret prompt that ends as `outcome`, unless its token is
    /// cancelled while it is up.
    pub(crate) fn secret(outcome: PromptOutcome) -> Step {
        Step {
            outcome,
            while_up: None,
        }
    }

    /// Runs `f` while the prompt is on screen, before it answers: a lock
    /// here ends it as `Interrupted`, as it ends a real one.
    pub(crate) fn while_up(mut self, f: impl FnOnce() + Send + 'static) -> Step {
        self.while_up = Some(Box::new(f));
        self
    }
}

/// Clones share one script: hand one to the queue and keep one to drive
/// it.
#[derive(Clone, Default)]
pub(crate) struct Scripted(Arc<Script>);

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    shown: Mutex<Vec<String>>,
}

impl Scripted {
    pub(crate) fn new() -> Scripted {
        Scripted::default()
    }

    /// Queues the step the next prompt takes. A prompt with no step queued
    /// panics.
    pub(crate) fn push(&self, step: Step) {
        self.0.steps.lock().expect("steps").push_back(step);
    }

    /// Every message shown so far, in order.
    pub(crate) fn shown(&self) -> Vec<String> {
        self.0.shown.lock().expect("shown").clone()
    }
}

impl Backend for Scripted {
    fn secret(
        &self,
        message: &str,
        _deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome> {
        let step = self
            .0
            .steps
            .lock()
            .expect("steps")
            .pop_front()
            .unwrap_or_else(|| panic!("a prompt nobody scripted: {message:?}"));
        self.0
            .shown
            .lock()
            .expect("shown")
            .push(message.to_string());
        if let Some(while_up) = step.while_up {
            while_up();
        }
        // A cancel ends a prompt that is up, whatever it would answer.
        if cancel.is_cancelled() {
            return Ok(PromptOutcome::Interrupted);
        }
        Ok(step.outcome)
    }
}
