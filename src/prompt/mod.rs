//! Prompts that ask the user something: `unlock`'s prompt
//! (`docs/design.md` decision #9, `Config::prompt`) and the SSH agent's
//! confirm prompt (`ssh_agent.confirm_prompt`, same contract —
//! `docs/ssh-agent.md` § 6.7).
//!
//! - [`Prompt`]: one kind of question, with its own backend and timeout:
//!   [`ask`](Prompt::ask) shows it and brings back the answer.
//! - [`PromptQueue`]: one prompt on screen at a time, across every kind,
//!   in the order they were asked for. The daemon builds one and every
//!   [`Prompt`] shares it.
//! - [`Backend`]: how a prompt is shown. [`SecretProgram`] and
//!   [`ConfirmProgram`], dmenu-style external programs, put it on screen;
//!   [`SecretTerminal`] asks on a terminal a requester passed
//!   (`docs/headless.md` § 4).
//! - [`PromptOutcome`]: how a prompt ended, generic over its answer;
//!   [`ConfirmAnswer`] is a confirm prompt's, and [`Declined`] says how one
//!   that didn't allow ended.
//! - [`CancelSource`] and [`CancelToken`]: how a lock ends the prompts it
//!   no longer wants answered.
//! - `message`: display sanitization for the untrusted text in a prompt's
//!   message, applied by [`Prompt::ask`], so callers pass plain text.

mod cancel;
#[cfg(test)]
mod fake;
mod message;
mod outcome;
mod program;
mod question;
mod queue;
mod terminal;
#[cfg(test)]
pub(crate) mod testing;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::event::Timespec;
use serde::{Deserialize, Serialize};

pub use cancel::{CancelSource, CancelToken};
#[cfg(test)]
pub(crate) use fake::{Scripted, Step};
pub use outcome::{ConfirmAnswer, Declined, PromptOutcome};
pub use program::{ConfirmProgram, SecretProgram};
pub use question::Prompt;
pub use queue::PromptQueue;
pub use terminal::{SecretTerminal, Terminal};

/// The longest answer read, in bytes; one more byte is an error. An answer
/// can be a secret, so this is the secrets' length cap.
pub(crate) const MAX_ANSWER_LEN: usize = 4096;

/// Where a prompt asks, and what a request names when it prefers one
/// (`Request::preferred_prompt`), as `"screen"` or `"terminal"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptOn {
    /// On screen, through a prompt program.
    Screen,
    /// On a terminal a requester passed.
    Terminal,
}

/// How a prompt whose answer is a `T` is shown. A [`Prompt`] calls it once
/// the prompt's turn has come, with a `message` that is safe to display.
/// It ends as [`PromptOutcome::Interrupted`] as soon as `cancel` is
/// cancelled, and as [`PromptOutcome::TimedOut`] at `deadline` (`None`:
/// never).
pub trait Backend<T>: Send + Sync {
    /// Whether the prompt waits its turn in the [`PromptQueue`]: it does when
    /// it takes the screen, and doesn't when it asks somewhere of its own.
    fn is_queued(&self) -> bool;

    fn show(
        &self,
        message: &str,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome<T>>;
}

/// A backend that several prompts share is shown through the `Arc`.
impl<T, B: Backend<T> + ?Sized> Backend<T> for Arc<B> {
    fn is_queued(&self) -> bool {
        (**self).is_queued()
    }

    fn show(
        &self,
        message: &str,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome<T>> {
        (**self).show(message, deadline, cancel)
    }
}

/// What a `poll` that waits `left` should be given as its timeout.
fn poll_timeout(left: Duration) -> Timespec {
    Timespec {
        tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: left.subsec_nanos().into(),
    }
}
