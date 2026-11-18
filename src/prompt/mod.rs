//! Prompts that ask the user something on screen: `unlock`'s prompt
//! (`docs/design.md` decision #9, `Config::prompt`) and the SSH agent's
//! approval prompt (`ssh_agent.confirm_prompt`, same contract —
//! `docs/ssh-agent.md` § 6.7).
//!
//! - [`Prompt`]: one kind of question, with its own backend and timeout:
//!   [`ask`](Prompt::ask) shows it and brings back the answer.
//! - [`PromptQueue`]: one prompt on screen at a time, across every kind,
//!   in the order they were asked for. The daemon builds one and every
//!   [`Prompt`] shares it.
//! - [`Backend`]: how a prompt is shown. [`SecretProgram`] and
//!   [`ConfirmProgram`], dmenu-style external programs, are the ones there
//!   are.
//! - [`PromptOutcome`]: how a prompt ended, generic over its answer;
//!   [`Approval`] is an approval prompt's, and [`Declined`] says how one
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

use std::io;
use std::time::Instant;

pub use cancel::{CancelSource, CancelToken};
#[cfg(test)]
pub(crate) use fake::{Scripted, Step};
pub use outcome::{Approval, Declined, PromptOutcome};
pub use program::{ConfirmProgram, SecretProgram};
pub use question::Prompt;
pub use queue::PromptQueue;

/// Where a prompt asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOn {
    /// On screen, through a prompt program.
    Screen,
}

/// How a prompt whose answer is a `T` is shown. A [`Prompt`] calls it once
/// the prompt's turn has come, with a `message` that is safe to display.
/// It ends as [`PromptOutcome::Interrupted`] as soon as `cancel` is
/// cancelled, and as [`PromptOutcome::TimedOut`] at `deadline` (`None`:
/// never).
pub trait Backend<T>: Send + Sync {
    fn show(
        &self,
        message: &str,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome<T>>;
}
