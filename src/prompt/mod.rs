//! Prompts that ask the user something on screen, such as `unlock`'s
//! prompt (`docs/design.md` decision #9, `Config::prompt`).
//!
//! - [`Prompt`]: one kind of question, with its own backend and timeout:
//!   [`ask`](Prompt::ask) shows it and brings back the answer.
//! - [`PromptQueue`]: one prompt on screen at a time, across every kind,
//!   in the order they were asked for. The daemon builds one and every
//!   [`Prompt`] shares it.
//! - [`Backend`]: how a prompt is shown. [`SecretProgram`], a dmenu-style
//!   external program, is the one there is.
//! - [`PromptOutcome`]: how a prompt ended, generic over its answer.
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
pub use outcome::PromptOutcome;
pub use program::SecretProgram;
pub use question::Prompt;
pub use queue::PromptQueue;

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
