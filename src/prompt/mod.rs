//! Prompts that ask the user something on screen, such as `unlock`'s
//! prompt (`docs/design.md` decision #9, `Config::prompt`).
//!
//! - [`PromptQueue`]: where every prompt is raised, built once by the
//!   daemon. One prompt is on screen at a time, in the order they were
//!   asked for.
//! - [`Backend`]: how a prompt is shown. [`Programs`], dmenu-style external
//!   programs, is the one there is.
//! - [`PromptOutcome`]: how a prompt ended, generic over its answer.
//! - [`CancelSource`] and [`CancelToken`]: how a lock ends the prompts it
//!   no longer wants answered.
//! - `message`: display sanitization for the untrusted text in a prompt's
//!   message, applied by the queue, so callers pass plain text.

mod cancel;
#[cfg(test)]
mod fake;
mod message;
mod outcome;
mod program;
mod queue;

use std::io;
use std::time::Instant;

pub use cancel::{CancelSource, CancelToken};
#[cfg(test)]
pub(crate) use fake::{Scripted, Step};
pub use outcome::PromptOutcome;
pub use program::Programs;
pub use queue::PromptQueue;

/// How a prompt is shown. A [`PromptQueue`] calls it once the prompt's turn
/// has come, with a `message` that is safe to display. Each method ends as
/// [`PromptOutcome::Interrupted`] as soon as `cancel` is cancelled, and as
/// [`PromptOutcome::TimedOut`] at `deadline` (`None`: never).
pub trait Backend: Send + Sync {
    /// Shows `message` and reads what the user types: a password.
    fn secret(
        &self,
        message: &str,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome>;
}
