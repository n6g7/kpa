//! Prompts that ask the user something on screen, such as `unlock`'s
//! prompt (`docs/design.md` decision #9, `Config::prompt`).
//!
//! - [`outcome`](PromptOutcome): how a prompt ended, generic over its
//!   answer.
//! - [`cancel_pair`]: how a lock ends a prompt it no longer wants answered.
//! - [`PromptQueue`]: one prompt on screen at a time, shared by every
//!   caller.
//! - `message`: display sanitization for the untrusted text in a prompt's
//!   message, applied by every backend, so callers pass plain text.
//! - [`run_prompt`]: the backend, a dmenu-style external program.

mod cancel;
mod message;
mod outcome;
mod program;
mod queue;

pub use cancel::{CancelWatch, PromptCancel, cancel_pair};
pub use outcome::PromptOutcome;
pub use program::run_prompt;
#[cfg(test)]
pub(crate) use program::spawn_lock;
pub use queue::PromptQueue;
