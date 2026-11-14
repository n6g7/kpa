//! Prompts that ask the user something on screen: `unlock`'s prompt
//! (`docs/design.md` decision #9, `Config::prompt`) and the SSH agent's
//! approval prompt (`ssh_agent.confirm_prompt`, same contract —
//! `docs/ssh-agent.md` § 6.7).
//!
//! - [`outcome`](PromptOutcome): how a prompt ended, generic over its
//!   answer; [`Approval`] is an approval prompt's.
//! - [`cancel_pair`]: how a lock ends a prompt it no longer wants answered.
//! - [`PromptQueue`]: one prompt on screen at a time, shared by every
//!   caller.
//! - `message`: what a prompt is about, escaped and length-capped here, so
//!   callers pass plain text.
//! - [`run_prompt`] and [`run_approval_prompt`]: the backend, a dmenu-style
//!   external program.

mod cancel;
mod message;
mod outcome;
mod program;
mod queue;

pub use cancel::{CancelWatch, PromptCancel, cancel_pair};
pub use outcome::{Approval, PromptOutcome};
#[cfg(test)]
pub(crate) use program::spawn_lock;
pub use program::{run_approval_prompt, run_prompt};
pub use queue::PromptQueue;
