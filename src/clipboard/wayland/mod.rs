//! kpa's own Wayland clipboard client (`docs/design.md` § Clipboard).
//!
//! - [`compositor`] finds the compositor to copy to and checks it before
//!   any secret reaches it.
//! - [`data_control`] covers the two clipboard protocols a compositor may
//!   offer a client without a window.
//! - [`copy`] offers one secret on every seat and serves pastes of it.

mod compositor;
mod copy;
mod data_control;

pub use compositor::connect;
pub use copy::{Offer, offer};

/// What went wrong reaching or using the compositor. Never carries a
/// secret: none is in scope where one of these is built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);
