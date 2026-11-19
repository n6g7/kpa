//! The user's display session as the rest of kpa reads it: the
//! [`DisplaySession`] type, and a [`DisplayWriter`] with its read-only
//! [`DisplayHandle`] copies. `auto_lock` holds the one writer; `authz`, the
//! clipboard and the other front ends hold handles.

use std::sync::{Arc, Mutex};

/// The user's display session, as the logind watch last saw it
/// (`docs/headless.md` § 3 and § 5).
///
/// Only `LockedHint` makes the display session locked. A locker that only sends the
/// `Lock` signal never reports the unlock (ASM-7), so its display session stays
/// [`DisplaySession::Unlocked`]. `active` is a separate fact, carried alongside
/// `LockedHint` for `authz::authorize_copy` alone: counting an
/// inactive session (one a VT switch moved away from) as locked would make
/// kpa lock the vault just for that, so `active` never touches
/// [`is_locked`](DisplaySession::is_locked) or `authz::may_prompt_on_screen`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DisplaySession {
    /// No display session (`User.Display` is `/`), or no working logind
    /// watch to say otherwise.
    #[default]
    None,
    /// The display session `session` (its logind id), with `LockedHint`
    /// true. `active` is the session's `Active` property.
    Locked { id: String, active: bool },
    /// The display session `session`, with `LockedHint` false. `active` is
    /// the session's `Active` property.
    Unlocked { id: String, active: bool },
}

impl DisplaySession {
    pub fn is_locked(&self) -> bool {
        matches!(self, DisplaySession::Locked { .. })
    }

    /// The display session's logind id, if there is one. Its scope is
    /// `session-<id>.scope`.
    pub fn id(&self) -> Option<&str> {
        match self {
            DisplaySession::None => None,
            DisplaySession::Locked { id, .. } | DisplaySession::Unlocked { id, .. } => Some(id),
        }
    }
}

/// The one writer of the display session. Not `Clone`: only `auto_lock`
/// holds it.
#[derive(Debug)]
pub struct DisplayWriter {
    shared: Arc<Mutex<DisplaySession>>,
}

/// A read-only copy of the display session's current state.
#[derive(Debug, Clone)]
pub struct DisplayHandle {
    shared: Arc<Mutex<DisplaySession>>,
}

/// The writer and a handle to read what it writes, starting at
/// [`DisplaySession::None`].
pub fn channel() -> (DisplayWriter, DisplayHandle) {
    let shared = Arc::new(Mutex::new(DisplaySession::None));
    (
        DisplayWriter {
            shared: shared.clone(),
        },
        DisplayHandle { shared },
    )
}

impl DisplayWriter {
    pub fn set(&self, session: DisplaySession) {
        *self.shared.lock().unwrap_or_else(|e| e.into_inner()) = session;
    }
}

impl DisplayHandle {
    pub fn get(&self) -> DisplaySession {
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_display_session() -> DisplaySession {
        DisplaySession::Locked {
            id: "31".to_string(),
            active: true,
        }
    }

    fn unlocked_display_session() -> DisplaySession {
        DisplaySession::Unlocked {
            id: "31".to_string(),
            active: true,
        }
    }

    #[test]
    fn the_display_session_names_its_session_and_whether_it_is_locked() {
        assert_eq!(DisplaySession::None.id(), None);
        assert!(!DisplaySession::None.is_locked());
        assert_eq!(locked_display_session().id(), Some("31"));
        assert!(locked_display_session().is_locked());
        assert_eq!(unlocked_display_session().id(), Some("31"));
        assert!(!unlocked_display_session().is_locked());
    }

    #[test]
    fn a_handle_reads_what_the_writer_set_and_copies_see_it_too() {
        let (writer, display) = channel();
        let copy = display.clone();
        assert_eq!(display.get(), DisplaySession::None);
        writer.set(locked_display_session());
        assert_eq!(display.get(), locked_display_session());
        assert_eq!(copy.get(), locked_display_session());
        writer.set(unlocked_display_session());
        assert_eq!(copy.get(), unlocked_display_session());
    }
}
