//! The user's display session as the rest of kpa reads it: the
//! [`DisplaySession`] type, and a [`DisplayWriter`] with its read-only
//! [`DisplayHandle`] copies. `auto_lock` holds the one writer; `authz`, the
//! clipboard and the other front ends hold handles.

use std::sync::{Arc, Mutex};

/// The user's display session: the graphical session whose screen the user
/// sits at (`docs/headless.md` § 3 and § 5).
///
/// - [`None`](DisplaySession::None): there is none, or kpa can't tell.
/// - [`Locked`](DisplaySession::Locked) and
///   [`Unlocked`](DisplaySession::Unlocked): there is one, and its screen is
///   locked or not. Only a screen reported locked makes it
///   [`Locked`](DisplaySession::Locked); a locker that never reports its
///   unlock leaves it unlocked.
/// - `active` says whether it is the session in front, which a VT switch
///   moves away from. It matters to `authz::authorize_copy` alone: counting
///   an inactive session as locked would make kpa lock its databases just
///   for that, so `active` never touches [`is_locked`](DisplaySession::is_locked)
///   or `authz::may_prompt_on_screen`.
/// - `id` names the session. It is opaque to everything but the clipboard and
///   `authz`, which use it to find the desktop's processes and its
///   compositor.
///
/// How the logind watcher builds the value is in
/// `frontends/auto_lock/logind.rs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DisplaySession {
    /// No display session, or no working watch to say otherwise.
    #[default]
    None,
    /// A display session whose screen is locked.
    Locked { id: String, active: bool },
    /// A display session whose screen is not locked.
    Unlocked { id: String, active: bool },
}

impl DisplaySession {
    /// The session `id`, locked or not, in front (`active`) or not.
    pub fn new(id: &str, locked: bool, active: bool) -> DisplaySession {
        let id = id.to_string();
        if locked {
            DisplaySession::Locked { id, active }
        } else {
            DisplaySession::Unlocked { id, active }
        }
    }

    /// The same session, locked or not as `locked` says. A no-op on
    /// [`DisplaySession::None`]: there is no session to lock.
    pub fn with_locked(&self, locked: bool) -> DisplaySession {
        match self {
            DisplaySession::None => DisplaySession::None,
            DisplaySession::Locked { id, active } | DisplaySession::Unlocked { id, active } => {
                DisplaySession::new(id, locked, *active)
            }
        }
    }

    /// The same session, in front or not as `active` says. A no-op on
    /// [`DisplaySession::None`].
    pub fn with_active(&self, active: bool) -> DisplaySession {
        match self {
            DisplaySession::None => DisplaySession::None,
            DisplaySession::Locked { id, .. } => DisplaySession::new(id, true, active),
            DisplaySession::Unlocked { id, .. } => DisplaySession::new(id, false, active),
        }
    }

    pub fn is_locked(&self) -> bool {
        matches!(self, DisplaySession::Locked { .. })
    }

    /// The display session's id, if there is one.
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

    fn inactive_unlocked_display_session() -> DisplaySession {
        DisplaySession::Unlocked {
            id: "31".to_string(),
            active: false,
        }
    }

    #[test]
    fn new_is_locked_or_unlocked_as_asked() {
        assert_eq!(
            DisplaySession::new("31", true, true),
            locked_display_session()
        );
        assert_eq!(
            DisplaySession::new("31", false, true),
            unlocked_display_session()
        );
        assert_eq!(
            DisplaySession::new("31", false, false),
            inactive_unlocked_display_session()
        );
    }

    /// `with_locked` and `with_active` carry the session across and only
    /// change the one property asked for; both are a no-op on
    /// `DisplaySession::None` (there is nothing to carry).
    #[test]
    fn with_locked_and_with_active_change_one_property_at_a_time() {
        assert_eq!(
            unlocked_display_session().with_locked(true),
            locked_display_session()
        );
        assert_eq!(
            locked_display_session().with_locked(false),
            unlocked_display_session()
        );
        assert_eq!(
            unlocked_display_session().with_active(false),
            inactive_unlocked_display_session()
        );
        assert_eq!(
            inactive_unlocked_display_session().with_active(true),
            unlocked_display_session()
        );
        assert_eq!(DisplaySession::None.with_locked(true), DisplaySession::None);
        assert_eq!(
            DisplaySession::None.with_active(false),
            DisplaySession::None
        );
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
