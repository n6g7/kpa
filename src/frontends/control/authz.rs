//! What kpa's own socket lets a request do, decided against the display
//! session as it is when the request is answered: where a `copy` may put its
//! secret, and where an `unlock` asks for the password. Pure: a requester
//! and a display session in, what the request may use or its refusal out.

use super::proto::{CopyError, UnlockError};
use crate::authn::Requester;
use crate::authz::{may_prompt_on_screen, on_desktop};
use crate::display_session::DisplaySession;
use crate::prompt::PromptOn;

/// The display session whose clipboard a `copy` from `requester` may put
/// its secret on: the requester is on the desktop, and the display session
/// is active and not locked (`docs/headless.md` § 5). Anything else is
/// `no_display`, and the clipboard is never touched. It is the display
/// session itself that comes back, not just its id: the clipboard backend
/// judges the compositor against it.
pub fn authorize_copy<'s>(
    requester: &Requester,
    display_session: &'s DisplaySession,
) -> Result<&'s DisplaySession, CopyError> {
    match display_session {
        DisplaySession::Unlocked { active: true, .. } if on_desktop(requester, display_session) => {
            Ok(display_session)
        }
        _ => Err(CopyError::NoDisplay),
    }
}

/// Where an `unlock` asks for the password. A requester that names a place
/// ([`Requester::preferred`]) is asked there or nowhere: `Screen` only where
/// a prompt may appear on screen ([`may_prompt_on_screen`]), `Terminal` only
/// if it passed one.
/// Otherwise the daemon asks on screen where a prompt may appear, and on the
/// terminal the requester passed where not. `no_prompt` where there is
/// nowhere to ask, since nobody could answer.
pub fn choose_unlock_prompt(
    requester: &Requester,
    display_session: &DisplaySession,
) -> Result<PromptOn, UnlockError> {
    let screen_allowed = may_prompt_on_screen(requester, display_session);
    let has_terminal = requester.terminal.is_some();
    match requester.preferred {
        Some(PromptOn::Screen) => screen_allowed.then_some(PromptOn::Screen),
        Some(PromptOn::Terminal) => has_terminal.then_some(PromptOn::Terminal),
        None if screen_allowed => Some(PromptOn::Screen),
        None => has_terminal.then_some(PromptOn::Terminal),
    }
    .ok_or(UnlockError::NoPrompt)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::prompt::Terminal;

    const UID: u32 = 1000;
    const DESKTOP: &str = "0::/user.slice/user-1000.slice/session-3.scope\n";
    const CRON: &str = "0::/system.slice/cron.service\n";

    fn requester(cgroup: &str) -> Requester {
        Requester {
            uid: UID,
            cgroup: Some(cgroup.to_string()),
            command: None,
            terminal: None,
            preferred: None,
        }
    }

    fn unlocked(id: &str, active: bool) -> DisplaySession {
        DisplaySession::Unlocked {
            id: id.to_string(),
            active,
        }
    }

    fn locked(id: &str) -> DisplaySession {
        DisplaySession::Locked {
            id: id.to_string(),
            active: true,
        }
    }

    /// A terminal a requester passed: the slave end of a pseudo-terminal.
    fn passed_terminal() -> Terminal {
        let (_master, slave) = crate::prompt::testing::pty();
        let (_client, connection) = UnixStream::pair().expect("connection");
        Terminal::new(slave, &connection).expect("a terminal")
    }

    /// `docs/headless.md` § 5: `copy` needs a requester on the desktop, an
    /// active display session, and `LockedHint` false; every other
    /// combination gets `no_display`.
    #[test]
    fn only_a_desktop_requester_on_an_active_unlocked_display_session_may_copy() {
        let (desktop, outside) = (requester(DESKTOP), requester(CRON));
        let active = unlocked("3", true);
        assert_eq!(authorize_copy(&desktop, &active), Ok(&active));
        for (requester, display_session) in [
            (&outside, unlocked("3", true)),
            (&desktop, locked("3")),
            (&outside, locked("3")),
            (&desktop, unlocked("3", false)),
            (&outside, unlocked("3", false)),
            (&desktop, DisplaySession::None),
            (&outside, DisplaySession::None),
        ] {
            assert_eq!(
                authorize_copy(requester, &display_session),
                Err(CopyError::NoDisplay),
                "{requester:?} on {display_session:?}"
            );
        }
    }

    #[test]
    fn a_prompt_is_asked_on_screen_where_one_may_appear_and_otherwise_on_the_terminal() {
        use PromptOn::{Screen, Terminal};

        // (screen allowed, terminal passed, where the request prefers) and
        // where it is asked.
        for (screen_allowed, has_terminal, preferred, expected) in [
            (true, true, None, Ok(Screen)),
            (true, false, None, Ok(Screen)),
            (false, true, None, Ok(Terminal)),
            (false, false, None, Err(UnlockError::NoPrompt)),
            // The terminal, even where the screen would do.
            (true, true, Some(Terminal), Ok(Terminal)),
            (false, true, Some(Terminal), Ok(Terminal)),
            (true, false, Some(Terminal), Err(UnlockError::NoPrompt)),
            (false, false, Some(Terminal), Err(UnlockError::NoPrompt)),
            // The screen only, never the terminal.
            (true, true, Some(Screen), Ok(Screen)),
            (true, false, Some(Screen), Ok(Screen)),
            (false, true, Some(Screen), Err(UnlockError::NoPrompt)),
            (false, false, Some(Screen), Err(UnlockError::NoPrompt)),
        ] {
            // A requester on the desktop of an unlocked display session may
            // be prompted on screen; one outside it may not.
            let mut requester = requester(if screen_allowed { DESKTOP } else { CRON });
            requester.terminal = has_terminal.then(passed_terminal);
            requester.preferred = preferred;
            assert_eq!(
                choose_unlock_prompt(&requester, &unlocked("3", true)),
                expected,
                "screen allowed: {screen_allowed}, terminal passed: {has_terminal}, \
                 preferred: {preferred:?}"
            );
        }
    }

    #[test]
    fn no_prompt_appears_on_screen_behind_a_locker_or_without_a_display_session() {
        let desktop = requester(DESKTOP);
        assert_eq!(
            choose_unlock_prompt(&desktop, &locked("3")),
            Err(UnlockError::NoPrompt)
        );
        assert_eq!(
            choose_unlock_prompt(&desktop, &DisplaySession::None),
            Err(UnlockError::NoPrompt)
        );
    }

    /// A prompt behind an inactive display session (a VT switch) still
    /// shows, so `active` is not read.
    #[test]
    fn an_unlock_prompt_ignores_whether_the_display_session_is_active() {
        assert_eq!(
            choose_unlock_prompt(&requester(DESKTOP), &unlocked("3", false)),
            Ok(PromptOn::Screen)
        );
    }
}
