//! What kpa's own socket lets a request do: one pure function per request
//! type, returning what the request may use or the refusal it gets
//! (`docs/headless.md` §§ 2 and 5).
//!
//! There are three policies, each in its own place. [`authz`] holds the
//! checks both sockets share (who may connect, who is on the desktop, where
//! a prompt may appear). This module is the policy of kpa's socket, built on
//! them, and `ssh_agent::policy` is the policy of the SSH agent's.
//! `policy` is unrelated: it holds the auto-lock rules and the
//! [`DisplaySession`] type.
//!
//! Each function takes the requester and the display session as it is when
//! the request is answered, and decides nothing else: the caller does the
//! work.

use crate::authn::Requester;
use crate::authz;
use crate::policy::DisplaySession;
use crate::proto::{CopyError, UnlockError, UnlockRequest};

/// The display session whose clipboard a `copy` from `requester` may put
/// its secret on: the requester is on the desktop, and the display session
/// is active and not locked (`docs/headless.md` § 5). Anything else is
/// `no_display`, and the clipboard is never touched.
pub fn copy<'s>(
    requester: &Requester,
    display_session: &'s DisplaySession,
) -> Result<&'s str, CopyError> {
    match display_session {
        DisplaySession::Unlocked { id, active: true }
            if authz::on_desktop(requester, display_session) =>
        {
            Ok(id)
        }
        _ => Err(CopyError::NoDisplay),
    }
}

/// Whether `request` may go on to unlock: a request that carries its
/// password needs no prompt, so it goes ahead from anywhere (that is how an
/// unlock from outside the desktop is answered). One that needs a prompt
/// may be answered only where a prompt may appear
/// ([`authz::may_prompt_on_screen`]), else it is `no_display`.
pub fn unlock(
    request: &UnlockRequest,
    requester: &Requester,
    display_session: &DisplaySession,
) -> Result<(), UnlockError> {
    if request.password.is_none() && !authz::may_prompt_on_screen(requester, display_session) {
        return Err(UnlockError::NoDisplay);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Password;
    use zeroize::Zeroizing;

    const DESKTOP: &str = "0::/user.slice/user-1000.slice/session-3.scope\n";
    const CRON: &str = "0::/system.slice/cron.service\n";

    fn requester(cgroup: &str) -> Requester {
        Requester {
            uid: 1000,
            cgroup: Some(cgroup.to_string()),
            command: None,
        }
    }

    fn unlocked(active: bool) -> DisplaySession {
        DisplaySession::Unlocked {
            id: "3".to_string(),
            active,
        }
    }

    fn locked() -> DisplaySession {
        DisplaySession::Locked {
            id: "3".to_string(),
            active: true,
        }
    }

    fn unlock_request(password: Option<&str>) -> UnlockRequest {
        UnlockRequest {
            db: "personal".to_string(),
            password: password.map(|password| Password::new(Zeroizing::new(password.to_string()))),
        }
    }

    /// `docs/headless.md` § 5: `copy` needs a requester on the desktop, an
    /// active display session, and `LockedHint` false; every other
    /// combination gets `no_display`.
    #[test]
    fn only_a_desktop_requester_on_an_active_unlocked_display_session_may_copy() {
        let (desktop, outside) = (requester(DESKTOP), requester(CRON));
        assert_eq!(copy(&desktop, &unlocked(true)), Ok("3"));
        assert_eq!(copy(&outside, &unlocked(true)), Err(CopyError::NoDisplay));
        assert_eq!(copy(&desktop, &locked()), Err(CopyError::NoDisplay));
        assert_eq!(copy(&outside, &locked()), Err(CopyError::NoDisplay));
        assert_eq!(copy(&desktop, &unlocked(false)), Err(CopyError::NoDisplay));
        assert_eq!(copy(&outside, &unlocked(false)), Err(CopyError::NoDisplay));
        assert_eq!(
            copy(&desktop, &DisplaySession::None),
            Err(CopyError::NoDisplay)
        );
        assert_eq!(
            copy(&outside, &DisplaySession::None),
            Err(CopyError::NoDisplay)
        );
    }

    #[test]
    fn an_unlock_that_needs_a_prompt_needs_a_requester_on_the_desktop_and_no_locker() {
        let (desktop, outside) = (requester(DESKTOP), requester(CRON));
        let asking = unlock_request(None);
        assert_eq!(unlock(&asking, &desktop, &unlocked(true)), Ok(()));
        assert_eq!(
            unlock(&asking, &desktop, &locked()),
            Err(UnlockError::NoDisplay)
        );
        assert_eq!(
            unlock(&asking, &outside, &unlocked(true)),
            Err(UnlockError::NoDisplay)
        );
        assert_eq!(
            unlock(&asking, &desktop, &DisplaySession::None),
            Err(UnlockError::NoDisplay)
        );
    }

    /// A prompt behind an inactive display session (a VT switch) still
    /// shows, so `active` is not read.
    #[test]
    fn an_unlock_prompt_ignores_whether_the_display_session_is_active() {
        assert_eq!(
            unlock(&unlock_request(None), &requester(DESKTOP), &unlocked(false)),
            Ok(())
        );
    }

    #[test]
    fn an_unlock_that_carries_its_password_goes_ahead_from_anywhere() {
        let carrying = unlock_request(Some("hunter2"));
        let outside = requester(CRON);
        assert_eq!(unlock(&carrying, &outside, &DisplaySession::None), Ok(()));
        assert_eq!(unlock(&carrying, &outside, &locked()), Ok(()));
    }
}
