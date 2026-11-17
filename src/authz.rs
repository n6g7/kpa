//! The checks about a [`Requester`] that both sockets share, made when a
//! request is answered, against the display session as it is then
//! (`docs/headless.md` §§ 2 and 3). What each socket's requests may do with
//! them is that socket's own policy: `request_policy` for kpa's socket,
//! `ssh_agent::policy` for the agent's.
//!
//! A requester holds facts read from its socket. Whether it runs on the
//! desktop is not one of them: it depends on which session is the display
//! session now, and a connection outlives sessions. So each decision here
//! takes the requester and the current [`DisplaySession`], and nothing
//! caches the answer. Every function is pure.
//!
//! This decides where to ask, not who may ask: a same-uid process can move
//! work into another cgroup (NG-1). Every failure, from a cgroup that
//! wasn't read to one that doesn't parse, counts as outside the desktop.

use crate::authn::Requester;
use crate::policy::DisplaySession;

/// Whether `requester` may talk to the daemon at all: only `owner`, the
/// daemon's own user, may.
pub fn may_connect(requester: &Requester, owner: u32) -> bool {
    requester.uid == owner
}

/// Whether `requester` runs on the desktop of `display_session`: under the
/// user's service manager, or in the display session's scope, which is
/// where the compositor and everything it spawns live.
pub fn on_desktop(requester: &Requester, display_session: &DisplaySession) -> bool {
    display_session
        .id()
        .is_some_and(|session| in_desktop_cgroup(requester, session))
}

/// Whether a prompt may be raised on screen for `requester`: it runs on the
/// desktop, and the display session isn't known to be locked. Never reads
/// `active`: an inactive display session (a VT switch) still shows a prompt.
pub fn may_prompt_on_screen(requester: &Requester, display_session: &DisplaySession) -> bool {
    on_desktop(requester, display_session) && !display_session.is_locked()
}

/// Whether the requester's cgroup is the desktop of the logind session
/// `session`.
///
/// Only the unified hierarchy's line (`0::<path>`) is read: there must be
/// exactly one, with an absolute path (a cgroup namespace shows a path
/// outside it as `/..`, which fails the prefix check anyway). The desktop is
/// a path under `/user.slice/user-<uid>.slice/`, in either
/// `user@<uid>.service` or `session-<session>.scope`.
fn in_desktop_cgroup(requester: &Requester, session: &str) -> bool {
    let Some(cgroup) = requester.cgroup.as_deref() else {
        return false;
    };
    if session.is_empty() {
        return false;
    }
    let mut unified = cgroup.lines().filter_map(|line| line.strip_prefix("0::"));
    let (Some(path), None) = (unified.next(), unified.next()) else {
        return false;
    };
    let uid = requester.uid;
    let Some(rest) = path.strip_prefix(&format!("/user.slice/user-{uid}.slice/")) else {
        return false;
    };
    let unit = rest.split('/').next().unwrap_or_default();
    unit == format!("user@{uid}.service") || unit == format!("session-{session}.scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 1000;
    const SESSION: &str = "3";
    const DESKTOP: &str = "0::/user.slice/user-1000.slice/session-3.scope\n";
    const CRON: &str = "0::/system.slice/cron.service\n";

    fn requester(cgroup: &str) -> Requester {
        Requester {
            uid: UID,
            cgroup: Some(cgroup.to_string()),
            command: None,
        }
    }

    fn without_cgroup() -> Requester {
        Requester {
            uid: UID,
            cgroup: None,
            command: None,
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

    /// Whether a requester with `cgroup` is on the desktop of the display
    /// session `SESSION`.
    fn on_desktop_of_session(cgroup: &str) -> bool {
        on_desktop(&requester(cgroup), &unlocked(SESSION, true))
    }

    #[test]
    fn the_desktop_is_the_service_manager_and_the_display_session() {
        let desktop = [
            // A compositor child: an app the compositor or launcher spawned.
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot-1234.scope\n",
            // The compositor itself, run as a user service.
            "0::/user.slice/user-1000.slice/user@1000.service/session.slice/compositor.service\n",
            // The service manager's own cgroup.
            "0::/user.slice/user-1000.slice/user@1000.service\n",
            // The display session's scope: a compositor started from a
            // login shell, and everything it spawns.
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            // A hybrid hierarchy: only the `0::` line counts.
            "12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice/user-1000.slice/session-3.scope\n",
        ];
        for cgroup in desktop {
            assert!(on_desktop_of_session(cgroup), "{cgroup:?}");
        }
    }

    #[test]
    fn everything_else_is_outside() {
        let outside = [
            // An SSH login, or any other session that isn't the display one.
            "0::/user.slice/user-1000.slice/session-5.scope\n",
            // A session id that only starts with the display session's.
            "0::/user.slice/user-1000.slice/session-31.scope\n",
            // A system service: a cron job, or a terminal server's shell,
            // even one used at the desk.
            "0::/system.slice/cron.service\n",
            "0::/system.slice/terminal-server.service/shell-7.scope\n",
            // A terminal server registered as a logind session: each
            // connection is its own remote session under the user's slice,
            // with a scope that isn't the display session's.
            "0::/user.slice/user-1000.slice/session-12.scope/shell.scope\n",
            // Another user's service manager and session.
            "0::/user.slice/user-1001.slice/user@1001.service/app.slice/a.scope\n",
            "0::/user.slice/user-1001.slice/session-3.scope\n",
            // Names that only start like the desktop's units.
            "0::/user.slice/user-1000.slice/user@1000.service-x/a.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope.d\n",
            // The user slice itself, and the root.
            "0::/user.slice/user-1000.slice\n",
            "0::/\n",
        ];
        for cgroup in outside {
            assert!(!on_desktop_of_session(cgroup), "{cgroup:?}");
        }
    }

    #[test]
    fn malformed_input_is_outside() {
        let malformed = [
            "",
            "\n",
            "garbage",
            // No unified line: a v1-only hierarchy.
            "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
            // A relative path, and a path outside a cgroup namespace.
            "0::user.slice/user-1000.slice/session-3.scope\n",
            "0::/../../user.slice/user-1000.slice/session-3.scope\n",
            // Two unified lines.
            "0::/user.slice/user-1000.slice/session-3.scope\n0::/system.slice/x.service\n",
            "0::/system.slice/x.service\n0::/user.slice/user-1000.slice/session-3.scope\n",
            // The prefix without its separator.
            "0::/user.slice/user-1000.sliceuser@1000.service\n",
        ];
        for cgroup in malformed {
            assert!(!on_desktop_of_session(cgroup), "{cgroup:?}");
        }
    }

    #[test]
    fn nothing_is_the_desktop_without_a_display_session() {
        let cgroups = [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-foot-1234.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/user.slice/user-1000.slice/session-.scope\n",
        ];
        for cgroup in cgroups {
            assert!(
                !on_desktop(&requester(cgroup), &DisplaySession::None),
                "{cgroup:?}"
            );
            assert!(
                !on_desktop(&requester(cgroup), &unlocked("", true)),
                "{cgroup:?}"
            );
        }
    }

    /// The same cgroup is the desktop in one session and outside it in
    /// another, or once there is none.
    #[test]
    fn a_requester_is_classified_against_the_session_it_is_asked_with() {
        let requester = requester(DESKTOP);
        assert!(on_desktop(&requester, &unlocked("3", true)));
        assert!(!on_desktop(&requester, &unlocked("4", true)));
        assert!(!on_desktop(&requester, &DisplaySession::None));
    }

    #[test]
    fn a_requester_whose_cgroup_was_not_read_is_outside() {
        assert!(!on_desktop(&without_cgroup(), &unlocked("3", true)));
    }

    #[test]
    fn only_a_requester_on_the_desktop_may_prompt_and_not_while_locked() {
        let (desktop, outside) = (requester(DESKTOP), requester(CRON));
        assert!(may_prompt_on_screen(&desktop, &unlocked("3", true)));
        assert!(!may_prompt_on_screen(&desktop, &locked("3")));
        assert!(!may_prompt_on_screen(&outside, &unlocked("3", true)));
        assert!(!may_prompt_on_screen(&outside, &locked("3")));
        assert!(!may_prompt_on_screen(&outside, &DisplaySession::None));
    }

    /// `may_prompt_on_screen` never reads `active`: an inactive display
    /// session (a VT switch) is treated like an active one for prompting.
    #[test]
    fn may_prompt_ignores_whether_the_display_session_is_active() {
        assert!(may_prompt_on_screen(
            &requester(DESKTOP),
            &unlocked("3", false)
        ));
    }

    #[test]
    fn only_the_daemons_own_user_may_connect() {
        let requester = without_cgroup();
        assert!(may_connect(&requester, UID));
        assert!(!may_connect(&requester, UID + 1));
    }
}
