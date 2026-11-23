//! A real `Databases` with the control socket's handlers on it, and the
//! stand-ins at the lowest seams: a recording clipboard, scripted prompts,
//! and a display session the test sets.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use super::{Api, CopyState};
use crate::authn::Requester;
use crate::clipboard::{OfferHandles, RecordingBackend};
use crate::config::Config;
use crate::databases::Databases;
use crate::display_session::{self, DisplaySession, DisplayWriter};
use crate::prompt::{PromptQueue, Scripted};
use crate::ssh::approvals::Approvals;

/// The display session the tests' display sessions name, and so the one a
/// requester on the desktop runs in.
pub(super) const SESSION: &str = "1";

pub(super) struct Fixture {
    pub api: Arc<Api>,
    pub databases: Arc<Databases>,
    pub display: Arc<DisplayWriter>,
    pub prompts: Scripted<Zeroizing<String>>,
    /// What the clipboard backend was handed, and each offer it started.
    pub offered: Arc<Mutex<Vec<String>>>,
    pub offers: OfferHandles,
}

/// `names` configured, all locked, behind an active, unlocked display
/// session; `extra` is more top-level config.
pub(super) fn fixture_with(names: &[&str], extra: &str) -> Fixture {
    let databases: String = names
        .iter()
        .map(|name| format!("[[database]]\nname = \"{name}\"\npath = \"{name}.kdbx\"\n"))
        .collect();
    let config = Config::parse(&format!("{extra}\n{databases}")).expect("valid config");
    let (backend, offered, offers) = RecordingBackend::new_tracking();
    let prompts = Scripted::new();
    let (display, handle) = display_session::channel();
    display.set(DisplaySession::Unlocked {
        id: SESSION.to_string(),
        active: true,
    });
    let copies = Arc::new(CopyState::new(Box::new(backend)));
    let approvals = Arc::new(Approvals::new());
    let mut core = Databases::for_test(config.databases.clone(), config.idle_timeout);
    core.observe(copies.clone());
    core.observe(approvals.clone());
    let databases = Arc::new(core);
    let api = Arc::new(Api::new(
        Arc::clone(&databases),
        handle,
        approvals,
        copies,
        Arc::new(PromptQueue::new()),
        Arc::new(prompts.clone()),
        &config,
    ));
    Fixture {
        api,
        databases,
        display: Arc::new(display),
        prompts,
        offered,
        offers,
    }
}

/// The cgroup of a process on the desktop of `SESSION`, or in a system
/// service.
fn cgroup_in(on_desktop: bool) -> String {
    let uid = crate::authn::process_uid();
    if on_desktop {
        format!("0::/user.slice/user-{uid}.slice/session-{SESSION}.scope\n")
    } else {
        "0::/system.slice/cron.service\n".to_string()
    }
}

/// Serves `fx`'s `Api` on a socket in a directory of its own, to connections
/// that come from the desktop of `SESSION` or, if not `on_desktop`, from a
/// system service. The directory goes when the returned handle does.
pub(super) fn serve(fx: &Fixture, on_desktop: bool) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("sock");
    crate::authn::assume_cgroup(&socket, &cgroup_in(on_desktop));
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    let api = Arc::clone(&fx.api);
    std::thread::spawn(move || super::serve(api, listener));
    (dir, socket)
}

/// `personal` and `work`.
pub(super) fn fixture() -> Fixture {
    fixture_with(&["personal", "work"], "")
}

/// A requester on the desktop of the display session `SESSION`, or, if not
/// `on_desktop`, in a system service.
pub(super) fn requester_in(on_desktop: bool) -> Requester {
    Requester {
        uid: crate::authn::process_uid(),
        cgroup: Some(cgroup_in(on_desktop)),
        command: None,
        terminal: None,
        preferred: None,
    }
}

pub(super) fn desktop() -> Requester {
    requester_in(true)
}

pub(super) fn outside() -> Requester {
    requester_in(false)
}
