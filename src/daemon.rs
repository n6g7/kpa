//! Wiring: builds the core and the front ends on it, registers what reacts
//! to a lock, and starts the threads. Nothing else decides what reacts to a
//! lock or in which order.
//!
//! Threads: the main thread accepts on kpa's socket and spawns a thread per
//! connection, capped, where a failed spawn drops that connection and nothing
//! else; the agent socket, if a database serves SSH keys, has its own accept
//! thread and per-connection threads; `auto_lock` has four (the logind watcher,
//! the sleep inhibitor's, the loop that reacts to events, the idle tick); the
//! tray has its service's thread and the loop that refreshes it; each
//! clipboard offer has a serving thread and an expiry thread. The core has
//! none: it is plain calls, so a test drives it from one.

use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::mpsc;

use zeroize::Zeroizing;

use crate::clipboard::{self, WaylandBackend};
use crate::config::Config;
use crate::databases::{Databases, Observer};
use crate::display_session::{self, DisplayHandle};
use crate::frontends::auto_lock::{self, Source};
use crate::frontends::control::{self, Api, CopyState};
use crate::frontends::ssh_agent::{self, Agent, SshState};
use crate::frontends::tray::{self, Tray};
use crate::paths::Paths;
use crate::prompt::{self, ConfirmAnswer, ConfirmProgram, Prompt, PromptQueue, SecretProgram};
use crate::ssh::approvals::Approvals;
use crate::ssh::keys;

/// What tests replace: the clipboard, and how the unlock and confirm
/// prompts ask on screen.
pub struct Backends {
    pub clipboard: Box<dyn clipboard::Backend>,
    pub unlock_prompt: Arc<dyn prompt::Backend<Zeroizing<String>>>,
    pub confirm_prompt: Arc<dyn prompt::Backend<ConfirmAnswer>>,
}

impl Backends {
    /// The Wayland clipboard and the configured prompt programs.
    pub fn real(config: &Config) -> Backends {
        Backends {
            clipboard: Box::new(WaylandBackend),
            unlock_prompt: Arc::new(SecretProgram::new(config.prompt.clone())),
            confirm_prompt: Arc::new(ConfirmProgram::new(config.ssh_agent.confirm_prompt.clone())),
        }
    }
}

/// Everything built, nothing running.
pub struct Daemon {
    pub databases: Arc<Databases>,
    api: Arc<Api>,
    agent: Arc<Agent>,
}

/// Builds the core with its observers registered, in this order: what holds
/// a secret (the clipboard offer, the approvals, the agent's keys), then
/// `sleep_hold`, so that when a suspend's lock has let the sleep delay go,
/// every offer has ended and every private key is gone, then the tray's,
/// which holds nothing.
///
/// The tray comes beside the daemon, not in it: it runs once, on a thread of
/// its own, and holds the receiving end of a channel, which a daemon shared
/// between threads can't.
pub fn build(
    config: Config,
    paths: Paths,
    backends: Backends,
    display: DisplayHandle,
    sleep_hold: Arc<dyn Observer>,
) -> (Daemon, Tray) {
    let copies = Arc::new(CopyState::new(backends.clipboard));
    let known_hosts = config.ssh_agent.known_hosts.clone();
    let approvals = Arc::new(Approvals::new());
    let ssh = Arc::new(SshState::new(
        keys::cache_dir(&paths),
        config.ssh_agent.backoff,
    ));
    let (changed, wake) = mpsc::channel();
    let mut databases = Databases::new(config.databases.clone(), config.idle_timeout);
    databases.observe(copies.clone());
    databases.observe(approvals.clone());
    databases.observe(ssh.clone());
    databases.observe(sleep_hold);
    databases.observe(Arc::new(tray::Changed::new(changed)));
    let databases = Arc::new(databases);

    // One prompt on screen at a time, whoever asks.
    let prompts = Arc::new(PromptQueue::new());
    let screen_unlock = Arc::new(Prompt::new(
        Arc::clone(&prompts),
        Arc::clone(&backends.unlock_prompt),
        config.prompt_timeout,
    ));
    let tray = Tray::new(
        Arc::clone(&databases),
        display.clone(),
        Arc::clone(&screen_unlock),
        wake,
    );
    let api = Arc::new(Api::new(
        Arc::clone(&databases),
        display.clone(),
        Arc::clone(&approvals),
        copies,
        Arc::clone(&prompts),
        backends.unlock_prompt,
        &config,
    ));
    let agent = Arc::new(Agent::new(
        Arc::clone(&databases),
        ssh,
        approvals,
        display,
        screen_unlock,
        Prompt::new(
            prompts,
            backends.confirm_prompt,
            config.confirm_prompt_timeout(),
        ),
        known_hosts,
    ));
    let daemon = Daemon {
        databases,
        api,
        agent,
    };
    (daemon, tray)
}

impl Daemon {
    /// Serves kpa's own socket on the calling thread, forever.
    pub fn serve_control(&self, listener: UnixListener) {
        control::serve(Arc::clone(&self.api), listener);
    }

    /// Serves the SSH agent's socket on the calling thread, forever.
    pub fn serve_agent(&self, listener: UnixListener) {
        ssh_agent::serve(Arc::clone(&self.agent), listener);
    }
}

/// Runs the daemon: the lock triggers, the tray, and the SSH agent's socket
/// if there is one, on threads of their own, kpa's own socket on this one.
pub fn serve(
    config: Config,
    paths: Paths,
    control: UnixListener,
    agent: Option<UnixListener>,
    source: Source,
) {
    let (writer, display) = display_session::channel();
    let (sleep_hold, auto_lock) = auto_lock::start(source, writer);
    let idle_timeout = config.idle_timeout;
    let backends = Backends::real(&config);
    let (daemon, tray) = build(config, paths, backends, display, Arc::new(sleep_hold));

    let databases = Arc::clone(&daemon.databases);
    std::thread::Builder::new()
        .name("auto-lock".to_string())
        .spawn(move || auto_lock.run(databases, idle_timeout))
        .expect("spawn the auto-lock thread");
    std::thread::Builder::new()
        .name("tray".to_string())
        .spawn(move || tray.run())
        .expect("spawn the tray thread");
    if let Some(listener) = agent {
        let agent = Arc::clone(&daemon.agent);
        std::thread::Builder::new()
            .name("ssh-agent".to_string())
            .spawn(move || ssh_agent::serve(agent, listener))
            .expect("spawn the ssh-agent thread");
    }
    daemon.serve_control(control);
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    use super::*;
    use crate::cancel::CancelToken;
    use crate::clipboard::{OfferHandles, RecordingBackend};
    use crate::databases::testing::TestEntry;
    use crate::display_session::DisplaySession;
    use crate::frontends::control::proto::{
        CopyRequest, Op, Request, UnlockRequest, encode_request,
    };
    use crate::prompt::{PromptOutcome, Scripted, Step};

    /// Notes whether the clipboard offer was still live when it was told of
    /// a lock.
    struct SleepHoldProbe {
        offers: OfferHandles,
        live_when_told: Mutex<Vec<bool>>,
    }

    impl Observer for SleepHoldProbe {
        fn locked(&self, _: &Databases, _: &str, _: &CancelToken) {
            let live = self.offers.lock().unwrap()[0].is_live();
            self.live_when_told.lock().unwrap().push(live);
        }
    }

    /// Hears everything and does nothing.
    struct NoSleepHold;

    impl Observer for NoSleepHold {}

    /// `names` configured, their files placeholders.
    fn config_of(dir: &Path, names: &[&str]) -> Config {
        let databases: String = names
            .iter()
            .map(|name| {
                let path = dir.join(format!("{name}.kdbx"));
                std::fs::write(&path, b"placeholder").expect("placeholder");
                format!(
                    "[[database]]\nname = \"{name}\"\npath = {:?}\n",
                    path.display().to_string()
                )
            })
            .collect();
        Config::parse(&databases).expect("valid config")
    }

    fn backends(unlock_prompt: Scripted<Zeroizing<String>>) -> (Backends, OfferHandles) {
        let (backend, _offered, offers) = RecordingBackend::new_tracking();
        let backends = Backends {
            clipboard: Box::new(backend),
            unlock_prompt: Arc::new(unlock_prompt),
            confirm_prompt: Arc::new(Scripted::<ConfirmAnswer>::new()),
        };
        (backends, offers)
    }

    /// An active, unlocked display session, session 1.
    fn desktop_display() -> DisplayHandle {
        let (writer, handle) = display_session::channel();
        writer.set(DisplaySession::Unlocked {
            id: "1".to_string(),
            active: true,
        });
        handle
    }

    /// Serves `api` on a socket in `dir`, to connections that come from the
    /// desktop of session 1.
    fn serve_on_the_desktop(api: Arc<Api>, dir: &Path) -> PathBuf {
        let socket = dir.join("sock");
        let uid = crate::authn::process_uid();
        crate::authn::assume_cgroup(
            &socket,
            &format!("0::/user.slice/user-{uid}.slice/session-1.scope\n"),
        );
        let listener = UnixListener::bind(&socket).expect("bind");
        std::thread::spawn(move || control::serve(api, listener));
        socket
    }

    /// The reply to `op`, as the line the daemon wrote.
    fn ask(socket: &Path, op: Op) -> String {
        let request = Request {
            v: crate::frontends::control::proto::VERSION,
            preferred_prompt: None,
            op,
        };
        let mut stream = UnixStream::connect(socket).expect("connect");
        stream
            .write_all(&encode_request(&request).expect("encodes"))
            .expect("send");
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).expect("reply");
        reply
    }

    /// The sleep hold is registered after what holds a secret, so when it
    /// is told of a lock the clipboard offer has ended.
    #[test]
    fn the_sleep_hold_is_told_after_the_secret_holders() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = config_of(dir.path(), &["personal"]);
        let (backends, offers) = backends(Scripted::new());
        let probe = Arc::new(SleepHoldProbe {
            offers,
            live_when_told: Mutex::new(Vec::new()),
        });
        let (daemon, _tray) = build(
            config,
            Paths::default(),
            backends,
            desktop_display(),
            probe.clone(),
        );
        daemon.databases.install_for_test(
            "personal",
            vec![TestEntry::new("site").field("Password", "secret")],
        );
        let uuid = daemon
            .databases
            .open("personal")
            .ok()
            .unwrap()
            .entries()
            .next()
            .unwrap()
            .uuid();
        let databases = Arc::clone(&daemon.databases);
        let socket = serve_on_the_desktop(Arc::clone(&daemon.api), dir.path());

        let reply = ask(
            &socket,
            Op::Copy(CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: "Password".to_string(),
            }),
        );
        assert!(reply.contains("\"ok\":true"), "the copy failed: {reply}");

        databases.lock_all();

        assert_eq!(*probe.live_when_told.lock().unwrap(), [false]);
    }

    /// The tray and kpa's own socket ask through one prompt queue: while the
    /// tray's unlock prompt is on screen, an unlock over the socket waits
    /// for its turn.
    #[test]
    fn an_unlock_from_the_tray_and_one_from_control_take_turns_on_screen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = config_of(dir.path(), &["personal", "work"]);
        let prompts = Scripted::<Zeroizing<String>>::new();
        let (up, tray_prompt_is_up) = mpsc::channel();
        let (release, held_up) = mpsc::channel::<()>();
        prompts.push(Step::new(PromptOutcome::Cancelled).while_up(move || {
            up.send(()).expect("the test is waiting");
            held_up.recv().expect("the test releases the prompt");
        }));
        prompts.push(Step::new(PromptOutcome::Cancelled));
        let (backends, _offers) = backends(prompts.clone());
        let (daemon, tray) = build(
            config,
            Paths::default(),
            backends,
            desktop_display(),
            Arc::new(NoSleepHold),
        );
        let socket = serve_on_the_desktop(Arc::clone(&daemon.api), dir.path());

        let clicked = std::thread::spawn(move || tray.unlock("personal"));
        tray_prompt_is_up
            .recv_timeout(Duration::from_secs(10))
            .expect("the tray's prompt comes up");
        let unlocking = std::thread::spawn(move || {
            ask(
                &socket,
                Op::Unlock(UnlockRequest {
                    db: "work".to_string(),
                }),
            )
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            prompts.shown(),
            ["Unlock personal"],
            "the socket's prompt was shown over the tray's"
        );

        release.send(()).expect("the prompt is up");

        assert_eq!(clicked.join().expect("tray thread"), Ok(()));
        let reply = unlocking.join().expect("control thread");
        assert!(reply.contains("prompt_cancelled"), "{reply}");
        assert_eq!(prompts.shown(), ["Unlock personal", "Unlock work"]);
    }
}
