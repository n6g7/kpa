//! Wiring: builds the core and the front ends on it, registers what reacts
//! to a lock, and starts the threads. Nothing else decides what reacts to a
//! lock or in which order.

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::clipboard::{self, WaylandBackend};
use crate::config::Config;
use crate::databases::{Databases, Observer};
use crate::display_session::{self, DisplayHandle};
use crate::frontends::auto_lock::{self, Source};
use crate::frontends::control::{self, Api, CopyState};
use crate::frontends::ssh_agent::{self, Agent, SshState};
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
/// every offer has ended and every private key is gone.
pub fn build(
    config: Config,
    paths: Paths,
    backends: Backends,
    display: DisplayHandle,
    sleep_hold: Arc<dyn Observer>,
) -> Daemon {
    let copies = Arc::new(CopyState::new(backends.clipboard));
    let approvals = Arc::new(Approvals::new());
    let ssh = Arc::new(SshState::new(
        keys::cache_dir(&paths),
        config.ssh_agent.backoff,
    ));
    let mut databases = Databases::new(config.databases.clone(), config.idle_timeout);
    databases.observe(copies.clone());
    databases.observe(approvals.clone());
    databases.observe(ssh.clone());
    databases.observe(sleep_hold);
    let databases = Arc::new(databases);

    // One prompt on screen at a time, whoever asks.
    let prompts = Arc::new(PromptQueue::new());
    let screen_unlock = Arc::new(Prompt::new(
        Arc::clone(&prompts),
        Arc::clone(&backends.unlock_prompt),
        config.prompt_timeout,
    ));
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
        paths.known_hosts,
    ));
    Daemon {
        databases,
        api,
        agent,
    }
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

/// Runs the daemon: the lock triggers, and the SSH agent's socket if there
/// is one, on threads of their own, kpa's own socket on this one.
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
    let daemon = build(config, paths, backends, display, Arc::new(sleep_hold));

    let databases = Arc::clone(&daemon.databases);
    std::thread::Builder::new()
        .name("auto-lock".to_string())
        .spawn(move || auto_lock.run(databases, idle_timeout))
        .expect("spawn the auto-lock thread");
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
    use std::sync::Mutex;

    use super::*;
    use crate::cancel::CancelToken;
    use crate::clipboard::{OfferHandles, RecordingBackend};
    use crate::databases::testing::TestEntry;
    use crate::display_session::DisplaySession;
    use crate::frontends::control::proto::{CopyRequest, Field, Op, Request, encode_request};

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

    /// The sleep hold is registered after what holds a secret, so when it
    /// is told of a lock the clipboard offer has ended.
    #[test]
    fn the_sleep_hold_is_told_after_the_secret_holders() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("personal.kdbx");
        std::fs::write(&path, b"placeholder").expect("placeholder");
        let config = Config::parse(&format!(
            "[[database]]\nname = \"personal\"\npath = {:?}\n",
            path.display().to_string()
        ))
        .expect("valid config");
        let (backend, _offered, offers) = RecordingBackend::new_tracking();
        let backends = Backends {
            clipboard: Box::new(backend),
            unlock_prompt: Arc::new(prompt::Scripted::<Zeroizing<String>>::new()),
            confirm_prompt: Arc::new(prompt::Scripted::<ConfirmAnswer>::new()),
        };
        let (display, handle) = display_session::channel();
        display.set(DisplaySession::Unlocked {
            id: "1".to_string(),
            active: true,
        });
        let probe = Arc::new(SleepHoldProbe {
            offers,
            live_when_told: Mutex::new(Vec::new()),
        });
        let daemon = build(config, Paths::default(), backends, handle, probe.clone());
        daemon.databases.install_for_test(
            "personal",
            vec![TestEntry::new("site").field("Password", "secret")],
        );
        let uuid = daemon.databases.open("personal").ok().unwrap().entries()[0].uuid;
        let socket = dir.path().join("sock");
        let uid = crate::authn::process_uid();
        crate::authn::assume_cgroup(
            &socket,
            &format!("0::/user.slice/user-{uid}.slice/session-1.scope\n"),
        );
        let listener = UnixListener::bind(&socket).expect("bind");
        let databases = Arc::clone(&daemon.databases);
        std::thread::spawn(move || daemon.serve_control(listener));
        let request = Request {
            v: crate::frontends::control::proto::VERSION,
            preferred_prompt: None,
            op: Op::Copy(CopyRequest {
                db: "personal".to_string(),
                uuid,
                field: Field::Password,
            }),
        };
        let mut stream = UnixStream::connect(&socket).expect("connect");
        stream
            .write_all(&encode_request(&request).expect("encodes"))
            .expect("send");
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).expect("reply");
        assert!(reply.contains("\"ok\":true"), "the copy failed: {reply}");

        databases.lock_all();

        assert_eq!(*probe.live_when_told.lock().unwrap(), [false]);
    }
}
