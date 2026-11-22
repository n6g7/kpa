//! Test helpers for this subsystem's unit tests: real
//! `session-bind@openssh.com` messages, and a real `Databases` with the agent
//! on it, with the stand-ins at the lowest seams: in-memory databases,
//! scripted prompts, and a display session the test sets.
//!
//! The real clock runs: a test that needs a backoff to have passed builds
//! the agent with none, and one that needs it to last builds it with a long
//! one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use signature::Signer;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::encoding::Encode;
use ssh_key::{Fingerprint, HashAlg, PrivateKey, Signature};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::wire::SessionBind;
use super::{Agent, SshState};
use crate::authn::Requester;
use crate::config::{DatabaseConfig, SshKeyConfig, SshKeyConfirm};
use crate::databases::Databases;
use crate::display_session::{self, DisplaySession, DisplayWriter};
use crate::paths::Paths;
use crate::prompt::{ConfirmAnswer, Prompt, PromptQueue, Scripted};
use crate::ssh::approvals::{Approvals, Grant, GrantSource, PendingRequest, Scope};
use crate::ssh::keys;
use crate::ssh::testing::{database, key_entry};

/// A real `session-bind@openssh.com` message for `session_id`, signed by
/// `host`.
pub(super) fn signed_bind(
    host: &PrivateKey,
    session_id: &[u8],
    is_forwarding: bool,
) -> SessionBind {
    let signature: Signature = host.try_sign(session_id).expect("signing should succeed");
    SessionBind {
        hostkey: host.public_key().to_bytes().expect("key encodes"),
        session_id: session_id.to_vec(),
        signature: signature.encode_vec().expect("signature encodes"),
        is_forwarding,
    }
}

/// A `session-bind@openssh.com` message as a host that presents a certificate
/// sends it: the host key is a host certificate for `host` and the host name
/// `principal`, made by `ca` for as long as there is time, and `host` signs
/// the session identifier.
pub(super) fn certified_bind(
    host: &PrivateKey,
    ca: &PrivateKey,
    principal: &str,
    session_id: &[u8],
    is_forwarding: bool,
) -> SessionBind {
    let mut builder = Builder::new(
        vec![0; 16],
        host.public_key().key_data().clone(),
        0,
        u64::MAX,
    )
    .expect("a valid window");
    builder
        .cert_type(CertType::Host)
        .expect("a host certificate")
        .valid_principal(principal)
        .expect("a principal");
    let certificate = builder.sign(ca).expect("the CA signs");
    SessionBind {
        hostkey: certificate.to_bytes().expect("certificate encodes"),
        ..signed_bind(host, session_id, is_forwarding)
    }
}

/// The data of an SSH login for `user` with `key`, signed over `session_id`:
/// a `SSH2_MSG_USERAUTH_REQUEST`, as the `ssh` client asks the agent to sign
/// it.
pub(super) fn login_data(key: &PrivateKey, session_id: &[u8], user: &str) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend((bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
    }
    let mut data = Vec::new();
    string(&mut data, session_id);
    data.push(50);
    string(&mut data, user.as_bytes());
    string(&mut data, b"ssh-connection");
    string(&mut data, b"publickey");
    data.push(1);
    string(&mut data, key.algorithm().as_str().as_bytes());
    string(
        &mut data,
        &key.public_key().to_bytes().expect("key encodes"),
    );
    data
}

/// The display session the fixture starts with, and so the one a requester
/// on the desktop runs in.
pub(super) const SESSION: &str = "3";

/// How long a cancelled prompt holds its database's prompts back, in a
/// fixture that lets it.
pub(super) const BACKOFF: Duration = Duration::from_secs(120);

/// How long a database may sit idle before the core locks it.
pub(super) const IDLE: Duration = Duration::from_secs(3600);

/// A requester on the desktop of the display session the fixture starts
/// with, so prompts may appear for it.
pub(super) fn requester() -> Requester {
    Requester {
        uid: 0,
        cgroup: Some(format!(
            "0::/user.slice/user-0.slice/session-{SESSION}.scope\n"
        )),
        command: None,
        terminal: None,
        preferred: None,
    }
}

/// A requester outside the desktop, in a system service, where no prompt
/// may appear for it.
pub(super) fn outside() -> Requester {
    Requester {
        cgroup: Some("0::/system.slice/cron.service\n".to_string()),
        ..requester()
    }
}

/// A requester outside the desktop, running `command`.
pub(super) fn outside_running(command: &str) -> Requester {
    Requester {
        command: Some(command.to_string()),
        ..outside()
    }
}

/// What a fixture is built with.
#[derive(Clone)]
pub(super) struct Options {
    pub(super) backoff: Duration,
    /// Where the agent finds `known_hosts`.
    pub(super) known_hosts: Vec<PathBuf>,
    /// Whether the public-key cache has a directory.
    pub(super) cache: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            backoff: BACKOFF,
            known_hosts: Vec::new(),
            cache: true,
        }
    }
}

/// The real core, with the agent's state and the approvals registered as
/// observers, and an agent on it. Prompts may appear for [`requester`]
/// unless [`Fixture::without_prompts`] says otherwise.
pub(super) struct Fixture {
    pub(super) databases: Arc<Databases>,
    pub(super) state: Arc<SshState>,
    pub(super) approvals: Arc<Approvals>,
    pub(super) agent: Arc<Agent>,
    /// The script the unlock prompt follows.
    pub(super) unlocks: Scripted<Zeroizing<String>>,
    /// The script the confirm prompts follow.
    pub(super) confirms: Scripted<ConfirmAnswer>,
    pub(super) display: Arc<DisplayWriter>,
    cache_dir: Option<tempfile::TempDir>,
}

impl Fixture {
    /// Every database in `configs`, locked.
    pub(super) fn new(configs: Vec<DatabaseConfig>, options: Options) -> Fixture {
        let cache_dir = options.cache.then(|| tempfile::tempdir().expect("tempdir"));
        let state = Arc::new(SshState::new(
            cache_dir.as_ref().and_then(cache_under),
            options.backoff,
        ));
        let approvals = Arc::new(Approvals::new());
        let mut databases = Databases::for_test(configs, IDLE);
        databases.observe(approvals.clone());
        databases.observe(state.clone());
        let databases = Arc::new(databases);
        let (writer, display) = display_session::channel();
        writer.set(DisplaySession::Unlocked {
            id: SESSION.to_string(),
            active: true,
        });
        let queue = Arc::new(PromptQueue::new());
        let unlocks = Scripted::new();
        let confirms = Scripted::new();
        let agent = Agent::new(
            Arc::clone(&databases),
            Arc::clone(&state),
            Arc::clone(&approvals),
            display,
            Arc::new(Prompt::new(
                Arc::clone(&queue),
                unlocks.clone(),
                Duration::from_secs(60),
            )),
            Prompt::new(queue, confirms.clone(), Duration::from_secs(60)),
            options.known_hosts,
        );
        Fixture {
            databases,
            state,
            approvals,
            agent: Arc::new(agent),
            unlocks,
            confirms,
            display: Arc::new(writer),
            cache_dir,
        }
    }

    /// One database, `personal`, serving `key` as `github` under `confirm`,
    /// unlocked.
    pub(super) fn unlocked(key: &PrivateKey, confirm: SshKeyConfirm) -> Fixture {
        Fixture::unlocked_with(key, confirm, Options::default())
    }

    pub(super) fn unlocked_with(
        key: &PrivateKey,
        confirm: SshKeyConfirm,
        options: Options,
    ) -> Fixture {
        let fixture = Fixture::new(vec![serving(key, confirm)], options);
        fixture.unlock(key);
        fixture
    }

    /// As [`Fixture::unlocked`], but locked as an earlier unlock leaves it:
    /// the cache lists `key`, and an unlock prompt that is answered with the
    /// right password opens the database with `key` in it.
    pub(super) fn locked(key: &PrivateKey, confirm: SshKeyConfirm) -> Fixture {
        Fixture::locked_with(key, confirm, Options::default())
    }

    pub(super) fn locked_with(
        key: &PrivateKey,
        confirm: SshKeyConfirm,
        options: Options,
    ) -> Fixture {
        let fixture = Fixture::new(vec![serving(key, confirm)], options);
        let cache = fixture.cache_dir().expect("a fixture with a cache");
        keys::write_cache(&cache, "personal", &[key.public_key().clone()]).expect("write cache");
        fixture.write(key);
        fixture
    }

    /// No prompt may appear: there is no display session.
    pub(super) fn without_prompts(self) -> Fixture {
        self.display.set(DisplaySession::None);
        self
    }

    /// Where the public-key cache lives.
    pub(super) fn cache_dir(&self) -> Option<PathBuf> {
        self.cache_dir.as_ref().and_then(cache_under)
    }

    /// `personal` is unlocked, as the user's own `kpa unlock` leaves it.
    pub(super) fn unlock(&self, key: &PrivateKey) {
        self.databases
            .install_for_test("personal", vec![key_entry("github", key)]);
    }

    /// `personal`'s file is a real database holding `key`, which the next
    /// unlock reads: `databases::testing::PASSWORD` opens it.
    pub(super) fn write(&self, key: &PrivateKey) {
        self.databases
            .write_for_test("personal", vec![key_entry("github", key)]);
    }

    /// Whether `personal` is unlocked.
    pub(super) fn is_unlocked(&self) -> bool {
        self.databases.any_unlocked()
    }

    /// What `kpa ssh pending` lists for `personal`.
    pub(super) fn pending(&self) -> Vec<PendingRequest> {
        match self.databases.open("personal") {
            Ok(open) => self.approvals.pending(&open, SystemTime::now()),
            Err(_) => Vec::new(),
        }
    }

    /// What `kpa ssh approve` does for the request `id` of `personal`: the
    /// key it approved, `None` if `personal` has no such request.
    pub(super) fn approve(&self, id: Uuid, window: Duration) -> Option<Fingerprint> {
        let open = self.databases.open("personal").ok()?;
        self.approvals
            .approve(&open, id, Instant::now(), SystemTime::now(), window)
    }

    /// What `kpa ssh grants` lists for `personal`.
    pub(super) fn grants(&self) -> Vec<Grant> {
        match self.databases.open("personal") {
            Ok(open) => self.approvals.granted(&open, Instant::now()),
            Err(_) => Vec::new(),
        }
    }

    /// Whether an approval covers `scope` in `personal` now.
    pub(super) fn is_approved(&self, scope: &Scope) -> bool {
        match self.databases.open("personal") {
            Ok(open) => self.approvals.covers(&open, scope, Instant::now()),
            Err(_) => false,
        }
    }

    /// Approves `scope` in `personal` until it locks.
    pub(super) fn grant(&self, scope: Scope) {
        let open = self.databases.open("personal").expect("unlocked");
        self.approvals
            .grant(&open, scope, GrantSource::OnScreen, SystemTime::now());
    }
}

/// Where the public-key cache lives under `dir`.
fn cache_under(dir: &tempfile::TempDir) -> Option<PathBuf> {
    keys::cache_dir(&Paths {
        cache_dir: Some(dir.path().to_path_buf()),
        ..Paths::default()
    })
}

/// `personal`, serving `key` as `github` under `confirm`.
pub(super) fn serving(key: &PrivateKey, confirm: SshKeyConfirm) -> DatabaseConfig {
    let settings = SshKeyConfig {
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256),
        name: None,
        confirm,
        forwarded: true,
        serve: true,
    };
    database("personal", vec![settings])
}
