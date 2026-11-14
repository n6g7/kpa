//! The SSH agent socket's listener and per-connection protocol loop
//! (`docs/ssh-agent.md` § 6.1): accepts connections, frames them with
//! [`wire`], tracks each one's `session-bind@openssh.com` state with
//! [`bind::SessionBindState`], and dispatches identities and signatures through
//! [`SshSign::ssh_identities`]/[`SshSign::ssh_sign`].
//!
//! Forwarding (session-bind verification aside) is out of scope here: every
//! forwarded `SIGN_REQUEST` is refused by `SshSign::ssh_sign` itself, not by
//! this module.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::log;
use crate::origin::Origin;
use crate::server::Server;
use crate::socket;

use super::bind::{self, BindOutcome, SessionBindState};
use super::wire::{self, AgentRequest, AgentResponse, Frame};

/// What the agent socket needs from the daemon: identity listing and
/// signing (`docs/ssh-agent.md` § 6). `dispatch` takes `&impl SshSign`
/// rather than naming `Server`, so the protocol loop stays decoupled from
/// the daemon, as `proto::dispatch` is via `Handler`.
pub trait SshSign {
    fn ssh_identities(&self, class: &bind::ConnectionClass) -> Vec<wire::Identity>;

    fn ssh_sign(
        &self,
        class: &bind::ConnectionClass,
        request: &wire::SignRequest,
        login_session_id: Option<&[u8]>,
        origin: Origin,
    ) -> wire::AgentResponse;
}

/// Connections handled at once — separate from the JSON socket's own cap
/// (`docs/ssh-agent.md` § 6.1).
const MAX_CONNECTIONS: usize = 64;

/// Once any byte of a new frame has arrived, each further read on it must
/// land within this. There is no deadline at all while nothing of a new
/// frame has arrived yet — connections are long-lived and often idle for
/// a long time (`docs/ssh-agent.md` § 6.1).
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Holds one of the [`MAX_CONNECTIONS`] slots; releases it when dropped.
/// A near-duplicate of `server::ConnectionSlot` — this socket has its own
/// cap, and the two are small enough not to share.
struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<ConnectionSlot> {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnectionSlot(Arc::clone(active)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections on the SSH agent socket forever, handling each on
/// its own thread. Mirrors `server::serve`'s shape: a stuck `accept`
/// pauses rather than spins, and a connection over the cap is dropped.
pub fn serve(server: Arc<Server>, listener: UnixListener) {
    let active = Arc::new(AtomicUsize::new(0));
    let owner = rustix::process::geteuid().as_raw();
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(slot) = ConnectionSlot::acquire(&active) else {
            continue;
        };
        let server = Arc::clone(&server);
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle_connection(&server, stream, owner);
        });
    }
}

/// Serves one connection until it closes, errors, or sends an oversize
/// frame.
fn handle_connection(server: &Server, mut stream: UnixStream, owner: u32) {
    let Ok(uid) = socket::peer_uid(&stream) else {
        return;
    };
    if uid != owner {
        log::warn(format_args!("rejected ssh agent connection from uid {uid}"));
        return;
    }
    let origin = server.origin_of(&stream, owner);

    let mut bindings = SessionBindState::new();
    let mut buf = Vec::new();
    loop {
        loop {
            match wire::next_frame(&buf) {
                Ok(Frame::Incomplete) => break,
                Err(_oversize) => return,
                Ok(Frame::Complete { message, consumed }) => {
                    let request = wire::decode_request(message);
                    let response = dispatch(server, &mut bindings, &request, origin);
                    buf.drain(..consumed);
                    if stream.write_all(&wire::encode_response(&response)).is_err() {
                        return;
                    }
                }
            }
        }

        let timeout = if buf.is_empty() {
            None
        } else {
            Some(FRAME_TIMEOUT)
        };
        if stream.set_read_timeout(timeout).is_err() {
            return;
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Answers one decoded request against `bindings`' accumulated state.
fn dispatch(
    server: &impl SshSign,
    bindings: &mut SessionBindState,
    request: &AgentRequest,
    origin: Origin,
) -> AgentResponse {
    match request {
        AgentRequest::RequestIdentities => {
            AgentResponse::IdentitiesAnswer(server.ssh_identities(&bindings.class()))
        }
        AgentRequest::SignRequest(sign_request) => {
            let class = bindings.class();
            server.ssh_sign(&class, sign_request, bindings.login_session_id(), origin)
        }
        AgentRequest::SessionBind(msg) => match bindings.apply(msg) {
            BindOutcome::Accepted => AgentResponse::Success,
            BindOutcome::Refused => AgentResponse::ExtensionFailure,
        },
        // The only extension this build answers for real.
        AgentRequest::ExtensionQuery => {
            AgentResponse::ExtensionResponse(vec!["session-bind@openssh.com".to_string()])
        }
        AgentRequest::Unsupported => AgentResponse::Failure,
    }
}
