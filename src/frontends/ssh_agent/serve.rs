//! The SSH agent socket's listener and per-connection protocol loop
//! (`docs/ssh-agent.md` § 6.1): accepts connections, frames them with
//! [`wire`], tracks each one's `session-bind@openssh.com` state with
//! [`bind::SessionBindState`], and dispatches identities and signatures to
//! the [`Agent`].
//!
//! What a request may do is the agent's decision, not this module's: a
//! forwarded `SIGN_REQUEST` reaches [`Agent::sign`] with its connection's
//! class like any other.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::authn::Requester;
use crate::authz;
use crate::log;

use super::Agent;
use super::bind::{self, BindOutcome, SessionBindState};
use super::wire::{self, AgentRequest, AgentResponse, Frame};

/// Connections handled at once — separate from the JSON socket's own cap
/// (`docs/ssh-agent.md` § 6.1).
const MAX_CONNECTIONS: usize = 64;

/// Of [`MAX_CONNECTIONS`], how many may be forwarded ones at once, so
/// remote hosts can't take every slot from local `ssh` and `git`.
const MAX_FORWARDED_CONNECTIONS: usize = 16;

/// How long a frame may take to arrive, from its first byte to its last.
/// There is no deadline at all while nothing of a new frame has arrived
/// yet — connections are long-lived and often idle for a long time
/// (`docs/ssh-agent.md` § 6.1).
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// What every connection on one agent socket shares: the counters behind
/// its two caps, and the frame deadline (shorter in tests).
struct Limits {
    connections: Arc<AtomicUsize>,
    forwarded: Arc<AtomicUsize>,
    frame_timeout: Duration,
}

impl Limits {
    fn new() -> Limits {
        Limits {
            connections: Arc::new(AtomicUsize::new(0)),
            forwarded: Arc::new(AtomicUsize::new(0)),
            frame_timeout: FRAME_TIMEOUT,
        }
    }
}

/// Holds one place under a cap of `cap` counted by `count`; gives it back
/// when dropped. A near-duplicate of `control::serve`'s `ConnectionSlot`: this socket
/// has caps of its own, and the two are small enough not to share.
struct CapSlot(Arc<AtomicUsize>);

impl CapSlot {
    fn acquire(count: &Arc<AtomicUsize>, cap: usize) -> Option<CapSlot> {
        if count.fetch_add(1, Ordering::SeqCst) >= cap {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(CapSlot(Arc::clone(count)))
    }
}

impl Drop for CapSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections on the SSH agent socket forever, handling each on
/// its own thread. Mirrors `control::serve`'s shape: a stuck `accept`
/// pauses rather than spins, and a connection over the cap is dropped.
pub fn serve(agent: Arc<Agent>, listener: UnixListener) {
    let limits = Arc::new(Limits::new());
    let owner = crate::authn::process_uid();
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(slot) = CapSlot::acquire(&limits.connections, MAX_CONNECTIONS) else {
            log::warn(format_args!(
                "ssh agent: {MAX_CONNECTIONS} connections already open; closed a new one"
            ));
            continue;
        };
        let agent = Arc::clone(&agent);
        let limits = Arc::clone(&limits);
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle_connection(agent.as_ref(), stream, owner, &limits);
        });
    }
}

/// Serves one connection until it closes, errors, sends an oversize frame,
/// lets a frame take longer than `limits.frame_timeout`, or becomes
/// forwarded while the forwarded cap is full.
fn handle_connection(agent: &Agent, mut stream: UnixStream, owner: u32, limits: &Limits) {
    let requester = match Requester::of(&stream) {
        Ok(requester) if authz::may_connect(&requester, owner) => requester,
        Ok(requester) => {
            log::warn(format_args!(
                "rejected ssh agent connection from uid {}",
                requester.uid
            ));
            return;
        }
        Err(_) => return,
    };

    let mut bindings = SessionBindState::new();
    // Held from the session-bind that makes this connection forwarded
    // until it closes.
    let mut forwarded_slot = None;
    let mut buf = Vec::new();
    // When the frame now arriving must be complete: set at its first byte,
    // cleared once it is.
    let mut frame_deadline: Option<Instant> = None;
    loop {
        loop {
            match wire::next_frame(&buf) {
                Ok(Frame::Incomplete) => break,
                Err(_oversize) => return,
                Ok(Frame::Complete { message, consumed }) => {
                    let request = wire::decode_request(message);
                    let response = dispatch(agent, &mut bindings, &request, &requester);
                    buf.drain(..consumed);
                    frame_deadline = None;
                    if forwarded_slot.is_none()
                        && matches!(bindings.class(), bind::ConnectionClass::Forwarded { .. })
                    {
                        let Some(slot) =
                            CapSlot::acquire(&limits.forwarded, MAX_FORWARDED_CONNECTIONS)
                        else {
                            log::warn(format_args!(
                                "ssh agent: {MAX_FORWARDED_CONNECTIONS} forwarded connections \
                                 already open; closed one that became forwarded"
                            ));
                            return;
                        };
                        forwarded_slot = Some(slot);
                    }
                    if stream.write_all(&wire::encode_response(&response)).is_err() {
                        return;
                    }
                }
            }
        }

        if buf.is_empty() {
            frame_deadline = None;
        } else if frame_deadline.is_none() {
            frame_deadline = Some(Instant::now() + limits.frame_timeout);
        }
        let timeout = match frame_deadline {
            None => None,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return;
                }
                Some(left)
            }
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
    agent: &Agent,
    bindings: &mut SessionBindState,
    request: &AgentRequest,
    requester: &Requester,
) -> AgentResponse {
    match request {
        AgentRequest::RequestIdentities => {
            AgentResponse::IdentitiesAnswer(agent.identities(&bindings.class(), requester))
        }
        AgentRequest::SignRequest(sign_request) => {
            let class = bindings.class();
            agent.sign(&class, sign_request, bindings.login_session_id(), requester)
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

#[cfg(test)]
mod tests {
    use ssh_key::PrivateKey;

    use super::super::testing::{Fixture, Options, outside, requester, signed_bind};
    use super::super::wire::{SignFlags, SignRequest};
    use super::*;
    use crate::config::SshKeyConfirm;
    use crate::ssh::testing::{database, test_key};

    /// An agent with one database, locked, and no keys.
    fn keyless() -> Fixture {
        Fixture::new(vec![database("personal", vec![])], Options::default())
    }

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len())
            .expect("a short field")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// The request OpenSSH makes to log in as `alice` with `key` on the
    /// connection `session_id`.
    fn login_request(key: &PrivateKey, session_id: &[u8]) -> AgentRequest {
        let key_blob = key.public_key().to_bytes().expect("key encodes");
        let mut data = string(session_id);
        data.push(50); // SSH_MSG_USERAUTH_REQUEST
        for field in ["alice", "ssh-connection", "publickey"] {
            data.extend(string(field.as_bytes()));
        }
        data.push(1); // sig-follows
        data.extend(string(b"ssh-ed25519"));
        data.extend(string(&key_blob));
        AgentRequest::SignRequest(SignRequest {
            key_blob,
            data,
            flags: SignFlags::new(0),
        })
    }

    fn signs(response: &AgentResponse) -> bool {
        matches!(response, AgentResponse::SignResponse(_))
    }

    /// What a request outside the desktop is listed differs from what one on
    /// it is: the connection's requester reaches the agent.
    #[test]
    fn identities_are_listed_for_the_connections_requester() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Once);
        let comment = |requester: &Requester| {
            let response = dispatch(
                &fx.agent,
                &mut SessionBindState::new(),
                &AgentRequest::RequestIdentities,
                requester,
            );
            let AgentResponse::IdentitiesAnswer(listed) = response else {
                panic!("expected an identities answer");
            };
            assert_eq!(listed.len(), 1);
            listed[0].comment.clone()
        };

        assert_eq!(comment(&requester()), "github");
        assert_eq!(
            comment(&outside()),
            "github (needs approval: kpa ssh pending)"
        );
    }

    /// A verified `session-bind` changes the class every later signature
    /// on the connection is asked with, and supplies its session id: a
    /// login for another session than the bound one is refused, which only
    /// a bound connection checks.
    #[test]
    fn a_session_bind_reaches_later_signatures() {
        let key = test_key(1);
        let fx = Fixture::unlocked(&key, SshKeyConfirm::Never);
        let mut state = SessionBindState::new();
        let mut ask =
            |request: &AgentRequest| dispatch(&fx.agent, &mut state, request, &requester());

        assert!(signs(&ask(&login_request(&key, b"other"))));
        let bound = ask(&AgentRequest::SessionBind(signed_bind(
            &test_key(2),
            b"sid",
            false,
        )));
        assert!(matches!(bound, AgentResponse::Success));
        assert!(!signs(&ask(&login_request(&key, b"other"))));
        assert!(signs(&ask(&login_request(&key, b"sid"))));
    }

    #[test]
    fn a_bad_session_bind_is_an_extension_failure() {
        let fx = keyless();
        let mut state = SessionBindState::new();
        let mut forged = signed_bind(&test_key(2), b"sid", false);
        forged.hostkey = test_key(3).public_key().to_bytes().expect("key encodes");
        let response = dispatch(
            &fx.agent,
            &mut state,
            &AgentRequest::SessionBind(forged),
            &requester(),
        );
        assert!(matches!(response, AgentResponse::ExtensionFailure));
    }

    #[test]
    fn only_session_bind_is_advertised_and_everything_else_fails() {
        let fx = keyless();
        let mut state = SessionBindState::new();
        let query = dispatch(
            &fx.agent,
            &mut state,
            &AgentRequest::ExtensionQuery,
            &requester(),
        );
        assert!(matches!(
            query,
            AgentResponse::ExtensionResponse(names) if names == ["session-bind@openssh.com"]
        ));
        let unsupported = dispatch(
            &fx.agent,
            &mut state,
            &AgentRequest::Unsupported,
            &requester(),
        );
        assert!(matches!(unsupported, AgentResponse::Failure));
    }

    /// Reads one framed response off `stream`: its type byte and body.
    fn read_response(stream: &mut UnixStream) -> Vec<u8> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("response length");
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).expect("response body");
        body
    }

    /// A connection answers each frame in order, including two that arrive
    /// in one write.
    #[test]
    fn a_connection_answers_each_frame_in_order() {
        let fx = keyless();
        let owner = crate::authn::process_uid();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");

        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, owner, &Limits::new()));
            let mut sign = vec![13u8];
            for field in [b"key".as_slice(), b"data".as_slice()] {
                sign.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
                sign.extend_from_slice(field);
            }
            sign.extend_from_slice(&0u32.to_be_bytes());
            let mut both = wire::encode_frame(&[11]); // REQUEST_IDENTITIES
            both.extend(wire::encode_frame(&sign));
            ours.write_all(&both).expect("write");

            assert_eq!(read_response(&mut ours)[0], 12); // IDENTITIES_ANSWER
            assert_eq!(read_response(&mut ours)[0], 5); // FAILURE: no such key
            drop(ours);
        });
    }

    /// A frame over `wire::MAX_FRAME_LEN` ends the connection unanswered.
    #[test]
    fn an_oversize_frame_closes_the_connection() {
        let fx = keyless();
        let owner = crate::authn::process_uid();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");

        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, owner, &Limits::new()));
            let len = u32::try_from(wire::MAX_FRAME_LEN + 1).unwrap();
            ours.write_all(&len.to_be_bytes()).expect("write");
            let mut rest = Vec::new();
            ours.read_to_end(&mut rest).expect("read");
            assert!(rest.is_empty(), "an oversize frame got a reply");
        });
    }

    /// Writes a framed `message` to `stream`.
    fn send(stream: &mut UnixStream, message: &[u8]) {
        stream
            .write_all(&wire::encode_frame(message))
            .expect("write");
    }

    /// Whether `stream`'s other end closed without replying, waiting at
    /// most a few seconds for it.
    fn closed_unanswered(stream: &mut UnixStream) -> bool {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut rest = Vec::new();
        let closed = match stream.read_to_end(&mut rest) {
            Ok(_) => true,
            Err(err) => err.kind() == std::io::ErrorKind::ConnectionReset,
        };
        closed && rest.is_empty()
    }

    /// A peer of another uid is closed before anything is read or asked
    /// about it.
    #[test]
    fn a_peer_of_another_uid_is_closed_unanswered() {
        let fx = keyless();
        let other = crate::authn::process_uid().wrapping_add(1);
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        send(&mut ours, &[11]); // REQUEST_IDENTITIES

        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, other, &Limits::new()));
            // The connection closes with the request unread, so the
            // kernel may reset it rather than end it: either way, no reply.
            let mut reply = Vec::new();
            let _ = ours.read_to_end(&mut reply);
            assert!(reply.is_empty(), "a refused peer got {reply:?}");
        });
    }

    /// The frame deadline runs from a frame's first byte, so a peer that
    /// trickles a frame one byte at a time is closed once it passes, however
    /// promptly each byte arrives.
    #[test]
    fn a_frame_that_trickles_in_is_closed_at_its_deadline() {
        let fx = keyless();
        let owner = crate::authn::process_uid();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let limits = Limits {
            frame_timeout: Duration::from_millis(200),
            ..Limits::new()
        };

        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, owner, &limits));
            let mut writer = ours.try_clone().expect("clone");
            scope.spawn(move || {
                let _ = writer.write_all(&100u32.to_be_bytes());
                for _ in 0..100 {
                    thread::sleep(Duration::from_millis(20));
                    if writer.write_all(&[0]).is_err() {
                        return;
                    }
                }
            });
            assert!(closed_unanswered(&mut ours));
        });
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "closed after {:?}",
            started.elapsed()
        );
    }

    /// A connection that a session-bind makes forwarded takes one of the
    /// forwarded places, and is closed unanswered when none is left.
    #[test]
    fn the_forwarded_cap_closes_a_connection_that_becomes_forwarded() {
        let fx = keyless();
        let owner = crate::authn::process_uid();
        // SSH_AGENTC_EXTENSION carrying a real forwarding session-bind.
        let forwarding_bind = || {
            let bind = signed_bind(&test_key(1), b"sid", true);
            let mut message = vec![27];
            for field in [
                b"session-bind@openssh.com".as_slice(),
                &bind.hostkey,
                &bind.session_id,
                &bind.signature,
            ] {
                message.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
                message.extend_from_slice(field);
            }
            message.push(1); // is_forwarding
            message
        };

        let full = Limits::new();
        full.forwarded
            .store(MAX_FORWARDED_CONNECTIONS, Ordering::SeqCst);
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, owner, &full));
            send(&mut ours, &forwarding_bind());
            assert!(closed_unanswered(&mut ours));
        });
        assert_eq!(
            full.forwarded.load(Ordering::SeqCst),
            MAX_FORWARDED_CONNECTIONS
        );

        let room = Limits::new();
        room.forwarded
            .store(MAX_FORWARDED_CONNECTIONS - 1, Ordering::SeqCst);
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        std::thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.agent, theirs, owner, &room));
            send(&mut ours, &forwarding_bind());
            assert_eq!(read_response(&mut ours), [6]); // SUCCESS
            assert_eq!(
                room.forwarded.load(Ordering::SeqCst),
                MAX_FORWARDED_CONNECTIONS
            );
            drop(ours);
        });
        assert_eq!(
            room.forwarded.load(Ordering::SeqCst),
            MAX_FORWARDED_CONNECTIONS - 1
        );
    }

    #[test]
    fn a_cap_refuses_once_full_and_frees_a_place_on_drop() {
        let count = Arc::new(AtomicUsize::new(0));
        let first = CapSlot::acquire(&count, 2).expect("room");
        let _second = CapSlot::acquire(&count, 2).expect("room");
        assert!(CapSlot::acquire(&count, 2).is_none());
        assert_eq!(count.load(Ordering::SeqCst), 2);
        drop(first);
        assert!(CapSlot::acquire(&count, 2).is_some());
    }
}
