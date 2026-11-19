//! The control socket's transport: accept connections, read one request line
//! from each, answer it through [`Api`], write one response line.
//!
//! The limits below (request size, I/O timeouts, concurrent connections)
//! exist because one crashed daemon loses every unlocked database at once:
//! nothing a client sends, and nothing the host refuses, should be able to
//! take it down. See `docs/review-2026-09-robustness.md` findings 1–4, 7, 9.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::Api;
use super::proto::{self, DecodeError, ProtocolError, Response};
use crate::authn::Requester;
use crate::authz;
use crate::log;
use crate::prompt::Terminal;
use crate::socket::{self, Received};

/// Longest request line accepted, and the size of the buffer each one is
/// read into. A request names a database or an entry, a few hundred bytes at
/// most, so this is far more than any needs: it bounds what a client can
/// make the daemon hold.
const MAX_REQUEST_LEN: usize = 64 * 1024;

/// How long a client gets to send its request, and to take its response.
/// An `unlock` can take much longer end to end — the user is typing — but
/// that time is spent between the read and the write, not inside either.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections handled at once; past this, new ones are refused by
/// closing them. Each holds a thread, and a flood should degrade into
/// refusals rather than into the host refusing a thread spawn.
const MAX_CONNECTIONS: usize = 64;

/// Holds one of the `MAX_CONNECTIONS` slots; releases it when dropped,
/// including when the thread it was moved into never gets to run.
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

/// Accept connections forever, handling each on its own thread.
///
/// Nothing here can end the loop or the process: an `accept` error (out of
/// file descriptors, say) pauses briefly instead of spinning; a connection
/// over `MAX_CONNECTIONS`, or one the host won't spawn a thread for, is
/// dropped — the client sees it closed — and the loop carries on.
pub fn serve(api: Arc<Api>, listener: UnixListener) {
    let active = Arc::new(AtomicUsize::new(0));
    let owner = crate::authn::process_uid();
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
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            continue;
        }
        let api = Arc::clone(&api);
        // On failure the closure — stream and slot with it — is dropped,
        // which closes the connection and releases the slot.
        let _ = thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle_connection(&api, stream, owner);
        });
    }
}

/// A `Write` that only counts, for sizing a buffer before filling it.
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Log the operations that change what the daemon is holding, one line per
/// event on stderr (see `crate::log`), for whatever is supervising the
/// daemon to collect. Successes are `info`; a failed or refused request is
/// `warn`.
///
/// **Reads are deliberately silent.** `status` and `list` change nothing,
/// and `list` in particular carries entry titles and usernames — a log is
/// the last place that should accumulate, since it outlives the unlocked
/// session that produced it and lands somewhere far less guarded than the
/// socket did. What gets logged is that an operation happened and to which
/// database. The one piece of vault content that does appear is the title
/// of the entry a `copy` took a field from: a record of which secret left
/// is the point of logging a copy. Never a secret, and never a title the
/// user marked protected.
///
/// Failures are logged too, not just successes: a failed `unlock` is the
/// event most worth having a record of.
fn log_response(response: &Response) {
    match response {
        // Success is logged by the core, and only when a database
        // was actually opened.
        Response::Unlock(Ok(_)) => {}
        Response::Unlock(Err(err)) => log::warn(format_args!("unlock failed: {err:?}")),

        Response::Lock(Ok(Some(db))) => log::info(format_args!("locked {db:?}")),
        Response::Lock(Ok(None)) => log::info(format_args!("locked every database")),
        Response::Lock(Err(err)) => log::warn(format_args!("lock failed: {err:?}")),

        Response::Protocol(err) => log::warn(format_args!("rejected request: {err:?}")),

        // `copy` is an access worth recording, same reasoning as `unlock`
        // and `lock` above — unlike `list`/`status`, which stay silent
        // (see the note on `Response::Status { .. } | Response::List(_)`
        // below). The field, the entry's title and the database are logged,
        // never the secret — and never a protected title.
        Response::Copy(Ok(outcome)) => log::info(format_args!(
            "copied {:?} of {:?} from {:?}",
            outcome.field, outcome.entry, outcome.db
        )),
        Response::Copy(Err(err)) => log::warn(format_args!("copy failed: {err:?}")),

        // Success is logged by the handler.
        Response::SshApprove(Ok(())) => {}
        Response::SshApprove(Err(err)) => log::warn(format_args!("ssh approve failed: {err:?}")),

        // Listed above rather than caught by a `_` arm on purpose: adding
        // an op should be a decision about whether it belongs in the log,
        // not something a wildcard answers silently. `ssh_keys` carries
        // entry titles, which stay out of the log like `list`'s.
        Response::Status { .. }
        | Response::List(_)
        | Response::SshKeys(_)
        | Response::SshPending(_) => {}
    }
}

/// Serialize `response` and send it, newline-terminated.
///
/// Serialized twice on purpose: once to measure (into the shared
/// [`ByteCounter`]), once into a zeroizing buffer allocated at exactly that
/// size. A `list` response holds every entry's title, username and
/// URL, and a buffer that grows while being filled frees an unwiped copy
/// at each reallocation — which is what survived a lock before
/// (`docs/review-2026-09-secrets.md` finding 5).
fn write_response(stream: &mut UnixStream, response: &Response) {
    let mut counter = ByteCounter(0);
    if serde_json::to_writer(&mut counter, response).is_err() {
        return;
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(counter.0 + 1));
    if serde_json::to_writer(&mut *buf, response).is_err() {
        return;
    }
    buf.push(b'\n');
    let _ = stream.write_all(&buf);
}

/// What `read_request` found on the socket.
enum RequestLine {
    /// The client closed the connection without sending anything.
    Closed,
    /// `MAX_REQUEST_LEN` bytes with no newline among them.
    TooLong,
    /// The line's length, newline excluded, and the file descriptor that
    /// came with it, if one did. A client that closes its end without a
    /// newline has still sent a line.
    Line { len: usize, fd: Option<OwnedFd> },
    /// More than one file descriptor came with the request. A request
    /// carries at most one, the terminal.
    TooManyFds,
}

/// Read one request line into `buf`, which never grows, and the file
/// descriptor sent with it if there is one.
///
/// Read straight from the socket rather than through a `BufReader`, which
/// can't receive the descriptor that comes with the line. Whatever is read
/// past the newline lands in `buf` too, and is ignored: a connection carries
/// one request.
fn read_request(stream: &UnixStream, buf: &mut [u8]) -> std::io::Result<RequestLine> {
    let mut len = 0;
    let mut fd = None;
    loop {
        if len == buf.len() {
            return Ok(RequestLine::TooLong);
        }
        let received = match socket::recv_with_fd(stream, &mut buf[len..]) {
            Ok(received) => received,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        let Received::Data {
            len: n,
            fd: arrived,
        } = received
        else {
            return Ok(RequestLine::TooManyFds);
        };
        if fd.is_some() && arrived.is_some() {
            return Ok(RequestLine::TooManyFds);
        }
        fd = fd.or(arrived);
        if n == 0 {
            return Ok(if len == 0 {
                RequestLine::Closed
            } else {
                RequestLine::Line { len, fd }
            });
        }
        if let Some(newline) = buf[len..len + n].iter().position(|&byte| byte == b'\n') {
            return Ok(RequestLine::Line {
                len: len + newline,
                fd,
            });
        }
        len += n;
    }
}

/// One connection: read exactly one request line, respond with exactly one
/// response line, done (`docs/design.md` § Protocol — one-shot connections
/// by design, not a limitation).
///
/// A request that doesn't fit — longer than `MAX_REQUEST_LEN` without a
/// newline, or not UTF-8 — gets `malformed_request`, and so does one that
/// comes with more than one file descriptor, or with one that isn't a
/// terminal. A socket error, or a
/// client that sends nothing within `IO_TIMEOUT`, just drops the
/// connection; there's no one left to tell. The reply is written before
/// the event is logged, so a slow or broken stdout can't cost the client
/// its answer.
///
/// A peer whose uid isn't `owner` (or whose credentials can't be read) is
/// dropped without a reply and without being read from. The socket's mode
/// already keeps other users out; this check covers a mode that ever
/// came out wrong.
fn handle_connection(api: &Api, mut stream: UnixStream, owner: u32) {
    let mut requester = match Requester::of(&stream) {
        Ok(requester) if authz::may_connect(&requester, owner) => requester,
        Ok(requester) => {
            log::warn(format_args!(
                "rejected connection from uid {}",
                requester.uid
            ));
            return;
        }
        Err(err) => {
            log::warn(format_args!(
                "rejected connection: peer credentials unavailable: {err}"
            ));
            return;
        }
    };
    log::debug(format_args!(
        "connection from {}",
        if authz::on_desktop(&requester, &api.display_session()) {
            "the desktop"
        } else {
            "outside the desktop"
        }
    ));

    let response = {
        let mut buf = vec![0u8; MAX_REQUEST_LEN];
        match read_request(&stream, &mut buf) {
            Ok(RequestLine::Closed) | Err(_) => return,
            Ok(RequestLine::TooLong | RequestLine::TooManyFds) => {
                Response::Protocol(ProtocolError::MalformedRequest)
            }
            Ok(RequestLine::Line { len, fd }) => {
                match fd.map(|fd| Terminal::new(fd, &stream)).transpose() {
                    Ok(terminal) => {
                        requester.terminal = terminal;
                        respond(api, &buf[..len], &requester)
                    }
                    Err(err) => {
                        log::debug(format_args!("the descriptor sent with a request: {err}"));
                        Response::Protocol(ProtocolError::MalformedRequest)
                    }
                }
            }
        }
    };

    // Log first: once a client has seen the response, the operation is
    // already in the log. (Logging after the write lets a client that
    // reads the log right after its reply, as the tests do, miss the line.)
    log_response(&response);
    write_response(&mut stream, &response);
}

/// The response to the request on `line`, from `requester`.
fn respond(api: &Api, line: &[u8], requester: &Requester) -> Response {
    match std::str::from_utf8(line).map(proto::decode_request) {
        Ok(Ok(request)) => api.handle(&request, requester),
        Ok(Err(DecodeError::VersionMismatch(client_v))) => {
            Response::Protocol(ProtocolError::VersionMismatch { client_v })
        }
        Ok(Err(DecodeError::MalformedRequest)) | Err(_) => {
            Response::Protocol(ProtocolError::MalformedRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::AsFd;

    use super::super::testing::fixture_with;
    use super::*;
    use crate::prompt::testing::pty;

    /// Send `request` bytes to `handle_connection` over a socket pair and
    /// return whatever it replies.
    fn exchange(request: &[u8]) -> String {
        // The handler may stop reading early (at the size cap) and reply; a
        // write error from that is expected, not a failure.
        exchange_with(|mut ours| {
            let _ = ours.write_all(request);
        })
    }

    /// Like `exchange`, with `send` putting whatever it likes on the
    /// requester's end of the connection.
    fn exchange_with(send: impl FnOnce(&UnixStream)) -> String {
        let fx = fixture_with(&[], "");
        let owner = crate::authn::process_uid();
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.api, theirs, owner));
            send(&ours);
            let _ = ours.shutdown(std::net::Shutdown::Write);
            let mut reply = String::new();
            let _ = (&ours).read_to_string(&mut reply);
            reply
        })
    }

    #[test]
    fn an_unterminated_oversized_request_is_refused_not_buffered() {
        let reply = exchange(&vec![b'a'; 1 << 20]);
        assert!(reply.contains("malformed_request"), "got {reply:?}");
    }

    #[test]
    fn a_non_utf8_request_gets_an_answer() {
        let reply = exchange(b"\xff\xfe\n");
        assert!(reply.contains("malformed_request"), "got {reply:?}");
    }

    const STATUS: &[u8] = b"{\"v\":2,\"op\":\"status\"}\n";

    #[test]
    fn a_request_may_come_with_a_terminal() {
        let (_master, slave) = pty();

        let reply = exchange_with(|ours| {
            socket::send_with_fd(ours, STATUS, Some(slave.as_fd())).expect("send");
        });

        assert!(reply.contains("\"ok\":true"), "got {reply:?}");
    }

    #[test]
    fn a_request_with_a_descriptor_that_is_not_a_terminal_is_refused() {
        let (not_a_terminal, _other) = UnixStream::pair().expect("socket pair");

        let reply = exchange_with(|ours| {
            socket::send_with_fd(ours, STATUS, Some(not_a_terminal.as_fd())).expect("send");
        });

        assert!(reply.contains("malformed_request"), "got {reply:?}");
    }

    #[test]
    fn a_request_with_more_than_one_descriptor_is_refused() {
        let (_first_master, first) = pty();
        let (_second_master, second) = pty();

        // In one message, and in two.
        let together = exchange_with(|ours| {
            socket::send_with_fds(ours, STATUS, &[first.as_fd(), second.as_fd()]);
        });
        let apart = exchange_with(|ours| {
            let (start, end) = STATUS.split_at(8);
            socket::send_with_fd(ours, start, Some(first.as_fd())).expect("send");
            socket::send_with_fd(ours, end, Some(second.as_fd())).expect("send");
        });

        for reply in [together, apart] {
            assert!(reply.contains("malformed_request"), "got {reply:?}");
        }
    }

    /// Runs `read_request` on a socket pair whose other end writes
    /// `pieces` a moment apart, so each tends to arrive as its own read.
    fn read_written(pieces: &[&[u8]], buf_len: usize) -> (std::io::Result<RequestLine>, Vec<u8>) {
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut buf = vec![0u8; buf_len];
        let read = thread::scope(|scope| {
            scope.spawn(move || {
                for piece in pieces {
                    let _ = ours.write_all(piece);
                    thread::sleep(Duration::from_millis(20));
                }
            });
            read_request(&theirs, &mut buf)
        });
        (read, buf)
    }

    #[test]
    fn read_request_stops_at_the_first_newline() {
        let (read, buf) = read_written(&[b"{\"v\":2,", b"\"op\":\"status\"}\nrest\n"], 64);
        let Ok(RequestLine::Line { len, .. }) = read else {
            panic!("expected a line");
        };
        assert_eq!(&buf[..len], b"{\"v\":2,\"op\":\"status\"}");
    }

    #[test]
    fn read_request_accepts_a_newline_in_the_last_byte_and_no_further() {
        let (read, _) = read_written(&[b"abc\n"], 4);
        assert!(matches!(read, Ok(RequestLine::Line { len: 3, .. })));
        let (read, _) = read_written(&[b"abcd\n"], 4);
        assert!(matches!(read, Ok(RequestLine::TooLong)));
    }

    #[test]
    fn read_request_takes_an_unterminated_line_at_eof() {
        let (read, _) = read_written(&[b"abc"], 64);
        assert!(matches!(read, Ok(RequestLine::Line { len: 3, .. })));
        let (read, _) = read_written(&[], 64);
        assert!(matches!(read, Ok(RequestLine::Closed)));
    }

    #[test]
    fn a_valid_request_is_still_answered() {
        let reply = exchange(b"{\"v\":2,\"op\":\"status\"}\n");
        assert_eq!(
            reply,
            format!(
                "{{\"v\":2,\"ok\":true,\"databases\":[],\"version\":{:?}}}\n",
                crate::VERSION
            )
        );
    }

    #[test]
    fn handle_connection_drops_a_peer_of_another_uid() {
        let fx = fixture_with(&[], "");
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        ours.write_all(b"{\"v\":2,\"op\":\"status\"}\n")
            .expect("write");
        // Any uid other than ours stands in for a peer we must refuse.
        let other = crate::authn::process_uid().wrapping_add(1);

        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.api, theirs, other));
        });
        // The server closes with the request still unread, so the kernel may
        // reset the connection instead of ending it. Either way, no reply.
        let mut reply = Vec::new();
        let _ = ours.read_to_end(&mut reply);
        assert!(reply.is_empty(), "a refused peer got {reply:?}");
    }

    #[test]
    fn handle_connection_answers_a_peer_of_our_uid() {
        let fx = fixture_with(&[], "");
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        ours.write_all(b"{\"v\":2,\"op\":\"status\"}\n")
            .expect("write");
        let owner = crate::authn::process_uid();

        thread::scope(|scope| {
            scope.spawn(|| handle_connection(&fx.api, theirs, owner));
        });
        let mut reply = String::new();
        ours.read_to_string(&mut reply).expect("read");
        assert!(reply.starts_with('{'), "expected a reply, got {reply:?}");
    }
}
