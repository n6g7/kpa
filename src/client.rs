//! Talking to the daemon as a client: one request per call, over the
//! socket, with the daemon's raw JSON response line printed verbatim
//! (`docs/design.md`'s "hand-debuggable with socat" argument, applied to
//! the CLI itself rather than just `socat`). `unlock` is the one exception
//! that can send two: a plain request first, then — on the daemon's
//! `no_display` — the master password read from this process's own
//! controlling terminal (`docs/headless.md` § 4).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kpa::output::{print_escaped, report_error};
use kpa::proto::{self, Op, Password, Request, Response, UnlockError, UnlockRequest};
use kpa::socket;

use super::tty::{self, TtyReadError};

pub(super) fn run_client(socket_path: &Path, op: Op) -> ExitCode {
    let request = Request {
        v: proto::VERSION,
        op,
    };

    match send_request(socket_path, &request) {
        Ok(line) => print_and_exit(&line),
        Err(err) => report_client_error(err),
    }
}

/// Reports a failed round trip. Only a failed connect means the daemon
/// may not be running. Once connected, a missing reply means it hit a
/// problem with this request, and suggesting it's down would send someone
/// looking in the wrong place.
pub(super) fn report_client_error(err: ClientError) -> ExitCode {
    match err {
        ClientError::Connect(..) => {
            report_error(format_args!("{err} (is `kpa serve` running?)"));
        }
        err => report_error(err),
    }
    ExitCode::FAILURE
}

/// Prints a response line and turns its `ok` field into an exit code.
/// Shared by every client subcommand that sends exactly one request and
/// shows the daemon's answer verbatim.
pub(super) fn print_and_exit(line: &str) -> ExitCode {
    print_escaped(line);
    // `Response` deliberately has no generic `Deserialize` — a successful
    // `Unlock` and a successful `Lock { db: Some(_) }` serialize
    // identically, so decoding one back into that type isn't meaningful
    // without already knowing which request produced it. All the client
    // needs is the one shared `ok` field, read out of a bare `Value`
    // instead.
    let ok = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `kpa version`: the CLI's own build version, plus the running daemon's if
/// one is reachable. Always exits `SUCCESS` — there is no daemon down to
/// report as *this* command's failure, only as a fact to print; every
/// other outcome below (no daemon, an old daemon that doesn't report a
/// version, a daemon up and matching or not) is equally just information.
///
/// Goes through [`send_request`]/[`check_peer_uid`] like any other op, so a
/// socket that answers but belongs to another uid is still refused before
/// anything is sent to it — `kpa version`'s string isn't secret, but the
/// path that reaches a daemon at all stays the one path.
///
/// `socket_path` is `--socket`, else the default; `None` when neither
/// is available.
pub(super) fn run_version(socket_path: Option<PathBuf>) -> ExitCode {
    println!("client: {}", kpa::VERSION);

    let Some(socket_path) = socket_path else {
        println!(
            "server: not running (XDG_RUNTIME_DIR is not set to an absolute path; \
             pass --socket to check)"
        );
        return ExitCode::SUCCESS;
    };

    let request = Request {
        v: proto::VERSION,
        op: Op::Status,
    };
    match send_request(&socket_path, &request) {
        Ok(line) => {
            let daemon_version = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|value| {
                    value
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                });
            match daemon_version {
                Some(version) => println!("server: {version}"),
                // An older daemon, from before this field existed.
                None => println!("server: unknown (daemon predates version reporting)"),
            }
        }
        Err(err @ ClientError::Connect(..)) => {
            println!("server: not running ({err}; is `kpa serve` running?)");
        }
        Err(err) => println!("server: {err}"),
    }
    ExitCode::SUCCESS
}

/// Errors sending one request and reading its response. A thin wrapper
/// rather than `Box<dyn Error>` so `?` stays usable while keeping the
/// "why" in each variant.
#[derive(Debug, thiserror::Error)]
pub(super) enum ClientError {
    #[error("connecting to {0}: {1}")]
    Connect(PathBuf, std::io::Error),
    #[error("encoding request: {0}")]
    Encode(serde_json::Error),
    #[error("sending request: {0}")]
    Send(std::io::Error),
    #[error("reading response: {0}")]
    Read(std::io::Error),
    #[error(
        "the daemon accepted the request but closed the connection without \
         responding; its log may say why"
    )]
    EmptyResponse,
    #[error("refusing to talk to {0}: it belongs to uid {1}, not us")]
    WrongPeer(PathBuf, u32),
}

/// Refuses to go on talking to `stream` unless its peer is `expected`,
/// mirroring `handle_connection`'s server-side check
/// (`src/server.rs:722-735`) on the other end of the same socket. An
/// unreadable credential is treated the same as a mismatch: a socket
/// where `SO_PEERCRED` can't be read is not one to trust with a request.
/// A separate function, rather than inlined in `send_request`, so a test
/// can inject a mismatched `expected` without needing a second real uid.
fn check_peer_uid(
    socket_path: &Path,
    stream: &UnixStream,
    expected: u32,
) -> Result<(), ClientError> {
    match socket::peer_uid(stream) {
        Ok(uid) if uid == expected => Ok(()),
        Ok(uid) => Err(ClientError::WrongPeer(socket_path.to_path_buf(), uid)),
        Err(err) => Err(ClientError::Connect(socket_path.to_path_buf(), err)),
    }
}

/// Sends one request and returns the daemon's raw response line, newline
/// included. Deliberately not decoded into a typed `Response` — see the
/// comment in `run_client` on why that type has no generic `Deserialize`.
pub(super) fn send_request(socket_path: &Path, request: &Request) -> Result<String, ClientError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| ClientError::Connect(socket_path.to_path_buf(), err))?;
    check_peer_uid(socket_path, &stream, rustix::process::geteuid().as_raw())?;

    let line = proto::encode_request(request).map_err(ClientError::Encode)?;
    stream.write_all(&line).map_err(ClientError::Send)?;

    let mut line = String::new();
    let n = BufReader::new(stream)
        .read_line(&mut line)
        .map_err(ClientError::Read)?;
    if n == 0 {
        return Err(ClientError::EmptyResponse);
    }

    Ok(line)
}

/// Whether `line` is the daemon's `no_display` error: nobody could answer
/// an on-screen prompt for this request (`docs/headless.md` § 4).
fn is_no_display(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|code| code == "no_display")
}

/// The line the daemon would send for `no_display`, built from the same
/// type it serializes rather than a hand-written literal. Used when
/// `--tty` skips the first request, so there is no real one to show: the
/// outcome — nobody could be asked — is the same either way.
fn synthetic_no_display_line() -> String {
    let response = Response::Unlock(Err(UnlockError::NoDisplay));
    format!(
        "{}\n",
        serde_json::to_string(&response).expect("Response::Unlock serializes")
    )
}

/// `kpa unlock`: a plain request first, unless `tty`. The daemon raises its
/// own prompt when the request comes from the desktop; everywhere else it
/// answers `no_display`, which is when this reads the password from the
/// terminal and sends it in a second request (`docs/headless.md` § 4).
/// `--tty` skips straight to the terminal read, which is how a desktop
/// terminal asks for it instead of the graphical prompt.
pub(super) fn run_unlock(socket_path: &Path, db: String, tty: bool) -> ExitCode {
    if !tty {
        let request = Request {
            v: proto::VERSION,
            op: Op::Unlock(UnlockRequest {
                db: db.clone(),
                password: None,
            }),
        };
        match send_request(socket_path, &request) {
            Ok(line) if !is_no_display(&line) => return print_and_exit(&line),
            Ok(line) => return unlock_from_terminal(socket_path, db, Some(line)),
            Err(err @ ClientError::Connect(..)) => {
                report_error(format_args!("{err} (is `kpa serve` running?)"));
                return ExitCode::FAILURE;
            }
            Err(err) => {
                report_error(err);
                return ExitCode::FAILURE;
            }
        }
    }
    unlock_from_terminal(socket_path, db, None)
}

/// Reads the master password from this process's controlling terminal and
/// sends it in a second `unlock` request. `no_display_line` is the first
/// request's actual response when there was one; `--tty` has none, so a
/// line built from the same error the daemon would have sent
/// (`synthetic_no_display_line`) stands in. Printed unchanged, without
/// ever touching the terminal, when there's no controlling terminal to
/// read.
fn unlock_from_terminal(
    socket_path: &Path,
    db: String,
    no_display_line: Option<String>,
) -> ExitCode {
    let password = match tty::read_tty_password(b"Master password: ") {
        Ok(password) => password,
        Err(TtyReadError::NoTty(_)) => {
            let line = no_display_line.unwrap_or_else(synthetic_no_display_line);
            return print_and_exit(&line);
        }
        Err(err) => {
            report_error(err);
            return ExitCode::FAILURE;
        }
    };

    let request = Request {
        v: proto::VERSION,
        op: Op::Unlock(UnlockRequest {
            db,
            password: Some(Password::new(password)),
        }),
    };
    match send_request(socket_path, &request) {
        Ok(line) => print_and_exit(&line),
        Err(err @ ClientError::Connect(..)) => {
            report_error(format_args!("{err} (is `kpa serve` running?)"));
            ExitCode::FAILURE
        }
        Err(err) => {
            report_error(err);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ClientError, check_peer_uid, is_no_display, synthetic_no_display_line};

    /// `UnixStream::pair()` gives both ends our own real uid, so the
    /// mismatch is simulated the same way `server.rs`'s
    /// `handle_connection_drops_a_peer_of_another_uid` does: not by
    /// faking the peer's credential, but by giving `check_peer_uid` a
    /// different `expected` uid to compare it against.
    #[test]
    fn refuses_a_socket_belonging_to_another_uid() {
        let (_ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let other = rustix::process::geteuid().as_raw().wrapping_add(1);

        let err = check_peer_uid(Path::new("/dev/null"), &theirs, other)
            .expect_err("a uid mismatch must be refused");
        assert!(matches!(err, ClientError::WrongPeer(..)), "{err:?}");
    }

    #[test]
    fn accepts_a_socket_belonging_to_our_own_uid() {
        let (_ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let our_uid = rustix::process::geteuid().as_raw();

        check_peer_uid(Path::new("/dev/null"), &theirs, our_uid)
            .expect("our own uid must be accepted");
    }

    #[test]
    fn recognizes_no_display_and_nothing_else() {
        assert!(is_no_display(
            r#"{"ok":false,"v":1,"error":"no_display","detail":"no display to prompt on"}"#
        ));
        assert!(!is_no_display(
            r#"{"ok":false,"v":1,"error":"wrong_credentials","db":"personal"}"#
        ));
        assert!(!is_no_display(r#"{"ok":true,"v":1,"db":"personal"}"#));
        assert!(!is_no_display("not json"));
    }

    /// What `--tty` prints when there's no controlling terminal — built
    /// from the same `Response`/`UnlockError` the daemon serializes, so it
    /// can't drift from the real wire form a plain `unlock` gets.
    #[test]
    fn synthetic_no_display_line_matches_the_daemons_own() {
        let line = synthetic_no_display_line();
        assert!(line.ends_with('\n'));
        assert!(is_no_display(&line));
        assert_eq!(
            line,
            "{\"v\":1,\"ok\":false,\"error\":\"no_display\",\"detail\":\"no display to prompt on\"}\n"
        );
    }
}
