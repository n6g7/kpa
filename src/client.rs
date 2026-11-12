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
use std::sync::atomic::{AtomicBool, Ordering};

use kpa::output::{print_escaped, report_error};
use kpa::proto::{
    self, MAX_PASSWORD_LEN, Op, Password, Request, Response, UnlockError, UnlockRequest,
};
use kpa::socket;
use zeroize::Zeroizing;

use super::default_socket_path;

pub(super) fn run_client(socket_path: &Path, op: Op) -> ExitCode {
    let request = Request {
        v: proto::VERSION,
        op,
    };

    match send_request(socket_path, &request) {
        Ok(line) => print_and_exit(&line),
        // Only a failed connect means the daemon may not be running. Once
        // connected, a missing reply means it hit a problem with this
        // request, and suggesting it's down would send someone looking in
        // the wrong place.
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

/// Prints a response line and turns its `ok` field into an exit code.
/// Shared by every client subcommand that sends exactly one request and
/// shows the daemon's answer verbatim.
fn print_and_exit(line: &str) -> ExitCode {
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
pub(super) fn run_version(socket: Option<PathBuf>) -> ExitCode {
    println!("client: {}", kpa::VERSION);

    let socket_path = socket.or_else(|| default_socket_path().ok());
    let Some(socket_path) = socket_path else {
        println!("server: not running (XDG_RUNTIME_DIR is not set; pass --socket to check)");
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
enum ClientError {
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
fn send_request(socket_path: &Path, request: &Request) -> Result<String, ClientError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| ClientError::Connect(socket_path.to_path_buf(), err))?;
    check_peer_uid(socket_path, &stream, rustix::process::geteuid().as_raw())?;

    let text = serde_json::to_string(request).map_err(ClientError::Encode)?;
    writeln!(stream, "{text}").map_err(ClientError::Send)?;

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
    let password = match read_tty_password() {
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

/// Written to `/dev/tty` before reading the password. No trailing
/// newline, so the password is typed on the same line.
const TTY_PROMPT: &[u8] = b"Master password: ";

/// Why reading the password from the terminal failed.
#[derive(Debug, thiserror::Error)]
enum TtyReadError {
    #[error("opening /dev/tty: {0}")]
    NoTty(std::io::Error),
    #[error("disabling terminal echo: {0}")]
    Termios(std::io::Error),
    #[error("password exceeds {MAX_PASSWORD_LEN} bytes")]
    TooLong,
    #[error("password is not valid UTF-8")]
    NotUtf8,
    #[error("interrupted")]
    Interrupted,
    #[error("reading /dev/tty: {0}")]
    Io(std::io::Error),
}

/// Set once by [`record_sigint`]. Checked only right after a read on
/// `/dev/tty` comes back `EINTR`, to tell a `SIGINT` from any other signal
/// that could also interrupt it.
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn record_sigint(_signum: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

/// Disables echo on `tty` and installs a `SIGINT` handler with
/// `SA_RESTART` off, for as long as the guard lives. Without the handler,
/// Ctrl-C's default disposition (terminate) would kill the process before
/// `Drop` could run, leaving echo off in the shell that follows; without
/// clearing `SA_RESTART`, the kernel would resume the interrupted `read`
/// itself and Ctrl-C would never surface as `EINTR` at all. Both are put
/// back when the guard drops — on every exit path out of
/// [`read_tty_password`]: success, a read error, or Ctrl-C.
struct TtyGuard<'a> {
    tty: &'a std::fs::File,
    echo: rustix::termios::Termios,
    sigint: libc::sigaction,
}

impl<'a> TtyGuard<'a> {
    fn new(tty: &'a std::fs::File) -> Result<TtyGuard<'a>, TtyReadError> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

        let echo = tcgetattr(tty).map_err(|err| TtyReadError::Termios(err.into()))?;
        let mut no_echo = echo.clone();
        no_echo.local_modes.remove(LocalModes::ECHO);
        tcsetattr(tty, OptionalActions::Now, &no_echo)
            .map_err(|err| TtyReadError::Termios(err.into()))?;

        SIGINT_RECEIVED.store(false, Ordering::SeqCst);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_sigint as *const () as usize;
        action.sa_flags = 0; // No `SA_RESTART`: an interrupted read must return `EINTR`.
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `action` and `previous` are live, correctly-sized
        // `sigaction` structs for the duration of these calls; `sigaction`
        // only ever reads the former and writes the latter.
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(libc::SIGINT, &action, &mut previous);
        }

        Ok(TtyGuard {
            tty,
            echo,
            sigint: previous,
        })
    }
}

impl Drop for TtyGuard<'_> {
    fn drop(&mut self) {
        let _ =
            rustix::termios::tcsetattr(self.tty, rustix::termios::OptionalActions::Now, &self.echo);
        // SAFETY: `self.sigint` is the disposition `TtyGuard::new` saved
        // before replacing it; this puts it back.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.sigint, std::ptr::null_mut());
        }
    }
}

/// Writes all of `buf` to `tty`, retrying on `EINTR` (a prompt is not the
/// password, so there's nothing here for Ctrl-C to interrupt).
fn write_tty(tty: &std::fs::File, mut buf: &[u8]) -> Result<(), TtyReadError> {
    while !buf.is_empty() {
        match rustix::io::write(tty, buf) {
            Ok(0) => {
                return Err(TtyReadError::Io(std::io::Error::other(
                    "short write to tty",
                )));
            }
            Ok(n) => buf = &buf[n..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(TtyReadError::Io(err.into())),
        }
    }
    Ok(())
}

/// Opens this process's controlling terminal, disables echo, prompts, and
/// reads one line as the master password — the way `ssh` and `sudo` read
/// theirs (`docs/headless.md` § 4). An absent `/dev/tty` (no controlling
/// terminal, e.g. a cron job) is `TtyReadError::NoTty`, which the caller
/// treats as `no_display`.
///
/// The password goes straight into a zeroizing buffer of exactly
/// `MAX_PASSWORD_LEN` bytes that never grows, as `Password::from_base64`
/// and the daemon's own prompt reader do: a reallocating buffer leaves an
/// unwiped copy of everything read so far behind at every resize. A line
/// that doesn't fit is refused outright rather than read in parts.
///
/// An empty line (just Enter) comes back as an empty password, which the
/// daemon treats as "no password" — the one way to reach a keyfile-only
/// database from here, same as from the graphical prompt.
fn read_tty_password() -> Result<Zeroizing<String>, TtyReadError> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(TtyReadError::NoTty)?;

    let _guard = TtyGuard::new(&tty)?;
    write_tty(&tty, TTY_PROMPT)?;
    let password = read_password_line(&tty)?;
    // With echo off, the terminal never showed the Enter keypress either;
    // write the newline ourselves so whatever prints next starts its own
    // line.
    write_tty(&tty, b"\n")?;
    Ok(password)
}

/// Reads one newline-terminated line from `fd` as the password: everything
/// up to (not including) the first `\n`, or everything read so far on EOF
/// with none. Split out from [`read_tty_password`] so the bound it enforces
/// — refused outright past `MAX_PASSWORD_LEN`, never read in parts — is
/// testable against a plain pipe, without a real terminal's own line-length
/// limit getting in the way.
fn read_password_line(fd: impl rustix::fd::AsFd) -> Result<Zeroizing<String>, TtyReadError> {
    // One byte more than the longest password accepted: a line of exactly
    // `MAX_PASSWORD_LEN` bytes still has room left for the newline that
    // ends it, while anything longer fills this buffer before a newline
    // ever appears in it, caught below without reading further.
    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_LEN + 1]);
    let mut len = 0;
    let newline = loop {
        if len == buf.len() {
            return Err(TtyReadError::TooLong);
        }
        match rustix::io::read(&fd, &mut buf[len..]) {
            // EOF (Ctrl-D) with no newline: take what's there.
            Ok(0) => break None,
            Ok(n) => {
                len += n;
                if let Some(at) = buf[..len].iter().position(|&b| b == b'\n') {
                    break Some(at);
                }
            }
            Err(rustix::io::Errno::INTR) => {
                if SIGINT_RECEIVED.load(Ordering::SeqCst) {
                    return Err(TtyReadError::Interrupted);
                }
                // Some other signal arrived; the read just hasn't happened yet.
            }
            Err(err) => return Err(TtyReadError::Io(err.into())),
        }
    };

    let end = newline.unwrap_or(len);
    if end > MAX_PASSWORD_LEN {
        return Err(TtyReadError::TooLong);
    }
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| TtyReadError::NotUtf8)?;
    let mut password = Zeroizing::new(String::with_capacity(text.len()));
    password.push_str(text);
    Ok(password)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::Path;

    use super::{
        ClientError, MAX_PASSWORD_LEN, TtyReadError, check_peer_uid, is_no_display,
        read_password_line, synthetic_no_display_line,
    };

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

    /// A plain pipe rather than a real terminal, so the bound tested here
    /// is `read_password_line`'s own, not a tty's separate line-length
    /// limit (Linux's `N_TTY_BUF_SIZE`, which is close to but not the same
    /// number).
    fn pipe() -> (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ) {
        std::os::unix::net::UnixStream::pair().expect("socket pair")
    }

    #[test]
    fn reads_up_to_the_newline_and_leaves_the_rest() {
        let (mut writer, reader) = pipe();
        writer
            .write_all(b"hunter2\nnot part of the password")
            .expect("write");

        let password = read_password_line(&reader).expect("short line");
        assert_eq!(password.as_str(), "hunter2");
    }

    #[test]
    fn an_empty_line_is_an_empty_password() {
        let (mut writer, reader) = pipe();
        writer.write_all(b"\n").expect("write");

        let password = read_password_line(&reader).expect("empty line");
        assert_eq!(password.as_str(), "");
    }

    #[test]
    fn eof_with_no_newline_returns_what_was_read() {
        let (writer, reader) = pipe();
        drop(writer); // EOF, having sent nothing

        let password = read_password_line(&reader).expect("EOF");
        assert_eq!(password.as_str(), "");
    }

    #[test]
    fn a_line_at_exactly_the_limit_is_accepted() {
        let (mut writer, reader) = pipe();
        let longest = "a".repeat(MAX_PASSWORD_LEN);
        writer.write_all(longest.as_bytes()).expect("write");
        writer.write_all(b"\n").expect("write");

        let password = read_password_line(&reader).expect("at the limit");
        assert_eq!(password.as_str(), longest);
    }

    #[test]
    fn a_line_over_the_limit_is_refused_rather_than_read_in_parts() {
        let (mut writer, reader) = pipe();
        // One byte over, and never terminated — `read_password_line` must
        // give up once its fixed buffer fills, not wait for a newline that
        // isn't coming.
        writer
            .write_all(&vec![b'a'; MAX_PASSWORD_LEN + 1])
            .expect("write");

        let err = read_password_line(&reader).expect_err("over the limit");
        assert!(matches!(err, TtyReadError::TooLong), "{err:?}");
    }
}
