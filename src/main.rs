//! CLI dispatch: `serve` runs the daemon; every other subcommand sends one
//! request over the socket and prints the raw JSON response line
//! (`docs/design.md`'s "hand-debuggable with socat" argument, applied to
//! the CLI itself rather than just `socat`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use kpa::config::Config;
use kpa::log::{self, Level};
use kpa::output::{print_escaped, report_error};
use kpa::policy;
use kpa::proto::{self, CopyRequest, Field, ListRequest, LockRequest, Op, Request, UnlockRequest};
use kpa::server::{self, Server};
use kpa::socket;
use kpa::tray;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "kpa", about = "A small read-only KeePass agent")]
struct Cli {
    /// Socket path. Defaults to `$XDG_RUNTIME_DIR/kpa/sock`.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Config file path, `serve` only. Defaults to
    /// `$XDG_CONFIG_HOME/kpa/config.toml`.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon: bind the socket and serve requests until killed.
    Serve {
        /// How much to log. Defaults to `log_level` in the config file,
        /// then `info`.
        #[arg(long, value_enum)]
        log_level: Option<Level>,
    },
    /// Aggregate lock state of every configured database.
    Status,
    /// Unlock one database, prompting for its password.
    Unlock { db: String },
    /// Lock one database, or every database if none is given.
    Lock { db: Option<String> },
    /// List entries: every unlocked database, or just one.
    #[command(visible_alias = "ls")]
    List { db: Option<String> },
    /// Copy one field of one entry to the clipboard; the daemon drops it
    /// again after `clipboard_timeout`. `field` is any name `kpa list`
    /// returns in an entry's `fields`: `username`, `password`, `url`,
    /// `notes`, `totp`, a custom field's bare key, or `custom:<key>` for a
    /// custom key that collides with one of those (`docs/design.md` §
    /// Protocol's collision rule).
    #[command(visible_alias = "cp")]
    Copy {
        db: String,
        uuid: Uuid,
        field: Field,
    },
    /// Print the version this binary was built from.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Reports the CLI's own version unconditionally, then best-efforts the
    // daemon's — so it still works with no `$XDG_RUNTIME_DIR` set and no
    // daemon running, handled before `socket_path` is resolved the way
    // every other subcommand needs it (which would otherwise fail loudly
    // in exactly the case this command has to tolerate quietly).
    if let Command::Version = cli.command {
        return run_version(cli.socket);
    }

    let socket_path = match cli.socket {
        Some(path) => path,
        None => match default_socket_path() {
            Ok(path) => path,
            Err(err) => {
                report_error(err);
                return ExitCode::FAILURE;
            }
        },
    };

    match cli.command {
        Command::Serve { log_level } => run_serve(&socket_path, cli.config, log_level),
        Command::Status => run_client(&socket_path, Op::Status),
        Command::Unlock { db } => run_client(&socket_path, Op::Unlock(UnlockRequest { db })),
        Command::Lock { db } => run_client(&socket_path, Op::Lock(LockRequest { db })),
        Command::List { db } => run_client(&socket_path, Op::List(ListRequest { db })),
        Command::Copy { db, uuid, field } => {
            run_client(&socket_path, Op::Copy(CopyRequest { db, uuid, field }))
        }
        Command::Version => unreachable!("handled above, before socket_path is resolved"),
    }
}

fn default_socket_path() -> Result<PathBuf, String> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("kpa").join("sock"))
        .ok_or_else(|| "XDG_RUNTIME_DIR is not set; pass --socket explicitly".to_string())
}

/// Mark this process non-dumpable (`PR_SET_DUMPABLE=0`), before anything
/// secret is loaded. A crash then writes no core file readable by the
/// user — with the decrypted vault in it — and, as a side effect, other
/// processes running as the same user can no longer ptrace it or read its
/// `/proc/<pid>/mem`, whatever the host's Yama setting.
///
/// That's kpa's claim only up to the host's `fs.suid_dumpable`: with it set
/// to `2`, the kernel still writes a core for a non-dumpable process, just
/// root-owned. Like the swap and ptrace notes in `docs/design.md`, that
/// part is a property of the machine, not of kpa.
fn forbid_core_dumps() -> rustix::io::Result<()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
}

fn run_serve(
    socket_path: &Path,
    config_path: Option<PathBuf>,
    log_level: Option<Level>,
) -> ExitCode {
    if let Err(err) = forbid_core_dumps() {
        report_error(format_args!("marking the daemon non-dumpable: {err}"));
        return ExitCode::FAILURE;
    }

    let config = match Config::load(config_path.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            report_error(err);
            return ExitCode::FAILURE;
        }
    };

    let listener = match socket::bind_socket(socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            report_error(format_args!("binding {}: {err}", socket_path.display()));
            return ExitCode::FAILURE;
        }
    };

    log::set_level(log_level.unwrap_or(config.log_level));
    log::info(format_args!(
        "kpa {} listening on {}",
        kpa::VERSION,
        socket_path.display()
    ));
    let server = Arc::new(Server::new(config));
    // Before serving, so no unlock can happen without the policy hearing of it.
    let events = policy::start(server.clone(), policy::Bus::System);
    server.set_policy_events(events);
    tray::start(server.clone());
    server::serve(server, listener);
    ExitCode::SUCCESS
}

fn run_client(socket_path: &Path, op: Op) -> ExitCode {
    let request = Request {
        v: proto::VERSION,
        op,
    };

    match send_request(socket_path, &request) {
        Ok(line) => {
            print_escaped(&line);
            // `Response` deliberately has no generic `Deserialize` — a
            // successful `Unlock` and a successful `Lock { db: Some(_) }`
            // serialize identically, so decoding one back into that type
            // isn't meaningful without already knowing which request
            // produced it. All the client needs is the one shared `ok`
            // field, read out of a bare `Value` instead.
            let ok = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|value| value.get("ok").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
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
fn run_version(socket: Option<PathBuf>) -> ExitCode {
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rustix::process::{DumpableBehavior, dumpable_behavior};

    use super::{ClientError, check_peer_uid, forbid_core_dumps};

    /// `docs/design.md` § Security promises the daemon is non-dumpable;
    /// this is what makes that a fact about the code rather than the doc.
    #[test]
    fn the_daemon_marks_itself_non_dumpable() {
        forbid_core_dumps().expect("prctl(PR_SET_DUMPABLE) should succeed");
        assert_eq!(
            dumpable_behavior().expect("prctl(PR_GET_DUMPABLE) should succeed"),
            DumpableBehavior::NotDumpable
        );
    }

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
}
