//! CLI dispatch: `serve` runs the daemon; every other subcommand sends one
//! request over the socket and prints the raw JSON response line
//! (`docs/design.md`'s "hand-debuggable with socat" argument, applied to
//! the CLI itself rather than just `socat`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use kpa::config::Config;
use kpa::output::{escape_for_terminal, print_escaped, report_error};
use kpa::policy;
use kpa::proto::{self, CopyRequest, Field, ListRequest, LockRequest, Op, Request, UnlockRequest};
use kpa::server::{self, Server};
use kpa::socket;
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
    Serve,
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
    /// again after `clipboard_timeout`.
    Copy {
        db: String,
        uuid: Uuid,
        field: FieldArg,
    },
}

/// `clap::ValueEnum` for `copy`'s `field` argument. A separate type from
/// `proto::Field` rather than deriving `ValueEnum` on it there: the
/// protocol module has no reason to depend on `clap`, same reasoning as
/// `LockRequest`/`UnlockRequest` not deriving it either.
#[derive(Clone, Copy, ValueEnum)]
enum FieldArg {
    Password,
    Username,
    Url,
    Notes,
}

impl From<FieldArg> for Field {
    fn from(arg: FieldArg) -> Field {
        match arg {
            FieldArg::Password => Field::Password,
            FieldArg::Username => Field::Username,
            FieldArg::Url => Field::Url,
            FieldArg::Notes => Field::Notes,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

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
        Command::Serve => run_serve(&socket_path, cli.config),
        Command::Status => run_client(&socket_path, Op::Status),
        Command::Unlock { db } => run_client(&socket_path, Op::Unlock(UnlockRequest { db })),
        Command::Lock { db } => run_client(&socket_path, Op::Lock(LockRequest { db })),
        Command::List { db } => run_client(&socket_path, Op::List(ListRequest { db })),
        Command::Copy { db, uuid, field } => run_client(
            &socket_path,
            Op::Copy(CopyRequest {
                db,
                uuid,
                field: field.into(),
            }),
        ),
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

fn run_serve(socket_path: &Path, config_path: Option<PathBuf>) -> ExitCode {
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

    // stdout, matching the operation log in `server::log_response` —
    // errors still go to stderr. Rust line-buffers stdout even when it
    // isn't a terminal, so lines reach a pipe as they happen. Written with
    // the error ignored rather than `println!`, which panics if stdout has
    // been closed: nobody reading the log is no reason to stop serving.
    let _ = writeln!(
        std::io::stdout().lock(),
        "kpa: listening on {}",
        escape_for_terminal(&socket_path.display().to_string())
    );
    let server = Arc::new(Server::new(config));
    // Before serving, so no unlock can happen without the policy hearing of it.
    let events = policy::start(server.clone(), policy::Bus::System);
    server.set_policy_events(events);
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
}

/// Sends one request and returns the daemon's raw response line, newline
/// included. Deliberately not decoded into a typed `Response` — see the
/// comment in `run_client` on why that type has no generic `Deserialize`.
fn send_request(socket_path: &Path, request: &Request) -> Result<String, ClientError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| ClientError::Connect(socket_path.to_path_buf(), err))?;

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
    use rustix::process::{DumpableBehavior, dumpable_behavior};

    use super::forbid_core_dumps;

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
}
