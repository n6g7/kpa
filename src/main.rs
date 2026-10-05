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
use kpa::proto::{self, ListRequest, LockRequest, Op, Request, UnlockRequest};
use kpa::server::{self, Server};

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
    }
}

fn default_socket_path() -> Result<PathBuf, String> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("kpa").join("sock"))
        .ok_or_else(|| "XDG_RUNTIME_DIR is not set; pass --socket explicitly".to_string())
}

/// Escapes the characters a terminal could act on, as `\uXXXX`. Every byte
/// the CLI writes to a terminal goes through here: the daemon's JSON line,
/// and any error text that can echo input or database content.
///
/// Escaped: C0 controls other than tab and newline, DEL, the C1 controls,
/// ALM, the zero-width and bidi format characters, the line and paragraph
/// separators, and the word joiner and invisible-operator range.
///
/// Every escaped character is in the BMP, so `\uXXXX` is valid JSON inside a
/// string. A serialized line therefore still parses to the same values, and
/// `\` and ASCII are never touched, so serde's own escapes pass through as
/// they are. Tab and newline are kept because they are layout, not control.
fn escape_for_terminal(text: &str) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if needs_terminal_escape(c) {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn needs_terminal_escape(c: char) -> bool {
    matches!(
        c,
        '\0'..='\u{8}'
            | '\u{b}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
    )
}

/// Prints `error: <message>` to stderr, with the message escaped.
fn report_error(message: impl std::fmt::Display) {
    eprintln!("error: {}", escape_for_terminal(&message.to_string()));
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

    let listener = match server::bind_socket(socket_path) {
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
    server::serve(Arc::new(Server::new(config)), listener);
    ExitCode::SUCCESS
}

fn run_client(socket_path: &Path, op: Op) -> ExitCode {
    let request = Request {
        v: proto::VERSION,
        op,
    };

    match send_request(socket_path, &request) {
        Ok(line) => {
            print!("{}", escape_for_terminal(&line));
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
    use kpa::proto::{Response, WireEntry};
    use rustix::process::{DumpableBehavior, dumpable_behavior};

    use super::{escape_for_terminal, forbid_core_dumps};

    /// The characters `escape_for_terminal` must never let through, written
    /// out as ranges independently of the function's own table.
    const HOSTILE: &[(char, char)] = &[
        ('\u{0}', '\u{8}'),
        ('\u{b}', '\u{1f}'),
        ('\u{7f}', '\u{9f}'),
        ('\u{61c}', '\u{61c}'),
        ('\u{200b}', '\u{200f}'),
        ('\u{2028}', '\u{202e}'),
        ('\u{2060}', '\u{2069}'),
        ('\u{feff}', '\u{feff}'),
        ('\u{fff9}', '\u{fffb}'),
    ];

    fn is_hostile(c: char) -> bool {
        HOSTILE.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
    }

    #[test]
    fn every_hostile_character_is_escaped_as_a_json_escape() {
        for &(lo, hi) in HOSTILE {
            for c in lo..=hi {
                let out = escape_for_terminal(&c.to_string());
                assert_eq!(
                    out,
                    format!("\\u{:04x}", c as u32),
                    "for U+{:04X}",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn tab_newline_and_ordinary_text_pass_through() {
        let text = "a\tb\nc \\\" é 漢 😀 \u{a0} \u{7e}";
        assert_eq!(escape_for_terminal(text), text);
    }

    /// A `list` line whose title is full of hostile characters. What reaches
    /// the terminal has none of them, and the JSON decodes to the title the
    /// database holds.
    #[test]
    fn a_listed_title_comes_out_escaped_and_still_decodes() {
        let title = "\u{9b}c\u{9d}0;t\u{9c}\u{202e}x\u{7f}\u{2028}";
        let response = Response::List(Ok(vec![WireEntry {
            db: "personal".to_string(),
            uuid: uuid::Uuid::nil(),
            title: Some(title.to_string()),
            username: Some("alice\u{2067}".to_string()),
            url: None,
            group: "Web\u{9b}".to_string(),
        }]));
        let line = format!(
            "{}\n",
            serde_json::to_string(&response).expect("serializes")
        );

        let printed = escape_for_terminal(&line);

        let body = printed
            .strip_suffix('\n')
            .expect("the line ends in a newline");
        assert!(
            !body.chars().any(is_hostile),
            "a hostile character reached the output: {printed:?}"
        );
        assert!(!body.contains('\n'));

        let decoded: serde_json::Value = serde_json::from_str(&printed).expect("still valid JSON");
        let entry = &decoded["entries"][0];
        assert_eq!(entry["title"], title);
        assert_eq!(entry["username"], "alice\u{2067}");
        assert_eq!(entry["group"], "Web\u{9b}");
    }

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
