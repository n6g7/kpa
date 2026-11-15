//! CLI entry point: parses arguments and dispatches. `serve` runs the
//! daemon here directly; every other subcommand goes to [`client`] — one
//! request, the daemon's raw JSON response line printed verbatim, except
//! `unlock`, which can send a second once the terminal read it needs is
//! done.

mod client;
mod tty;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use kpa::config::Config;
use kpa::log::{self, Level};
use kpa::output::report_error;
use kpa::paths::Paths;
use kpa::policy;
use kpa::proto::{CopyRequest, Field, ListRequest, LockRequest, Op};
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
    /// Unlock one database. The daemon prompts on screen when the request
    /// comes from the desktop; otherwise this reads the master password
    /// from this terminal and sends it instead (`docs/headless.md` § 4).
    Unlock {
        db: String,
        /// Read the password from this terminal right away, rather than
        /// trying a plain request first. What a desktop terminal uses to
        /// ask for the terminal read instead of the graphical prompt.
        #[arg(long)]
        tty: bool,
    },
    /// Lock one database, or every database if none is given.
    Lock { db: Option<String> },
    /// List entries: every unlocked database, or just one.
    #[command(visible_alias = "ls")]
    List { db: Option<String> },
    /// Copy one field of one entry to the clipboard; the daemon drops it
    /// again after `clipboard_timeout`. `field` is `username`, `password`,
    /// `url`, `notes`, a custom field's bare key, or `custom:<key>` for a
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
    dispatch(Cli::parse())
}

/// Everything `main` does once arguments are parsed. Marks this process
/// non-dumpable first, before any subcommand's dispatch — including
/// `Unlock`'s terminal read, which holds the master password — can begin.
/// If that fails, this returns without dispatching to anything: a
/// subcommand that holds a secret must never run dumpable, and the ones
/// that don't lose nothing by also refusing.
fn dispatch(cli: Cli) -> ExitCode {
    if let Err(err) = forbid_core_dumps() {
        report_error(format_args!("marking this process non-dumpable: {err}"));
        return ExitCode::FAILURE;
    }

    // The socket and cache locations, read from the environment once. The
    // config path and the Wayland socket are looked up by their own
    // subsystems.
    let paths = Paths::from_env();

    // Reports the CLI's own version unconditionally, then best-efforts the
    // daemon's — so it still works with no `$XDG_RUNTIME_DIR` set and no
    // daemon running, handled before `socket_path` is resolved the way
    // every other subcommand needs it (which would otherwise fail loudly
    // in exactly the case this command has to tolerate quietly).
    if let Command::Version = cli.command {
        return client::run_version(cli.socket.or_else(|| default_socket_path(&paths).ok()));
    }

    let socket_path = match cli.socket {
        Some(path) => path,
        None => match default_socket_path(&paths) {
            Ok(path) => path,
            Err(err) => {
                report_error(err);
                return ExitCode::FAILURE;
            }
        },
    };

    match cli.command {
        Command::Serve { log_level } => run_serve(&socket_path, cli.config, log_level, paths),
        Command::Status => client::run_client(&socket_path, Op::Status),
        Command::Unlock { db, tty } => client::run_unlock(&socket_path, db, tty),
        Command::Lock { db } => client::run_client(&socket_path, Op::Lock(LockRequest { db })),
        Command::List { db } => client::run_client(&socket_path, Op::List(ListRequest { db })),
        Command::Copy { db, uuid, field } => {
            client::run_client(&socket_path, Op::Copy(CopyRequest { db, uuid, field }))
        }
        Command::Version => unreachable!("handled above, before socket_path is resolved"),
    }
}

/// The main socket's default: `kpa/sock` under the runtime directory.
fn default_socket_path(paths: &Paths) -> Result<PathBuf, String> {
    paths
        .runtime_dir
        .as_ref()
        .map(|dir| dir.join("kpa").join("sock"))
        .ok_or_else(|| {
            "XDG_RUNTIME_DIR is not set to an absolute path; pass --socket explicitly".to_string()
        })
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
    paths: Paths,
) -> ExitCode {
    // `dispatch` already marked this process non-dumpable, before it ever
    // reached this subcommand.
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
    let server = Arc::new(Server::new(config, paths));
    // Before serving, so no unlock can happen without the policy hearing of it.
    let events = policy::start(server.clone(), policy::Bus::System);
    server.set_policy_events(events);
    tray::start(server.clone());
    server::serve(server, listener);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};

    use super::{Cli, Command, dispatch, forbid_core_dumps};

    /// `PR_SET_DUMPABLE` is process-wide, not per-thread, and `cargo test`
    /// runs these in parallel in one process. The two tests below take
    /// turns through this lock rather than racing each other's state.
    static DUMPABLE_LOCK: Mutex<()> = Mutex::new(());

    /// `docs/design.md` § Security promises the daemon is non-dumpable;
    /// this is what makes that a fact about the code rather than the doc.
    #[test]
    fn the_daemon_marks_itself_non_dumpable() {
        let _turn = DUMPABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        forbid_core_dumps().expect("prctl(PR_SET_DUMPABLE) should succeed");
        assert_eq!(
            dumpable_behavior().expect("prctl(PR_GET_DUMPABLE) should succeed"),
            DumpableBehavior::NotDumpable
        );
    }

    /// `kpa unlock` holds the master password from the terminal read
    /// onward, so it must be non-dumpable too, not just the daemon. This
    /// drives `dispatch` down the `Unlock` arm and checks the process is
    /// already non-dumpable by the time it gets there. The socket points
    /// nowhere, so `send_request` fails at connect and this never reaches
    /// the terminal read — no pty needed, and nothing to hang on if one is
    /// attached.
    #[test]
    fn the_unlock_path_marks_itself_non_dumpable_before_dispatch() {
        let _turn = DUMPABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Known starting state, regardless of whether the other test in
        // this process already ran.
        set_dumpable_behavior(DumpableBehavior::Dumpable)
            .expect("prctl(PR_SET_DUMPABLE) should succeed");

        dispatch(Cli {
            socket: Some(PathBuf::from("/nonexistent-kpa-f01-test/sock")),
            config: None,
            command: Command::Unlock {
                db: "test".to_string(),
                tty: false,
            },
        });

        assert_eq!(
            dumpable_behavior().expect("prctl(PR_GET_DUMPABLE) should succeed"),
            DumpableBehavior::NotDumpable
        );
    }
}
