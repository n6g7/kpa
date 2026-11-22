//! CLI entry point: parses arguments and dispatches. `serve` runs the
//! daemon here directly; every other subcommand goes to [`client`] — one
//! request, and the daemon's raw JSON response line printed verbatim or,
//! for a command with a text view, that view of it; `unlock` passes its
//! terminal along for the daemon to ask for the master password on.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use kpa::config::Config;
use kpa::daemon;
use kpa::frontends::auto_lock::Source;
use kpa::frontends::control::client::{
    self, Format, ssh_grants_report, ssh_keys_report, ssh_requests_report,
};
use kpa::frontends::control::proto::{
    CopyRequest, Field, ListRequest, LockRequest, Op, SshApproveRequest, SshKeysReport,
    SshKeysRequest,
};
use kpa::log::{self, Level};
use kpa::output::report_error;
use kpa::paths::Paths;
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

    /// Print the daemon's raw JSON response line. `ssh keys` prints text
    /// without it; the other commands print the JSON line either way,
    /// until they have a text output of their own. `version` has no JSON
    /// form and ignores it.
    #[arg(long, global = true)]
    json: bool,

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
    /// Unlock one database. The daemon asks for the master password on
    /// screen when the request comes from the desktop; otherwise it asks on
    /// this terminal (`docs/headless.md` § 4).
    Unlock {
        db: String,
        /// Have the daemon ask on this terminal even where it could ask on
        /// screen. What a desktop terminal uses to type the password
        /// instead of using the graphical prompt.
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
    /// custom key that collides with one of those (`docs/protocol.md`'s
    /// collision rule).
    #[command(visible_alias = "cp")]
    Copy {
        db: String,
        uuid: Uuid,
        field: Field,
    },
    /// The SSH agent: its keys, and the requests refused for want of an
    /// approval.
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
    /// Print the version this binary was built from.
    Version,
}

#[derive(Subcommand)]
enum SshCommand {
    /// Show the SSH keys the unlocked databases hold, and the attachments
    /// skipped and why (`docs/ssh-agent.md` § 6.4).
    Keys {
        /// Only this database's keys.
        #[arg(long)]
        database: Option<String>,
        /// Print a `[[database.ssh_key]]` block per key instead, to paste
        /// into the config.
        #[arg(long, conflicts_with = "json")]
        toml: bool,
        /// Show every column: the database, the entry and the attachment
        /// too.
        #[arg(long)]
        full: bool,
    },
    /// List the SSH requests that came from outside the desktop and were
    /// refused for want of an approval, each with the id `kpa ssh approve`
    /// takes (`docs/ssh-agent.md` § 6.8). A request nobody approves expires
    /// after 5 minutes.
    Pending,
    /// List the signature approvals currently granted, with how long each
    /// lasts, how it was given and how often it has been used
    /// (`docs/ssh-agent.md` § 6.8). `kpa lock <database>` drops a database's.
    Grants {
        /// Show every column: the database, the forwarding session, the
        /// age, how it was granted, when it was last used and the idle lock.
        #[arg(long)]
        full: bool,
    },
    /// Approve one pending SSH request, by the id `kpa ssh pending` shows;
    /// the command that was refused then works on its next try.
    Approve { id: Uuid },
}

fn main() -> ExitCode {
    dispatch(Cli::parse())
}

/// Everything `main` does once arguments are parsed. Marks this process
/// non-dumpable first, before any subcommand's dispatch can begin. If that
/// fails, this returns without dispatching to anything: `serve` holds
/// secrets and must never run dumpable, and the clients lose nothing by
/// also refusing.
fn dispatch(cli: Cli) -> ExitCode {
    if let Err(err) = forbid_core_dumps() {
        report_error(format_args!("marking this process non-dumpable: {err}"));
        return ExitCode::FAILURE;
    }

    // The socket and cache locations, read from the
    // environment once. The config path and the Wayland socket are looked
    // up by their own subsystems.
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
        Command::Ssh {
            command:
                SshCommand::Keys {
                    database,
                    toml,
                    full,
                },
        } => client::run(
            &socket_path,
            Op::SshKeys(SshKeysRequest { db: database }),
            if cli.json { Format::Json } else { Format::Text },
            |report: SshKeysReport| ssh_keys_report::render(&report, toml, full),
        ),
        Command::Ssh {
            command: SshCommand::Pending,
        } => client::run(
            &socket_path,
            Op::SshPending,
            if cli.json { Format::Json } else { Format::Text },
            |pending: ssh_requests_report::Pending| {
                ssh_requests_report::render(&pending, SystemTime::now())
            },
        ),
        Command::Ssh {
            command: SshCommand::Grants { full },
        } => client::run(
            &socket_path,
            Op::SshGrants,
            if cli.json { Format::Json } else { Format::Text },
            |grants: ssh_grants_report::Grants| {
                ssh_grants_report::render(&grants, SystemTime::now(), full)
            },
        ),
        Command::Ssh {
            command: SshCommand::Approve { id },
        } => client::run(
            &socket_path,
            Op::SshApprove(SshApproveRequest { id }),
            if cli.json { Format::Json } else { Format::Text },
            |approved: ssh_requests_report::Approved| ssh_requests_report::approved(id, &approved),
        ),
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
/// root-owned. Like the swap and ptrace notes in `docs/design.md` § Secrets, that
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

    // The SSH agent's socket (`docs/ssh-agent.md` § 7), bound only once a
    // database serves SSH keys.
    let agent = if config.databases.iter().any(|cfg| cfg.serve_ssh_keys) {
        let Some(path) = config.ssh_agent.socket_path(paths.runtime_dir.as_deref()) else {
            report_error(
                "ssh_agent.socket is unset and XDG_RUNTIME_DIR is not set to an absolute path; \
                 a database has serve_ssh_keys = true, so the SSH agent socket needs one",
            );
            return ExitCode::FAILURE;
        };
        match socket::bind_socket(&path) {
            Ok(listener) => Some((path, listener)),
            Err(err) => {
                report_error(format_args!(
                    "binding the ssh agent socket {}: {err}",
                    path.display()
                ));
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    log::set_level(log_level.unwrap_or(config.log_level));
    log::info(format_args!(
        "kpa {} listening on {}",
        kpa::VERSION,
        socket_path.display()
    ));
    let agent = agent.map(|(path, listener)| {
        log::info(format_args!("ssh agent listening on {}", path.display()));
        listener
    });
    daemon::serve(config, paths, listener, agent, Source::system());
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

    /// `docs/design.md` § Secrets promises the daemon is non-dumpable;
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

    /// `dispatch` marks a client non-dumpable too, not just the daemon, and
    /// does it before the subcommand runs. This drives it down the `Unlock`
    /// arm and checks the process is already non-dumpable by the time it
    /// gets there. The socket points nowhere, so `send_request` fails at
    /// connect and this never passes a terminal along — nothing to hang on
    /// if one is attached.
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
            json: false,
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
