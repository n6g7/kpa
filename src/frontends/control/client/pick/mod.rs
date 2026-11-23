//! `kpa pick`: choose an entry in fzf and `copy` one of its fields
//! (`docs/design.md` § The picker).
//!
//! The list of entries lives in this process and reaches fzf through a pipe;
//! nothing from a database is written to a file. `keys` is what each key
//! copies, `lines` what fzf is shown and how its answer is read, `fzf` the
//! process; this file is the order they run in.

mod fzf;
mod keys;
mod lines;

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{ExitCode, ExitStatus};

use serde::Deserialize;
use serde::de::IgnoredAny;

use self::keys::Action;
use super::{ClientError, exchange, parse_response, report_client_error, tty};
use crate::frontends::control::proto::{
    CopyRequest, DatabaseStatus, Field, ListRequest, Op, PromptOn, Request, UnlockRequest,
    WireEntry,
};
use crate::output::{escape_one_line, print_escaped, report_error};

/// The program that is run as fzf, looked up on `PATH`.
const FZF: &str = "fzf";

/// `kpa pick`: the entries of every unlocked database in fzf, starting from
/// `query`, and the field its key names copied from the one chosen. Nothing
/// is printed but what was copied, or why nothing was.
pub fn run_pick(socket_path: &Path, query: &[String]) -> ExitCode {
    let terminal = tty::controlling_terminal();
    match pick_with(socket_path, OsStr::new(FZF), query, terminal.as_ref()) {
        Ok(copied) => {
            print_escaped(&format!("{copied}\n"));
            ExitCode::SUCCESS
        }
        Err(PickError::Cancelled) => ExitCode::FAILURE,
        Err(PickError::Client(err)) => report_client_error(err),
        Err(err) => {
            report_error(err);
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum PickError {
    #[error("{0}")]
    Client(#[from] ClientError),
    /// The daemon refused a request, as a sentence.
    #[error("{0}")]
    Daemon(String),
    #[error(
        "a copy from here can't land (no_display): kpa copies to the desktop's clipboard, \
         and only for a requester on the desktop while its screen is unlocked"
    )]
    CannotCopy,
    #[error("no database is configured")]
    NoDatabases,
    #[error("the unlocked databases hold no entries")]
    NoEntries,
    #[error("fzf is not on PATH; `kpa pick` needs it to choose an entry")]
    NoFzf,
    #[error("running fzf: {0}")]
    Fzf(io::Error),
    #[error("fzf failed ({0})")]
    FzfFailed(ExitStatus),
    #[error("fzf answered with something `kpa pick` did not offer it")]
    UnreadableChoice,
    #[error("the entry has no field to copy")]
    NoFields,
    /// The user left fzf without choosing. Nothing to report.
    #[error("cancelled")]
    Cancelled,
}

/// What `status` answers that `pick` reads. `can_copy` is absent from a daemon
/// that predates it, which is not a refusal: it is advisory, and `copy`
/// decides.
#[derive(Deserialize)]
struct Status {
    databases: Vec<DatabaseStatus>,
    #[serde(default)]
    can_copy: Option<bool>,
}

#[derive(Deserialize)]
struct Listed {
    entries: Vec<WireEntry>,
}

#[derive(Deserialize)]
struct Copied {
    copied: String,
    expires_in: u64,
}

/// Sends `op` and decodes the answer; `terminal` is passed along for a
/// daemon that has to ask on it.
fn ask<T: serde::de::DeserializeOwned>(
    socket_path: &Path,
    request: &Request,
    terminal: Option<&File>,
) -> Result<T, PickError> {
    let line = exchange(socket_path, request, terminal)?;
    parse_response(&line).map_err(PickError::Daemon)
}

/// `run_pick` with fzf and the terminal given: the sentence for what was
/// copied.
fn pick_with(
    socket_path: &Path,
    fzf: &OsStr,
    query: &[String],
    terminal: Option<&File>,
) -> Result<String, PickError> {
    let status: Status = ask(socket_path, &Request::new(Op::Status), None)?;
    // Before anything is unlocked or fzf is up: a pick that can't copy is
    // wasted.
    if status.can_copy == Some(false) {
        return Err(PickError::CannotCopy);
    }
    if status.databases.is_empty() {
        return Err(PickError::NoDatabases);
    }

    let mut locked: Vec<&str> = status
        .databases
        .iter()
        .filter(|database| database.locked)
        .map(|database| database.name.as_str())
        .collect();
    if locked.len() == status.databases.len() {
        for db in std::mem::take(&mut locked) {
            let request = Request {
                preferred_prompt: Some(PromptOn::Terminal),
                ..Request::new(Op::Unlock(UnlockRequest { db: db.to_string() }))
            };
            ask::<IgnoredAny>(socket_path, &request, terminal)?;
        }
    }

    let listed: Listed = ask(
        socket_path,
        &Request::new(Op::List(ListRequest { db: None })),
        None,
    )?;
    let entries = listed.entries;
    if entries.is_empty() {
        return Err(PickError::NoEntries);
    }

    let mut args = vec![
        "--delimiter".to_string(),
        lines::DELIMITER.to_string(),
        "--with-nth".to_string(),
        "2..".to_string(),
        "--expect".to_string(),
        keys::EXPECT.to_string(),
        "--query".to_string(),
        query.join(" "),
    ];
    if !locked.is_empty() {
        let names: Vec<String> = locked
            .iter()
            .map(|name| escape_one_line(name, usize::MAX))
            .collect();
        args.extend([
            "--header".to_string(),
            format!("locked: {}", names.join(", ")),
        ]);
    }
    let answer = fzf::run(fzf, &args, &lines::entry_lines(&entries))?;

    // The first line is the key fzf ended on, the second the line chosen.
    let mut answer = answer.lines();
    let key = answer.next().unwrap_or_default();
    let chosen = answer.next().unwrap_or_default();
    let action = keys::action(key).ok_or(PickError::UnreadableChoice)?;
    let entry = lines::index_of(chosen, entries.len())
        .map(|index| &entries[index])
        .ok_or(PickError::UnreadableChoice)?;

    let field = match action {
        Action::Copy(field) => field,
        Action::ChooseField => choose_field(fzf, entry)?,
    };
    let request = Request::new(Op::Copy(CopyRequest {
        db: entry.db.clone(),
        uuid: entry.uuid,
        field,
    }));
    let copied: Copied = ask(socket_path, &request, None)?;
    Ok(format!(
        "copied {} of {:?} from {:?}; the clipboard clears in {}s",
        copied.copied,
        entry.title.as_deref().unwrap_or("(no title)"),
        entry.db,
        copied.expires_in
    ))
}

/// A second fzf over the names of `entry`'s own fields.
fn choose_field(fzf: &OsStr, entry: &WireEntry) -> Result<Field, PickError> {
    if entry.fields.is_empty() {
        return Err(PickError::NoFields);
    }
    let args = [
        "--delimiter".to_string(),
        lines::DELIMITER.to_string(),
        "--with-nth".to_string(),
        "2..".to_string(),
    ];
    let answer = fzf::run(fzf, &args, &lines::field_lines(&entry.fields))?;
    let name = lines::index_of(
        answer.lines().next().unwrap_or_default(),
        entry.fields.len(),
    )
    .map(|index| &entry.fields[index])
    .ok_or(PickError::UnreadableChoice)?;
    let Ok(field) = name.parse::<Field>();
    Ok(field)
}

#[cfg(test)]
mod tests;
