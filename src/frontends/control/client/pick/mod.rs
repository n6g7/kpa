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
use std::io;
use std::path::Path;
use std::process::{ExitCode, ExitStatus};

use self::keys::Action;
use super::{ClientError, parse_response, report_client_error, send_request};
use crate::frontends::control::proto::{
    CopyOutcome, CopyRequest, Field, ListRequest, ListResponse, Op, Request, StatusResponse,
    WireEntry,
};
use crate::output::{print_escaped, report_error};

/// The program that is run as fzf, looked up on `PATH`.
const FZF: &str = "fzf";

/// `kpa pick`: the entries of every unlocked database in fzf, starting from
/// `query`, and the field its key names copied from the one chosen. Nothing
/// is printed but what was copied, or why nothing was.
pub fn run_pick(socket_path: &Path, query: &[String]) -> ExitCode {
    match pick_with(socket_path, OsStr::new(FZF), query) {
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
    /// Carries the name of one of them, for the sentence.
    #[error("every database is locked; run `kpa unlock {0}` and try again")]
    AllLocked(String),
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

/// Sends `request` and decodes the answer.
fn ask<T: serde::de::DeserializeOwned>(
    socket_path: &Path,
    request: &Request,
) -> Result<T, PickError> {
    let line = send_request(socket_path, request)?;
    parse_response(&line).map_err(PickError::Daemon)
}

/// `run_pick` with fzf given: the sentence for what was copied.
fn pick_with(socket_path: &Path, fzf: &OsStr, query: &[String]) -> Result<String, PickError> {
    let status: StatusResponse = ask(socket_path, &Request::new(Op::Status))?;
    // Before anything is listed or fzf is up: a pick that can't copy is
    // wasted.
    if !status.can_copy {
        return Err(PickError::CannotCopy);
    }
    if status.databases.is_empty() {
        return Err(PickError::NoDatabases);
    }

    let locked: Vec<&str> = status
        .databases
        .iter()
        .filter(|database| database.locked)
        .map(|database| database.name.as_str())
        .collect();
    if locked.len() == status.databases.len() {
        return Err(PickError::AllLocked(locked[0].to_string()));
    }

    let ListResponse { entries } = ask(
        socket_path,
        &Request::new(Op::List(ListRequest { db: None })),
    )?;
    if entries.is_empty() {
        return Err(PickError::NoEntries);
    }

    let args = fzf::entry_args(&query.join(" "), &locked);
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
    let copied: CopyOutcome = ask(socket_path, &request)?;
    Ok(format!(
        "copied {} of {:?} from {:?}; the clipboard clears in {}s",
        copied.copied,
        lines::title_of(entry),
        entry.db,
        copied.expires_in
    ))
}

/// A second fzf over the names of `entry`'s own fields.
fn choose_field(fzf: &OsStr, entry: &WireEntry) -> Result<Field, PickError> {
    if entry.fields.is_empty() {
        return Err(PickError::NoFields);
    }
    let lines = lines::field_lines(lines::title_of(entry), &entry.fields);
    let answer = fzf::run(fzf, &fzf::field_args(), &lines)?;
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
