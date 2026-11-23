//! Running fzf over a list held in memory.

use std::ffi::OsStr;
use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use super::PickError;

/// Runs `program` with `args`, feeds it `lines` on a pipe and returns what it
/// printed. Its stderr and `/dev/tty` are the user's terminal, which is where
/// fzf draws. Nothing is written to a file: the lines go through the pipe and
/// no history is asked for.
///
/// A user who ended fzf without choosing (Esc, Ctrl+C, or no line matching)
/// is [`PickError::Cancelled`].
pub(super) fn run(program: &OsStr, args: &[String], lines: &[String]) -> Result<String, PickError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| match err.kind() {
            ErrorKind::NotFound => PickError::NoFzf,
            _ => PickError::Fzf(err),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        for line in lines {
            // fzf that has gone has no more to read. Its exit status says why.
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
    }
    let output = child.wait_with_output().map_err(PickError::Fzf)?;
    match output.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&output.stdout).into_owned()),
        // fzf's own codes: 1 for no match, 130 for an interrupt.
        Some(1 | 130) => Err(PickError::Cancelled),
        _ => Err(PickError::FzfFailed(output.status)),
    }
}
