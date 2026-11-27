//! Running fzf over a list held in memory, and what it is told on its command
//! line.

use std::ffi::OsStr;
use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use super::PickError;
use super::keys;
use super::lines::DELIMITER;
use crate::output::escape_one_line;

/// What every fzf `kpa pick` runs is told: show the text after the index, open
/// below the prompt, and never keep a history or run a preview. These two are
/// off on the command line because a user's `FZF_DEFAULT_OPTS` or
/// `FZF_DEFAULT_OPTS_FILE` could otherwise turn them on: `--history` would
/// write what is typed to a file, and `--preview` would run a program on every
/// highlighted line. Options on the command line win over those defaults.
/// Everything else in them (colours, bindings) is left to the user.
fn common_args(prompt: &str) -> Vec<String> {
    [
        "--delimiter",
        DELIMITER,
        "--with-nth",
        "2..",
        "--height=60%",
        "--layout=reverse",
        "--no-history",
        "--no-preview",
        "--prompt",
        prompt,
    ]
    .map(str::to_string)
    .to_vec()
}

/// The arguments for choosing an entry: it ends on the keys of
/// [`keys::EXPECT`], starts from `query`, and its header says what each key
/// copies, and on a second line which databases are `locked` and so not
/// listed.
pub(super) fn entry_args(query: &str, locked: &[&str]) -> Vec<String> {
    let mut header = keys::HELP.to_string();
    if !locked.is_empty() {
        let names: Vec<String> = locked
            .iter()
            .map(|name| escape_one_line(name, usize::MAX))
            .collect();
        header.push_str(&format!("\nlocked: {}", names.join(", ")));
    }
    let mut args = common_args("kpa> ");
    args.extend(
        [
            "--header",
            &header,
            "--expect",
            keys::EXPECT,
            "--query",
            query,
        ]
        .iter()
        .map(|arg| arg.to_string()),
    );
    args
}

/// The arguments for choosing one of the fields of an entry. Its title heads
/// the list as the first line, which fzf shows and never lets be chosen
/// ([`super::lines::field_lines`]): the title is vault text, so it travels on the
/// pipe and never on the command line.
pub(super) fn field_args() -> Vec<String> {
    let mut args = common_args("field> ");
    args.push("--header-lines=1".to_string());
    args
}

/// Runs `program` with `args`, feeds it `lines` on a pipe and returns what it
/// printed. Its stderr and `/dev/tty` are the user's terminal, which is where
/// fzf draws. Nothing is written to a file: the lines go through the pipe.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn value_of<'a>(args: &'a [String], flag: &str) -> &'a str {
        let at = args.iter().position(|arg| arg == flag).expect(flag);
        &args[at + 1]
    }

    #[test]
    fn every_fzf_opens_below_the_prompt_and_keeps_no_history_or_preview() {
        for args in [entry_args("", &[]), field_args()] {
            for flag in [
                "--height=60%",
                "--layout=reverse",
                "--no-history",
                "--no-preview",
            ] {
                assert!(args.iter().any(|arg| arg == flag), "{flag} in {args:?}");
            }
            assert_eq!(value_of(&args, "--with-nth"), "2..");
        }
    }

    #[test]
    fn the_entry_header_names_the_keys_and_then_the_locked_databases() {
        let args = entry_args("hub", &["work", "arch\nive"]);
        assert_eq!(value_of(&args, "--prompt"), "kpa> ");
        assert_eq!(value_of(&args, "--query"), "hub");
        assert_eq!(value_of(&args, "--expect"), keys::EXPECT);
        assert_eq!(
            value_of(&args, "--header"),
            format!("{}\nlocked: work, arch\\u000aive", keys::HELP)
        );
        assert_eq!(value_of(&entry_args("", &[]), "--header"), keys::HELP);
    }

    #[test]
    fn the_field_fzf_takes_its_header_from_the_list_and_has_no_text_of_the_entry() {
        let args = field_args();
        assert_eq!(value_of(&args, "--prompt"), "field> ");
        assert!(args.iter().any(|arg| arg == "--header-lines=1"));
        assert!(
            !args
                .iter()
                .any(|arg| arg == "--header" || arg == "--expect")
        );
    }
}
