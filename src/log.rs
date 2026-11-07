//! The daemon's log: one line per event on stderr, at one of four levels.
//!
//! Everything the daemon says about itself goes through [`log`], so there is
//! one place to audit for what may reach a log. The rule (`docs/design.md`
//! § Logging): a line names the operation, the database and the error kind,
//! never what was in a database. No level is exempt, `debug` included: a log
//! outlives the unlocked session that produced it and lands somewhere far
//! less guarded than the socket (`docs/threat-model.md` TB-7).
//!
//! A line to a terminal or file starts with a local-time RFC 3339 timestamp. Under journald
//! there is none: the journal stamps its own, and a second clock here would
//! only disagree with it.

use chrono::{DateTime, FixedOffset, Local, SecondsFormat};
use std::fmt::{self, Write as _};
use std::io::{IsTerminal as _, Write as _};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::Deserialize;

/// How much the daemon says. A level shows its own lines and every more
/// severe one's: `warn` shows warnings and errors.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum Level {
    /// Something the daemon needed to do failed and it cannot recover.
    Error,
    /// Something failed or was refused, and the daemon carried on.
    Warn,
    /// A change in what the daemon is holding: unlock, lock, copy.
    #[default]
    Info,
    /// Why the daemon did what it did: prompts, bus state, clipboard offers.
    Debug,
}

impl Level {
    /// Upper case and padded to a common width, so messages line up.
    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
        }
    }

    /// The SGR colour code for the level's label.
    fn colour(self) -> &'static str {
        match self {
            Level::Error => "1;31",
            Level::Warn => "33",
            Level::Info => "32",
            Level::Debug => "34",
        }
    }

    /// The syslog severity journald reads from a `<N>` line prefix.
    fn priority(self) -> u8 {
        match self {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug => 7,
        }
    }
}

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Set the most verbose level that gets logged. Called once, after the
/// config is read; until then the level is `info`.
pub fn set_level(level: Level) {
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

fn enabled(level: Level) -> bool {
    level as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

pub fn error(args: fmt::Arguments<'_>) {
    log(Level::Error, args);
}

pub fn warn(args: fmt::Arguments<'_>) {
    log(Level::Warn, args);
}

pub fn info(args: fmt::Arguments<'_>) {
    log(Level::Info, args);
}

pub fn debug(args: fmt::Arguments<'_>) {
    log(Level::Debug, args);
}

/// Write one line to stderr. Never panics, unlike `eprintln!`: a closed or
/// broken stderr must not take the daemon down with it. `args` is only
/// formatted when the level is enabled.
pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    let line = format_line(level, style(), Local::now().fixed_offset(), args);
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// How lines are laid out, decided once from where stderr goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    /// `<N>message`: journald reads the priority and adds its own timestamp.
    Journal,
    /// `2026-11-06T09:33:05-08:00 WARN  message`.
    Plain,
    /// `Plain` with the timestamp dimmed and the level coloured.
    Colour,
}

fn style() -> Style {
    static STYLE: OnceLock<Style> = OnceLock::new();
    *STYLE.get_or_init(|| {
        if journal_attached() {
            Style::Journal
        } else if wants_colour(
            std::io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("TERM").as_deref(),
        ) {
            Style::Colour
        } else {
            Style::Plain
        }
    })
}

/// Colour only on a terminal that can show it. `NO_COLOR` set to anything
/// non-empty turns it off (https://no-color.org), and `TERM=dumb` can't
/// show it.
fn wants_colour(
    is_terminal: bool,
    no_colour: Option<&std::ffi::OsStr>,
    term: Option<&std::ffi::OsStr>,
) -> bool {
    is_terminal && no_colour.is_none_or(|v| v.is_empty()) && term.is_some_and(|t| t != "dumb")
}

/// One finished line, newline included. The journal style ignores `now`. Control characters in the message
/// are escaped, so a crafted database name in a request cannot start a
/// second line (or, under journald, a second `<N>` priority) or inject
/// terminal escapes.
fn format_line(
    level: Level,
    style: Style,
    now: DateTime<FixedOffset>,
    args: fmt::Arguments<'_>,
) -> String {
    let stamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut line = match style {
        Style::Journal => format!("<{}>", level.priority()),
        Style::Plain => format!("{} {} ", stamp, level.label()),
        Style::Colour => format!(
            "\x1b[2m{}\x1b[0m \x1b[{}m{}\x1b[0m ",
            stamp,
            level.colour(),
            level.label()
        ),
    };
    let mut message = String::new();
    let _ = message.write_fmt(args);
    for c in message.chars() {
        if c.is_control() {
            let _ = write!(line, "{}", c.escape_default());
        } else {
            line.push(c);
        }
    }
    line.push('\n');
    line
}

/// Whether stderr is the journal. systemd sets `JOURNAL_STREAM` to the
/// `device:inode` of the stream it connected to a service's stdout and
/// stderr; stderr being that same file is what says lines will be parsed
/// for `<N>` priorities. The variable alone is not enough: it is inherited
/// by children whose stderr has been redirected elsewhere.
fn journal_attached() -> bool {
    static ATTACHED: OnceLock<bool> = OnceLock::new();
    *ATTACHED.get_or_init(|| {
        let Ok(var) = std::env::var("JOURNAL_STREAM") else {
            return false;
        };
        match rustix::fs::fstat(std::io::stderr()) {
            Ok(stat) => matches_journal_stream(&var, stat.st_dev, stat.st_ino),
            Err(_) => false,
        }
    })
}

fn matches_journal_stream(var: &str, dev: u64, ino: u64) -> bool {
    var.split_once(':')
        .and_then(|(d, i)| Some((d.parse::<u64>().ok()?, i.parse::<u64>().ok()?)))
        == Some((dev, ino))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> DateTime<FixedOffset> {
        DateTime::from_timestamp(0, 0).unwrap().fixed_offset()
    }

    #[test]
    fn plain_lines_carry_a_timestamp_and_the_level() {
        assert_eq!(
            format_line(
                Level::Warn,
                Style::Plain,
                epoch(),
                format_args!("unlock failed")
            ),
            "1970-01-01T00:00:00Z WARN  unlock failed\n"
        );
    }

    #[test]
    fn colour_lines_dim_the_timestamp_and_colour_the_level() {
        assert_eq!(
            format_line(Level::Error, Style::Colour, epoch(), format_args!("x")),
            "\x1b[2m1970-01-01T00:00:00Z\x1b[0m \x1b[1;31mERROR\x1b[0m x\n"
        );
    }

    #[test]
    fn colour_needs_a_capable_terminal_and_no_opt_out() {
        use std::ffi::OsStr;
        let xterm = Some(OsStr::new("xterm-256color"));
        assert!(wants_colour(true, None, xterm));
        assert!(wants_colour(true, Some(OsStr::new("")), xterm));
        assert!(!wants_colour(false, None, xterm));
        assert!(!wants_colour(true, Some(OsStr::new("1")), xterm));
        assert!(!wants_colour(true, None, Some(OsStr::new("dumb"))));
        assert!(!wants_colour(true, None, None));
    }

    #[test]
    fn timestamps_keep_the_local_offset() {
        let now = DateTime::parse_from_rfc3339("2026-11-06T09:33:05.678-08:00").unwrap();
        assert_eq!(
            format_line(Level::Info, Style::Plain, now, format_args!("x")),
            "2026-11-06T09:33:05-08:00 INFO  x\n"
        );
    }

    #[test]
    fn journal_lines_carry_a_syslog_priority() {
        assert_eq!(
            format_line(Level::Error, Style::Journal, epoch(), format_args!("x")),
            "<3>x\n"
        );
        assert_eq!(
            format_line(Level::Warn, Style::Journal, epoch(), format_args!("x")),
            "<4>x\n"
        );
        assert_eq!(
            format_line(Level::Info, Style::Journal, epoch(), format_args!("x")),
            "<6>x\n"
        );
        assert_eq!(
            format_line(Level::Debug, Style::Journal, epoch(), format_args!("x")),
            "<7>x\n"
        );
    }

    #[test]
    fn control_characters_cannot_start_another_line() {
        let line = format_line(
            Level::Info,
            Style::Journal,
            epoch(),
            format_args!("a\n<3>b\r\x1b[2J"),
        );
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(line.ends_with('\n'));
        assert!(!line.contains('\x1b'));
    }

    #[test]
    fn more_verbose_levels_are_ordered_after_less_verbose_ones() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn journal_stream_must_match_stderr_exactly() {
        assert!(matches_journal_stream("12:345", 12, 345));
        assert!(!matches_journal_stream("12:346", 12, 345));
        assert!(!matches_journal_stream("13:345", 12, 345));
        assert!(!matches_journal_stream("12", 12, 345));
        assert!(!matches_journal_stream("a:b", 12, 345));
    }
}
