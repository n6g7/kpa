//! The daemon's log: one line per event on stderr, at one of four levels.
//!
//! Everything the daemon says about itself goes through [`log`], so there is
//! one place to audit for what may reach a log. The rule (`docs/design.md`
//! § Logging): a line names the operation, the database and the error kind,
//! never what was in a database. No level is exempt, `debug` included: a log
//! outlives the unlocked session that produced it and lands somewhere far
//! less guarded than the socket (`docs/threat-model.md` TB-7).
//!
//! No timestamps: a supervisor stamps its own, and a second clock here would
//! only disagree with it.

use std::fmt::{self, Write as _};
use std::io::Write as _;
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
    fn name(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
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
    let line = format_line(level, journal_attached(), args);
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// One finished line, newline included. Control characters in the message
/// are escaped, so a crafted database name in a request cannot start a
/// second line (or, under journald, a second `<N>` priority).
fn format_line(level: Level, journal: bool, args: fmt::Arguments<'_>) -> String {
    let mut line = if journal {
        format!("<{}>", level.priority())
    } else {
        format!("kpa: {}: ", level.name())
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

    #[test]
    fn plain_lines_carry_the_level() {
        assert_eq!(
            format_line(Level::Warn, false, format_args!("unlock failed")),
            "kpa: warn: unlock failed\n"
        );
    }

    #[test]
    fn journal_lines_carry_a_syslog_priority() {
        assert_eq!(format_line(Level::Error, true, format_args!("x")), "<3>x\n");
        assert_eq!(format_line(Level::Warn, true, format_args!("x")), "<4>x\n");
        assert_eq!(format_line(Level::Info, true, format_args!("x")), "<6>x\n");
        assert_eq!(format_line(Level::Debug, true, format_args!("x")), "<7>x\n");
    }

    #[test]
    fn control_characters_cannot_start_another_line() {
        let line = format_line(Level::Info, true, format_args!("a\n<3>b\r\x1b[2J"));
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
