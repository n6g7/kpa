//! What `kpa pick` shows fzf, and how it reads fzf's answer back. Pure: no
//! process, no socket.
//!
//! A line is `<index>\t<text>`. fzf shows only the text (`--with-nth 2..`)
//! and hands back the whole line, so the answer is the index `pick` put in
//! front, an index into the list it holds, never something read out of the
//! text. The text is vault text made one-line safe: the escaping turns tab
//! and newline into `\uXXXX`, so it can neither end a line nor contain the
//! tab that follows the index.

use crate::frontends::control::proto::WireEntry;
use crate::output::escape_one_line;

/// What fzf is told to treat as the field delimiter.
pub(super) const DELIMITER: &str = "\t";

/// The most bytes (escaped) of an entry's title the field list's header line
/// takes: the budget a prompt gives a key's name.
const MAX_HEADER_LEN: usize = 64;

fn line(index: usize, text: &str) -> String {
    format!("{index}{DELIMITER}{}", escape_one_line(text, usize::MAX))
}

/// The title `entry` is shown under: `list` leaves out a protected one.
pub(super) fn title_of(entry: &WireEntry) -> &str {
    entry.title.as_deref().unwrap_or("(no title)")
}

/// One line per entry, in the order given: its title, its username when it
/// has one, and its database.
pub(super) fn entry_lines(entries: &[WireEntry]) -> Vec<String> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let title = title_of(entry);
            let username = match entry.username.as_deref() {
                Some(username) if !username.is_empty() => format!("  {username}"),
                _ => String::new(),
            };
            line(index, &format!("{title}{username}  [{}]", entry.db))
        })
        .collect()
}

/// The lines of the list for choosing one of the `fields` of the entry titled
/// `title`: first a header line, which fzf shows and can't choose (it is
/// started with `--header-lines=1`), holding the title cut to
/// [`MAX_HEADER_LEN`], then one line per field name, in the order given. The
/// header has no index, only the delimiter, so what is shown is the title and
/// the indexes of the lines after it are those of `fields`.
pub(super) fn field_lines(title: &str, fields: &[String]) -> Vec<String> {
    std::iter::once(format!(
        "{DELIMITER}{}",
        escape_one_line(title, MAX_HEADER_LEN)
    ))
    .chain(
        fields
            .iter()
            .enumerate()
            .map(|(index, field)| line(index, field)),
    )
    .collect()
}

/// The index at the front of `answer`, a line fzf printed, if it is one of
/// the `count` lines it was given.
pub(super) fn index_of(answer: &str, count: usize) -> Option<usize> {
    let (index, _) = answer.split_once(DELIMITER)?;
    index.parse().ok().filter(|&index| index < count)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn entry(title: Option<&str>, username: Option<&str>) -> WireEntry {
        WireEntry {
            db: "personal".to_string(),
            uuid: Uuid::nil(),
            title: title.map(str::to_string),
            username: username.map(str::to_string),
            url: None,
            group: "Dev".to_string(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn a_line_shows_the_title_username_and_database_after_its_index() {
        let lines = entry_lines(&[
            entry(Some("GitHub"), Some("alice")),
            entry(None, None),
            entry(Some("Bank"), Some("")),
        ]);
        assert_eq!(lines[0], "0\tGitHub  alice  [personal]");
        assert_eq!(lines[1], "1\t(no title)  [personal]");
        assert_eq!(lines[2], "2\tBank  [personal]");
    }

    /// Vault text can't add a line, a field or a control sequence to what
    /// fzf is given: only the index's tab is a tab, and every line is one.
    #[test]
    fn hostile_text_cannot_split_a_line_or_reach_the_terminal_raw() {
        let hostile = entry(Some("a\tb\nc\u{1b}[2Jd\u{202e}e\r"), Some("x\ny"));
        let lines = entry_lines(&[hostile]);
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.matches('\t').count(), 1, "{line:?}");
        assert!(
            !line.contains(['\n', '\r', '\u{1b}', '\u{202e}']),
            "{line:?}"
        );
        assert!(
            line.contains("\\u0009") && line.contains("\\u000a"),
            "{line:?}"
        );
    }

    #[test]
    fn the_index_is_read_from_the_front_not_from_the_text() {
        let lines = entry_lines(&[entry(Some("7\t1"), None), entry(Some("b"), None)]);
        assert_eq!(index_of(&lines[0], 2), Some(0));
        assert_eq!(index_of(&lines[1], 2), Some(1));
    }

    #[test]
    fn an_answer_that_is_not_one_of_the_lines_given_has_no_index() {
        assert_eq!(index_of("2\tx", 2), None);
        assert_eq!(index_of("x\ty", 2), None);
        assert_eq!(index_of("no delimiter", 2), None);
        assert_eq!(index_of("", 2), None);
    }

    #[test]
    fn a_field_line_carries_its_index_and_the_escaped_name() {
        let lines = field_lines(
            "GitHub",
            &["password".to_string(), "custom:a\tb".to_string()],
        );
        assert_eq!(lines, ["\tGitHub", "0\tpassword", "1\tcustom:a\\u0009b"]);
    }

    /// The title heading the field list is one line with no tab but the
    /// delimiter, and is cut to its budget between whole escapes.
    #[test]
    fn the_header_line_is_the_escaped_title_cut_to_its_budget() {
        let lines = field_lines("a\tb\nc\u{1b}", &[]);
        assert_eq!(lines, ["\ta\\u0009b\\u000ac\\u001b"]);

        let long = field_lines(&"w".repeat(200_000), &[]);
        assert_eq!(long, [format!("\t{}", "w".repeat(MAX_HEADER_LEN))]);

        let escapes = field_lines(&"\u{1b}".repeat(100), &[]);
        assert_eq!(escapes[0].len(), 1 + 60);
        assert!(escapes[0][1..].split("\\u001b").all(str::is_empty));
    }
}
