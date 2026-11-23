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

fn line(index: usize, text: &str) -> String {
    format!("{index}{DELIMITER}{}", escape_one_line(text, usize::MAX))
}

/// One line per entry, in the order given: its title, username, database and
/// group.
pub(super) fn entry_lines(entries: &[WireEntry]) -> Vec<String> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let title = entry.title.as_deref().unwrap_or("(no title)");
            let username = entry.username.as_deref().unwrap_or("");
            line(
                index,
                &format!("{title}  {username}  [{}] {}", entry.db, entry.group),
            )
        })
        .collect()
}

/// One line per field name, in the order given.
pub(super) fn field_lines(fields: &[String]) -> Vec<String> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| line(index, field))
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
    fn a_line_shows_the_title_username_database_and_group_after_its_index() {
        let lines = entry_lines(&[entry(Some("GitHub"), Some("alice")), entry(None, None)]);
        assert_eq!(lines[0], "0\tGitHub  alice  [personal] Dev");
        assert_eq!(lines[1], "1\t(no title)    [personal] Dev");
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
        let lines = field_lines(&["password".to_string(), "custom:a\tb".to_string()]);
        assert_eq!(lines, ["0\tpassword", "1\tcustom:a\\u0009b"]);
    }
}
