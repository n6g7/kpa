//! Escaping text from the vault or the user for a terminal
//! (`docs/threat-model.md` T-13).

use std::fmt::Write as _;

/// Escapes the characters a terminal could act on, as `\uXXXX`. Every byte
/// the CLI writes to a terminal goes through here: the daemon's JSON line,
/// and any error text that can echo input or database content.
///
/// Escaped: C0 controls other than tab and newline, DEL, the C1 controls,
/// ALM, the zero-width and bidi format characters, the line and paragraph
/// separators, and the word joiner and invisible-operator range.
///
/// Every escaped character is in the BMP, so `\uXXXX` is valid JSON inside a
/// string. A serialized line therefore still parses to the same values, and
/// `\` and ASCII are never touched, so serde's own escapes pass through as
/// they are. Tab and newline are kept because they are layout, not control.
pub fn escape_for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if needs_terminal_escape(c) {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn needs_terminal_escape(c: char) -> bool {
    matches!(
        c,
        '\0'..='\u{8}'
            | '\u{b}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
    )
}

/// `text` escaped for a one-line display of untrusted text, at most
/// `max_len` bytes: what [`escape_for_terminal`] escapes, plus tab and
/// newline, which it keeps for terminal output but which would break a
/// line here. The cap falls between whole characters and whole escapes,
/// never inside one. Used for a prompt's message and an SSH identity's
/// comment.
pub fn escape_one_line(text: &str, max_len: usize) -> String {
    let mut line = String::with_capacity(text.len().min(max_len));
    let mut piece = String::new();
    let mut utf8 = [0u8; 4];
    for c in text.chars() {
        piece.clear();
        if needs_terminal_escape(c) || matches!(c, '\t' | '\n') {
            let _ = write!(piece, "\\u{:04x}", c as u32);
        } else {
            piece.push_str(c.encode_utf8(&mut utf8));
        }
        if line.len() + piece.len() > max_len {
            break;
        }
        line.push_str(&piece);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::escape_for_terminal;
    use crate::frontends::control::proto::{ListResponse, Response, WireEntry};

    /// The characters `escape_for_terminal` must never let through, written
    /// out as ranges independently of the function's own table.
    const HOSTILE: &[(char, char)] = &[
        ('\u{0}', '\u{8}'),
        ('\u{b}', '\u{1f}'),
        ('\u{7f}', '\u{9f}'),
        ('\u{61c}', '\u{61c}'),
        ('\u{200b}', '\u{200f}'),
        ('\u{2028}', '\u{202e}'),
        ('\u{2060}', '\u{2069}'),
        ('\u{feff}', '\u{feff}'),
        ('\u{fff9}', '\u{fffb}'),
    ];

    fn is_hostile(c: char) -> bool {
        HOSTILE.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
    }

    #[test]
    fn every_hostile_character_is_escaped_as_a_json_escape() {
        for &(lo, hi) in HOSTILE {
            for c in lo..=hi {
                let out = escape_for_terminal(&c.to_string());
                assert_eq!(
                    out,
                    format!("\\u{:04x}", c as u32),
                    "for U+{:04X}",
                    c as u32
                );
            }
        }
    }

    #[test]
    fn tab_newline_and_ordinary_text_pass_through() {
        let text = "a\tb\nc \\\" é 漢 😀 \u{a0} \u{7e}";
        assert_eq!(escape_for_terminal(text), text);
    }

    /// A `list` line whose title is full of hostile characters. What reaches
    /// the terminal has none of them, and the JSON decodes to the title the
    /// database holds.
    #[test]
    fn a_listed_title_comes_out_escaped_and_still_decodes() {
        let title = "\u{9b}c\u{9d}0;t\u{9c}\u{202e}x\u{7f}\u{2028}";
        let response = Response::List(Ok(ListResponse {
            entries: vec![WireEntry {
                db: "personal".to_string(),
                uuid: uuid::Uuid::nil(),
                title: Some(title.to_string()),
                username: Some("alice\u{2067}".to_string()),
                url: None,
                group: "Web\u{9b}".to_string(),
                fields: Vec::new(),
            }],
        }));
        let line = format!(
            "{}\n",
            serde_json::to_string(&response).expect("serializes")
        );

        let printed = escape_for_terminal(&line);

        let body = printed
            .strip_suffix('\n')
            .expect("the line ends in a newline");
        assert!(
            !body.chars().any(is_hostile),
            "a hostile character reached the output: {printed:?}"
        );
        assert!(!body.contains('\n'));

        let decoded: serde_json::Value = serde_json::from_str(&printed).expect("still valid JSON");
        let entry = &decoded["entries"][0];
        assert_eq!(entry["title"], title);
        assert_eq!(entry["username"], "alice\u{2067}");
        assert_eq!(entry["group"], "Web\u{9b}");
    }
}
