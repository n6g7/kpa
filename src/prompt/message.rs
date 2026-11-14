//! Display sanitization for the untrusted text in a prompt's message
//! (`docs/ssh-agent.md` § 6.6, § 6.7). A message carries database and
//! entry names, key comments, `known_hosts` names and the login user from a
//! client's request, any of which can hold bidi overrides or control
//! characters that spoof or break whatever displays it, a graphical prompt
//! as much as a terminal. So every prompt backend runs every message
//! through [`sanitize_message`] before showing it, and callers pass plain
//! text.

use std::fmt::Write as _;

/// Longest prompt message kept: generous for "Unlock personal" and for the
/// key names and destinations an approval prompt adds, short enough that a
/// hostile database or entry name can't hand the prompt program an
/// unbounded message.
const MAX_PROMPT_MESSAGE_LEN: usize = 256;

/// Turns `text` into what a prompt may safely display: the characters that
/// could spoof or drive a display (controls, tab and newline included,
/// bidi and zero-width format characters, and the like) written as
/// `\uXXXX`, then capped at `MAX_PROMPT_MESSAGE_LEN` bytes on a character
/// boundary.
///
/// A prompt message is one line: dmenu-style prompts and placeholders
/// render a single line, so a newline in an untrusted name could push the
/// real key or destination out of view or fake a second line. Tab and
/// newline are escaped for that reason.
///
/// The rest of the escaping reuses `output::escape_for_terminal`, which
/// covers that set but keeps tab and newline for its terminal output. The
/// reuse is an implementation detail: the message is not meant for a
/// terminal in particular.
pub(super) fn sanitize_message(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in crate::output::escape_for_terminal(text).chars() {
        if matches!(c, '\t' | '\n') {
            let _ = write!(escaped, "\\u{:04x}", c as u32);
        } else {
            escaped.push(c);
        }
    }
    let mut end = escaped.len().min(MAX_PROMPT_MESSAGE_LEN);
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    escaped.truncate(end);
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_message_escapes_hostile_characters() {
        let message = sanitize_message("Unlock personal\u{202e}evil");
        assert!(!message.contains('\u{202e}'), "{message:?}");
        assert!(message.contains("\\u202e"), "{message:?}");
    }

    #[test]
    fn sanitize_message_keeps_a_message_on_one_line() {
        let message = sanitize_message("Approve github\nApprove\r\tother");
        for c in ['\n', '\r', '\t'] {
            assert!(!message.contains(c), "{message:?}");
        }
        assert_eq!(message, "Approve github\\u000aApprove\\u000d\\u0009other");
    }

    #[test]
    fn sanitize_message_caps_its_length_on_a_char_boundary() {
        // "é" is two bytes, so the cap lands mid-character unless
        // `sanitize_message` backs off to the nearest boundary.
        let long = "é".repeat(MAX_PROMPT_MESSAGE_LEN);
        let message = sanitize_message(&long);
        assert!(message.len() <= MAX_PROMPT_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    }
}
