//! Display sanitization for the untrusted text in a prompt's message
//! (`docs/ssh-agent.md` § 6.6, § 6.7). A message carries database and
//! entry names, key comments, `known_hosts` names and the login user from a
//! client's request, any of which can hold bidi overrides or control
//! characters that spoof or break whatever displays it, a graphical prompt
//! as much as a terminal. So every prompt backend runs every message
//! through [`sanitize_message`] before showing it, and callers pass plain
//! text.

/// Longest prompt message kept: generous for "Unlock personal" and for the
/// key names and destinations an approval prompt adds, short enough that a
/// hostile database or entry name can't hand the prompt program an
/// unbounded message.
const MAX_PROMPT_MESSAGE_LEN: usize = 256;

/// Turns `text` into what a prompt may safely display: the characters that
/// could spoof or drive a display (controls other than tab and newline,
/// bidi and zero-width format characters, and the like) written as
/// `\uXXXX`, then capped at `MAX_PROMPT_MESSAGE_LEN` bytes on a character
/// boundary.
///
/// The escaping reuses `output::escape_for_terminal`, which covers that
/// set. The reuse is an implementation detail: the message is not meant
/// for a terminal in particular.
pub(super) fn sanitize_message(text: &str) -> String {
    let escaped = crate::output::escape_for_terminal(text);
    let mut end = escaped.len().min(MAX_PROMPT_MESSAGE_LEN);
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    escaped[..end].to_string()
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
    fn sanitize_message_caps_its_length_on_a_char_boundary() {
        // "é" is two bytes, so the cap lands mid-character unless
        // `sanitize_message` backs off to the nearest boundary.
        let long = "é".repeat(MAX_PROMPT_MESSAGE_LEN);
        let message = sanitize_message(&long);
        assert!(message.len() <= MAX_PROMPT_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    }
}
