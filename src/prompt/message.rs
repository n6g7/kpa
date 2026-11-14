//! What a prompt is about, made safe to show (`docs/ssh-agent.md` § 6.6,
//! § 6.7). Callers pass plain text; every prompt runs it through
//! [`prompt_message`] before it reaches the prompt program.

/// Longest prompt message kept: generous for "Unlock personal" and for the
/// key names and destinations an approval prompt adds, short enough that a
/// hostile database or entry name can't hand the prompt program an
/// unbounded message.
const MAX_PROMPT_MESSAGE_LEN: usize = 256;

/// Turns `text` into what a prompt program may safely be asked to render:
/// the same escaping the CLI applies to its own terminal output
/// (`output::escape_for_terminal`, since a prompt can show the same
/// hostile characters a terminal would act on — bidi overrides and the
/// like), capped at `MAX_PROMPT_MESSAGE_LEN` bytes on a character
/// boundary.
pub(super) fn prompt_message(text: &str) -> String {
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
    fn prompt_message_escapes_hostile_characters() {
        let message = prompt_message("Unlock personal\u{202e}evil");
        assert!(!message.contains('\u{202e}'), "{message:?}");
        assert!(message.contains("\\u202e"), "{message:?}");
    }

    #[test]
    fn prompt_message_caps_its_length_on_a_char_boundary() {
        // "é" is two bytes, so the cap lands mid-character unless
        // `prompt_message` backs off to the nearest boundary.
        let long = "é".repeat(MAX_PROMPT_MESSAGE_LEN);
        let message = prompt_message(&long);
        assert!(message.len() <= MAX_PROMPT_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    }
}
