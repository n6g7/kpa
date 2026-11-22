//! What a prompt asks: [`Question`], its one-line message and the data behind
//! it. A prompt program gets the message in `KPA_PROMPT_MESSAGE` and the data
//! as JSON in `KPA_PROMPT_DATA` (`docs/design.md`, "Configuration and
//! logging").
//!
//! The data holds the pieces the message is made of, so a program that wants
//! a richer display than one line doesn't parse the line. Whoever asks builds
//! both from the same pieces, so the two can't disagree. A prompt knows how it
//! asks, and nothing about what: the data's fields are the asker's.

use serde_json::{Map, Value};

use super::message::sanitize_message;

/// A prompt's message, shown to the user in one line, and the data behind
/// it.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    /// Plain text. [`Prompt::ask`](super::Prompt::ask) sanitizes it before
    /// anything shows it.
    pub message: String,
    /// Named values, JSON ones. [`Prompt::ask`](super::Prompt::ask) escapes
    /// every string in them, nested ones too; the asker cuts each to its
    /// budget. A prompt program's backend adds `v` to what is here.
    pub data: Map<String, Value>,
}

impl Question {
    /// A question that says `message` and has no data yet.
    pub fn new(message: impl Into<String>) -> Question {
        Question {
            message: message.into(),
            data: Map::new(),
        }
    }

    /// This question with `value` as its data's `field`.
    pub fn with(mut self, field: &str, value: impl Into<Value>) -> Question {
        self.data.insert(field.to_string(), value.into());
        self
    }

    /// This question, made safe to display: its message is sanitized and every
    /// string in its data escaped the same way.
    pub(super) fn sanitized(&self) -> Question {
        Question {
            message: sanitize_message(&self.message),
            data: self
                .data
                .iter()
                .map(|(field, value)| (field.clone(), escaped(value)))
                .collect(),
        }
    }
}

/// `value` with every string in it, however deep, sanitized as a message is.
fn escaped(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(sanitize_message(text)),
        Value::Array(items) => Value::Array(items.iter().map(escaped).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(field, value)| (field.clone(), escaped(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_question_carries_its_fields() {
        let question = Question::new("Pick one")
            .with("count", 2)
            .with("choices", json!(["a", "b"]))
            .with("title", "Work");

        assert_eq!(question.message, "Pick one");
        assert_eq!(
            Value::Object(question.data),
            json!({"count": 2, "choices": ["a", "b"], "title": "Work"})
        );
    }

    /// Every string, at any depth, is escaped the way the message is, and what
    /// is not a string is left alone.
    #[test]
    fn sanitizing_escapes_every_string_however_deep() {
        let question = Question::new("Unlock\u{202e}evil")
            .with("name", "per\nsonal")
            .with(
                "nested",
                json!({"deep": ["a\u{200b}b", {"leaf": "x\ty"}], "n": 1}),
            );

        let safe = question.sanitized();

        assert_eq!(safe.message, "Unlock\\u202eevil");
        assert_eq!(
            Value::Object(safe.data),
            json!({
                "name": "per\\u000asonal",
                "nested": {"deep": ["a\\u200bb", {"leaf": "x\\u0009y"}], "n": 1},
            })
        );
    }
}
