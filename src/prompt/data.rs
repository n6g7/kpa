//! What a prompt asks: [`Question`], its one-line message and the
//! [`PromptData`] behind it. A prompt program gets the message in
//! `KPA_PROMPT_MESSAGE` and the data as JSON in `KPA_PROMPT_DATA`
//! (`docs/design.md`, "Configuration and logging").
//!
//! The data holds the pieces the message is made of, so a program that wants
//! a richer display than one line doesn't parse the line. Whoever asks builds
//! both from the same pieces, so the two can't disagree.
//!
//! This is plain data: strings and small structs, and nothing about SSH.
//! What fills it in knows its own subject.

use serde::Serialize;

use super::message::sanitize_message;

/// What `PromptData::v` is. A change a consumer can't ignore bumps it.
const DATA_VERSION: u32 = 1;

/// A prompt's message, shown to the user in one line, and the data behind
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Plain text. [`Prompt::ask`](super::Prompt::ask) sanitizes it before
    /// anything shows it.
    pub message: String,
    pub data: PromptData,
}

impl Question {
    /// The question that unlocks `database` and nothing more: "Unlock
    /// personal".
    pub fn unlock(database: &str) -> Question {
        let mut data = PromptData::new(PromptKind::Unlock);
        data.database = Some(sanitize_message(database));
        Question {
            message: format!("Unlock {database}"),
            data,
        }
    }
}

/// Which prompt asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptKind {
    /// For the master password of a database.
    Unlock,
    /// For an approval, answered `Allow` or `Deny`.
    Confirm,
}

/// The pieces behind a prompt's message: the JSON in `KPA_PROMPT_DATA`.
/// Every piece is absent when it doesn't apply.
///
/// Each string is display-safe: its control, bidi and zero-width characters
/// are written as `\uXXXX`, and it is cut to the budget its piece has in the
/// message, whoever fills it in. It is not quoted for a sentence: a `"` in a
/// name is a `"`, as a JSON string holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptData {
    pub v: u32,
    pub kind: PromptKind,
    /// The database the prompt is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// The key a signature asks to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<PromptKey>,
    /// What the key is for: `login`, `sshsig` or `other`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The remote user of a login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The namespace of an `SSHSIG` request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Where the signature is accepted, if the connection is bound to a host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<PromptHost>,
    /// The host a forwarded connection comes through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarding_host: Option<PromptHost>,
}

impl PromptData {
    /// The data of a `kind` prompt that says nothing more yet.
    pub fn new(kind: PromptKind) -> PromptData {
        PromptData {
            v: DATA_VERSION,
            kind,
            database: None,
            key: None,
            purpose: None,
            user: None,
            namespace: None,
            destination: None,
            forwarding_host: None,
        }
    }
}

/// A key, as a prompt names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptKey {
    /// Its name: an override's, else its entry's title, else `<database>
    /// <fingerprint>` for a locked database's.
    pub name: String,
    pub fingerprint: String,
    /// Its algorithm, `ssh-ed25519` for one.
    #[serde(rename = "type")]
    pub key_type: String,
}

/// A host, as a prompt names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptHost {
    /// The name `known_hosts` gives its host key, if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn json_of(data: &PromptData) -> serde_json::Value {
        serde_json::to_value(data).expect("serializes")
    }

    #[test]
    fn a_plain_unlock_names_its_database_and_nothing_else() {
        let question = Question::unlock("personal");

        assert_eq!(question.message, "Unlock personal");
        assert_eq!(
            json_of(&question.data),
            json!({"v": 1, "kind": "unlock", "database": "personal"})
        );
    }

    #[test]
    fn a_database_name_is_escaped_in_the_data() {
        let question = Question::unlock("per\nsonal\u{202e}");

        assert_eq!(
            question.data.database.as_deref(),
            Some("per\\u000asonal\\u202e")
        );
    }

    #[test]
    fn pieces_that_do_not_apply_are_left_out() {
        let mut data = PromptData::new(PromptKind::Confirm);
        data.key = Some(PromptKey {
            name: "github".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            key_type: "ssh-ed25519".to_string(),
        });
        data.purpose = Some("sshsig".to_string());
        data.namespace = Some("git".to_string());
        data.forwarding_host = Some(PromptHost {
            name: None,
            fingerprint: "SHA256:def".to_string(),
        });

        assert_eq!(
            json_of(&data),
            json!({
                "v": 1,
                "kind": "confirm",
                "key": {"name": "github", "fingerprint": "SHA256:abc", "type": "ssh-ed25519"},
                "purpose": "sshsig",
                "namespace": "git",
                "forwarding_host": {"fingerprint": "SHA256:def"},
            })
        );
    }
}
