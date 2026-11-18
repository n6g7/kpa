//! `unlock`: the only op that reads a file and the only one that asks for
//! credentials — which is why its error type is by far the largest of the
//! four.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::error::{ErrorCode, ErrorFields};
use crate::authn::Requester;

/// Longest password accepted, in bytes, whether it comes from the prompt's
/// stdout or from a request. Either way it is decoded into a buffer of
/// exactly this size, which never grows.
pub const MAX_PASSWORD_LEN: usize = 4096;

/// What `{"op":"unlock", ...}` carries; `Op::Unlock` wraps it. `db` is
/// required — there is no "unlock everything".
///
/// `password`, when present, is the master password itself, and the
/// daemon unlocks with it instead of prompting. Omitted, not null, when
/// absent, so a plain unlock keeps its wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnlockRequest {
    pub db: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Password>,
}

/// A master password carried in a request, as base64 on the wire.
///
/// Base64 rather than a plain JSON string because base64 never needs
/// escaping: `serde_json` hands an unescaped string over as a slice of the
/// request line (`visit_borrowed_str`), and it is decoded from there
/// straight into a zeroizing buffer. A string with escapes would first be
/// unescaped into `serde_json`'s own scratch buffer, which nothing wipes,
/// so one is refused instead (see also `decode_request`, which refuses it
/// before `serde_json` gets the chance).
///
/// `Debug` never prints the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(Zeroizing<String>);

// The one field is `Zeroizing`, so dropping a `Password` wipes it.
impl ZeroizeOnDrop for Password {}

/// Why a `password` field was refused. The wire never sees these: they all
/// surface as `malformed_request`, like every other decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    #[error("password exceeds {MAX_PASSWORD_LEN} bytes")]
    TooLong,
    #[error("password is not valid base64")]
    NotBase64,
    #[error("password is not valid UTF-8")]
    NotUtf8,
    #[error("password contains JSON escapes")]
    Escaped,
}

impl Password {
    pub fn new(password: Zeroizing<String>) -> Password {
        Password(password)
    }

    /// Decode a password from its base64 wire form.
    ///
    /// The bytes go into a zeroizing buffer of `MAX_PASSWORD_LEN` that
    /// never grows, then into a `Zeroizing<String>` sized exactly, as
    /// `server::prompt_password` does with the prompt's output.
    pub fn from_base64(encoded: &str) -> Result<Password, PasswordError> {
        if base64::encoded_len(MAX_PASSWORD_LEN, true).is_some_and(|max| encoded.len() > max) {
            return Err(PasswordError::TooLong);
        }
        let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_LEN]);
        let len = STANDARD
            .decode_slice(encoded, &mut buf[..])
            .map_err(|err| match err {
                base64::DecodeSliceError::OutputSliceTooSmall => PasswordError::TooLong,
                base64::DecodeSliceError::DecodeError(_) => PasswordError::NotBase64,
            })?;
        let text = std::str::from_utf8(&buf[..len]).map_err(|_| PasswordError::NotUtf8)?;

        let mut password = Zeroizing::new(String::with_capacity(text.len()));
        password.push_str(text);
        Ok(Password(password))
    }

    pub fn as_zeroizing(&self) -> &Zeroizing<String> {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl Serialize for Password {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut encoded = Zeroizing::new(String::with_capacity(
            base64::encoded_len(self.0.len(), true).unwrap_or(0),
        ));
        STANDARD.encode_string(self.0.as_bytes(), &mut encoded);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Password, D::Error> {
        deserializer.deserialize_str(PasswordVisitor)
    }
}

/// How serde builds a `Password`. A serde `Visitor` is the callback object
/// a deserializer hands each value to: it calls the `visit_*` method that
/// matches what it found in the input (`visit_u64` for a number, a string
/// method for a string, and so on), and the visitor turns that into the
/// target type or an error. Methods left out refuse that kind of value.
///
/// Written by hand rather than derived because which string method gets
/// called matters here. `visit_borrowed_str` gets a slice of the request
/// line itself, so the only copy made is the zeroizing one `from_base64`
/// decodes into. `visit_str` gets a string the deserializer had to copy
/// first, typically to unescape it, and that copy is already out of reach,
/// so it is refused.
struct PasswordVisitor;

impl<'de> Visitor<'de> for PasswordVisitor {
    type Value = Password;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a base64 string with no escapes")
    }

    fn visit_borrowed_str<E: de::Error>(self, encoded: &'de str) -> Result<Password, E> {
        Password::from_base64(encoded).map_err(E::custom)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Password, E> {
        Err(E::custom(PasswordError::Escaped))
    }
}

/// Everything `unlock` can fail with. Every variant but `NoDisplay` names
/// the database the unlock was for, even when the cause isn't about the
/// database itself (a dismissed prompt). `NoDisplay` is about where the
/// request came from, not about any database, so it names none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    UnknownDb {
        db: String,
    },
    /// The prompt command exited unsuccessfully — typically the user
    /// dismissing it.
    PromptCancelled {
        db: String,
    },
    /// The prompt command couldn't be run at all: not on `PATH`, not
    /// executable, and so on.
    PromptFailed {
        db: String,
        detail: String,
    },
    WrongCredentials {
        db: String,
    },
    /// The `.kdbx` or its keyfile isn't where the config says it is.
    NotFound {
        db: String,
    },
    Corrupt {
        db: String,
    },
    Io {
        db: String,
    },
    /// Another `unlock` of the same database is already prompting. Refused
    /// rather than queued, so one keypress can't stack up password prompts.
    InProgress {
        db: String,
    },
    /// A `lock` arrived while this unlock was prompting or deriving the
    /// key. The lock wins: the database this unlock opened is discarded.
    /// Reported as `locked`, which is the state it leaves behind.
    LockedDuringUnlock {
        db: String,
    },
    /// The database file changed while it was being read, so the read
    /// can't be trusted. Nothing was unlocked; try again.
    Stale {
        db: String,
    },
    /// No prompt was raised, because nobody could answer it: the request
    /// came from outside the desktop, or the screen is known to be locked.
    NoDisplay,
}

impl UnlockError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            UnlockError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            UnlockError::PromptCancelled { db } => {
                ErrorFields::new(ErrorCode::PromptCancelled).db(db)
            }
            // Reported as plain `io`: from the client's side "the daemon
            // couldn't run the prompt" is an I/O failure like any other,
            // and `detail` says which one. `prompt_cancelled` stays
            // distinct because that one is the user's own doing.
            UnlockError::PromptFailed { db, detail } => ErrorFields::new(ErrorCode::Io)
                .db(db)
                .detail(detail.as_str()),
            UnlockError::WrongCredentials { db } => {
                ErrorFields::new(ErrorCode::WrongCredentials).db(db)
            }
            UnlockError::NotFound { db } => ErrorFields::new(ErrorCode::NotFound).db(db),
            UnlockError::Corrupt { db } => ErrorFields::new(ErrorCode::Corrupt).db(db),
            UnlockError::Io { db } => ErrorFields::new(ErrorCode::Io).db(db),
            UnlockError::InProgress { db } => ErrorFields::new(ErrorCode::UnlockInProgress).db(db),
            UnlockError::LockedDuringUnlock { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            UnlockError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
            UnlockError::NoDisplay => {
                ErrorFields::new(ErrorCode::NoDisplay).detail("no display to prompt on")
            }
        }
    }
}

/// Serving `unlock`. A request that carries a `password` is unlocked with
/// it; otherwise the implementor owns credential acquisition, and nothing
/// about *how* it asks for one appears in this signature.
pub trait Unlock {
    /// `Ok` names the database that is now unlocked. `requester` says where the
    /// request came from, which decides whether a prompt may be raised on
    /// screen. `message` is what the prompt says; `None` is the plain
    /// "Unlock <db>".
    fn unlock(
        &self,
        request: &UnlockRequest,
        requester: &Requester,
        message: Option<&str>,
    ) -> Result<String, UnlockError>;
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize as _;

    use super::*;

    fn password(text: &str) -> Password {
        Password::new(Zeroizing::new(text.to_string()))
    }

    #[test]
    fn debug_never_prints_the_password() {
        let request = UnlockRequest {
            db: "personal".to_string(),
            password: Some(password("hunter2")),
        };
        let printed = format!("{request:?} {request:#?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(!printed.contains(&STANDARD.encode("hunter2")), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn decodes_base64() {
        let decoded = Password::from_base64(&STANDARD.encode("hunter2 ünïcode")).expect("valid");
        assert_eq!(decoded.as_zeroizing().as_str(), "hunter2 ünïcode");
        let empty = Password::from_base64("").expect("empty is valid");
        assert_eq!(empty.as_zeroizing().as_str(), "");
    }

    #[test]
    fn accepts_exactly_the_longest_password() {
        let longest = "a".repeat(MAX_PASSWORD_LEN);
        let decoded = Password::from_base64(&STANDARD.encode(&longest)).expect("at the limit");
        assert_eq!(decoded.as_zeroizing().as_str(), longest);
    }

    #[test]
    fn refuses_a_password_over_the_limit() {
        // One byte over gets past the length check on the encoded form and
        // is caught by the buffer; far over is never decoded at all.
        for len in [MAX_PASSWORD_LEN + 1, MAX_PASSWORD_LEN * 4] {
            let encoded = STANDARD.encode("a".repeat(len));
            assert_eq!(
                Password::from_base64(&encoded),
                Err(PasswordError::TooLong),
                "{len}"
            );
        }
    }

    #[test]
    fn refuses_invalid_base64() {
        // Not the alphabet, missing padding, too much padding, non-zero
        // trailing bits, non-ASCII.
        for encoded in ["not base64!", "aGk", "aGk==", "aGl=", "a\u{e9}=="] {
            assert_eq!(
                Password::from_base64(encoded),
                Err(PasswordError::NotBase64),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn refuses_bytes_that_are_not_utf8() {
        assert_eq!(
            Password::from_base64(&STANDARD.encode(b"\xff\xfe")),
            Err(PasswordError::NotUtf8)
        );
    }

    #[test]
    fn serializes_as_base64() {
        let value = serde_json::to_value(password("hunter2")).expect("serializes");
        assert_eq!(value, serde_json::json!(STANDARD.encode("hunter2")));
    }

    /// The wipe happens in `Zeroizing`'s `Drop`, after which the memory is
    /// gone. What can be checked here is that `Password` promises it, and
    /// that the wipe leaves nothing readable; `tests/zeroize.rs` checks the
    /// freed memory itself.
    #[test]
    fn zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Password>();

        let mut secret = password("hunter2");
        secret.0.zeroize();
        assert_eq!(secret.as_zeroizing().as_str(), "");
    }
}
