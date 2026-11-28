//! `copy`: hand one field of one entry to the clipboard. The secret itself
//! never rides the wire back out — the response says which field and for
//! how long, never the value (`docs/design.md` decision #4: "the daemon
//! owns the clipboard, so the secret never enters the client's address
//! space").

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::error::{ErrorCode, ErrorFields};
use crate::databases::EntryField;

/// What `{"op":"copy", ...}` carries; `Op::Copy` wraps it. `field` accepts
/// any name a KeePass client wrote for this entry — see [`Field`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopyRequest {
    pub db: String,
    pub uuid: Uuid,
    pub field: Field,
}

/// The prefix that makes a field name mean a custom field by its literal
/// key, whatever the key is spelled like.
const CUSTOM_PREFIX: &str = "custom:";

/// The fields `copy` can be asked for: the four it always could, `totp`
/// (the code generated at copy time from the entry's `otp` field), and
/// any custom (user-defined) field — a string-like type rather than a
/// bare `String`, so the five built-ins stay enforced by the type while
/// still letting `copy` reach a real custom field by its KeePass key.
///
/// Decoding never fails: any wire string is a valid `Field`, because any
/// string naming a built-in or a real custom key is meaningful, and one
/// that names neither simply won't resolve to anything on the entry asked
/// about — `copy` then fails with `FieldEmpty`, the same as an empty or
/// absent field (there is no more specific, still-honest code for "this
/// name doesn't mean anything here" without echoing vault content back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Username,
    Password,
    Url,
    Notes,
    /// The code generated from the entry's `otp` field at the moment of
    /// the `copy` — never the seed itself. `docs/protocol.md`.
    Totp,
    /// A custom (user-defined) field, addressed by its literal KeePass
    /// key: either a bare name that neither collides with a reserved one
    /// nor starts with `custom:`, or any key at all when given with the
    /// `custom:` prefix (which always means a custom field, bypassing the
    /// collision rule).
    Custom(String),
    /// A bare `title` request. KeePass reserves `Title` (exact case) for
    /// the entry's own title, which `copy` never serves, and the
    /// collision rule keeps a bare `title` from reaching a custom field
    /// spelled the same way in a different case — that needs
    /// `custom:title` instead. So this never resolves to anything on any
    /// entry; `copy` reports it the same as any other name with nothing
    /// to give.
    ReservedTitle,
}

impl Field {
    /// The field of an entry this names; `None` for a bare `title`, which
    /// names none.
    pub fn entry_field(&self) -> Option<EntryField> {
        match self {
            Field::Username => Some(EntryField::Username),
            Field::Password => Some(EntryField::Password),
            Field::Url => Some(EntryField::Url),
            Field::Notes => Some(EntryField::Notes),
            Field::Totp => Some(EntryField::Totp),
            Field::Custom(key) => Some(EntryField::Custom(key.clone())),
            Field::ReservedTitle => None,
        }
    }

    /// The wire name for this field — what [`decode`](Field::decode) of
    /// this exact string produces again, so encoding and decoding agree.
    fn encode(&self) -> String {
        match self {
            Field::Username => "username".to_string(),
            Field::Password => "password".to_string(),
            Field::Url => "url".to_string(),
            Field::Notes => "notes".to_string(),
            Field::Totp => "totp".to_string(),
            Field::ReservedTitle => "title".to_string(),
            // Bare when decoding the bare key gives this field back; behind
            // the prefix otherwise: a key that collides with a built-in or
            // `title` (in any case) or that itself begins with the prefix.
            // Derived from `decode`, so no name can decode to another field.
            Field::Custom(key) => {
                if Field::decode(key) == *self {
                    key.clone()
                } else {
                    format!("{CUSTOM_PREFIX}{key}")
                }
            }
        }
    }

    /// Decodes one wire field name. The `custom:` prefix is matched
    /// literally (lowercase, exact) — it is protocol syntax, not vault
    /// content — and always yields `Custom` with the rest of the string as
    /// the literal key, bypassing the collision check below entirely. Only
    /// one prefix is stripped, so `custom:custom:x` is the key `custom:x`.
    /// Otherwise, a name that matches one of the four built-ins or `totp`
    /// case-insensitively is that built-in; a bare `title`
    /// (case-insensitively) is `ReservedTitle`; anything else is `Custom`
    /// with the raw string as the literal key.
    fn decode(raw: &str) -> Field {
        if let Some(key) = raw.strip_prefix(CUSTOM_PREFIX) {
            return Field::Custom(key.to_string());
        }
        if raw.eq_ignore_ascii_case("username") {
            Field::Username
        } else if raw.eq_ignore_ascii_case("password") {
            Field::Password
        } else if raw.eq_ignore_ascii_case("url") {
            Field::Url
        } else if raw.eq_ignore_ascii_case("notes") {
            Field::Notes
        } else if raw.eq_ignore_ascii_case("totp") {
            Field::Totp
        } else if raw.eq_ignore_ascii_case("title") {
            Field::ReservedTitle
        } else {
            Field::Custom(raw.to_string())
        }
    }
}

/// The wire spelling of a field of an entry, as `list`'s `fields` names it.
impl From<&EntryField> for Field {
    fn from(field: &EntryField) -> Field {
        match field {
            EntryField::Username => Field::Username,
            EntryField::Password => Field::Password,
            EntryField::Url => Field::Url,
            EntryField::Notes => Field::Notes,
            EntryField::Totp => Field::Totp,
            EntryField::Custom(key) => Field::Custom(key.clone()),
        }
    }
}

/// The wire name, as `list`'s `fields` spells it.
impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl Serialize for Field {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Field::decode(&raw))
    }
}

/// Lets the CLI (and anything else parsing a field name from plain text)
/// build a `Field` directly, without going through JSON — `Err` never
/// happens (see the type's own doc comment), but `FromStr` still needs an
/// `Err` type, and `std::convert::Infallible` is exactly "this can't fail"
/// spelled as a type.
impl std::str::FromStr for Field {
    type Err = std::convert::Infallible;

    fn from_str(raw: &str) -> Result<Field, Self::Err> {
        Ok(Field::decode(raw))
    }
}

/// Everything `copy` can fail with. Every variant but `NoDisplay` names the
/// database the copy was for. `NoDisplay` is about where the request came
/// from, not about any database, so it names none — same shape as
/// `UnlockError::NoPrompt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyError {
    UnknownDb {
        db: String,
    },
    /// Named a database that is configured but currently locked.
    Locked {
        db: String,
    },
    /// The database's file changed on disk since it was unlocked. The
    /// database is dropped by the time this is returned, same as `list`.
    Stale {
        db: String,
    },
    /// The uuid doesn't name an entry in this database.
    UnknownUuid {
        db: String,
    },
    /// The entry exists, but the requested field is absent or empty on it —
    /// there's nothing to copy. Empty counts the same as absent: either way
    /// there is no secret to hand to the clipboard. Also what a field name
    /// that doesn't resolve to anything on this entry reports (see
    /// [`Field`]'s doc comment).
    FieldEmpty {
        db: String,
    },
    /// The clipboard backend couldn't take the secret — no reachable Wayland
    /// compositor, a missing protocol, or similar. `detail` is the
    /// backend's own error text, which never carries the secret itself.
    Clipboard {
        db: String,
        detail: String,
    },
    /// Nobody could paste the secret where it would land: the requester
    /// isn't on the desktop, or the display session isn't active and
    /// unlocked (`docs/headless.md` § 5). The clipboard is never touched.
    NoDisplay,
}

impl CopyError {
    pub(super) fn fields(&self) -> ErrorFields<'_> {
        match self {
            CopyError::UnknownDb { db } => ErrorFields::new(ErrorCode::UnknownDb).db(db),
            CopyError::Locked { db } => ErrorFields::new(ErrorCode::Locked).db(db),
            CopyError::Stale { db } => ErrorFields::new(ErrorCode::Stale)
                .db(db)
                .detail("database changed on disk"),
            CopyError::UnknownUuid { db } => ErrorFields::new(ErrorCode::UnknownUuid).db(db),
            CopyError::FieldEmpty { db } => ErrorFields::new(ErrorCode::FieldEmpty).db(db),
            // Collapsed to `io`, same as `UnlockError::PromptFailed`: from
            // the client's side, "the daemon couldn't reach the clipboard"
            // is an I/O failure like any other.
            CopyError::Clipboard { db, detail } => ErrorFields::new(ErrorCode::Io)
                .db(db)
                .detail(detail.as_str()),
            CopyError::NoDisplay => ErrorFields::new(ErrorCode::NoDisplay)
                .detail("no active, unlocked display session for the requester to paste into"),
        }
    }
}

/// What a successful `copy` answers on the wire, as the daemon builds it and
/// a client reads it: which field, and for how long, never its value.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CopyOutcome {
    pub copied: Field,
    /// Whole seconds until the daemon drops its clipboard offer on its own.
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A field is written as it is on the wire, `custom:` prefix included.
    #[test]
    fn a_field_displays_as_its_wire_name() {
        assert_eq!(Field::Totp.to_string(), "totp");
        assert_eq!(Field::Custom("api-key".to_string()).to_string(), "api-key");
        assert_eq!(
            Field::Custom("Password".to_string()).to_string(),
            "custom:Password"
        );
    }

    /// Every name `copy` recognizes without a `custom:` prefix, both
    /// directions — this is the wire vocabulary `docs/protocol.md` documents.
    #[test]
    fn builtin_names_round_trip() {
        let cases = [
            ("username", Field::Username),
            ("password", Field::Password),
            ("url", Field::Url),
            ("notes", Field::Notes),
            ("totp", Field::Totp),
        ];
        for (name, field) in cases {
            assert_eq!(Field::decode(name), field, "decoding {name:?}");
            assert_eq!(field.encode(), name, "encoding {field:?}");
        }
    }

    /// A built-in name is matched regardless of case, and still means the
    /// built-in — the collision rule's whole point.
    #[test]
    fn builtin_names_are_matched_case_insensitively() {
        assert_eq!(Field::decode("Password"), Field::Password);
        assert_eq!(Field::decode("PASSWORD"), Field::Password);
        assert_eq!(Field::decode("PaSsWoRd"), Field::Password);
    }

    /// A bare name that doesn't collide with anything reserved is a custom
    /// field, addressed by that literal key, and round-trips bare.
    #[test]
    fn a_non_colliding_bare_name_is_a_literal_custom_key() {
        let field = Field::decode("api-key");
        assert_eq!(field, Field::Custom("api-key".to_string()));
        assert_eq!(field.encode(), "api-key");
    }

    /// A custom field whose key collides case-insensitively with a
    /// built-in must be reached through the `custom:` prefix — a bare
    /// request with that spelling means the built-in instead, never this
    /// custom field, however the entry's data is actually shaped.
    #[test]
    fn a_colliding_bare_name_means_the_builtin_not_the_custom_field() {
        assert_eq!(Field::decode("Password"), Field::Password);
        assert_eq!(
            Field::decode("custom:Password"),
            Field::Custom("Password".to_string())
        );
    }

    /// `custom:` always means a custom field, literally, even for a key
    /// that doesn't collide with anything — gratuitous, but not wrong.
    #[test]
    fn the_custom_prefix_works_on_a_non_colliding_key_too() {
        assert_eq!(
            Field::decode("custom:api-key"),
            Field::Custom("api-key".to_string())
        );
    }

    /// A custom field encodes with the `custom:` prefix exactly when a bare
    /// request for its key would mean something else: the key collides with
    /// a reserved name, or starts with the prefix itself.
    #[test]
    fn custom_fields_encode_the_prefix_only_when_needed() {
        assert_eq!(Field::Custom("api-key".to_string()).encode(), "api-key");
        assert_eq!(
            Field::Custom("Password".to_string()).encode(),
            "custom:Password"
        );
        assert_eq!(Field::Custom("TOTP".to_string()).encode(), "custom:TOTP");
        assert_eq!(Field::Custom("Title".to_string()).encode(), "custom:Title");
        assert_eq!(
            Field::Custom("custom:Password".to_string()).encode(),
            "custom:custom:Password"
        );
        assert_eq!(
            Field::Custom("custom:x".to_string()).encode(),
            "custom:custom:x"
        );
    }

    /// Whatever a custom key says, the name it is encoded under decodes to
    /// that key and to no other field: a key spelled like a built-in, like
    /// `title`, or like prefixed syntax cannot make its name mean another
    /// field.
    #[test]
    fn a_custom_key_decodes_from_its_own_encoding() {
        let keys = [
            "Password",
            "PASSWORD",
            "pAssWord",
            "Username",
            "URL",
            "Notes",
            "TOTP",
            "totp",
            "title",
            "Title",
            "TITLE",
            "custom:Password",
            "custom:password",
            "custom:x",
            "custom:",
            "custom:custom:x",
            "Custom:x",
            "x",
            "api-key",
            "otp",
            "OTP",
            "",
            "🙂",
        ];
        for key in keys {
            let field = Field::Custom(key.to_string());
            assert_eq!(Field::decode(&field.encode()), field, "key {key:?}");
        }
    }

    /// A field of an entry is spelled on the wire as `list` names it, and
    /// the name parses back to that same field of the entry: for the
    /// standard fields, the code made from `otp`, and custom keys spelled
    /// like any of them or like the prefix.
    #[test]
    fn an_entry_field_round_trips_through_its_wire_name() {
        let custom = |key: &str| EntryField::Custom(key.to_string());
        let fields = [
            (EntryField::Username, "username"),
            (EntryField::Password, "password"),
            (EntryField::Url, "url"),
            (EntryField::Notes, "notes"),
            (EntryField::Totp, "totp"),
            (custom("api-key"), "api-key"),
            (custom("PASSWORD"), "custom:PASSWORD"),
            (custom("totp"), "custom:totp"),
            (custom("Title"), "custom:Title"),
            (custom("custom:Password"), "custom:custom:Password"),
        ];
        for (field, name) in fields {
            let wire = Field::from(&field).to_string();
            assert_eq!(wire, name);
            assert_eq!(Field::decode(&wire).entry_field(), Some(field));
        }
        assert_eq!(Field::ReservedTitle.entry_field(), None);
    }

    /// A bare `title` is reserved but never copyable, and round-trips as
    /// its own variant rather than falling through to `Custom`.
    #[test]
    fn bare_title_is_reserved_not_custom() {
        assert_eq!(Field::decode("title"), Field::ReservedTitle);
        assert_eq!(Field::decode("TITLE"), Field::ReservedTitle);
        assert_eq!(Field::ReservedTitle.encode(), "title");
    }

    /// `custom:title` reaches a genuine custom field literally keyed
    /// `title`, bypassing the reservation — the one way to address it.
    #[test]
    fn custom_title_prefix_reaches_a_literal_custom_field() {
        assert_eq!(
            Field::decode("custom:title"),
            Field::Custom("title".to_string())
        );
    }

    /// `Field` never fails to decode — any string is some `Field`, even an
    /// empty one (which then simply won't resolve to any field on an
    /// entry, same as an empty field value does).
    #[test]
    fn decoding_never_fails() {
        for raw in ["", "custom:", "🙂", "a very long made up field name"] {
            let _ = Field::decode(raw);
        }
    }

    /// `FromStr`, used by the CLI, agrees with the wire decoder.
    #[test]
    fn from_str_matches_decode() {
        use std::str::FromStr;
        assert_eq!(Field::from_str("password").unwrap(), Field::Password);
        assert_eq!(
            Field::from_str("custom:Password").unwrap(),
            Field::Custom("Password".to_string())
        );
    }
}
