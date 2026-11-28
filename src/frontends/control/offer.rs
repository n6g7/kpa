//! What `copy` offers of an entry, and under which names: the one place that
//! decides. `list` prints these names, and `copy` finds its argument among
//! them by exact match, so a name `list` shows is a name `copy` resolves to
//! the same thing, whatever the entry's keys are spelled like.

use zeroize::Zeroizing;

use super::proto::TOTP;
use crate::databases::{Entry, StoredFields, fields};

/// The keys of the standard fields, offered first and in this order.
const STANDARD: [&str; 4] = [
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
];

/// One thing `copy` can put on the clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Copyable {
    /// The value of the stored field with this exact key.
    Stored(String),
    /// The code made now from the entry's TOTP seed, which is never itself
    /// offered.
    Totp,
}

impl Copyable {
    /// The name on the wire: the key of a stored field as it is, `totp` for
    /// the code.
    pub(super) fn name(&self) -> &str {
        match self {
            Copyable::Stored(key) => key,
            Copyable::Totp => TOTP,
        }
    }

    /// The value, `None` where there is nothing to copy: the field is
    /// empty or gone, or the seed makes no code.
    pub(super) fn value(&self, entry: &Entry<'_>) -> Option<Zeroizing<String>> {
        match self {
            Copyable::Stored(key) => entry.field(key),
            Copyable::Totp => entry.totp(),
        }
    }
}

/// What `copy` offers of an entry that stores `stored`: the standard fields
/// that have a value (`UserName`, `Password`, `URL`, `Notes`, in that
/// order), then the code when a seed is stored, then every other stored key
/// in sorted order. `Title` is never offered, and a stored field keyed
/// exactly `totp` is not either: the name is the code's. A key that
/// differs from either only in case is a different field and is offered.
pub(super) fn offered(stored: &StoredFields) -> Vec<Copyable> {
    let has = |key: &str| stored.keys.iter().any(|stored| stored == key);
    let mut offered: Vec<Copyable> = STANDARD
        .into_iter()
        .filter(|key| has(key))
        .map(|key| Copyable::Stored(key.to_string()))
        .collect();
    if stored.totp {
        offered.push(Copyable::Totp);
    }
    offered.extend(
        stored
            .keys
            .iter()
            .filter(|key| !STANDARD.contains(&key.as_str()))
            .filter(|key| key.as_str() != fields::TITLE && key.as_str() != TOTP)
            .map(|key| Copyable::Stored(key.clone())),
    );
    offered
}

/// The names `list` gives an entry that stores `stored`.
pub(super) fn names(stored: &StoredFields) -> Vec<String> {
    offered(stored)
        .iter()
        .map(|copyable| copyable.name().to_string())
        .collect()
}

/// What `name` asks for on an entry that stores `stored`; `None` if the
/// entry offers nothing by that name.
pub(super) fn find(stored: &StoredFields, name: &str) -> Option<Copyable> {
    offered(stored)
        .into_iter()
        .find(|copyable| copyable.name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(keys: &[&str], totp: bool) -> StoredFields {
        let mut keys: Vec<String> = keys.iter().map(|key| key.to_string()).collect();
        keys.sort();
        StoredFields { keys, totp }
    }

    fn stored_key(key: &str) -> Copyable {
        Copyable::Stored(key.to_string())
    }

    /// Standard keys first, in the fixed order, then the code, then the
    /// other keys sorted; `Title` is left out.
    #[test]
    fn the_standard_fields_come_first_then_the_code_then_the_rest() {
        let entry = stored(
            &[
                "zeta", "Notes", "Title", "URL", "UserName", "Password", "api-key",
            ],
            true,
        );
        assert_eq!(
            names(&entry),
            [
                "UserName", "Password", "URL", "Notes", "totp", "api-key", "zeta"
            ]
        );
    }

    /// A key is offered under its exact spelling, whatever it looks like.
    /// `totp` alone is the code's, and `Title` is never offered; the same
    /// words in another case are fields of their own.
    #[test]
    fn a_key_is_offered_as_it_is_spelled_except_title_and_totp() {
        let entry = stored(
            &[
                "PASSWORD", "password", "totp", "TOTP", "Totp", "Title", "title", "custom:x",
                "OTP", "", "é",
            ],
            false,
        );
        assert_eq!(
            names(&entry),
            [
                "", "OTP", "PASSWORD", "TOTP", "Totp", "custom:x", "password", "title", "é"
            ]
        );
    }

    /// A stored `totp` is not what `totp` copies: with a seed the name is
    /// the code, without one it is nothing.
    #[test]
    fn a_stored_totp_never_answers_to_the_codes_name() {
        let with_seed = stored(&["totp"], true);
        assert_eq!(names(&with_seed), ["totp"]);
        assert_eq!(find(&with_seed, "totp"), Some(Copyable::Totp));

        let without = stored(&["totp"], false);
        assert!(names(&without).is_empty());
        assert_eq!(find(&without, "totp"), None);
    }

    /// Every offered name finds what it was made from, and only that.
    #[test]
    fn a_name_finds_what_it_was_listed_for() {
        let entry = stored(
            &[
                "Password", "PASSWORD", "password", "TOTP", "custom:x", "x", "",
            ],
            true,
        );
        for copyable in offered(&entry) {
            assert_eq!(find(&entry, copyable.name()), Some(copyable.clone()));
        }
        assert_eq!(find(&entry, "Password"), Some(stored_key("Password")));
        assert_eq!(find(&entry, "x"), Some(stored_key("x")));
        assert_eq!(find(&entry, "totp"), Some(Copyable::Totp));
        assert_eq!(find(&entry, "Title"), None);
        assert_eq!(find(&entry, "otp"), None);
        assert_eq!(find(&entry, "custom:Password"), None);
    }
}
