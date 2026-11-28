//! What `copy` offers of an entry, and under which names: the one place that
//! decides. `list` prints these names, and `copy` finds its argument among
//! them by exact match, so a name `list` shows is a name `copy` resolves to
//! the same thing, whatever the entry's keys are spelled like.
//!
//! Only a field that may leave the process is offered under its own key. The
//! one-time-password seed, which only derives, is never offered: `totp` is
//! the code made from it.

use zeroize::Zeroizing;

use super::proto::TOTP;
use crate::databases::{Entry, fields};
use crate::otp;

/// The keys of the standard fields, offered first and in this order.
const STANDARD: [&str; 4] = [
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
];

/// One thing `copy` can put on the clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Copyable<'a> {
    /// The value of the field with this exact key.
    Field { key: &'a str, value: &'a str },
    /// The code made now from the entry's one-time-password seed.
    Totp,
}

impl Copyable<'_> {
    /// The name on the wire: the key of a field as it is, `totp` for the
    /// code.
    pub(super) fn name(&self) -> &str {
        match self {
            Copyable::Field { key, .. } => key,
            Copyable::Totp => TOTP,
        }
    }

    /// The value to copy, `None` where there is nothing: the seed makes no
    /// code.
    pub(super) fn value(&self, entry: &Entry<'_>) -> Option<Zeroizing<String>> {
        match self {
            Copyable::Field { value, .. } => Some(Zeroizing::new(value.to_string())),
            Copyable::Totp => otp::code(entry),
        }
    }
}

/// What `copy` offers of `entry`: the standard fields that have a value
/// (`UserName`, `Password`, `URL`, `Notes`, in that order), then the code
/// when a seed is stored, then every other field that may leave the process,
/// by key in sorted order. `Title` is never offered, and a field keyed
/// exactly `totp` is not either: the name is the code's. A key that differs
/// from either only in case is a different field and is offered.
pub(super) fn offered<'a>(entry: &'a Entry<'_>) -> Vec<Copyable<'a>> {
    let mut shareable: Vec<(&str, &str)> = entry
        .fields()
        .filter_map(|field| field.value.shareable().map(|value| (field.key, value)))
        .collect();
    shareable.sort();
    let field = |(key, value): (&'a str, &'a str)| Copyable::Field { key, value };

    let mut offered: Vec<Copyable<'a>> = STANDARD
        .into_iter()
        .filter_map(|standard| shareable.iter().find(|(key, _)| *key == standard))
        .map(|&pair| field(pair))
        .collect();
    if otp::has_seed(entry) {
        offered.push(Copyable::Totp);
    }
    offered.extend(
        shareable
            .iter()
            .filter(|(key, _)| !STANDARD.contains(key))
            .filter(|(key, _)| *key != fields::TITLE && *key != TOTP)
            .map(|&pair| field(pair)),
    );
    offered
}

/// The names `list` gives `entry`.
pub(super) fn names(entry: &Entry<'_>) -> Vec<String> {
    offered(entry)
        .iter()
        .map(|copyable| copyable.name().to_string())
        .collect()
}

/// What `name` asks for on `entry`; `None` if the entry offers nothing by
/// that name.
pub(super) fn find<'a>(entry: &'a Entry<'_>, name: &str) -> Option<Copyable<'a>> {
    offered(entry)
        .into_iter()
        .find(|copyable| copyable.name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Databases;
    use crate::databases::testing::TestEntry;

    const SEED: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";

    /// Runs `check` on an entry that stores `stored`, `Title` and the other
    /// standard keys among them.
    fn with_entry(stored: &[(&str, &str)], check: impl FnOnce(&Entry<'_>)) {
        let mut entry = TestEntry::new("title");
        for (key, value) in stored {
            entry = entry.field(key, value);
        }
        let databases = Databases::with_entries_for_test(vec![entry]);
        let open = databases.open("personal").expect("unlocked");
        check(&open.entries().next().expect("the entry"));
    }

    fn field<'a>(key: &'a str, value: &'a str) -> Copyable<'a> {
        Copyable::Field { key, value }
    }

    /// Standard keys first, in the fixed order, then the code, then the
    /// other keys sorted; `Title` is left out.
    #[test]
    fn the_standard_fields_come_first_then_the_code_then_the_rest() {
        with_entry(
            &[
                ("zeta", "z"),
                ("Notes", "n"),
                ("Title", "t"),
                ("URL", "u"),
                ("UserName", "a"),
                ("Password", "p"),
                ("api-key", "k"),
                ("otp", SEED),
            ],
            |entry| {
                assert_eq!(
                    names(entry),
                    [
                        "UserName", "Password", "URL", "Notes", "totp", "api-key", "zeta"
                    ]
                );
            },
        );
    }

    /// A key is offered under its exact spelling, whatever it looks like.
    /// `totp` alone is the code's, and `Title` is never offered; the same
    /// words in another case are fields of their own.
    #[test]
    fn a_key_is_offered_as_it_is_spelled_except_title_and_totp() {
        with_entry(
            &[
                ("PASSWORD", "1"),
                ("password", "2"),
                ("totp", "3"),
                ("TOTP", "4"),
                ("Totp", "5"),
                ("Title", "6"),
                ("title", "7"),
                ("custom:x", "8"),
                ("OTP", "9"),
                ("", "10"),
                ("é", "11"),
            ],
            |entry| {
                assert_eq!(
                    names(entry),
                    [
                        "", "OTP", "PASSWORD", "TOTP", "Totp", "custom:x", "password", "title", "é"
                    ]
                );
            },
        );
    }

    /// A stored `totp` is not what `totp` copies: with a seed the name is
    /// the code, without one it is nothing.
    #[test]
    fn a_stored_totp_never_answers_to_the_codes_name() {
        with_entry(&[("totp", "stored"), ("otp", SEED)], |entry| {
            assert_eq!(names(entry), ["totp"]);
            assert_eq!(find(entry, "totp"), Some(Copyable::Totp));
        });
        with_entry(&[("totp", "stored")], |entry| {
            assert!(names(entry).is_empty());
            assert_eq!(find(entry, "totp"), None);
        });
    }

    /// The seed only derives: it is never offered under its own key, `otp`
    /// finds nothing, and `totp` is there whether or not the seed makes a
    /// code. An empty field is not offered.
    #[test]
    fn the_seed_is_never_offered_under_its_own_key() {
        with_entry(
            &[("otp", "not a url"), ("Password", ""), ("URL", "u")],
            |entry| {
                assert_eq!(names(entry), ["URL", "totp"]);
                assert_eq!(find(entry, "otp"), None);
                assert_eq!(find(entry, "totp"), Some(Copyable::Totp));
                assert!(Copyable::Totp.value(entry).is_none());
            },
        );
    }

    /// A field the user protected in their client is offered like any other:
    /// protection decides what `list` shows, not what `copy` can copy.
    #[test]
    fn a_protected_field_is_offered() {
        let databases = Databases::with_entries_for_test(vec![
            TestEntry::new("title").protected_field("Password", "hunter2"),
        ]);
        let open = databases.open("personal").expect("unlocked");
        let entry = open.entries().next().expect("the entry");

        let found = find(&entry, "Password").expect("offered");
        assert_eq!(found, field("Password", "hunter2"));
        assert_eq!(
            found.value(&entry).as_deref().map(String::as_str),
            Some("hunter2")
        );
    }

    /// Every offered name finds what it was made from, and only that.
    #[test]
    fn a_name_finds_what_it_was_listed_for() {
        with_entry(
            &[
                ("Password", "a"),
                ("PASSWORD", "b"),
                ("password", "c"),
                ("TOTP", "d"),
                ("custom:x", "e"),
                ("x", "f"),
                ("", "g"),
                ("otp", SEED),
            ],
            |entry| {
                for copyable in offered(entry) {
                    assert_eq!(find(entry, copyable.name()).as_ref(), Some(&copyable));
                }
                assert_eq!(find(entry, "Password"), Some(field("Password", "a")));
                assert_eq!(find(entry, "x"), Some(field("x", "f")));
                assert_eq!(find(entry, "totp"), Some(Copyable::Totp));
                assert_eq!(find(entry, "Title"), None);
                assert_eq!(find(entry, "otp"), None);
                assert_eq!(find(entry, "custom:Password"), None);
            },
        );
    }
}
