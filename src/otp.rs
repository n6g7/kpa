//! One-time passwords: the code of the moment, made from the seed an entry
//! stores in its `otp` field (`docs/threat-model.md` G-3).
//!
//! The seed comes out of `databases` only as a derive-only value, and this is
//! the one place that reads it, as `ssh` is the one that reads an attachment
//! (`clippy.toml` allows nothing else): a code leaves the process, the seed
//! never does.
//!
//! Only the de-facto-standard `otp` field is read. The legacy KeeOtp
//! `TimeOtp-Seed`, `-Length` and `-Period` fields are a different, older
//! convention that `keepass` doesn't parse, and they stay ordinary fields.

use keepass::db::TOTP;
use zeroize::Zeroizing;

use crate::databases::{Entry, Value, fields};

/// The longest period, in seconds, an `otp` field may ask for: a day.
const MAX_PERIOD: u64 = 86_400;
/// The most digits an `otp` field may ask a code to have.
const MAX_DIGITS: u32 = 10;

/// Whether the entry stores a seed a code can be made from: a non-empty `otp`
/// field. Not whether the seed is any good; [`code`] decides that.
pub fn has_seed(entry: &Entry<'_>) -> bool {
    entry
        .fields()
        .any(|field| field.key == fields::OTP && matches!(field.value, Value::DeriveOnly(_)))
}

/// The code of this moment from the entry's `otp` field. `None` for an entry
/// without one, one that doesn't parse as an `otpauth://` URL, one whose
/// period or number of digits is outside what a code can be made with, or a
/// clock that can't be read: `copy` reports all of these the same, as a
/// field with nothing to give, and never the parse error, which could echo
/// back raw seed bytes.
///
/// The period and the digits are the entry author's, and the code library
/// divides by the period and raises 10 to the digits without checking either,
/// so a period of 0 or a large number of digits would panic it. Both are
/// checked before it runs: with a period of 1 to 86400 and 1 to 10 digits (a
/// code is under 2^31, so more digits add only zeros) nothing in it can
/// divide by zero or overflow.
pub fn code(entry: &Entry<'_>) -> Option<Zeroizing<String>> {
    let seed = entry.fields().find(|field| field.key == fields::OTP)?;
    let Value::DeriveOnly(seed) = seed.value else {
        return None;
    };
    // Making the code is deriving from the seed: the one use of it here.
    #[allow(clippy::disallowed_methods)]
    let url = seed.reveal();
    let totp: TOTP = url.parse().ok()?;
    if !(1..=MAX_PERIOD).contains(&totp.period) || !(1..=MAX_DIGITS).contains(&totp.digits) {
        return None;
    }
    totp.value_now().ok().map(|code| Zeroizing::new(code.code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::Databases;
    use crate::databases::testing::TestEntry;

    const SEED: &str =
        "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

    /// The code, and whether there is a seed, of an entry holding `fields`.
    fn made_from(fields: &[(&str, &str)]) -> (bool, Option<String>) {
        let mut entry = TestEntry::new("site");
        for (key, value) in fields {
            entry = entry.field(key, value);
        }
        let databases = Databases::with_entries_for_test(vec![entry]);
        let open = databases.open("personal").expect("unlocked");
        let entry = open.entries().next().expect("the entry");
        (
            has_seed(&entry),
            code(&entry).map(|code| code.as_str().to_string()),
        )
    }

    /// A valid seed makes a code of the digits it asks for.
    #[test]
    fn a_valid_seed_makes_a_code() {
        let (seed, code) = made_from(&[("otp", SEED)]);

        assert!(seed);
        let code = code.expect("a code");
        assert_eq!(code.len(), 6, "expected a 6-digit code, got {code:?}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    /// A seed protected in the user's client makes a code like any other.
    #[test]
    fn a_protected_seed_makes_a_code() {
        let databases = Databases::with_entries_for_test(vec![
            TestEntry::new("site").protected_field("otp", SEED),
        ]);
        let open = databases.open("personal").expect("unlocked");
        let entry = open.entries().next().expect("the entry");

        assert!(code(&entry).is_some());
    }

    /// No `otp` field, or one that doesn't parse as an `otpauth://` URL,
    /// makes no code, and an empty one is no seed. Other spellings of the key
    /// are ordinary fields, and a stored `totp` is no seed.
    #[test]
    fn without_a_valid_seed_there_is_no_code() {
        assert_eq!(made_from(&[]), (false, None));
        assert_eq!(made_from(&[("otp", "not an otpauth url")]), (true, None));
        assert_eq!(made_from(&[("otp", "")]), (false, None));
        assert_eq!(made_from(&[("OTP", SEED)]), (false, None));
        assert_eq!(made_from(&[("totp", SEED)]), (false, None));
        assert_eq!(
            made_from(&[("TimeOtp-Seed", "JBSWY3DPEHPK3PXP")]),
            (false, None)
        );
    }

    /// An `otp` field's period and number of digits are the entry author's:
    /// a period of 0 or a huge number of digits would panic the code library,
    /// so such a field has no code, as an unparsable one has none, and the
    /// bounds themselves still give one.
    #[test]
    fn a_period_or_digit_count_a_code_cannot_be_made_with_makes_no_code() {
        let url = |query: &str| format!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&{query}");
        for query in [
            "period=0&digits=6",
            "period=86401&digits=6",
            "period=18446744073709551615&digits=6",
            "period=30&digits=0",
            "period=30&digits=11",
            "period=30&digits=19",
            "period=30&digits=20",
            "period=30&digits=100",
            "period=0&digits=100",
        ] {
            assert_eq!(made_from(&[("otp", &url(query))]), (true, None), "{query}");
        }
        for (query, length) in [
            ("period=1&digits=1", 1),
            ("period=30&digits=6", 6),
            ("period=86400&digits=10", 10),
            ("digits=8", 8),
            ("", 8),
        ] {
            let (_, code) = made_from(&[("otp", &url(query))]);
            let code = code.unwrap_or_else(|| panic!("a code for {query:?}"));
            assert_eq!(code.len(), length, "{query}");
            assert!(code.chars().all(|c| c.is_ascii_digit()), "{query}");
        }
    }
}
