//! The keys `kpa pick` ends fzf on, and what each one copies.

use crate::databases::fields;
use crate::frontends::control::proto::TOTP;

/// What fzf is told to end on besides Enter (`--expect`). Every key here has
/// an [`action`].
pub(super) const EXPECT: &str = "ctrl-u,ctrl-l,ctrl-t,ctrl-o";

/// What fzf's header says each key copies.
pub(super) const HELP: &str =
    "enter: password  ctrl-u: username  ctrl-l: url  ctrl-t: totp  ctrl-o: any field";

/// What a key asks for on the entry fzf ended on.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Action {
    /// Copy the field of this name: the key of a standard field, or the
    /// code. Sent as it is; the entry may have none.
    Copy(&'static str),
    /// Pick one of the entry's own fields, custom ones included, first.
    ChooseField,
}

/// The action for `key`, the first line fzf printed: empty when it ended on
/// Enter, else the key's name.
pub(super) fn action(key: &str) -> Option<Action> {
    Some(match key {
        "" => Action::Copy(fields::PASSWORD),
        "ctrl-u" => Action::Copy(fields::USERNAME),
        "ctrl-l" => Action::Copy(fields::URL),
        "ctrl-t" => Action::Copy(TOTP),
        "ctrl-o" => Action::ChooseField,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_key_copies_its_field() {
        assert_eq!(action(""), Some(Action::Copy("Password")));
        assert_eq!(action("ctrl-u"), Some(Action::Copy("UserName")));
        assert_eq!(action("ctrl-l"), Some(Action::Copy("URL")));
        assert_eq!(action("ctrl-t"), Some(Action::Copy("totp")));
        assert_eq!(action("ctrl-o"), Some(Action::ChooseField));
        assert_eq!(action("ctrl-x"), None);
    }

    #[test]
    fn fzf_is_told_to_end_on_exactly_the_keys_that_have_an_action() {
        for key in EXPECT.split(',') {
            assert!(action(key).is_some(), "{key}");
        }
        assert_eq!(EXPECT.split(',').count(), 4);
    }

    #[test]
    fn the_header_names_every_key() {
        for key in EXPECT.split(',').chain(["enter"]) {
            assert!(HELP.contains(&format!("{key}: ")), "{key}");
        }
    }
}
