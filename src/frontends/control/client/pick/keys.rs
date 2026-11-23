//! The keys `kpa pick` ends fzf on, and what each one copies.

use crate::frontends::control::proto::Field;

/// What fzf is told to end on besides Enter (`--expect`). Every key here has
/// an [`action`].
pub(super) const EXPECT: &str = "ctrl-u,ctrl-l,ctrl-t,ctrl-o";

/// What a key asks for on the entry fzf ended on.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Action {
    Copy(Field),
    /// Pick one of the entry's own fields, custom ones included, first.
    ChooseField,
}

/// The action for `key`, the first line fzf printed: empty when it ended on
/// Enter, else the key's name.
pub(super) fn action(key: &str) -> Option<Action> {
    Some(match key {
        "" => Action::Copy(Field::Password),
        "ctrl-u" => Action::Copy(Field::Username),
        "ctrl-l" => Action::Copy(Field::Url),
        "ctrl-t" => Action::Copy(Field::Totp),
        "ctrl-o" => Action::ChooseField,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_key_copies_its_field() {
        assert_eq!(action(""), Some(Action::Copy(Field::Password)));
        assert_eq!(action("ctrl-u"), Some(Action::Copy(Field::Username)));
        assert_eq!(action("ctrl-l"), Some(Action::Copy(Field::Url)));
        assert_eq!(action("ctrl-t"), Some(Action::Copy(Field::Totp)));
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
}
