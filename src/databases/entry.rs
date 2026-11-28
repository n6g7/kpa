//! The entries of an unlocked database, as `databases` hands them out: every
//! string field with a value and every attachment, borrowed from the open
//! database while its guard lives, so nothing is copied until a front end
//! copies the one value it serves. KeePass's own conventions are decided
//! here and nowhere else: which entries are current, which field is a
//! one-time-password seed, and that an attachment is only ever used to derive
//! something. Nothing here makes a code or applies a rule about what a front
//! end may show.

use std::cell::OnceCell;

use keepass::Database;
use keepass::db::{AttachmentRef, EntryId, EntryRef, GroupId, GroupRef};
use uuid::Uuid;

use super::fields;
use super::secret::{Secret, Value};

/// One entry of an open database.
pub struct Entry<'a> {
    db: &'a Database,
    entry: EntryRef<'a>,
    group: GroupRef<'a>,
    in_recycle_bin: bool,
    /// The entry's attachments, read at the first call of
    /// [`Entry::attachments`]: the references are what the values borrow
    /// from, so they have to live as long as the entry does.
    attachments: OnceCell<Vec<(String, AttachmentRef<'a>)>>,
}

/// A string field of an entry that has a value.
pub struct Field<'a> {
    pub key: &'a str,
    /// Shareable, except for the one-time-password seed (the field keyed
    /// `otp`), which only derives.
    pub value: Value<'a, str>,
    /// Whether the user marked the field protected in their KeePass client.
    /// What that is worth is for the front end to decide.
    pub protected: bool,
}

/// An attachment of an entry, which only derives: nothing in kpa needs one
/// to leave the process.
pub struct Attachment<'a> {
    pub name: &'a str,
    pub value: Value<'a, [u8]>,
}

impl<'a> Entry<'a> {
    /// `None` if the entry's group is missing, which `keepass` doesn't let
    /// happen.
    fn new(db: &'a Database, entry: EntryRef<'a>, in_recycle_bin: bool) -> Option<Entry<'a>> {
        let group = db.group(entry.parent().id())?;
        Some(Entry {
            db,
            entry,
            group,
            in_recycle_bin,
            attachments: OnceCell::new(),
        })
    }

    pub fn uuid(&self) -> Uuid {
        self.entry.id().uuid()
    }

    /// The name of the group the entry is in.
    pub fn group(&self) -> &str {
        &self.group.name
    }

    /// The entry's string fields that have a value, in no particular order.
    pub fn fields(&self) -> impl Iterator<Item = Field<'_>> {
        self.entry.fields.iter().filter_map(|(key, raw)| {
            let text = raw.get().as_str();
            if text.is_empty() {
                return None;
            }
            let value = if key == fields::OTP {
                Value::DeriveOnly(Secret::new(text))
            } else {
                Value::Shareable(text)
            };
            Some(Field {
                key,
                value,
                protected: raw.is_protected(),
            })
        })
    }

    /// The entry's attachments. None for an entry in the recycle bin.
    pub fn attachments(&self) -> impl Iterator<Item = Attachment<'_>> {
        let attachments: &[(String, AttachmentRef<'a>)] = if self.in_recycle_bin {
            &[]
        } else {
            self.attachments.get_or_init(|| {
                self.entry
                    .attachments_named()
                    .filter_map(|(name, attachment)| {
                        let attachment = self.db.attachment(attachment.id())?;
                        Some((name.to_string(), attachment))
                    })
                    .collect()
            })
        };
        attachments.iter().map(|(name, attachment)| Attachment {
            name,
            value: Value::DeriveOnly(Secret::new(attachment.data.get().as_slice())),
        })
    }
}

/// The entry `uuid`, looked up directly rather than by walking the tree.
/// Never a historical revision. An entry in the recycle bin is found like any
/// other.
pub(super) fn find(db: &Database, uuid: Uuid) -> Option<Entry<'_>> {
    let entry = db.entry(EntryId::from_uuid(uuid))?;
    let in_recycle_bin = in_recycle_bin(db, &entry);
    Entry::new(db, entry, in_recycle_bin)
}

/// Whether one of the entry's ancestors, walked up to the root, is the
/// recycle bin group. Iterative, and stops at a group it has already seen,
/// so a malformed parent chain can't loop.
fn in_recycle_bin(db: &Database, entry: &EntryRef<'_>) -> bool {
    let Some(recycle_bin) = db.recycle_bin().map(|group| group.id()) else {
        return false;
    };
    let mut seen = std::collections::HashSet::new();
    let mut group = Some(entry.parent().id());
    while let Some(id) = group {
        if id == recycle_bin {
            return true;
        }
        if !seen.insert(id) {
            break;
        }
        group = db
            .group(id)
            .and_then(|group| group.parent().map(|parent| parent.id()));
    }
    false
}

/// Every entry of the database, in tree order, the recycle bin's included
/// (its entries have no attachments). An explicit worklist rather than
/// recursion: a `.kdbx` with a deep enough group nesting would otherwise
/// overflow the stack and abort the process.
pub(super) fn entries(db: &Database) -> Entries<'_> {
    Entries {
        db,
        recycle_bin: db.recycle_bin().map(|group| group.id()),
        groups: vec![(db.root().id(), false)],
        ids: Vec::new().into_iter(),
        in_recycle_bin: false,
    }
}

pub(super) struct Entries<'a> {
    db: &'a Database,
    recycle_bin: Option<GroupId>,
    /// Groups still to visit, each with whether it is under the recycle bin.
    groups: Vec<(GroupId, bool)>,
    /// The entries of the group being visited, still to hand out.
    ids: std::vec::IntoIter<EntryId>,
    in_recycle_bin: bool,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        loop {
            for id in self.ids.by_ref() {
                let entry = self
                    .db
                    .entry(id)
                    .and_then(|entry| Entry::new(self.db, entry, self.in_recycle_bin));
                if entry.is_some() {
                    return entry;
                }
            }
            let (id, under_bin) = self.groups.pop()?;
            let Some(group) = self.db.group(id) else {
                continue;
            };
            self.in_recycle_bin = under_bin || Some(id) == self.recycle_bin;
            self.ids = group.entry_ids().collect::<Vec<_>>().into_iter();
            let children: Vec<_> = group.group_ids().collect();
            self.groups.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|child| (child, self.in_recycle_bin)),
            );
        }
    }
}

/// How many entries the database has, counting those in the recycle bin.
/// The same worklist as [`entries`], without a handle per entry.
pub(super) fn count(db: &Database) -> usize {
    let mut count = 0;
    let mut stack = vec![db.root().id()];
    while let Some(id) = stack.pop() {
        let Some(group) = db.group(id) else {
            continue;
        };
        count += group.entries().count();
        stack.extend(group.groups().map(|child| child.id()));
    }
    count
}

#[cfg(test)]
mod tests {
    use keepass::db::{Value as KeepassValue, fields};

    use super::*;

    /// What a field looks like to a reader: its key, its text when it may be
    /// shared (`None` when it only derives), and whether it is protected.
    type Seen = (String, Option<String>, bool);

    fn seen_fields(entry: &Entry<'_>) -> Vec<Seen> {
        let mut seen: Vec<Seen> = entry
            .fields()
            .map(|field| {
                (
                    field.key.to_string(),
                    field.value.shareable().map(str::to_string),
                    field.protected,
                )
            })
            .collect();
        seen.sort();
        seen
    }

    fn shared(key: &str, value: &str, protected: bool) -> Seen {
        (key.to_string(), Some(value.to_string()), protected)
    }

    /// The names of the attachments the entries have, in the order the walk
    /// meets them.
    fn attachment_names(db: &Database) -> Vec<String> {
        entries(db)
            .flat_map(|entry| {
                entry
                    .attachments()
                    .map(|attachment| attachment.name.to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// `count` must agree with the walk everywhere, including in nested
    /// groups and when fields are protected: it is what `status` reports.
    #[test]
    fn count_matches_the_walk() {
        let mut db = Database::new();
        assert_eq!(count(&db), 0);

        {
            let mut root = db.root_mut();
            root.add_entry().set_unprotected(fields::TITLE, "top");
            let mut child = root.add_group();
            child.add_entry().set_protected(fields::TITLE, "hidden");
            child
                .add_group()
                .add_entry()
                .set_unprotected(fields::TITLE, "deep");
        }

        assert_eq!(count(&db), 3);
        assert_eq!(count(&db), entries(&db).count());
    }

    /// The walk doesn't recurse once per group nesting level: that would
    /// overflow and abort the process well before this depth on a 2 MiB
    /// thread stack. Built in memory, and fails loudly (abort) rather than
    /// merely failing an assertion on regression.
    #[test]
    fn the_walk_survives_deeply_nested_groups() {
        let mut db = Database::new();
        let mut id = db.root().id();
        for _ in 0..100_000 {
            let mut group = db.group_mut(id).expect("just-created group must exist");
            id = group.add_group().id();
        }
        db.group_mut(id)
            .expect("just-created group must exist")
            .add_entry()
            .set_unprotected(fields::TITLE, "deep");

        let entry = entries(&db).next().expect("the one entry");
        assert_eq!(seen_fields(&entry), [shared("Title", "deep", false)]);
        assert_eq!(entries(&db).count(), 1);
    }

    /// An entry's fields are the exact keys of the string fields that have a
    /// value, protected ones included, with whether each is protected; one
    /// with an empty value is left out.
    #[test]
    fn fields_are_the_exact_keys_of_the_fields_with_a_value() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "site");
            entry.set_unprotected(fields::URL, "https://example.com");
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.set_unprotected(fields::NOTES, "");
            entry.set_unprotected("PASSWORD", "one");
            entry.set_unprotected("custom:x", "four");
            entry.set_unprotected("", "five");
            entry.set_unprotected("empty", "");
            entry.id().uuid()
        };

        let entry = find(&db, uuid).expect("entry");
        assert_eq!(
            seen_fields(&entry),
            [
                shared("", "five", false),
                shared("PASSWORD", "one", false),
                shared("Password", "hunter2", true),
                shared("Title", "site", false),
                shared("URL", "https://example.com", false),
                shared("custom:x", "four", false),
            ]
        );
    }

    /// The field keyed `otp` holds the one-time-password seed and only
    /// derives; a key that differs from `otp` only in case is an ordinary
    /// field, and an empty seed is no field.
    #[test]
    fn only_the_otp_field_derives() {
        let mut db = Database::new();
        let (with_seed, empty_seed) = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::OTP, "otpauth://totp/x?secret=ABC");
            entry.set_unprotected("OTP", "not the seed");
            let with_seed = entry.id().uuid();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::OTP, "");
            (with_seed, entry.id().uuid())
        };

        assert_eq!(
            seen_fields(&find(&db, with_seed).expect("entry")),
            [
                shared("OTP", "not the seed", false),
                ("otp".to_string(), None, false),
            ]
        );
        assert!(seen_fields(&find(&db, empty_seed).expect("entry")).is_empty());
    }

    /// A seed read through its `Secret` is the field's text.
    #[test]
    #[allow(clippy::disallowed_methods)] // The test reads the seed it just stored.
    fn a_seed_reveals_the_text_of_its_field() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_protected(fields::OTP, "otpauth://totp/x?secret=ABC");
            entry.id().uuid()
        };

        let entry = find(&db, uuid).expect("entry");
        let field = entry.fields().next().expect("the seed");
        assert!(field.protected);
        let Value::DeriveOnly(secret) = field.value else {
            panic!("a seed only derives");
        };
        assert_eq!(secret.reveal(), "otpauth://totp/x?secret=ABC");
    }

    /// An unknown uuid is `None`, and an entry's group is named.
    #[test]
    fn find_finds_an_entry_by_uuid_in_its_group() {
        let mut db = Database::new();
        let uuid = {
            let mut root = db.root_mut();
            let mut child = root.add_group();
            child.name = "Web".to_string();
            child.add_entry().id().uuid()
        };

        assert_eq!(find(&db, uuid).expect("entry").group(), "Web");
        assert_eq!(find(&db, uuid).expect("entry").uuid(), uuid);
        assert!(find(&db, Uuid::new_v4()).is_none());
    }

    /// An entry in the recycle bin, however deep, is found and walked like
    /// any other and has no attachments.
    #[test]
    fn an_entry_in_the_recycle_bin_has_no_attachments() {
        let mut db = Database::new();
        let (entry_id, bin_id) = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            let bin_id = bin.id();
            let mut nested = bin.add_group();
            let mut entry = nested.add_entry();
            entry.set_unprotected(fields::TITLE, "recycled");
            entry.add_attachment("bin.key", KeepassValue::unprotected(b"BIN".to_vec()));
            (entry.id(), bin_id)
        };
        let uuid = entry_id.uuid();
        assert_eq!(
            find(&db, uuid).expect("entry").attachments().count(),
            1,
            "sanity: it is not the recycle bin yet"
        );

        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        assert_eq!(find(&db, uuid).expect("entry").attachments().count(), 0);
        assert_eq!(
            seen_fields(&find(&db, uuid).expect("entry")),
            [shared("Title", "recycled", false)]
        );
        assert_eq!(count(&db), 1);
        let walked = entries(&db).next().expect("the walk meets it");
        assert_eq!(walked.attachments().count(), 0);
        assert!(attachment_names(&db).is_empty());
    }

    /// The attachments of an entry have their names and their bytes (only
    /// to derive from), and come from the entry they were asked of.
    #[test]
    #[allow(clippy::disallowed_methods)] // The test reads the bytes it just stored.
    fn an_entry_has_its_own_attachments() {
        let mut db = Database::new();
        let (wanted, other) = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.add_attachment("a.key", KeepassValue::unprotected(b"A".to_vec()));
            entry.add_attachment("b.key", KeepassValue::protected(b"B".to_vec()));
            let wanted = entry.id().uuid();
            let mut other = root.add_entry();
            other.add_attachment("c.key", KeepassValue::unprotected(b"C".to_vec()));
            (wanted, other.id().uuid())
        };

        let read = |uuid| {
            let entry = find(&db, uuid).expect("entry");
            let mut read: Vec<(String, Vec<u8>)> = entry
                .attachments()
                .map(|attachment| {
                    let Value::DeriveOnly(secret) = attachment.value else {
                        panic!("an attachment only derives");
                    };
                    (attachment.name.to_string(), secret.reveal().to_vec())
                })
                .collect();
            read.sort();
            read
        };

        assert_eq!(
            read(wanted),
            [
                ("a.key".to_string(), b"A".to_vec()),
                ("b.key".to_string(), b"B".to_vec())
            ]
        );
        assert_eq!(read(other), [("c.key".to_string(), b"C".to_vec())]);
    }

    /// The walk meets entries in tree order: a group's own entries, then
    /// each of its groups in turn, depth first, in their stored order.
    #[test]
    fn the_walk_is_in_tree_order() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.add_entry()
                .add_attachment("root", KeepassValue::unprotected(b"0".to_vec()));
            let mut first = root.add_group();
            first
                .add_entry()
                .add_attachment("first", KeepassValue::unprotected(b"1".to_vec()));
            first
                .add_group()
                .add_entry()
                .add_attachment("first/nested", KeepassValue::unprotected(b"2".to_vec()));
            root.add_group()
                .add_entry()
                .add_attachment("second", KeepassValue::unprotected(b"3".to_vec()));
        }

        assert_eq!(
            attachment_names(&db),
            ["root", "first", "first/nested", "second"]
        );
    }

    /// An attachment that exists only on a historical revision of an entry,
    /// never on its current one, is invisible.
    #[test]
    fn an_attachment_only_in_history_is_invisible() {
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.add_attachment("old.key", KeepassValue::unprotected(b"OLD".to_vec()));
            entry.id()
        };

        // Snapshots the attachment into history, then removes it from the
        // live entry: the only remaining copy is historical.
        db.entry_mut(id)
            .expect("just-created entry must exist")
            .edit_tracking(|e| {
                e.as_mut().remove_attachment_by_name("old.key");
            });

        assert!(
            db.entry(id)
                .expect("entry still exists")
                .history
                .as_ref()
                .is_some_and(|h| !h.get_entries().is_empty()),
            "the attachment should have been pushed into history"
        );
        assert!(attachment_names(&db).is_empty());
    }

    /// An entry moved into the recycle bin has no attachments.
    #[test]
    fn a_moved_entry_loses_its_attachments_to_the_recycle_bin() {
        let mut db = Database::new();
        let (entry_id, bin_id) = {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.add_attachment("bin.key", KeepassValue::unprotected(b"BIN".to_vec()));
            let entry_id = entry.id();
            let bin_id = root.add_group().id();
            (entry_id, bin_id)
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        db.entry_mut(entry_id)
            .expect("just-created entry must exist")
            .move_to(bin_id)
            .expect("the recycle bin group exists");

        assert!(attachment_names(&db).is_empty());
        assert_eq!(count(&db), 1);
    }
}
