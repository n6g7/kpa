//! In-memory databases for unit tests in any subsystem: the real core with a
//! database installed at the file read, so locks, tokens and observers behave
//! as in production. No test names a `keepass` type.

use std::io::Write;
use std::time::Duration;

use keepass::DatabaseKey;
use keepass::config::KdfConfig;
use keepass::db::{Value, fields};

use super::vault;
use super::{Databases, Slot};
use crate::config::DatabaseConfig;

/// The password of the databases [`Databases::write_for_test`] writes.
pub(crate) const PASSWORD: &str = "hunter2";

/// One entry of an in-memory database.
pub(crate) struct TestEntry {
    title: String,
    fields: Vec<(String, String)>,
    attachments: Vec<(String, Vec<u8>)>,
    in_recycle_bin: bool,
}

impl TestEntry {
    pub(crate) fn new(title: &str) -> TestEntry {
        TestEntry {
            title: title.to_string(),
            fields: Vec::new(),
            attachments: Vec::new(),
            in_recycle_bin: false,
        }
    }

    pub(crate) fn field(mut self, key: &str, value: &str) -> TestEntry {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    pub(crate) fn attachment(mut self, name: &str, data: impl Into<Vec<u8>>) -> TestEntry {
        self.attachments.push((name.to_string(), data.into()));
        self
    }

    pub(crate) fn in_recycle_bin(mut self) -> TestEntry {
        self.in_recycle_bin = true;
        self
    }
}

pub(super) fn build(entries: Vec<TestEntry>) -> keepass::Database {
    let mut db = keepass::Database::new();
    let mut bin_id = None;
    {
        let mut root = db.root_mut();
        for entry in entries {
            let mut group = if entry.in_recycle_bin {
                let bin = root.add_group();
                bin_id = Some(bin.id());
                bin
            } else {
                root.add_group()
            };
            let mut added = group.add_entry();
            added.set_unprotected(fields::TITLE, entry.title);
            for (key, value) in entry.fields {
                added.set_unprotected(key, value);
            }
            for (name, data) in entry.attachments {
                added.add_attachment(name, Value::unprotected(data));
            }
        }
    }
    if let Some(bin_id) = bin_id {
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
    }
    db
}

impl Databases {
    /// Like `new`, with each path pointed at a placeholder file in a temp
    /// directory that a field of `Databases` keeps alive.
    pub(crate) fn for_test(mut configs: Vec<DatabaseConfig>, idle_timeout: Duration) -> Databases {
        let dir = tempfile::tempdir().expect("temp dir");
        for config in &mut configs {
            let path = dir.path().join(format!("{}.kdbx", config.name));
            std::fs::write(&path, b"placeholder").expect("placeholder file");
            config.path = path;
        }
        let mut databases = Databases::new(configs, idle_timeout);
        databases.scratch = Some(dir);
        databases
    }

    /// Installs an in-memory database through the same path as `finish`.
    pub(crate) fn install_for_test(&self, name: &str, entries: Vec<TestEntry>) {
        let index = self.index(name).expect("a configured database");
        let stamp = vault::Fingerprint::from_file(&self.configs[index].path)
            .expect("`for_test` made the placeholder file");
        let token = {
            let mut slots = self.slots();
            let slot: &mut Slot = &mut slots[index];
            let token = slot.source.token();
            assert!(slot.install(&token, build(entries), stamp));
            token
        };
        self.installed(index, &token);
    }

    /// Writes a real database holding `entries` to `name`'s file, which
    /// [`PASSWORD`] opens: an unlock reads it as it reads any file. Its key
    /// derivation is a single round, so reading it is quick.
    pub(crate) fn write_for_test(&self, name: &str, entries: Vec<TestEntry>) {
        let index = self.index(name).expect("a configured database");
        let mut db = build(entries);
        db.config.kdf_config = KdfConfig::Aes { rounds: 1 };
        let mut file = std::fs::File::create(&self.configs[index].path).expect("the file");
        db.save(&mut file, DatabaseKey::new().with_password(PASSWORD))
            .expect("saves");
    }

    /// Rewrites the placeholder file, so the freshness guard sees a change.
    pub(crate) fn change_file_for_test(&self, name: &str) {
        let index = self.index(name).expect("a configured database");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.configs[index].path)
            .expect("placeholder file");
        file.write_all(b"changed").expect("write");
    }
}
