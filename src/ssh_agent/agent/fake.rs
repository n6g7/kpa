//! [`FakeHost`]: an in-memory [`SshHost`] for this module's tests.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use keepass::Database;

use super::{SlotView, SshHost, SshSlot};
use crate::config::DatabaseConfig;
use crate::origin::{Origin, PeerOrigin};

/// Configured databases, each with its slot; at most the first one open.
pub(super) struct FakeHost {
    databases: Vec<DatabaseConfig>,
    slots: Mutex<HashMap<String, (Option<Database>, SshSlot)>>,
}

impl FakeHost {
    /// Every database in `databases`, locked.
    pub(super) fn locked(databases: Vec<DatabaseConfig>) -> FakeHost {
        let slots = databases
            .iter()
            .map(|cfg| (cfg.name.clone(), (None, SshSlot::default())))
            .collect();
        FakeHost {
            databases,
            slots: Mutex::new(slots),
        }
    }

    /// Like `locked`, but the first database is open as `db`, scanned as
    /// an unlock would.
    pub(super) fn unlocked(databases: Vec<DatabaseConfig>, db: Database) -> FakeHost {
        let host = FakeHost::locked(databases);
        let cfg = &host.databases[0];
        {
            let mut slots = host.slots.lock().expect("slots");
            let (open, ssh) = slots.get_mut(&cfg.name).expect("configured");
            *ssh = SshSlot::scan(&db, cfg);
            *open = Some(db);
        }
        host
    }
}

impl PeerOrigin for FakeHost {
    fn origin_of(&self, _: &UnixStream, _: u32) -> Origin {
        Origin::Desktop
    }
}

impl SshHost for FakeHost {
    fn databases(&self) -> &[DatabaseConfig] {
        &self.databases
    }

    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R> {
        let mut slots = self.slots.lock().expect("slots");
        let (open, ssh) = slots.get_mut(db)?;
        Some(f(SlotView::new(open.as_ref(), ssh)))
    }
}
