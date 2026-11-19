//! `copy`: put one field of one entry on the clipboard, and end that offer
//! when the unlock it came from is locked.

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::proto::{CopyError, CopyOutcome, CopyRequest, Field};
use super::{Api, authz};
use crate::authn::Requester;
use crate::cancel::CancelToken;
use crate::clipboard::{Clipboard, Offer};
use crate::databases::{Databases, Entry, Observer, OpenError, fields};
use crate::display_session::DisplaySession;

/// The clipboard, and the one offer a `copy` has made that is still live:
/// which database and unlock it came from. An observer that ends the offer
/// when that unlock is locked.
pub struct CopyState {
    clipboard: Arc<Clipboard>,
    held: Arc<Mutex<Option<Held>>>,
}

struct Held {
    db: String,
    unlock: CancelToken,
    offer: Arc<Offer>,
}

fn held(held: &Mutex<Option<Held>>) -> MutexGuard<'_, Option<Held>> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

impl CopyState {
    pub fn new(clipboard: Clipboard) -> CopyState {
        CopyState {
            clipboard: Arc::new(clipboard),
            held: Arc::new(Mutex::new(None)),
        }
    }

    /// Hands `value` to the clipboard as the content of `session` for
    /// `timeout`, remembering which unlock of `db` it came from. A lock that
    /// ended `unlock` before the offer was recorded ends the offer here and
    /// the copy is `Locked`: either that lock's notice finds the record, or
    /// this finds the token cancelled, since the lock cancels it before any
    /// observer is told.
    fn offer(
        &self,
        value: Zeroizing<String>,
        session: &DisplaySession,
        db: &str,
        unlock: &CancelToken,
        timeout: Duration,
    ) -> Result<(), CopyError> {
        let offer = self
            .clipboard
            .offer(value, session)
            .map_err(|err| CopyError::Clipboard {
                db: db.to_string(),
                detail: err.to_string(),
            })?;
        {
            let mut current = held(&self.held);
            if unlock.is_cancelled() {
                drop(current);
                self.clipboard.expire(&offer);
                return Err(CopyError::Locked { db: db.to_string() });
            }
            *current = Some(Held {
                db: db.to_string(),
                unlock: unlock.clone(),
                offer: Arc::clone(&offer),
            });
        }

        let clipboard = Arc::clone(&self.clipboard);
        let current = Arc::clone(&self.held);
        let _ = thread::Builder::new().spawn(move || {
            thread::sleep(timeout);
            clipboard.expire(&offer);
            let mut current = held(&current);
            if current
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(&held.offer, &offer))
            {
                *current = None;
            }
        });
        Ok(())
    }
}

impl Observer for CopyState {
    /// Ends the offer if it came from the unlock this lock ended, and
    /// leaves any other: a lock of another database, or a late notice for
    /// an old unlock.
    fn locked(&self, _: &Databases, db: &str, unlock: &CancelToken) {
        let mut current = held(&self.held);
        if current
            .as_ref()
            .is_some_and(|held| held.db == db && held.unlock == *unlock)
            && let Some(held) = current.take()
        {
            self.clipboard.expire(&held.offer);
        }
    }
}

impl Api {
    /// Only a requester on the desktop, with the display session active and
    /// unlocked, reaches the clipboard (`docs/headless.md` § 5). That is
    /// checked first, so a refused requester learns nothing about the
    /// database names.
    pub(super) fn copy(
        &self,
        request: &CopyRequest,
        requester: &Requester,
    ) -> Result<CopyOutcome, CopyError> {
        let session = self.display.get();
        let session = authz::authorize_copy(requester, &session)?;

        let name = request.db.as_str();
        let db = || name.to_string();
        let (value, entry, unlock) = {
            let open = self.databases.open(name).map_err(|err| match err {
                OpenError::UnknownDb => CopyError::UnknownDb { db: db() },
                OpenError::Locked => CopyError::Locked { db: db() },
                OpenError::Stale => CopyError::Stale { db: db() },
            })?;
            let read = open
                .entry(request.uuid)
                .ok_or_else(|| CopyError::UnknownUuid { db: db() })?;
            let value = field_value(&read, &request.field)
                .ok_or_else(|| CopyError::FieldEmpty { db: db() })?;
            let title = read.title().unwrap_or_else(|| request.uuid.to_string());
            (value, title, open.unlock_token())
            // The guard is released here: the clipboard handoff is a round
            // trip to the compositor, and must not stall every other request.
        };

        self.copies
            .offer(value, session, name, &unlock, self.clipboard_timeout)?;

        // Only a successful handoff counts as activity.
        if let Ok(mut open) = self.databases.open(name) {
            open.touch();
        }
        Ok(CopyOutcome {
            db: db(),
            entry,
            field: request.field.clone(),
            expires_in: self.clipboard_timeout.as_secs(),
        })
    }
}

/// What `field` names on `entry`; `None` where there is nothing to copy:
/// absent, empty, or a bare `title`, which is never copyable.
fn field_value(entry: &Entry<'_>, field: &Field) -> Option<Zeroizing<String>> {
    match field {
        Field::Username => entry.field(fields::USERNAME),
        Field::Password => entry.field(fields::PASSWORD),
        Field::Url => entry.field(fields::URL),
        Field::Notes => entry.field(fields::NOTES),
        // Generated now from the `otp` field's seed, which is never returned.
        Field::Totp => entry.totp(),
        Field::Custom(key) => entry.field(key),
        Field::ReservedTitle => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::databases::testing::TestEntry;
    use crate::frontends::control::proto::LockRequest;
    use crate::frontends::control::testing::{
        Fixture, SESSION, desktop, fixture, fixture_with, outside,
    };
    use uuid::Uuid;

    /// Unlocks `name` with one entry holding a password, and returns the
    /// entry's uuid.
    fn unlock_with_entry(fx: &Fixture, name: &str) -> Uuid {
        fx.databases.install_for_test(
            name,
            vec![
                TestEntry::new("site")
                    .field("Password", "entrypass1")
                    .field("UserName", ""),
            ],
        );
        fx.databases.open(name).ok().unwrap().entries()[0].uuid
    }

    fn copy(fx: &Fixture, db: &str, uuid: Uuid, field: Field) -> Result<CopyOutcome, CopyError> {
        fx.api.copy(
            &CopyRequest {
                db: db.to_string(),
                uuid,
                field,
            },
            &desktop(),
        )
    }

    fn live(fx: &Fixture, index: usize) -> bool {
        fx.offers.lock().unwrap()[index].is_live()
    }

    #[test]
    fn copy_of_an_unknown_db_a_locked_db_and_an_unknown_uuid() {
        let fx = fixture();
        assert_eq!(
            copy(&fx, "nope", Uuid::nil(), Field::Password),
            Err(CopyError::UnknownDb {
                db: "nope".to_string()
            })
        );
        assert_eq!(
            copy(&fx, "personal", Uuid::nil(), Field::Password),
            Err(CopyError::Locked {
                db: "personal".to_string()
            })
        );
        unlock_with_entry(&fx, "personal");
        assert_eq!(
            copy(&fx, "personal", Uuid::new_v4(), Field::Password),
            Err(CopyError::UnknownUuid {
                db: "personal".to_string()
            })
        );
    }

    #[test]
    fn copy_of_an_absent_empty_or_title_field_is_field_empty() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        for field in [
            Field::Url,
            Field::Username,
            Field::Totp,
            Field::Custom("nothing".to_string()),
            Field::ReservedTitle,
        ] {
            assert_eq!(
                copy(&fx, "personal", uuid, field),
                Err(CopyError::FieldEmpty {
                    db: "personal".to_string()
                })
            );
        }
        assert!(fx.offered.lock().unwrap().is_empty());
    }

    #[test]
    fn copy_is_refused_without_a_desktop_requester_on_an_active_unlocked_display_session() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        let request = CopyRequest {
            db: "personal".to_string(),
            uuid,
            field: Field::Password,
        };

        assert_eq!(fx.api.copy(&request, &outside()), Err(CopyError::NoDisplay));
        for session in [
            DisplaySession::None,
            DisplaySession::Locked {
                id: SESSION.to_string(),
                active: true,
            },
            DisplaySession::Unlocked {
                id: SESSION.to_string(),
                active: false,
            },
        ] {
            fx.display.set(session);
            assert_eq!(fx.api.copy(&request, &desktop()), Err(CopyError::NoDisplay));
        }
        assert!(fx.offered.lock().unwrap().is_empty());
    }

    #[test]
    fn a_successful_copy_reaches_the_clipboard() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");

        let outcome = copy(&fx, "personal", uuid, Field::Password).expect("copied");

        assert_eq!(*fx.offered.lock().unwrap(), ["entrypass1"]);
        assert_eq!(outcome.entry, "site");
        assert_eq!(outcome.db, "personal");
    }

    #[test]
    fn locking_the_database_a_copy_came_from_ends_the_offer_and_another_does_not() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        unlock_with_entry(&fx, "work");
        copy(&fx, "personal", uuid, Field::Password).expect("copied");
        assert!(live(&fx, 0), "sanity: nothing has ended it yet");

        fx.databases.lock("work").unwrap();
        assert!(live(&fx, 0), "a lock of another database leaves it");

        fx.databases.lock("personal").unwrap();
        assert!(!live(&fx, 0));
    }

    #[test]
    fn every_kind_of_lock_ends_the_offer() {
        for kind in ["lock_all", "idle", "stale", "request"] {
            let fx = fixture();
            let uuid = unlock_with_entry(&fx, "personal");
            copy(&fx, "personal", uuid, Field::Password).expect("copied");
            match kind {
                "lock_all" => fx.databases.lock_all(),
                "idle" => fx
                    .databases
                    .expire_idle(Instant::now() + Duration::from_secs(7200)),
                "stale" => {
                    fx.databases.change_file_for_test("personal");
                    fx.databases.drop_stale(["personal"]);
                }
                _ => {
                    let lock = LockRequest {
                        db: Some("personal".to_string()),
                    };
                    fx.api.lock(&lock).expect("configured");
                }
            }
            assert!(!live(&fx, 0), "{kind} left the offer live");
        }
    }

    /// The freshness guard ends the offer wherever it is noticed.
    #[test]
    fn a_stale_database_is_noticed_and_its_offer_ended_by_each_entry_point() {
        for entry_point in ["status", "list", "list all", "unlock", "copy", "ssh keys"] {
            let fx = fixture();
            let uuid = unlock_with_entry(&fx, "personal");
            copy(&fx, "personal", uuid, Field::Password).expect("copied");
            fx.databases.change_file_for_test("personal");
            match entry_point {
                "status" => drop(fx.api.status()),
                "list" => drop(fx.api.list(&crate::frontends::control::proto::ListRequest {
                    db: Some("personal".to_string()),
                })),
                "list all" => drop(
                    fx.api
                        .list(&crate::frontends::control::proto::ListRequest { db: None }),
                ),
                "unlock" => drop(fx.api.unlock(
                    &crate::frontends::control::proto::UnlockRequest {
                        db: "personal".to_string(),
                    },
                    &outside(),
                )),
                "copy" => drop(copy(&fx, "personal", uuid, Field::Password)),
                _ => drop(
                    fx.api
                        .ssh_keys(&crate::frontends::control::proto::SshKeysRequest { db: None }),
                ),
            }
            assert!(!live(&fx, 0), "{entry_point} left the offer live");
        }
    }

    /// A lock that lands between reading the secret and recording the offer
    /// ends the offer: the copy is `Locked` and its own offer is gone.
    #[test]
    fn a_copy_overtaken_by_a_lock_ends_its_own_offer() {
        let fx = fixture();
        unlock_with_entry(&fx, "personal");
        let token = fx.databases.open("personal").ok().unwrap().unlock_token();
        fx.databases.lock("personal").unwrap();

        let result = fx.api.copies.offer(
            Zeroizing::new("secret".to_string()),
            &DisplaySession::Unlocked {
                id: SESSION.to_string(),
                active: true,
            },
            "personal",
            &token,
            Duration::from_secs(60),
        );

        assert_eq!(
            result,
            Err(CopyError::Locked {
                db: "personal".to_string()
            })
        );
        assert!(!live(&fx, 0), "the copy left its offer live");
    }

    /// A late notice for an old unlock leaves a newer offer alone.
    #[test]
    fn a_late_lock_notice_for_an_old_unlock_leaves_a_newer_offer() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        let old = fx.databases.open("personal").ok().unwrap().unlock_token();
        fx.databases.lock("personal").unwrap();
        let uuid = {
            let _ = uuid;
            unlock_with_entry(&fx, "personal")
        };
        copy(&fx, "personal", uuid, Field::Password).expect("copied");

        fx.api.copies.locked(&fx.databases, "personal", &old);

        assert!(live(&fx, 0));
    }

    #[test]
    fn a_successful_copy_counts_as_activity_and_a_refused_one_does_not() {
        let fx = fixture_with(&["personal"], "idle_timeout = \"1h\"");
        let uuid = unlock_with_entry(&fx, "personal");
        let timeout = Duration::from_secs(3600);

        std::thread::sleep(Duration::from_millis(20));
        let before = Instant::now();
        assert!(copy(&fx, "personal", Uuid::new_v4(), Field::Password).is_err());
        // The refusal did not reset the timer, so the install's activity,
        // which is older than `before`, is what is measured.
        fx.databases.expire_idle(before + timeout);
        assert!(!fx.databases.any_unlocked());

        let uuid2 = unlock_with_entry(&fx, "personal");
        let _ = uuid;
        std::thread::sleep(Duration::from_millis(20));
        let before = Instant::now();
        copy(&fx, "personal", uuid2, Field::Password).expect("copied");
        fx.databases
            .expire_idle(before + timeout - Duration::from_millis(10));
        assert!(fx.databases.any_unlocked(), "the copy reset the timer");
    }
}
