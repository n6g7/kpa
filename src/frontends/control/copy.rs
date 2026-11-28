//! `copy`: put one field of one entry on the clipboard, and end that offer
//! when the unlock it came from is locked.

use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::proto::{CopyError, CopyOutcome, CopyRequest};
use super::{Api, authz, offer};
use crate::authn::Requester;
use crate::cancel::CancelToken;
use crate::clipboard::{Backend, Offer};
use crate::databases::{Databases, Observer, OpenError};
use crate::display_session::DisplaySession;
use crate::log;

/// The clipboard, and every offer a `copy` has made that may still be live,
/// each with the database and unlock it came from. An observer that ends the
/// offers of an unlock when it is locked.
pub struct CopyState {
    clipboard: Box<dyn Backend>,
    held: Arc<Mutex<Vec<Held>>>,
}

struct Held {
    db: String,
    unlock: CancelToken,
    offer: Arc<Offer>,
}

fn held(held: &Mutex<Vec<Held>>) -> MutexGuard<'_, Vec<Held>> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

impl CopyState {
    pub fn new(clipboard: Box<dyn Backend>) -> CopyState {
        CopyState {
            clipboard,
            held: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Hands `value` to the clipboard as the content of `session` for
    /// `timeout`, remembering which unlock of `db` it came from. A copy of
    /// an unlock that is already locked offers nothing, and one a lock
    /// overtakes while the clipboard takes the offer ends it: either way the
    /// copy is `Locked`.
    fn offer(
        &self,
        value: Zeroizing<String>,
        session: &DisplaySession,
        db: &str,
        unlock: &CancelToken,
        timeout: Duration,
    ) -> Result<(), CopyError> {
        let locked = || CopyError::Locked { db: db.to_string() };
        if unlock.is_cancelled() {
            return Err(locked());
        }
        let offer = self
            .clipboard
            .start(value, session, unlock)
            .map_err(|err| CopyError::Clipboard {
                db: db.to_string(),
                detail: err.to_string(),
            })?;
        if !self.record(db, unlock, &offer) {
            offer.end();
            return Err(locked());
        }

        let records = Arc::clone(&self.held);
        let _ = thread::Builder::new().spawn(move || {
            thread::sleep(timeout);
            offer.end();
            held(&records).retain(|held| !Arc::ptr_eq(&held.offer, &offer));
        });
        Ok(())
    }

    /// Remembers `offer` as one of `unlock`'s, unless `unlock` has been
    /// locked: then it is not remembered, and `false`. A lock cancels its
    /// token before any observer is told, and `locked` takes the records, so
    /// either that notice finds this record or this finds the token
    /// cancelled.
    fn record(&self, db: &str, unlock: &CancelToken, offer: &Arc<Offer>) -> bool {
        let mut records = held(&self.held);
        if unlock.is_cancelled() {
            return false;
        }
        records.push(Held {
            db: db.to_string(),
            unlock: unlock.clone(),
            offer: Arc::clone(offer),
        });
        true
    }
}

impl Observer for CopyState {
    /// Ends every offer that came from the unlock this lock ended, and
    /// leaves any other: a lock of another database, or a late notice for
    /// an old unlock.
    fn locked(&self, _: &Databases, db: &str, unlock: &CancelToken) {
        held(&self.held).retain(|held| {
            let ended = held.db == db && held.unlock == *unlock;
            if ended {
                held.offer.end();
            }
            !ended
        });
    }
}

impl Api {
    /// Whether a `copy` from `requester` passes the gate that decides where
    /// it may land, asked of the display session as it is now. It is
    /// `status`'s `can_copy`, so it says nothing of the database or the
    /// field a `copy` would name.
    pub(super) fn can_copy(&self, requester: &Requester) -> bool {
        authz::authorize_copy(requester, &self.display.get()).is_ok()
    }

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
            // What the entry offers is worked out here, from the entry as it
            // is now, the same way `list` does; the name must be one of them.
            let value = offer::find(&read.stored_fields(), &request.field)
                .and_then(|copyable| copyable.value(&read))
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
        // A record of which secret left is the point of logging a copy:
        // the field, the entry's title (never a protected one) and the
        // database, never the value.
        log::info(format_args!(
            "copied {:?} of {entry:?} from {name:?}",
            request.field
        ));
        Ok(CopyOutcome {
            copied: request.field.clone(),
            expires_in: self.clipboard_timeout.as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::clipboard::{Backend, ClipboardError, OfferHandles};
    use crate::clock::Moment;
    use crate::config::Config;
    use crate::databases::testing::TestEntry;
    use crate::frontends::control::proto::LockRequest;
    use crate::frontends::control::testing::{
        Fixture, SESSION, desktop, fixture, fixture_with, outside,
    };
    use crate::frontends::control::wire_entries;
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

    fn copy(fx: &Fixture, db: &str, uuid: Uuid, field: &str) -> Result<CopyOutcome, CopyError> {
        fx.api.copy(
            &CopyRequest {
                db: db.to_string(),
                uuid,
                field: field.to_string(),
            },
            &desktop(),
        )
    }

    const SEED: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6";

    /// An entry with a title, a TOTP seed and a stored field under each of
    /// `keys`, whose value is `value-of-<key>`.
    fn entry_with(keys: &[&str]) -> TestEntry {
        let mut entry = TestEntry::new("value-of-Title").field("otp", SEED);
        for key in keys {
            entry = entry.field(key, &format!("value-of-{key}"));
        }
        entry
    }

    /// Every name `list` shows for an entry copies, in `copy`, the field it
    /// was listed for, whatever the entry's keys are spelled like: a stored
    /// field by its exact key, the code for `totp`. The title and the seed
    /// are never among them.
    #[test]
    fn every_listed_name_copies_the_field_it_was_listed_for() {
        let keys = [
            "UserName",
            "Password",
            "PASSWORD",
            "password",
            "totp",
            "TOTP",
            "title",
            "custom:x",
            "custom:Password",
            "OTP",
            "",
            "é",
            "api-key",
        ];
        let fx = fixture();
        fx.databases
            .install_for_test("personal", vec![entry_with(&keys)]);
        let open = fx.databases.open("personal").ok().unwrap();
        let uuid = open.entries()[0].uuid;
        let listed = wire_entries("personal", &open.entries())[0].fields.clone();
        drop(open);

        // `totp` the stored field is not offered; `totp` the code is.
        let mut expected: Vec<&str> = keys.to_vec();
        expected.sort();
        for name in &listed {
            copy(&fx, "personal", uuid, name).expect("a listed name copies");
            let offered = fx.offered.lock().unwrap().last().unwrap().clone();
            if name == "totp" {
                assert_eq!(offered.len(), 6, "the code, not the stored field");
                assert!(offered.chars().all(|c| c.is_ascii_digit()));
            } else {
                assert_eq!(offered, format!("value-of-{name}"), "{name:?}");
            }
        }
        let mut names: Vec<&str> = listed.iter().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, expected, "every key is offered under its own name");
        let offered = fx.offered.lock().unwrap().clone();
        for secret in [SEED, "value-of-Title", "value-of-totp"] {
            assert!(!offered.iter().any(|value| value == secret), "{secret}");
        }
    }

    fn live(fx: &Fixture, index: usize) -> bool {
        fx.offers.lock().unwrap()[index].is_live()
    }

    #[test]
    fn copy_of_an_unknown_db_a_locked_db_and_an_unknown_uuid() {
        let fx = fixture();
        assert_eq!(
            copy(&fx, "nope", Uuid::nil(), "Password"),
            Err(CopyError::UnknownDb {
                db: "nope".to_string()
            })
        );
        assert_eq!(
            copy(&fx, "personal", Uuid::nil(), "Password"),
            Err(CopyError::Locked {
                db: "personal".to_string()
            })
        );
        unlock_with_entry(&fx, "personal");
        assert_eq!(
            copy(&fx, "personal", Uuid::new_v4(), "Password"),
            Err(CopyError::UnknownUuid {
                db: "personal".to_string()
            })
        );
    }

    #[test]
    fn copy_of_an_absent_empty_or_unlisted_field_is_field_empty() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        for field in [
            "URL", "UserName", "totp", "nothing", "password", "PASSWORD", "",
        ] {
            assert_eq!(
                copy(&fx, "personal", uuid, field),
                Err(CopyError::FieldEmpty {
                    db: "personal".to_string()
                }),
                "{field:?}"
            );
        }
        assert!(fx.offered.lock().unwrap().is_empty());
    }

    /// `Title` is never offered, not even when named exactly, and not as
    /// another spelling of a field either.
    #[test]
    fn the_title_is_never_copied() {
        let fx = fixture();
        fx.databases.install_for_test(
            "personal",
            vec![TestEntry::new("the-title").field("title", "a field of its own")],
        );
        let open = fx.databases.open("personal").ok().unwrap();
        let uuid = open.entries()[0].uuid;
        assert_eq!(
            wire_entries("personal", &open.entries())[0].fields,
            ["title"]
        );
        drop(open);

        for field in ["Title", "custom:Title"] {
            assert_eq!(
                copy(&fx, "personal", uuid, field),
                Err(CopyError::FieldEmpty {
                    db: "personal".to_string()
                }),
                "{field:?}"
            );
        }
        copy(&fx, "personal", uuid, "title").expect("a field keyed `title` is its own");
        assert_eq!(*fx.offered.lock().unwrap(), ["a field of its own"]);
    }

    /// The entry's `otp` field holds the TOTP seed: `totp` offers the code
    /// made from it, and no name reaches the seed itself. A field keyed
    /// `OTP` is a different field and copies.
    #[test]
    fn the_otp_field_is_never_copied_only_its_code() {
        let fx = fixture();
        fx.databases
            .install_for_test("personal", vec![entry_with(&["OTP"])]);
        let uuid = fx.databases.open("personal").ok().unwrap().entries()[0].uuid;

        for field in ["otp", "custom:otp"] {
            assert_eq!(
                copy(&fx, "personal", uuid, field),
                Err(CopyError::FieldEmpty {
                    db: "personal".to_string()
                })
            );
        }
        assert!(fx.offered.lock().unwrap().is_empty());

        copy(&fx, "personal", uuid, "totp").expect("the code is offered");
        copy(&fx, "personal", uuid, "OTP").expect("copied");
        let offered = fx.offered.lock().unwrap().clone();
        assert_eq!(offered.len(), 2);
        assert_eq!(offered[0].len(), 6);
        assert!(offered[0].chars().all(|c| c.is_ascii_digit()));
        assert_eq!(offered[1], "value-of-OTP");
    }

    /// `totp` is the code's name: a field stored under exactly that key is
    /// not offered, and `copy … totp` gives the code, or nothing when the
    /// entry has no seed. `TOTP` and `Totp` are fields of their own.
    #[test]
    fn a_stored_totp_field_is_not_the_code() {
        let fx = fixture();
        fx.databases.install_for_test(
            "personal",
            vec![
                TestEntry::new("with seed")
                    .field("otp", SEED)
                    .field("totp", "stored")
                    .field("TOTP", "upper")
                    .field("Totp", "mixed"),
                TestEntry::new("no seed").field("totp", "stored"),
            ],
        );
        let open = fx.databases.open("personal").ok().unwrap();
        let entries = open.entries();
        let uuid = |title: &str| {
            entries
                .iter()
                .find(|e| e.title.as_deref() == Some(title))
                .expect("entry")
                .uuid
        };
        let (with_seed, no_seed) = (uuid("with seed"), uuid("no seed"));
        let listed = wire_entries("personal", &entries);
        drop(open);
        for entry in &listed {
            let expected: &[&str] = if entry.uuid == with_seed {
                &["totp", "TOTP", "Totp"]
            } else {
                &[]
            };
            assert_eq!(entry.fields, expected);
        }

        copy(&fx, "personal", with_seed, "totp").expect("the code");
        copy(&fx, "personal", with_seed, "TOTP").expect("upper");
        copy(&fx, "personal", with_seed, "Totp").expect("mixed");
        let offered = fx.offered.lock().unwrap().clone();
        assert_eq!(offered[0].len(), 6);
        assert!(offered[0].chars().all(|c| c.is_ascii_digit()));
        assert_eq!(offered[1..], ["upper", "mixed"]);

        assert_eq!(
            copy(&fx, "personal", no_seed, "totp"),
            Err(CopyError::FieldEmpty {
                db: "personal".to_string()
            })
        );
        assert_eq!(fx.offered.lock().unwrap().len(), 3);
    }

    #[test]
    fn copy_is_refused_without_a_desktop_requester_on_an_active_unlocked_display_session() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        let request = CopyRequest {
            db: "personal".to_string(),
            uuid,
            field: "Password".to_string(),
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

    /// `status`'s `can_copy` is the gate's answer for the requester that
    /// asked: yes only on the desktop of an active, unlocked display session,
    /// and it agrees with what a `copy` from the same requester then does.
    #[test]
    fn can_copy_is_yes_only_where_a_copy_would_pass_the_gate() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        let request = CopyRequest {
            db: "personal".to_string(),
            uuid,
            field: "Password".to_string(),
        };
        let session = |locked: bool, active: bool| {
            let id = SESSION.to_string();
            if locked {
                DisplaySession::Locked { id, active }
            } else {
                DisplaySession::Unlocked { id, active }
            }
        };

        for (display_session, requester, can_copy) in [
            (session(false, true), desktop(), true),
            (session(false, true), outside(), false),
            (session(true, true), desktop(), false),
            (session(false, false), desktop(), false),
            (DisplaySession::None, desktop(), false),
        ] {
            fx.display.set(display_session.clone());
            assert_eq!(
                fx.api.can_copy(&requester),
                can_copy,
                "{requester:?} on {display_session:?}"
            );
            assert_eq!(
                fx.api.copy(&request, &requester).is_ok(),
                can_copy,
                "{requester:?} on {display_session:?}"
            );
        }
    }

    #[test]
    fn a_successful_copy_reaches_the_clipboard() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");

        let outcome = copy(&fx, "personal", uuid, "Password").expect("copied");

        assert_eq!(*fx.offered.lock().unwrap(), ["entrypass1"]);
        assert_eq!(outcome.copied, "Password");
    }

    /// The log says which field of which entry left which database, and
    /// never the value.
    #[test]
    fn a_successful_copy_is_logged_without_the_secret() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");

        let log = capture_stderr(|| {
            copy(&fx, "personal", uuid, "Password").expect("copied");
        });

        assert!(
            log.contains(" INFO  copied \"Password\" of \"site\" from \"personal\"\n"),
            "{log}"
        );
        assert!(!log.contains("entrypass1"), "{log}");
    }

    /// Runs `body` with fd 2 pointed at a temp file, puts the original back
    /// (also when `body` panics, so the failure still reaches the test
    /// harness's output), and returns what was written. `crate::log` writes
    /// to fd 2 directly, so the harness's output capture doesn't see it.
    fn capture_stderr(body: impl FnOnce()) -> String {
        use std::io::{Read, Seek};
        use std::os::fd::{AsFd, OwnedFd};

        /// Points fd 2 back at the descriptor it holds when dropped.
        struct Restore(OwnedFd);

        impl Drop for Restore {
            fn drop(&mut self) {
                rustix::stdio::dup2_stderr(&self.0).expect("restore stderr");
            }
        }

        let mut file = tempfile::tempfile().expect("tempfile");
        {
            let _restore = Restore(rustix::io::dup(std::io::stderr().as_fd()).expect("dup stderr"));
            rustix::stdio::dup2_stderr(&file).expect("point stderr at the file");
            body();
        }
        let mut log = String::new();
        file.rewind().expect("rewind");
        file.read_to_string(&mut log).expect("read log");
        log
    }

    #[test]
    fn locking_the_database_a_copy_came_from_ends_the_offer_and_another_does_not() {
        let fx = fixture();
        let uuid = unlock_with_entry(&fx, "personal");
        unlock_with_entry(&fx, "work");
        copy(&fx, "personal", uuid, "Password").expect("copied");
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
            copy(&fx, "personal", uuid, "Password").expect("copied");
            match kind {
                "lock_all" => fx.databases.lock_all(),
                "idle" => fx
                    .databases
                    .expire_idle(Moment::now() + Duration::from_secs(7200)),
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
            copy(&fx, "personal", uuid, "Password").expect("copied");
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
                "copy" => drop(copy(&fx, "personal", uuid, "Password")),
                _ => drop(
                    fx.api
                        .ssh_keys(&crate::frontends::control::proto::SshKeysRequest { db: None }),
                ),
            }
            assert!(!live(&fx, 0), "{entry_point} left the offer live");
        }
    }

    /// A copy of an unlock that is already locked offers nothing to the
    /// clipboard.
    #[test]
    fn a_copy_of_an_unlock_that_is_already_locked_offers_nothing() {
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
        assert!(
            fx.offered.lock().unwrap().is_empty(),
            "the secret reached the clipboard"
        );
    }

    /// What the tests below run a `CopyState` against: a backend that, like
    /// a compositor, ends the previous offer when a new one starts, and that
    /// runs `after_taken` once, on the first offer, after the compositor has
    /// taken it and before the offer comes back.
    struct Compositor {
        last: Mutex<Option<Arc<Offer>>>,
        offers: OfferHandles,
        after_taken: Arc<Mutex<Option<Hook>>>,
    }

    type Hook = Box<dyn FnOnce() + Send>;

    impl Backend for Compositor {
        fn start(
            &self,
            _secret: Zeroizing<String>,
            _display_session: &DisplaySession,
            _unlock: &CancelToken,
        ) -> Result<Arc<Offer>, ClipboardError> {
            let offer = Arc::new(Offer::detached());
            let previous = self.last.lock().unwrap().replace(Arc::clone(&offer));
            if let Some(previous) = previous {
                previous.end();
            }
            self.offers.lock().unwrap().push(Arc::clone(&offer));
            let hook = self.after_taken.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            Ok(offer)
        }
    }

    /// Databases `a` and `b`, unlocked, with a `CopyState` on a
    /// [`Compositor`] observing them.
    struct Rig {
        databases: Arc<Databases>,
        copies: Arc<CopyState>,
        /// Every offer the compositor took, oldest first.
        offers: OfferHandles,
        after_taken: Arc<Mutex<Option<Hook>>>,
    }

    fn rig() -> Rig {
        let offers = OfferHandles::default();
        let after_taken = Arc::new(Mutex::new(None));
        let copies = Arc::new(CopyState::new(Box::new(Compositor {
            last: Mutex::new(None),
            offers: Arc::clone(&offers),
            after_taken: Arc::clone(&after_taken),
        })));
        let configs = Config::parse(
            "[[database]]\nname = \"a\"\npath = \"a.kdbx\"\n\
             [[database]]\nname = \"b\"\npath = \"b.kdbx\"\n",
        )
        .expect("valid config")
        .databases;
        let mut core = Databases::for_test(configs, Duration::from_secs(3600));
        core.observe(copies.clone());
        let databases = Arc::new(core);
        for name in ["a", "b"] {
            databases.install_for_test(name, vec![TestEntry::new("site")]);
        }
        Rig {
            databases,
            copies,
            offers,
            after_taken,
        }
    }

    impl Rig {
        fn token(&self, db: &str) -> CancelToken {
            self.databases.open(db).ok().unwrap().unlock_token()
        }

        fn offer(&self, secret: &str, db: &str, unlock: &CancelToken) -> Result<(), CopyError> {
            self.copies.offer(
                Zeroizing::new(secret.to_string()),
                &DisplaySession::Unlocked {
                    id: SESSION.to_string(),
                    active: true,
                },
                db,
                unlock,
                Duration::from_secs(3600),
            )
        }

        fn after_taken(&self, hook: impl FnOnce() + Send + 'static) {
            *self.after_taken.lock().unwrap() = Some(Box::new(hook));
        }

        fn live_offers(&self) -> Vec<bool> {
            let offers = self.offers.lock().unwrap();
            offers.iter().map(|offer| offer.is_live()).collect()
        }
    }

    /// A lock that lands while the compositor takes the offer ends it: the
    /// copy is `Locked` and its own offer is gone.
    #[test]
    fn a_copy_overtaken_by_a_lock_ends_its_own_offer() {
        let rig = rig();
        let token = rig.token("a");
        let databases = Arc::clone(&rig.databases);
        rig.after_taken(move || databases.lock("a").unwrap());

        let result = rig.offer("secret", "a", &token);

        assert_eq!(
            result,
            Err(CopyError::Locked {
                db: "a".to_string()
            })
        );
        assert_eq!(rig.live_offers(), [false]);
    }

    /// Two copies overlap: the first is held up after the compositor took
    /// its offer, the second completes, and then the first returns. The
    /// second's offer is the live one, and the lock of its database ends it,
    /// whatever order the copies finished in.
    #[test]
    fn overlapping_copies_leave_no_offer_that_a_lock_cannot_end() {
        let rig = rig();
        let (first_token, second_token) = (rig.token("a"), rig.token("b"));
        let (entered, first_is_held_up) = mpsc::channel();
        let (release, held_up) = mpsc::channel::<()>();
        rig.after_taken(move || {
            entered.send(()).expect("the test is waiting");
            held_up.recv().expect("the test releases the copy");
        });

        thread::scope(|scope| {
            let first = scope.spawn(|| rig.offer("slow", "a", &first_token));
            first_is_held_up
                .recv_timeout(Duration::from_secs(10))
                .expect("the first copy is inside the clipboard");
            rig.offer("fast", "b", &second_token).expect("copied");
            release.send(()).expect("the first copy waits");
            first.join().expect("first copy").expect("copied");
        });
        assert_eq!(
            rig.live_offers(),
            [false, true],
            "sanity: the second is live"
        );

        rig.databases.lock("b").unwrap();
        rig.databases.lock("a").unwrap();

        assert_eq!(rig.live_offers(), [false, false]);
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
        copy(&fx, "personal", uuid, "Password").expect("copied");

        fx.api.copies.locked(&fx.databases, "personal", &old);

        assert!(live(&fx, 0));
    }

    #[test]
    fn a_successful_copy_counts_as_activity_and_a_refused_one_does_not() {
        let fx = fixture_with(&["personal"], "idle_timeout = \"1h\"");
        let uuid = unlock_with_entry(&fx, "personal");
        let timeout = Duration::from_secs(3600);

        std::thread::sleep(Duration::from_millis(20));
        let before = Moment::now();
        assert!(copy(&fx, "personal", Uuid::new_v4(), "Password").is_err());
        // The refusal did not reset the timer, so the install's activity,
        // which is older than `before`, is what is measured.
        fx.databases.expire_idle(before + timeout);
        assert!(!fx.databases.any_unlocked());

        let uuid2 = unlock_with_entry(&fx, "personal");
        let _ = uuid;
        std::thread::sleep(Duration::from_millis(20));
        let before = Moment::now();
        copy(&fx, "personal", uuid2, "Password").expect("copied");
        fx.databases
            .expire_idle(before + timeout - Duration::from_millis(10));
        assert!(fx.databases.any_unlocked(), "the copy reset the timer");
    }
}
