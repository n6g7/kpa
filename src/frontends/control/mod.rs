//! kpa's own socket: the front end `kpa status`, `unlock`, `lock`, `list`,
//! `copy` and `ssh keys` talk to. [`serve`](fn@serve) is the transport, [`Api`] answers
//! each request against the databases, and [`CopyState`] ends a clipboard
//! offer when the unlock it came from is locked.

pub mod client;
pub mod proto;

mod authz;
mod copy;
mod deadline;
mod serve;
#[cfg(test)]
mod testing;
mod unlock;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use self::proto::{
    DatabaseStatus, ListError, ListRequest, ListResponse, LockError, LockRequest, Op, Request,
    Response, SshApproveError, SshApproveRequest, SshKeysError, SshKeysReport, SshKeysRequest,
    StatusResponse, WireEntry, WireGrant, WireHost, WirePending, WireRequestDetails, WireScope,
    WireSkippedKey, WireSshKey,
};
use crate::authn::Requester;
use crate::clock::Moment;
use crate::config::Config;
use crate::databases::{Databases, EntrySummary, Open, OpenError, UnknownDb};
use crate::display_session::DisplayHandle;
use crate::log;
use crate::prompt::{self, PromptQueue};
use crate::ssh::approvals::{Approvals, GrantSource, Host, Lasts, Scope};
use crate::ssh::keys;

pub use copy::CopyState;
pub use serve::serve;

/// What the control socket's handlers share.
pub struct Api {
    databases: Arc<Databases>,
    display: DisplayHandle,
    approvals: Arc<Approvals>,
    copies: Arc<CopyState>,
    /// The daemon's one prompt queue, so only one prompt is on screen.
    prompts: Arc<PromptQueue>,
    /// How the unlock prompt asks on screen.
    screen_unlock: Arc<dyn prompt::Backend<Zeroizing<String>>>,
    prompt_timeout: Duration,
    clipboard_timeout: Duration,
    retry_window: Duration,
}

impl Api {
    pub fn new(
        databases: Arc<Databases>,
        display: DisplayHandle,
        approvals: Arc<Approvals>,
        copies: Arc<CopyState>,
        prompts: Arc<PromptQueue>,
        screen_unlock: Arc<dyn prompt::Backend<Zeroizing<String>>>,
        config: &Config,
    ) -> Api {
        Api {
            databases,
            display,
            approvals,
            copies,
            prompts,
            screen_unlock,
            prompt_timeout: config.prompt_timeout,
            clipboard_timeout: config.clipboard_timeout,
            retry_window: config.ssh_agent.retry_window,
        }
    }

    /// The response to `request` from `requester`: the only place an op's
    /// outcome becomes a `Response` variant. The request's own say about
    /// where to be asked joins the facts about its requester.
    fn handle(&self, request: &Request, requester: &Requester) -> Response {
        let requester = &Requester {
            preferred: request.preferred_prompt,
            ..requester.clone()
        };
        match &request.op {
            Op::Status => Response::Status(StatusResponse {
                databases: self.status(),
                version: crate::VERSION.to_string(),
                can_copy: self.can_copy(requester),
            }),
            Op::Unlock(unlock) => Response::Unlock(self.unlock(unlock, requester)),
            Op::Lock(lock) => Response::Lock(self.lock(lock)),
            Op::List(list) => {
                Response::List(self.list(list).map(|entries| ListResponse { entries }))
            }
            Op::Copy(copy) => Response::Copy(self.copy(copy, requester)),
            Op::SshKeys(keys) => Response::SshKeys(self.ssh_keys(keys)),
            Op::SshPending => Response::SshPending(self.ssh_pending()),
            Op::SshApprove(approve) => Response::SshApprove(self.ssh_approve(approve)),
            Op::SshGrants => Response::SshGrants(self.ssh_grants()),
        }
    }

    fn names(&self) -> Vec<&str> {
        self.databases
            .configs()
            .iter()
            .map(|config| config.name.as_str())
            .collect()
    }

    /// A stale database is locked first, so it is reported as locked.
    fn status(&self) -> Vec<DatabaseStatus> {
        self.databases.drop_stale(self.names());
        self.databases
            .snapshot()
            .into_iter()
            .map(|snapshot| DatabaseStatus {
                locked: snapshot.is_locked(),
                name: snapshot.name,
                entries: snapshot.entries,
            })
            .collect()
    }

    /// `Ok` echoes what was locked: `None` means every database.
    fn lock(&self, request: &LockRequest) -> Result<Option<String>, LockError> {
        match request.db.as_deref() {
            Some(name) => {
                self.databases
                    .lock(name)
                    .map_err(|UnknownDb| LockError::UnknownDb {
                        db: name.to_string(),
                    })?;
                Ok(Some(name.to_string()))
            }
            None => {
                self.databases.lock_all();
                Ok(None)
            }
        }
    }

    /// Reads each of `names` in order: `read` gets each one that is
    /// unlocked, `locked` each that is not. The first stale one fails the
    /// whole read, naming it, rather than being skipped as if it were
    /// locked; the stale ones after it are locked too.
    fn each_open(
        &self,
        names: &[&str],
        mut read: impl FnMut(&str, Open<'_>),
        mut locked: impl FnMut(&str),
    ) -> Result<(), String> {
        for (index, name) in names.iter().enumerate() {
            match self.databases.open(name) {
                Ok(open) => read(name, open),
                Err(OpenError::Stale) => {
                    self.databases
                        .drop_stale(names[index + 1..].iter().copied());
                    return Err(name.to_string());
                }
                Err(OpenError::Locked) => locked(name),
                Err(OpenError::UnknownDb) => {}
            }
        }
        Ok(())
    }

    /// Each database a successful list reads gets its own idle timer reset.
    fn list(&self, request: &ListRequest) -> Result<Vec<WireEntry>, ListError> {
        let mut entries = Vec::new();
        if let Some(name) = request.db.as_deref() {
            let db = || name.to_string();
            let mut open = self.databases.open(name).map_err(|err| match err {
                OpenError::UnknownDb => ListError::UnknownDb { db: db() },
                OpenError::Locked => ListError::Locked { db: db() },
                OpenError::Stale => ListError::Stale { db: db() },
            })?;
            open.touch();
            return Ok(wire_entries(name, &open.entries()));
        }
        self.each_open(
            &self.names(),
            |name, mut open| {
                open.touch();
                entries.extend(wire_entries(name, &open.entries()));
            },
            |_| {},
        )
        .map_err(|db| ListError::Stale { db })?;
        Ok(entries)
    }

    /// Scans the unlocked databases for SSH keys, as `list` reads them. A
    /// request for every database lists the locked ones in the report; one
    /// that names a database fails on it if it is locked.
    fn ssh_keys(&self, request: &SshKeysRequest) -> Result<SshKeysReport, SshKeysError> {
        let names = match &request.db {
            Some(name) => {
                if !self.names().contains(&name.as_str()) {
                    return Err(SshKeysError::UnknownDb { db: name.clone() });
                }
                vec![name.as_str()]
            }
            None => self.names(),
        };
        let mut report = SshKeysReport::default();
        let mut locked = Vec::new();
        self.each_open(
            &names,
            |name, mut open| {
                let config = self.databases.configs().iter().find(|c| c.name == name);
                let scan = keys::scan(&open);
                open.touch();
                report.keys.extend(scan.found.into_iter().map(|key| {
                    WireSshKey {
                        db: name.to_string(),
                        key_type: key.public_key.algorithm().to_string(),
                        fingerprint: key.fingerprint.to_string(),
                        name: keys::key_name(
                            name,
                            key.fingerprint,
                            config
                                .and_then(|config| config.ssh_key_settings(key.fingerprint).name)
                                .as_deref(),
                            key.entry_title.as_deref(),
                        ),
                        entry: key.entry_uuid,
                        title: key.entry_title,
                        attachment: key.attachment_name,
                    }
                }));
                report
                    .skipped
                    .extend(scan.skipped.into_iter().map(|skipped| WireSkippedKey {
                        db: name.to_string(),
                        title: skipped.entry_title,
                        attachment: skipped.attachment_name,
                        reason: skipped.reason.to_string(),
                    }));
            },
            |name| locked.push(name.to_string()),
        )
        .map_err(|db| SshKeysError::Stale { db })?;
        if let (Some(db), [_]) = (&request.db, locked.as_slice()) {
            return Err(SshKeysError::Locked { db: db.clone() });
        }
        report.locked = locked;
        Ok(report)
    }

    /// Every unlocked database's pending requests, in config order, oldest
    /// first.
    fn ssh_pending(&self) -> Vec<WirePending> {
        let now = SystemTime::now();
        let mut pending = Vec::new();
        for config in self.databases.configs().iter().filter(|c| c.serve_ssh_keys) {
            if let Ok(open) = self.databases.open(&config.name) {
                for request in self.approvals.pending(&open, now) {
                    let session = self
                        .approvals
                        .forwarding_session(&open, &request.approval.scope);
                    pending.push((request, session));
                }
            }
        }
        pending
            .into_iter()
            .map(|(pending, session)| WirePending {
                id: pending.id,
                refused_at: unix_seconds(pending.refused_at),
                scope: wire_scope(&pending.approval.scope, session),
                remember: pending.approval.remember,
                request: WireRequestDetails {
                    purpose: pending.request.purpose.to_string(),
                    user: pending.request.user,
                    namespace: pending.request.namespace,
                    class: pending.request.class.to_string(),
                    command: pending.request.command,
                },
            })
            .collect()
    }

    /// Every unlocked database's approvals, in config order, oldest first.
    fn ssh_grants(&self) -> Vec<WireGrant> {
        let now = Instant::now();
        let mut grants = Vec::new();
        for config in self.databases.configs().iter().filter(|c| c.serve_ssh_keys) {
            let Ok(open) = self.databases.open(&config.name) else {
                continue;
            };
            let idle_lock_in = open.idle_left(Moment::now()).as_secs();
            for grant in self.approvals.granted(&open, now) {
                let by = match grant.by {
                    GrantSource::OnScreen => "on_screen",
                    GrantSource::Cli => "cli",
                };
                let expires_in = grant.time_left(now).map(|left| left.as_secs());
                let session = self.approvals.forwarding_session(&open, &grant.scope);
                grants.push(WireGrant {
                    granted_at: unix_seconds(grant.granted_at),
                    scope: wire_scope(&grant.scope, session),
                    remember: grant.lasts == Lasts::UntilLock,
                    expires_in,
                    by: by.to_string(),
                    uses: grant.uses,
                    last_used_at: grant.last_used_at.map(unix_seconds),
                    idle_lock_in,
                });
            }
        }
        grants
    }

    /// Approves what the pending request `id` asked for, in whichever
    /// database holds it.
    fn ssh_approve(&self, request: &SshApproveRequest) -> Result<(), SshApproveError> {
        let (now, wall) = (Instant::now(), SystemTime::now());
        for config in self.databases.configs().iter().filter(|c| c.serve_ssh_keys) {
            let Ok(open) = self.databases.open(&config.name) else {
                continue;
            };
            if let Some(key) =
                self.approvals
                    .approve(&open, request.id, now, wall, self.retry_window)
            {
                log::info(format_args!(
                    "ssh approve: key {key} approved in {:?} by request id",
                    config.name
                ));
                return Ok(());
            }
        }
        Err(SshApproveError::NotPending)
    }
}

/// What an approval covers, as the wire shows it: the key it is for, and
/// where the signature goes.
fn wire_scope(scope: &Scope, forwarding_session: Option<u32>) -> WireScope {
    let key = scope.key().clone();
    WireScope {
        key: WireSshKey {
            db: key.database,
            key_type: key.public_key.algorithm().to_string(),
            fingerprint: key.fingerprint.to_string(),
            name: key.name,
            entry: key.entry_uuid,
            title: key.title,
            attachment: key.attachment.unwrap_or_default(),
        },
        destination: scope.destination().map(wire_host),
        forwarding_host: scope.forwarding_host().map(wire_host),
        forwarding_session,
    }
}

fn wire_host(host: &Host) -> WireHost {
    WireHost {
        fingerprint: host.fingerprint,
        name: host.name.clone(),
    }
}

/// `at` in Unix seconds, 0 for a time before the epoch.
fn unix_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// `EntrySummary` implements `Drop` (via `ZeroizeOnDrop`), which forbids
/// moving individual fields out of it, hence the clones. Both it and
/// `WireEntry` zeroize on drop, so neither copy outlives the response.
fn wire_entries(db_name: &str, entries: &[EntrySummary]) -> Vec<WireEntry> {
    entries
        .iter()
        .map(|entry| WireEntry {
            db: db_name.to_string(),
            uuid: entry.uuid,
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            group: entry.group.clone(),
            fields: entry.fields.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ssh_key::LineEnding;

    use super::*;
    use crate::databases::testing::TestEntry;
    use crate::frontends::control::testing::{Fixture, fixture, fixture_with};
    use crate::ssh::testing::{approval, requested, test_key};

    const HOUR: Duration = Duration::from_secs(3600);

    fn list(db: Option<&str>) -> ListRequest {
        ListRequest {
            db: db.map(str::to_string),
        }
    }

    /// Whether `name` is still unlocked after the idle timer would have run
    /// from `at`.
    fn survives_idle_at(fx: &Fixture, name: &str, at: Moment) -> bool {
        fx.databases.expire_idle(at);
        fx.databases
            .snapshot()
            .iter()
            .any(|snapshot| snapshot.name == name && !snapshot.is_locked())
    }

    #[test]
    fn status_reports_every_database_and_locks_a_stale_one_first() {
        let fx = fixture();
        fx.databases
            .install_for_test("personal", vec![TestEntry::new("one")]);
        let status = fx.api.status();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].entries, Some(1));
        assert!(status[1].locked);

        fx.databases.change_file_for_test("personal");
        assert!(fx.api.status()[0].locked);
    }

    #[test]
    fn lock_names_what_it_locked_and_refuses_an_unknown_database() {
        let fx = fixture();
        fx.databases.install_for_test("personal", vec![]);
        fx.databases.install_for_test("work", vec![]);

        let one = LockRequest {
            db: Some("work".to_string()),
        };
        assert_eq!(fx.api.lock(&one), Ok(Some("work".to_string())));
        assert!(fx.databases.any_unlocked());
        assert_eq!(fx.api.lock(&LockRequest { db: None }), Ok(None));
        assert!(!fx.databases.any_unlocked());
        let unknown = LockRequest {
            db: Some("nope".to_string()),
        };
        assert_eq!(
            fx.api.lock(&unknown),
            Err(LockError::UnknownDb {
                db: "nope".to_string()
            })
        );
    }

    #[test]
    fn list_reads_one_or_every_unlocked_database() {
        let fx = fixture();
        fx.databases
            .install_for_test("personal", vec![TestEntry::new("one")]);

        let named = fx.api.list(&list(Some("personal"))).expect("listed");
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].db, "personal");
        assert_eq!(
            fx.api.list(&list(Some("work"))),
            Err(ListError::Locked {
                db: "work".to_string()
            })
        );
        assert_eq!(
            fx.api.list(&list(Some("nope"))),
            Err(ListError::UnknownDb {
                db: "nope".to_string()
            })
        );
        // Every database skips the locked one.
        assert_eq!(fx.api.list(&list(None)).expect("listed").len(), 1);
    }

    #[test]
    fn list_of_every_database_names_the_first_stale_one_and_locks_the_rest() {
        let fx = fixture();
        fx.databases.install_for_test("personal", vec![]);
        fx.databases.install_for_test("work", vec![]);
        fx.databases.change_file_for_test("personal");
        fx.databases.change_file_for_test("work");

        assert_eq!(
            fx.api.list(&list(None)),
            Err(ListError::Stale {
                db: "personal".to_string()
            })
        );
        assert!(!fx.databases.any_unlocked(), "work was locked too");
        assert_eq!(
            fx.api.list(&list(Some("personal"))),
            Err(ListError::Locked {
                db: "personal".to_string()
            })
        );
    }

    #[test]
    fn a_successful_list_resets_the_idle_timer_of_what_it_read_only() {
        let fx = fixture_with(&["personal", "work"], "idle_timeout = \"1h\"");
        fx.databases.install_for_test("personal", vec![]);
        fx.databases.install_for_test("work", vec![]);
        std::thread::sleep(Duration::from_millis(20));
        let before = Moment::now();

        fx.api.list(&list(Some("personal"))).expect("listed");

        let at = before + HOUR - Duration::from_millis(10);
        assert!(survives_idle_at(&fx, "personal", at), "the list reset it");
        assert!(!survives_idle_at(&fx, "work", at), "the other kept running");
    }

    #[test]
    fn status_lock_and_refused_requests_do_not_reset_the_idle_timer() {
        let fx = fixture_with(&["personal", "work"], "idle_timeout = \"1h\"");
        fx.databases.install_for_test("personal", vec![]);
        std::thread::sleep(Duration::from_millis(20));
        let before = Moment::now();

        fx.api.status();
        let _ = fx.api.list(&list(Some("work")));
        let _ = fx.api.list(&list(Some("nope")));
        let _ = fx.api.lock(&LockRequest {
            db: Some("work".to_string()),
        });

        assert!(!survives_idle_at(&fx, "personal", before + HOUR));
    }

    fn key_entry(title: &str, seed: u64) -> TestEntry {
        let pem = test_key(seed).to_openssh(LineEnding::LF).expect("encodes");
        TestEntry::new(title).attachment("id_ed25519", pem.as_bytes().to_vec())
    }

    #[test]
    fn ssh_keys_scans_through_the_guard_and_lists_locked_databases() {
        let fx = fixture();
        fx.databases
            .install_for_test("personal", vec![key_entry("github", 1)]);

        let all = fx.api.ssh_keys(&SshKeysRequest { db: None }).expect("scan");
        assert_eq!(all.keys.len(), 1);
        assert_eq!(all.keys[0].title.as_deref(), Some("github"));
        assert_eq!(all.locked, ["work"]);

        assert_eq!(
            fx.api.ssh_keys(&SshKeysRequest {
                db: Some("work".to_string())
            }),
            Err(SshKeysError::Locked {
                db: "work".to_string()
            })
        );
        assert_eq!(
            fx.api.ssh_keys(&SshKeysRequest {
                db: Some("nope".to_string())
            }),
            Err(SshKeysError::UnknownDb {
                db: "nope".to_string()
            })
        );
    }

    #[test]
    fn a_pending_request_is_listed_approved_and_dropped_by_a_lock() {
        let fx = fixture_with(
            &[],
            "[[database]]\nname = \"personal\"\npath = \"p.kdbx\"\nserve_ssh_keys = true\n",
        );
        fx.databases.install_for_test("personal", vec![]);
        {
            let open = fx.databases.open("personal").ok().unwrap();
            fx.api.approvals.record(
                &open,
                approval(1, None, true),
                requested("ssh"),
                SystemTime::now(),
            );
        }

        let pending = fx.api.ssh_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request.command.as_deref(), Some("ssh"));

        assert_eq!(
            fx.api.ssh_approve(&SshApproveRequest { id: pending[0].id }),
            Ok(())
        );
        assert_eq!(
            fx.api.ssh_approve(&SshApproveRequest { id: pending[0].id }),
            Err(SshApproveError::NotPending)
        );

        {
            let open = fx.databases.open("personal").ok().unwrap();
            fx.api.approvals.record(
                &open,
                approval(2, None, true),
                requested("scp"),
                SystemTime::now(),
            );
        }
        fx.databases.lock_all();
        assert!(fx.api.ssh_pending().is_empty());
    }

    /// An approval a request got by `ssh approve` is listed with how it was
    /// given, and a lock drops it.
    #[test]
    fn a_grant_is_listed_with_its_source_and_dropped_by_a_lock() {
        let fx = fixture_with(
            &[],
            "[[database]]\nname = \"personal\"\npath = \"p.kdbx\"\nserve_ssh_keys = true\n",
        );
        assert!(fx.api.ssh_grants().is_empty());
        fx.databases.install_for_test("personal", vec![]);
        {
            let open = fx.databases.open("personal").ok().unwrap();
            fx.api.approvals.record(
                &open,
                approval(1, None, true),
                requested("ssh"),
                SystemTime::now(),
            );
        }
        let id = fx.api.ssh_pending()[0].id;
        fx.api
            .ssh_approve(&SshApproveRequest { id })
            .expect("approves");

        let grants = fx.api.ssh_grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].by, "cli");
        assert!(grants[0].remember);
        assert_eq!((grants[0].uses, grants[0].expires_in), (0, None));
        assert!(grants[0].idle_lock_in > 0);

        fx.databases.lock_all();
        assert!(fx.api.ssh_grants().is_empty());
    }
}
