//! The agent's own logic (`docs/ssh-agent.md` § 6): the per-database key
//! state, the scan at unlock, identity listing, and the sign flow (find,
//! classify, decide, prompt, sign, consume, touch).
//!
//! It reaches the daemon only through [`SshHost`], which `server::Server`
//! implements; nothing here names `server`. Every [`SshHost`] is an
//! [`SshSign`], the interface [`serve`](super::serve) speaks.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

use keepass::Database;
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::log;
use crate::origin::{Origin, PeerOrigin};
use crate::prompt::prompt_message;
use crate::vault;
use ssh_key::encoding::{Decode, Encode, Reader};
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, PublicKey};

use super::approve::Approvals;
use super::serve::SshSign;
use super::{bind, classify, keys, policy as ssh_policy, wire as ssh_wire};

/// What the agent needs from the daemon that hosts it. `Server` implements
/// it as a thin adapter over its slots; the agent's logic stays here.
pub trait SshHost: PeerOrigin {
    /// Every configured database, in config order.
    fn databases(&self) -> &[DatabaseConfig];

    /// Where the public-key cache lives (`docs/ssh-agent.md` § 6.4).
    fn ssh_cache_dir(&self) -> Option<PathBuf>;

    /// `~/.ssh/known_hosts`, for naming an approval prompt's destination.
    fn known_hosts_path(&self) -> Option<PathBuf>;

    /// Freshness guard for `db`: locks it if its file changed on disk.
    fn drop_if_stale(&self, db: &str);

    /// Runs `f` on `db`'s slot under the daemon's slots mutex, or returns
    /// `None` if there is no such database. `f` must not block.
    fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R>;

    /// Whether a prompt may be raised for a connection from `origin`.
    fn may_prompt(&self, origin: Origin) -> bool;

    /// Raises the approval prompt, queued behind any other, and reports
    /// whether it answered `Allow`. A lock on `cancel_watch`'s peer ends it.
    /// Runs outside the slots mutex.
    fn confirm(&self, message: &str, cancel_watch: &UnixStream) -> bool;
}

/// One database's slot as the agent sees it, under the slots mutex.
pub struct SlotView<'a> {
    /// The open database, `None` while locked.
    pub db: Option<&'a Database>,
    pub ssh: &'a mut SshSlot,
    last_activity: &'a mut Instant,
}

impl<'a> SlotView<'a> {
    pub(crate) fn new(
        db: Option<&'a Database>,
        ssh: &'a mut SshSlot,
        last_activity: &'a mut Instant,
    ) -> SlotView<'a> {
        SlotView {
            db,
            ssh,
            last_activity,
        }
    }

    /// Resets the database's idle timer to now.
    pub fn touch(&mut self) {
        *self.last_activity = Instant::now();
    }
}

/// The SSH-agent-specific half of a database's slot, split out so a lock's
/// "drop everything" has one field to clear.
#[derive(Default)]
pub struct SshSlot {
    served: Vec<keys::ServedKey>,
    /// Read on first use (`docs/ssh-agent.md` § 6.4); zeroized by dropping
    /// the entry, which happens for all of them together on lock.
    private_keys: HashMap<ssh_key::Fingerprint, PrivateKey>,
    approvals: Approvals,
    /// How a lock ends an approval prompt in flight for this database,
    /// the same mechanism the slot's own `prompt_cancel` uses for
    /// `unlock`'s prompt: dropping this hangs up the other end, which the
    /// prompt is watching. Dropping the whole `SshSlot` on lock drops it
    /// along with everything else here.
    prompt_cancel: Option<UnixStream>,
}

impl SshSlot {
    /// Scans `db`, just unlocked, for SSH keys, resolves `cfg`'s overrides
    /// against what it finds, and writes the public-key cache —
    /// everything `docs/ssh-agent.md` § 6.4 says happens "after each scan".
    /// Scanning is header-reading only, so this runs under the slots mutex
    /// without stalling anything noticeably.
    pub fn scan(&mut self, db: &Database, cfg: &DatabaseConfig, cache_dir: Option<&Path>) {
        let attachments = vault::list_attachments(db);
        let scan = keys::scan(&attachments);
        for skipped in &scan.skipped {
            log::debug(format_args!(
                "ssh key scan: skipped {:?} on {:?}: {:?}",
                skipped.attachment_name, cfg.name, skipped.reason
            ));
        }
        self.served = keys::resolve(cfg, &scan.found);
        let Some(dir) = cache_dir else {
            return;
        };
        let public_keys: Vec<PublicKey> = self
            .served
            .iter()
            .map(|key| key.public_key.clone())
            .collect();
        if let Err(err) = keys::write_cache(dir, &cfg.name, &public_keys) {
            log::warn(format_args!(
                "ssh key cache: failed to write {:?}: {err}",
                cfg.name
            ));
        }
    }
}

/// The literal hostname `known_hosts` has for `dest`, if it has one that
/// isn't hashed (`docs/ssh-agent.md` § 6.7: "the host name when
/// `~/.ssh/known_hosts` has an unhashed entry for it"). A hashed entry
/// can't be reversed without the hostname that produced it, so it's
/// skipped rather than guessed at.
fn known_hosts_name(path: PathBuf, dest: &KeyData) -> Option<String> {
    KnownHosts::read_file(path)
        .ok()?
        .into_iter()
        .find_map(|entry| match entry.host_patterns() {
            HostPatterns::Patterns(patterns) if entry.public_key().key_data() == dest => {
                patterns.first().cloned()
            }
            _ => None,
        })
}

/// Decode a raw public-key blob off the wire (`SIGN_REQUEST`'s `key_blob`,
/// `IDENTITIES_ANSWER`'s), rejecting trailing bytes.
fn key_data_from_blob(blob: &[u8]) -> ssh_key::Result<KeyData> {
    let mut reader: &[u8] = blob;
    let key_data = KeyData::decode(&mut reader)?;
    reader.ensure_finished()?;
    Ok(key_data)
}

/// Produces the raw signature bytes `SIGN_RESPONSE` carries, choosing
/// `rsa-sha2-256`/`512` from `flags` for an RSA key (`docs/ssh-agent.md`
/// § 6.5 — a bare `ssh-rsa`/SHA-1 request, asking for neither, is refused)
/// and the key's own algorithm for anything else.
fn sign_with(key: &PrivateKey, data: &[u8], flags: ssh_wire::SignFlags) -> Option<Vec<u8>> {
    use signature::Signer;

    let signature = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(rsa) => {
            let hash = if flags.rsa_sha2_512() {
                HashAlg::Sha512
            } else if flags.rsa_sha2_256() {
                HashAlg::Sha256
            } else {
                return None;
            };
            (rsa, Some(hash)).try_sign(data).ok()?
        }
        _ => key.try_sign(data).ok()?,
    };
    signature.encode_vec().ok()
}

/// The approval prompt's message (`docs/ssh-agent.md` § 6.7): the key name
/// and purpose, the remote user for a login, and — when this connection is
/// bound to one — the destination, by host-key fingerprint, plus the
/// literal hostname from an unhashed `~/.ssh/known_hosts` entry if there is
/// one. `known_hosts_entry` is looked up by the caller (`known_hosts_name`)
/// rather than here, since this function has no socket or filesystem
/// access of its own — it only assembles text.
fn ssh_approval_message(
    served: &keys::ServedKey,
    purpose: &classify::Purpose,
    destination: Option<&KeyData>,
    known_hosts_entry: Option<&str>,
) -> String {
    let mut message = match purpose {
        classify::Purpose::Login(login) => {
            format!("Approve {} for {}", served.name, login.user)
        }
        classify::Purpose::SshSig { namespace } => {
            format!("Approve {} to sign ({namespace})", served.name)
        }
        classify::Purpose::Other => format!("Approve {}", served.name),
    };
    if let Some(dest) = destination {
        let fingerprint = dest.fingerprint(HashAlg::Sha256);
        match known_hosts_entry {
            Some(name) => message.push_str(&format!(" on {name} ({fingerprint})")),
            None => message.push_str(&format!(" on {fingerprint}")),
        }
    }
    message
}

/// A short label for a log line or an approval prompt's message — never
/// the full `ConnectionClass` (whose `Debug` dumps a `KeyData`).
fn connection_class_label(class: &bind::ConnectionClass) -> &'static str {
    match class {
        bind::ConnectionClass::LocalUnbound => "local",
        bind::ConnectionClass::LocalBound { .. } => "local, bound",
        bind::ConnectionClass::Forwarded { .. } => "forwarded",
    }
}

/// A short label for a log line's purpose.
fn purpose_label(purpose: &classify::Purpose) -> &'static str {
    match purpose {
        classify::Purpose::Login(_) => "login",
        classify::Purpose::SshSig { .. } => "sshsig",
        classify::Purpose::Other => "other",
    }
}

/// One line per `SIGN_REQUEST` outcome (`docs/ssh-agent.md` § 11): the
/// key's name, its purpose, the connection's class, the destination's
/// fingerprint (if the connection is bound to one), and the decision.
/// `REQUEST_IDENTITIES` has no equivalent call — it's never logged, like
/// `list` on the JSON socket.
fn log_ssh_sign(
    served: &keys::ServedKey,
    purpose: &classify::Purpose,
    class: &bind::ConnectionClass,
    destination: Option<&KeyData>,
    decision: &str,
) {
    let dest = destination.map(|d| d.fingerprint(HashAlg::Sha256));
    let log = if decision == "signed" {
        log::info
    } else {
        log::warn
    };
    match dest {
        Some(dest) => log(format_args!(
            "ssh sign {decision}: {:?} ({}, {}, dest {dest})",
            served.name,
            purpose_label(purpose),
            connection_class_label(class),
        )),
        None => log(format_args!(
            "ssh sign {decision}: {:?} ({}, {})",
            served.name,
            purpose_label(purpose),
            connection_class_label(class),
        )),
    }
}

/// `cfg`'s served keys right now: scanned-and-resolved if its database
/// is unlocked, read from the public-key cache (names falling back to
/// `<database> <fingerprint>`, since the cache holds no titles) if
/// it's locked. Runs the freshness guard first.
fn served_keys(host: &impl SshHost, cfg: &DatabaseConfig) -> Vec<keys::ServedKey> {
    host.drop_if_stale(&cfg.name);
    match host.with_slot(&cfg.name, |slot| {
        slot.db.is_some().then(|| slot.ssh.served.clone())
    }) {
        None => return Vec::new(),
        Some(Some(served)) => return served,
        Some(None) => {}
    }
    let Some(dir) = host.ssh_cache_dir() else {
        return Vec::new();
    };
    keys::read_cache(&dir, &cfg.name)
        .into_iter()
        .filter_map(|public_key| {
            let fingerprint = public_key.fingerprint(HashAlg::Sha256);
            let settings = cfg.ssh_key_settings(fingerprint);
            if !settings.serve {
                return None;
            }
            Some(keys::ServedKey {
                database: cfg.name.clone(),
                public_key,
                fingerprint,
                name: keys::key_name(&cfg.name, fingerprint, settings.name.as_deref(), None),
                entry_uuid: Uuid::nil(),
                confirm: settings.confirm,
                forwarded: settings.forwarded,
            })
        })
        .collect()
}

/// The database config and served key for `fingerprint` — the first
/// opted-in database in config order that serves it
/// (`docs/ssh-agent.md` § 6.4's dedupe rule).
fn find_key(
    host: &impl SshHost,
    fingerprint: ssh_key::Fingerprint,
) -> Option<(DatabaseConfig, keys::ServedKey)> {
    for cfg in host.databases().iter().filter(|cfg| cfg.serve_ssh_keys) {
        if let Some(key) = served_keys(host, cfg)
            .into_iter()
            .find(|key| key.fingerprint == fingerprint)
        {
            return Some((cfg.clone(), key));
        }
    }
    None
}

/// Reads (lazily, caching the result for this database's slot until
/// lock) the key behind `served` and signs `request.data` with it.
fn load_and_sign(
    host: &impl SshHost,
    db_name: &str,
    served: &keys::ServedKey,
    request: &ssh_wire::SignRequest,
) -> Option<Vec<u8>> {
    host.with_slot(db_name, |slot| {
        let db = slot.db?;
        let private_key = match slot.ssh.private_keys.entry(served.fingerprint) {
            Entry::Occupied(cached) => cached.into_mut(),
            Entry::Vacant(vacant) => {
                let attachment = vault::list_attachments(db).into_iter().find(|a| {
                    a.entry_uuid == served.entry_uuid
                        && keys::scan(std::slice::from_ref(a))
                            .found
                            .iter()
                            .any(|k| k.fingerprint == served.fingerprint)
                })?;
                vacant.insert(keys::parse_private_key(&attachment.data)?)
            }
        };
        sign_with(private_key, &request.data, request.flags)
    })
    .flatten()
}

/// How a lock ends an approval prompt in flight: cleared once the prompt
/// returns, on every path, so a later prompt for the same database starts
/// from a clean slot.
struct PromptGuard<'a, H: SshHost> {
    host: &'a H,
    name: &'a str,
}

impl<H: SshHost> Drop for PromptGuard<'_, H> {
    fn drop(&mut self) {
        self.host.with_slot(self.name, |slot| {
            slot.ssh.prompt_cancel = None;
        });
    }
}

/// Raises the approval prompt for `served` and reports whether it answered
/// `Allow`. Stores the cancel half in `db_name`'s `SshSlot::prompt_cancel`
/// for the prompt's duration, so a lock on another thread can end it
/// exactly like it ends `unlock`'s own prompt.
fn run_approval_prompt(
    host: &impl SshHost,
    db_name: &str,
    served: &keys::ServedKey,
    purpose: &classify::Purpose,
    destination: Option<&KeyData>,
) -> bool {
    let known_hosts_entry = destination.and_then(|dest| {
        host.known_hosts_path()
            .and_then(|p| known_hosts_name(p, dest))
    });
    let message = prompt_message(&ssh_approval_message(
        served,
        purpose,
        destination,
        known_hosts_entry.as_deref(),
    ));
    let Ok((cancel, watch)) = UnixStream::pair() else {
        return false;
    };
    let armed = host
        .with_slot(db_name, |slot| {
            // The database may have locked since the caller last checked.
            if slot.db.is_none() {
                return false;
            }
            slot.ssh.prompt_cancel = Some(cancel);
            true
        })
        .unwrap_or(false);
    if !armed {
        return false;
    }
    let _guard = PromptGuard {
        host,
        name: db_name,
    };
    host.confirm(&message, &watch)
}

impl<H: SshHost> SshSign for H {
    /// Every key this connection may list right now (`docs/ssh-agent.md`
    /// § 6.4 "Which keys a connection sees"), deduped by config order and
    /// filtered by `class` (a forwarded connection never sees a
    /// `forwarded = false` key).
    fn ssh_identities(&self, class: &bind::ConnectionClass) -> Vec<ssh_wire::Identity> {
        let per_database: Vec<Vec<keys::ServedKey>> = self
            .databases()
            .iter()
            .filter(|cfg| cfg.serve_ssh_keys)
            .map(|cfg| served_keys(self, cfg))
            .collect();
        keys::dedupe_by_config_order(per_database)
            .into_iter()
            .filter(|key| ssh_policy::listable(class, key.forwarded))
            .filter_map(|key| {
                key.public_key
                    .to_bytes()
                    .ok()
                    .map(|key_blob| ssh_wire::Identity {
                        key_blob,
                        comment: key.name,
                    })
            })
            .collect()
    }

    /// Answers one `SIGN_REQUEST` (`docs/ssh-agent.md` § 6.1, § 6.7, § 6.9):
    /// classifies it, runs `policy::decide`, and either signs or refuses.
    /// Forwarded connections are refused outright in this build — forwarding
    /// is a later task — and a locked database is refused rather than
    /// unlocked on demand, likewise later work.
    fn ssh_sign(
        &self,
        class: &bind::ConnectionClass,
        request: &ssh_wire::SignRequest,
        login_session_id: Option<&[u8]>,
        origin: Origin,
    ) -> ssh_wire::AgentResponse {
        let Ok(key_data) = key_data_from_blob(&request.key_blob) else {
            return ssh_wire::AgentResponse::Failure;
        };
        let public_key = PublicKey::new(key_data, "");
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        let purpose = classify::classify(&request.data, &public_key);

        let Some((cfg, served)) = find_key(self, fingerprint) else {
            return ssh_wire::AgentResponse::Failure;
        };

        let destination = match class {
            bind::ConnectionClass::LocalBound { dest } => Some(dest.clone()),
            _ => None,
        };

        if matches!(class, bind::ConnectionClass::Forwarded { .. }) {
            log_ssh_sign(
                &served,
                &purpose,
                class,
                destination.as_ref(),
                "forwarding not supported yet",
            );
            return ssh_wire::AgentResponse::Failure;
        }

        let key_settings = ssh_policy::KeySettings {
            fingerprint,
            confirm: served.confirm,
            forwarded: served.forwarded,
        };

        self.drop_if_stale(&cfg.name);
        let locked = self
            .with_slot(&cfg.name, |slot| slot.db.is_none())
            .unwrap_or(true);
        if locked {
            // Unlock on demand is a later task; refuse outright for now.
            log_ssh_sign(&served, &purpose, class, destination.as_ref(), "locked");
            return ssh_wire::AgentResponse::Failure;
        }

        let may_prompt = self.may_prompt(origin);
        let Some(decision) = self.with_slot(&cfg.name, |slot| {
            ssh_policy::decide(
                key_settings,
                class,
                &purpose,
                login_session_id,
                false,
                &slot.ssh.approvals,
                may_prompt,
                false,
            )
        }) else {
            return ssh_wire::AgentResponse::Failure;
        };

        match decision {
            ssh_policy::Decision::Sign => {}
            ssh_policy::Decision::PromptApprove => {
                if !run_approval_prompt(self, &cfg.name, &served, &purpose, destination.as_ref()) {
                    log_ssh_sign(
                        &served,
                        &purpose,
                        class,
                        destination.as_ref(),
                        "approval denied",
                    );
                    return ssh_wire::AgentResponse::Failure;
                }
                self.with_slot(&cfg.name, |slot| {
                    slot.ssh.approvals.grant_local(
                        fingerprint,
                        destination.as_ref(),
                        served.confirm,
                    );
                });
            }
            ssh_policy::Decision::PromptUnlock | ssh_policy::Decision::Refuse(_) => {
                log_ssh_sign(
                    &served,
                    &purpose,
                    class,
                    destination.as_ref(),
                    "refused by policy",
                );
                return ssh_wire::AgentResponse::Failure;
            }
        }

        let Some(signature) = load_and_sign(self, &cfg.name, &served, request) else {
            log_ssh_sign(
                &served,
                &purpose,
                class,
                destination.as_ref(),
                "loading or signing failed",
            );
            return ssh_wire::AgentResponse::Failure;
        };

        self.with_slot(&cfg.name, |mut slot| {
            slot.ssh
                .approvals
                .consume_local(fingerprint, destination.as_ref());
            if ssh_policy::is_idle_activity(class, true) {
                slot.touch();
            }
        });
        log_ssh_sign(&served, &purpose, class, destination.as_ref(), "signed");
        ssh_wire::AgentResponse::SignResponse(signature)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::config::SshKeyConfig;

    const ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    /// A host whose one database is locked, with its key cache in `dir`.
    struct LockedHost {
        databases: Vec<DatabaseConfig>,
        dir: PathBuf,
        slot: Mutex<(SshSlot, Instant)>,
    }

    impl PeerOrigin for LockedHost {
        fn origin_of(&self, _: &UnixStream, _: u32) -> Origin {
            Origin::Outside
        }
    }

    impl SshHost for LockedHost {
        fn databases(&self) -> &[DatabaseConfig] {
            &self.databases
        }

        fn ssh_cache_dir(&self) -> Option<PathBuf> {
            Some(self.dir.clone())
        }

        fn known_hosts_path(&self) -> Option<PathBuf> {
            None
        }

        fn drop_if_stale(&self, _: &str) {}

        fn with_slot<R>(&self, db: &str, f: impl FnOnce(SlotView<'_>) -> R) -> Option<R> {
            if db != self.databases[0].name {
                return None;
            }
            let mut guard = self.slot.lock().unwrap();
            let (ssh, last_activity) = &mut *guard;
            Some(f(SlotView::new(None, ssh, last_activity)))
        }

        fn may_prompt(&self, _: Origin) -> bool {
            false
        }

        fn confirm(&self, _: &str, _: &UnixStream) -> bool {
            false
        }
    }

    fn host(dir: &Path, ssh_keys: Vec<SshKeyConfig>) -> LockedHost {
        let public_key = PublicKey::from_openssh(ED25519_PUB).expect("test public key");
        keys::write_cache(dir, "personal", &[public_key]).expect("write cache");
        LockedHost {
            databases: vec![DatabaseConfig {
                name: "personal".to_string(),
                path: "/v.kdbx".into(),
                keyfile: None,
                serve_ssh_keys: true,
                ssh_keys,
            }],
            dir: dir.to_path_buf(),
            slot: Mutex::new((SshSlot::default(), Instant::now())),
        }
    }

    #[test]
    fn a_locked_database_lists_its_cached_keys_under_a_fallback_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = host(dir.path(), vec![]);
        let identities = host.ssh_identities(&bind::ConnectionClass::LocalUnbound);
        assert_eq!(identities.len(), 1);
        assert!(identities[0].comment.starts_with("personal SHA256:"));
    }

    #[test]
    fn a_serve_false_override_hides_a_cached_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fingerprint = PublicKey::from_openssh(ED25519_PUB)
            .expect("test public key")
            .fingerprint(HashAlg::Sha256);
        let hidden = SshKeyConfig {
            fingerprint: fingerprint.to_string(),
            name: None,
            confirm: Default::default(),
            forwarded: true,
            serve: false,
        };
        let host = host(dir.path(), vec![hidden]);
        assert!(
            host.ssh_identities(&bind::ConnectionClass::LocalUnbound)
                .is_empty()
        );
    }
}
