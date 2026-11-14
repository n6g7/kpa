//! The SSH agent's side of `Server` (`docs/ssh-agent.md` § 6): the per-database
//! key state a `Slot` carries, scanning at unlock, the identities and
//! signatures [`serve`](super::serve) asks for, and the approval prompt.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::log;
use crate::origin::Origin;
use crate::prompt::{Approval, PromptOutcome, prompt_message, run_approval_prompt};
use crate::server::{Server, Slot, slots};
use crate::vault;
use ssh_key::encoding::{Decode, Encode, Reader};
use ssh_key::known_hosts::{HostPatterns, KnownHosts};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PrivateKey, PublicKey};

use super::approve::Approvals;
use super::serve::SshSign;
use super::{bind, classify, keys, policy as ssh_policy, wire as ssh_wire};

/// The SSH-agent-specific half of a [`Slot`], split out so `Slot::lock`'s
/// "drop everything" has one field to clear instead of four.
#[derive(Default)]
pub(crate) struct SshSlot {
    pub(crate) served: Vec<keys::ServedKey>,
    /// Read on first use (`docs/ssh-agent.md` § 6.4); zeroized by dropping
    /// the entry, which happens for all of them together on lock.
    pub(crate) private_keys: HashMap<ssh_key::Fingerprint, PrivateKey>,
    pub(crate) approvals: Approvals,
    /// How a lock ends an approval prompt in flight for this database,
    /// the same mechanism `Slot::prompt_cancel` uses for `unlock`'s own
    /// prompt: dropping this hangs up the other end, which
    /// `ssh_run_approval_prompt`'s `run_prompt` call is watching.
    /// Reinstating `Slot::lock`'s wholesale `self.ssh = SshSlot::default()`
    /// already drops it along with everything else here.
    pub(crate) prompt_cancel: Option<UnixStream>,
}

impl Server {
    /// Use `dir` for the SSH key cache instead of
    /// `keys::default_cache_dir()` — like `assume_origin`, for tests that
    /// build their own `Server` and must not depend on this process's
    /// real `$XDG_CACHE_HOME`/`$HOME`.
    #[doc(hidden)]
    pub fn assume_ssh_cache_dir(&self, dir: PathBuf) {
        let _ = self.assumed_ssh_cache_dir.set(dir);
    }

    /// Where the SSH public-key cache lives (`docs/ssh-agent.md` § 6.4).
    pub(crate) fn ssh_cache_dir(&self) -> Option<PathBuf> {
        self.assumed_ssh_cache_dir
            .get()
            .cloned()
            .or_else(keys::default_cache_dir)
    }

    /// Use `path` for `~/.ssh/known_hosts` instead of this process's real
    /// `$HOME` — like `assume_ssh_cache_dir`, for tests.
    #[doc(hidden)]
    pub fn assume_known_hosts_path(&self, path: PathBuf) {
        let _ = self.assumed_known_hosts_path.set(path);
    }

    /// `~/.ssh/known_hosts`, for naming an approval prompt's destination
    /// (`docs/ssh-agent.md` § 6.7). `None` without `$HOME`.
    fn known_hosts_path(&self) -> Option<PathBuf> {
        if let Some(path) = self.assumed_known_hosts_path.get() {
            return Some(path.clone());
        }
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".ssh/known_hosts"))
    }

    /// The literal hostname `~/.ssh/known_hosts` has for `dest`, if it has
    /// one that isn't hashed (`docs/ssh-agent.md` § 6.7: "the host name
    /// when `~/.ssh/known_hosts` has an unhashed entry for it"). A hashed
    /// entry can't be reversed without the hostname that produced it, so
    /// it's skipped rather than guessed at.
    fn known_hosts_name(&self, dest: &KeyData) -> Option<String> {
        let path = self.known_hosts_path()?;
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
}

/// Scans `slot`'s just-unlocked database for SSH keys, resolves `cfg`'s
/// overrides against what it finds, and writes the public-key cache —
/// everything `docs/ssh-agent.md` § 6.4 says happens "after each scan".
/// Scanning is header-reading only, so this runs under the slots mutex
/// without stalling anything noticeably.
pub(crate) fn scan_ssh_keys(slot: &mut Slot, cfg: &DatabaseConfig, cache_dir: Option<&Path>) {
    let Some(db) = slot.db.as_ref() else {
        return;
    };
    let attachments = vault::list_attachments(db);
    let scan = keys::scan(&attachments);
    for skipped in &scan.skipped {
        log::debug(format_args!(
            "ssh key scan: skipped {:?} on {:?}: {:?}",
            skipped.attachment_name, cfg.name, skipped.reason
        ));
    }
    slot.ssh.served = keys::resolve(cfg, &scan.found);
    let Some(dir) = cache_dir else {
        return;
    };
    let public_keys: Vec<PublicKey> = slot
        .ssh
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
/// one. `known_hosts_entry` is looked up by the caller (`Server::known_hosts_name`)
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

impl Server {
    /// `cfg`'s served keys right now: scanned-and-resolved if its database
    /// is unlocked, read from the public-key cache (names falling back to
    /// `<database> <fingerprint>`, since the cache holds no titles) if
    /// it's locked. Runs the freshness guard first.
    fn ssh_served(&self, cfg: &DatabaseConfig) -> Vec<keys::ServedKey> {
        self.drop_stale([cfg.name.as_str()]);
        let mut dbs = slots(&self.dbs);
        let Some(slot) = dbs.get_mut(&cfg.name) else {
            return Vec::new();
        };
        if slot.db.is_some() {
            return slot.ssh.served.clone();
        }
        drop(dbs);
        let Some(dir) = self.ssh_cache_dir() else {
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
    fn ssh_find(
        &self,
        fingerprint: ssh_key::Fingerprint,
    ) -> Option<(DatabaseConfig, keys::ServedKey)> {
        for cfg in self
            .config
            .databases
            .iter()
            .filter(|cfg| cfg.serve_ssh_keys)
        {
            if let Some(key) = self
                .ssh_served(cfg)
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
    fn ssh_load_and_sign(
        &self,
        db_name: &str,
        served: &keys::ServedKey,
        request: &ssh_wire::SignRequest,
    ) -> Option<Vec<u8>> {
        let mut dbs = slots(&self.dbs);
        let slot = dbs.get_mut(db_name)?;
        let db = slot.db.as_ref()?;
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
    }

    /// Raises the approval prompt (`ssh_agent.confirm_prompt`) for `served`,
    /// through the same queue `unlock`'s prompt shares, and reports whether
    /// it answered `Allow`. Stores the cancel half in `db_name`'s
    /// `SshSlot::prompt_cancel` for the prompt's duration, so a lock on
    /// another thread can end it exactly like it ends `unlock`'s own
    /// prompt — cleared again once this returns, on every path, by
    /// `SshPromptGuard`.
    fn ssh_run_approval_prompt(
        &self,
        db_name: &str,
        served: &keys::ServedKey,
        purpose: &classify::Purpose,
        destination: Option<&KeyData>,
    ) -> bool {
        let argv = &self.config.ssh_agent.confirm_prompt;
        if argv.is_empty() {
            return false;
        }
        let known_hosts_entry = destination.and_then(|dest| self.known_hosts_name(dest));
        let message = prompt_message(&ssh_approval_message(
            served,
            purpose,
            destination,
            known_hosts_entry.as_deref(),
        ));
        let Ok((cancel, watch)) = UnixStream::pair() else {
            return false;
        };
        {
            let mut dbs = slots(&self.dbs);
            let Some(slot) = dbs.get_mut(db_name) else {
                return false;
            };
            // The database may have locked since the caller last checked.
            if slot.db.is_none() {
                return false;
            }
            slot.ssh.prompt_cancel = Some(cancel);
        }
        let _guard = SshPromptGuard {
            dbs: &self.dbs,
            name: db_name,
        };
        matches!(
            run_approval_prompt(
                &self.prompt_queue,
                argv,
                &message,
                self.config.prompt_timeout,
                &watch,
            ),
            Ok(PromptOutcome::Answer(Approval::Allow))
        )
    }

    /// Whether the SSH agent socket should run at all: at least one
    /// database opts in.
    pub fn ssh_agent_enabled(&self) -> bool {
        self.config.databases.iter().any(|cfg| cfg.serve_ssh_keys)
    }

    /// Where to bind the SSH agent socket (`docs/ssh-agent.md` § 7).
    pub fn ssh_agent_socket_path(&self, runtime_dir: Option<&Path>) -> Option<PathBuf> {
        self.config.ssh_agent.socket_path(runtime_dir)
    }
}

/// How a lock ends an SSH approval prompt in flight, the same way
/// `UnlockingFlag` ends `unlock`'s own: cleared once `ssh_run_approval_prompt`
/// returns, on every path, so a later prompt for the same database starts
/// from a clean slot.
struct SshPromptGuard<'a> {
    dbs: &'a Mutex<HashMap<String, Slot>>,
    name: &'a str,
}

impl Drop for SshPromptGuard<'_> {
    fn drop(&mut self) {
        if let Some(slot) = slots(self.dbs).get_mut(self.name) {
            slot.ssh.prompt_cancel = None;
        }
    }
}

impl SshSign for Server {
    /// Every key this connection may list right now (`docs/ssh-agent.md`
    /// § 6.4 "Which keys a connection sees"), deduped by config order and
    /// filtered by `class` (a forwarded connection never sees a
    /// `forwarded = false` key).
    fn ssh_identities(&self, class: &bind::ConnectionClass) -> Vec<ssh_wire::Identity> {
        let per_database: Vec<Vec<keys::ServedKey>> = self
            .config
            .databases
            .iter()
            .filter(|cfg| cfg.serve_ssh_keys)
            .map(|cfg| self.ssh_served(cfg))
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

        let Some((cfg, served)) = self.ssh_find(fingerprint) else {
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

        self.drop_stale([cfg.name.as_str()]);
        let locked = slots(&self.dbs)
            .get(&cfg.name)
            .is_none_or(|slot| slot.db.is_none());
        if locked {
            // Unlock on demand is a later task; refuse outright for now.
            log_ssh_sign(&served, &purpose, class, destination.as_ref(), "locked");
            return ssh_wire::AgentResponse::Failure;
        }

        let may_prompt = self.desk().may_prompt(origin);
        let decision = {
            let dbs = slots(&self.dbs);
            let Some(slot) = dbs.get(&cfg.name) else {
                return ssh_wire::AgentResponse::Failure;
            };
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
        };

        match decision {
            ssh_policy::Decision::Sign => {}
            ssh_policy::Decision::PromptApprove => {
                if !self.ssh_run_approval_prompt(&cfg.name, &served, &purpose, destination.as_ref())
                {
                    log_ssh_sign(
                        &served,
                        &purpose,
                        class,
                        destination.as_ref(),
                        "approval denied",
                    );
                    return ssh_wire::AgentResponse::Failure;
                }
                let mut dbs = slots(&self.dbs);
                if let Some(slot) = dbs.get_mut(&cfg.name) {
                    slot.ssh.approvals.grant_local(
                        fingerprint,
                        destination.as_ref(),
                        served.confirm,
                    );
                }
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

        let Some(signature) = self.ssh_load_and_sign(&cfg.name, &served, request) else {
            log_ssh_sign(
                &served,
                &purpose,
                class,
                destination.as_ref(),
                "loading or signing failed",
            );
            return ssh_wire::AgentResponse::Failure;
        };

        let mut dbs = slots(&self.dbs);
        if let Some(slot) = dbs.get_mut(&cfg.name) {
            slot.ssh
                .approvals
                .consume_local(fingerprint, destination.as_ref());
            if ssh_policy::is_idle_activity(class, true) {
                slot.touch();
            }
        }
        log_ssh_sign(&served, &purpose, class, destination.as_ref(), "signed");
        ssh_wire::AgentResponse::SignResponse(signature)
    }
}
