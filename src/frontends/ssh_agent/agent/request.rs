//! [`Request`]: one `SIGN_REQUEST` as the sign flow sees it, and the log
//! line it ends in (`docs/design.md` § Secrets).

use std::path::Path;

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::sign::Refused;
use super::signer;
use crate::authn::Requester;
use crate::frontends::ssh_agent::bind::ConnectionClass;
use crate::frontends::ssh_agent::classify::{self, Purpose};
use crate::frontends::ssh_agent::wire::SignRequest;
use crate::log;
use crate::output::escape_one_line;
use crate::ssh::approvals::RequestDetails;
use crate::ssh::known_hosts::HostNames;

/// The longest login user, `SSHSIG` namespace or command name a pending
/// request keeps: all come from the request.
const MAX_PENDING_TEXT_LEN: usize = 64;

/// The longest host name a log line carries, as long as one in a prompt's
/// message.
const MAX_LOGGED_HOST_NAME_LEN: usize = 56;

/// One `SIGN_REQUEST`, as the flow and its log line see it.
pub(super) struct Request<'a> {
    pub(super) key: PublicKey,
    pub(super) fingerprint: Fingerprint,
    pub(super) purpose: Purpose,
    pub(super) class: &'a ConnectionClass,
    pub(super) sign: &'a SignRequest,
    pub(super) login_session_id: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// `sign`'s request, if its key blob decodes.
    pub(super) fn parse(
        class: &'a ConnectionClass,
        sign: &'a SignRequest,
        login_session_id: Option<&'a [u8]>,
    ) -> Option<Request<'a>> {
        let key = PublicKey::new(signer::key_data_from_blob(&sign.key_blob).ok()?, "");
        Some(Request {
            fingerprint: key.fingerprint(HashAlg::Sha256),
            purpose: classify::classify(&sign.data, &key),
            key,
            class,
            sign,
            login_session_id,
        })
    }

    /// The connection's bound destination, if it has one.
    pub(super) fn destination(&self) -> Option<&KeyData> {
        match self.class {
            ConnectionClass::LocalBound { dest } => Some(dest),
            ConnectionClass::Forwarded { dest, .. } => dest.as_ref(),
            ConnectionClass::LocalUnbound => None,
        }
    }

    /// The host the local `ssh` forwarded the agent to, on a forwarded
    /// connection.
    pub(super) fn forwarding_host(&self) -> Option<&KeyData> {
        match self.class {
            ConnectionClass::Forwarded { host, .. } => Some(host),
            ConnectionClass::LocalUnbound | ConnectionClass::LocalBound { .. } => None,
        }
    }

    /// What this request is, for the user who is asked to approve it while
    /// it is pending (`docs/ssh-agent.md` § 6.8). Its own text is cut.
    pub(super) fn requested(&self, requester: &Requester) -> RequestDetails {
        let capped = |text: &str| capped(text, MAX_PENDING_TEXT_LEN).to_string();
        let (user, namespace) = match &self.purpose {
            Purpose::Login(login) => (Some(capped(&login.user)), None),
            Purpose::SshSig { namespace } => (None, Some(capped(namespace))),
            Purpose::Other => (None, None),
        };
        RequestDetails {
            purpose: self.purpose.label(),
            user,
            namespace,
            class: self.class.label(),
            command: requester.command.as_deref().map(capped),
        }
    }
}

/// `text` cut to at most `max_len` bytes, on a character boundary.
fn capped(text: &str, max_len: usize) -> &str {
    let mut end = text.len().min(max_len);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One line per `SIGN_REQUEST` for a served key (`docs/design.md`
/// § Secrets), as [`sign_line`] words it. A signature is `info`, everything else
/// `warn`. `known_hosts` is read, once, for a request that names a host.
pub(super) fn log_sign(
    db: &str,
    name: Option<String>,
    request: &Request<'_>,
    known_hosts: Option<&Path>,
    outcome: &Result<Vec<u8>, Refused>,
) {
    let log = match outcome {
        Ok(_) => log::info,
        Err(_) => log::warn,
    };
    let names = if request.destination().is_some() || request.forwarding_host().is_some() {
        HostNames::read(known_hosts)
    } else {
        HostNames::default()
    };
    let line = sign_line(db, name.as_deref(), request, &names, outcome);
    log(format_args!("{line}"));
}

/// The log line for one `SIGN_REQUEST`: the key by fingerprint, and by
/// `name` if its database's config names it (already escaped); its
/// database; its purpose; the connection's class; the destination if the
/// connection is bound to one; the forwarding host if the connection is
/// forwarded; and what happened. A host is its fingerprint, and the name
/// `names` gives it before the fingerprint, in parentheses, when it gives
/// one: `dest github.com (SHA256:…)`. Never the entry's title, which is vault
/// content (G-4).
pub(super) fn sign_line(
    db: &str,
    name: Option<&str>,
    request: &Request<'_>,
    names: &HostNames,
    outcome: &Result<Vec<u8>, Refused>,
) -> String {
    let outcome: &dyn std::fmt::Display = match outcome {
        Ok(_) => &"signed",
        Err(refused) => refused,
    };
    let name = name
        .map(|name| format!(" named \"{name}\""))
        .unwrap_or_default();
    let (purpose, class) = (request.purpose.label(), request.class.label());
    let destination = request
        .destination()
        .map(|dest| format!(", dest {}", host(dest, names)))
        .unwrap_or_default();
    let forwarding = request
        .forwarding_host()
        .map(|via| format!(", via {}", host(via, names)))
        .unwrap_or_default();
    format!(
        "ssh sign {outcome}: key {}{name} in {db:?} ({purpose}, {class}{destination}{forwarding})",
        request.fingerprint,
    )
}

/// A host as a log line says it: its fingerprint, led by the name `names`
/// gives its host key, escaped and cut, if it gives one.
fn host(key: &KeyData, names: &HostNames) -> String {
    let fingerprint = key.fingerprint(HashAlg::Sha256);
    match names.name(&fingerprint) {
        Some(name) => format!(
            "{} ({fingerprint})",
            escape_one_line(name, MAX_LOGGED_HOST_NAME_LEN)
        ),
        None => fingerprint.to_string(),
    }
}
