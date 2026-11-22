//! [`Request`]: one `SIGN_REQUEST` as the sign flow sees it, and the log
//! line it ends in (`docs/design.md` § Secrets).

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::sign::Refused;
use super::signer;
use crate::authn::Requester;
use crate::frontends::ssh_agent::bind::{BoundHost, ConnectionClass};
use crate::frontends::ssh_agent::classify::{self, Purpose};
use crate::frontends::ssh_agent::wire::SignRequest;
use crate::log;
use crate::output::escape_one_line;
use crate::ssh::approvals::RequestDetails;
use crate::ssh::known_hosts::HostNames;

/// The longest login user, `SSHSIG` namespace or command name a pending
/// request keeps: all come from the request.
const MAX_PENDING_TEXT_LEN: usize = 64;

/// The longest host name kept, as long as one in a prompt's message.
const MAX_HOST_NAME_LEN: usize = 56;

/// The names `known_hosts` gives the hosts a request is bound to, each
/// escaped and cut: one place they are worked out, for the prompts, the log
/// line and the approval's scope to say the same.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct HostLabels {
    pub(super) destination: Option<String>,
    pub(super) forwarding_host: Option<String>,
}

/// One `SIGN_REQUEST`, as the flow and its log line see it.
pub(super) struct Request<'a> {
    pub(super) key: PublicKey,
    pub(super) fingerprint: Fingerprint,
    pub(super) purpose: Purpose,
    pub(super) class: &'a ConnectionClass,
    pub(super) sign: &'a SignRequest,
    pub(super) login_session_id: Option<&'a [u8]>,
    /// The names of its hosts: none until [`Request::named`].
    pub(super) hosts: HostLabels,
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
            hosts: HostLabels::default(),
        })
    }

    /// This request with its hosts named as `names` names them at the Unix
    /// time `now`: a host that presented a certificate by a principal of it
    /// a CA the file trusts signed, any host by a plain entry for its key.
    pub(super) fn named(mut self, names: &HostNames, now: u64) -> Request<'a> {
        let label = |host: &BoundHost| {
            names
                .name_of(host.key(), host.certificate(), now)
                .map(|name| escape_one_line(&name, MAX_HOST_NAME_LEN))
        };
        self.hosts = HostLabels {
            destination: self.destination_host().and_then(label),
            forwarding_host: self.forwarding_bound_host().and_then(label),
        };
        self
    }

    /// Whether the connection is bound to a host there could be a name for.
    pub(super) fn has_hosts(&self) -> bool {
        self.destination_host().is_some() || self.forwarding_bound_host().is_some()
    }

    /// The connection's bound destination, if it has one.
    fn destination_host(&self) -> Option<&BoundHost> {
        match self.class {
            ConnectionClass::LocalBound { dest } => Some(dest),
            ConnectionClass::Forwarded { dest, .. } => dest.as_ref(),
            ConnectionClass::LocalUnbound => None,
        }
    }

    /// The host the local `ssh` forwarded the agent to, on a forwarded
    /// connection.
    fn forwarding_bound_host(&self) -> Option<&BoundHost> {
        match self.class {
            ConnectionClass::Forwarded { host, .. } => Some(host),
            ConnectionClass::LocalUnbound | ConnectionClass::LocalBound { .. } => None,
        }
    }

    /// The key of the connection's bound destination, if it has one.
    pub(super) fn destination(&self) -> Option<&KeyData> {
        self.destination_host().map(BoundHost::key)
    }

    /// The key of the host the local `ssh` forwarded the agent to, on a
    /// forwarded connection.
    pub(super) fn forwarding_host(&self) -> Option<&KeyData> {
        self.forwarding_bound_host().map(BoundHost::key)
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
/// `warn`.
pub(super) fn log_sign(
    db: &str,
    name: Option<String>,
    request: &Request<'_>,
    outcome: &Result<Vec<u8>, Refused>,
) {
    let log = match outcome {
        Ok(_) => log::info,
        Err(_) => log::warn,
    };
    let line = sign_line(db, name.as_deref(), request, outcome);
    log(format_args!("{line}"));
}

/// The log line for one `SIGN_REQUEST`: the key by fingerprint, and by
/// `name` if its database's config names it (already escaped); its
/// database; its purpose; the connection's class; the destination if the
/// connection is bound to one; the forwarding host if the connection is
/// forwarded; and what happened. A host is its fingerprint, led by its name
/// from the request's [`HostLabels`] when it has one: `dest github.com
/// (SHA256:…)`. Never the entry's title, which is vault content (G-4).
pub(super) fn sign_line(
    db: &str,
    name: Option<&str>,
    request: &Request<'_>,
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
        .map(|dest| {
            format!(
                ", dest {}",
                host(dest, request.hosts.destination.as_deref())
            )
        })
        .unwrap_or_default();
    let forwarding = request
        .forwarding_host()
        .map(|via| {
            format!(
                ", via {}",
                host(via, request.hosts.forwarding_host.as_deref())
            )
        })
        .unwrap_or_default();
    format!(
        "ssh sign {outcome}: key {}{name} in {db:?} ({purpose}, {class}{destination}{forwarding})",
        request.fingerprint,
    )
}

/// A host as a log line says it: its fingerprint, led by its `name`, if it
/// has one.
fn host(key: &KeyData, name: Option<&str>) -> String {
    let fingerprint = key.fingerprint(HashAlg::Sha256);
    match name {
        Some(name) => format!("{name} ({fingerprint})"),
        None => fingerprint.to_string(),
    }
}
