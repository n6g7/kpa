//! [`Request`]: one `SIGN_REQUEST` as the sign flow sees it, and the log
//! line it ends in (`docs/ssh-agent.md` § 11).

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::sign::Refused;
use super::signer;
use crate::authn::Requester;
use crate::frontends::ssh_agent::approve::RequestDetails;
use crate::frontends::ssh_agent::bind::ConnectionClass;
use crate::frontends::ssh_agent::classify::{self, Purpose};
use crate::frontends::ssh_agent::wire::SignRequest;
use crate::log;

/// The longest login user, `SSHSIG` namespace or command name a pending
/// request keeps: all come from the request.
const MAX_PENDING_TEXT_LEN: usize = 64;

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
            _ => None,
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

/// One line per `SIGN_REQUEST` for a served key (`docs/ssh-agent.md`
/// § 11), as [`sign_line`] words it. A signature is `info`, everything else
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
/// database; its purpose; the connection's class; the destination's
/// fingerprint if the connection is bound to one; and what happened. Never
/// the entry's title, which is vault content (G-4).
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
        .map(|dest| format!(", dest {}", dest.fingerprint(HashAlg::Sha256)))
        .unwrap_or_default();
    format!(
        "ssh sign {outcome}: key {}{name} in {db:?} ({purpose}, {class}{destination})",
        request.fingerprint,
    )
}
