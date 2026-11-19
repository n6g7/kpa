//! [`Request`]: one `SIGN_REQUEST` as the sign flow sees it, and the log
//! line it ends in (`docs/ssh-agent.md` § 11).

use ssh_key::public::KeyData;
use ssh_key::{Fingerprint, HashAlg, PublicKey};

use super::sign::Refused;
use super::signer;
use crate::log;
use crate::ssh_agent::bind::ConnectionClass;
use crate::ssh_agent::classify::{self, Purpose};
use crate::ssh_agent::wire::SignRequest;

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
    let purpose = match request.purpose {
        Purpose::Login(_) => "login",
        Purpose::SshSig { .. } => "sshsig",
        Purpose::Other => "other",
    };
    let class = match request.class {
        ConnectionClass::LocalUnbound => "local",
        ConnectionClass::LocalBound { .. } => "local, bound",
        ConnectionClass::Forwarded { .. } => "forwarded",
    };
    let destination = request
        .destination()
        .map(|dest| format!(", dest {}", dest.fingerprint(HashAlg::Sha256)))
        .unwrap_or_default();
    format!(
        "ssh sign {outcome}: key {}{name} in {db:?} ({purpose}, {class}{destination})",
        request.fingerprint,
    )
}
