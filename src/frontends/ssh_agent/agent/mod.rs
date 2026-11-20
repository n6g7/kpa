//! The agent's own logic (`docs/ssh-agent.md` § 6): the per-database key
//! state, the scan at unlock, identity listing, and the sign flow, on the
//! core.
//!
//! - [`Agent`]: what [`serve`](super::serve) answers each request with.
//! - [`SshState`]: what the agent keeps per database and per unlock, as an
//!   observer of the core: the scan, the private keys, the backoff.
//! - `hold`: [`Hold`], one database as the agent reads it, over the core's
//!   guard and the state.
//! - `identities`: which keys a connection sees, and which key a request
//!   names.
//! - `sign`: the sign flow, with `request` for one `SIGN_REQUEST`, `prompts`
//!   for the unlock and confirm prompts, `message` for what they say and
//!   `signer` for the signature itself.
//!
//! It reads the databases through the core's guard, and the approvals
//! through `ssh::approvals`; nothing here names another front end.

mod hold;
mod identities;
mod message;
mod prompts;
mod request;
mod sign;
mod signer;
mod state;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use zeroize::Zeroizing;

pub use state::SshState;

use self::hold::Hold;
use self::sign::Refused;
use crate::databases::Databases;
use crate::display_session::DisplayHandle;
use crate::prompt::{ConfirmAnswer, Prompt};
use crate::ssh::approvals::Approvals;

/// The SSH agent: what [`serve`](super::serve::serve) runs.
pub struct Agent {
    databases: Arc<Databases>,
    state: Arc<SshState>,
    approvals: Arc<Approvals>,
    display: DisplayHandle,
    /// The screen unlock prompt, which a signature for a locked database
    /// asks on. It waits its turn in the daemon's prompt queue, as the
    /// confirm prompt does, so only one prompt is on screen at a time.
    screen_unlock: Arc<Prompt<Zeroizing<String>>>,
    confirm_prompt: Prompt<ConfirmAnswer>,
    /// OpenSSH's known-hosts file, for naming a prompt's destination.
    known_hosts: Option<PathBuf>,
    /// One per database, held by the one signature that is asking about it
    /// (`prompts`). The others wait on it, then look again.
    turns: HashMap<String, Mutex<()>>,
}

impl Agent {
    /// `state` and `approvals` are the ones registered as observers of
    /// `databases`.
    pub fn new(
        databases: Arc<Databases>,
        state: Arc<SshState>,
        approvals: Arc<Approvals>,
        display: DisplayHandle,
        screen_unlock: Arc<Prompt<Zeroizing<String>>>,
        confirm_prompt: Prompt<ConfirmAnswer>,
        known_hosts: Option<PathBuf>,
    ) -> Agent {
        let turns = databases
            .configs()
            .iter()
            .map(|config| (config.name.clone(), Mutex::new(())))
            .collect();
        Agent {
            databases,
            state,
            approvals,
            display,
            screen_unlock,
            confirm_prompt,
            known_hosts,
            turns,
        }
    }

    /// `db` as the agent reads it now, behind the core's freshness guard.
    /// Not to be held across a prompt, or a call into the core.
    fn hold<'a>(&'a self, db: &'a str) -> Result<Hold<'a>, Refused> {
        self.state
            .hold(&self.databases, db, Instant::now(), SystemTime::now())
            .ok_or(Refused::NotServed)
    }
}
