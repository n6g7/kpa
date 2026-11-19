//! The agent's own logic (`docs/ssh-agent.md` § 6): the per-database key
//! state, the scan at unlock, identity listing, and the sign flow.
//!
//! - [`SshHost`]: what the agent needs from the daemon that hosts it, and
//!   [`SlotView`], one database's slot as the agent sees it.
//! - [`SshSlot`]: the agent's per-database state, which the host keeps in
//!   each slot and locks with it.
//! - `identities`: which keys a connection sees, and which key a request
//!   names.
//! - `sign`: the sign flow, with `request` for one `SIGN_REQUEST`, `prompts` for
//!   the unlock and confirm prompts, `message` for what they say and
//!   `signer` for the signature itself.
//! - [`Agent`]: all of it behind [`SshSign`], the interface
//!   [`serve`](super::serve) speaks.
//!
//! It reaches the daemon only through [`SshHost`] and the confirm prompt
//! the daemon hands it; nothing here names `server`.

#[cfg(test)]
mod fake;
mod host;
mod identities;
mod message;
mod pending;
mod prompts;
mod request;
mod sign;
mod signer;
mod state;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use host::{SlotView, SshHost};
pub use pending::{approve_pending, pending_requests};
pub use state::SshSlot;

use super::bind::ConnectionClass;
use super::serve::SshSign;
use super::wire::{AgentResponse, Identity, SignRequest};
use crate::authn::Requester;
use crate::paths::Paths;
use crate::prompt::{ConfirmAnswer, Prompt};
use crate::ssh::keys;

/// The SSH agent for one host: what [`serve`](super::serve::serve) runs.
pub struct Agent<H> {
    host: Arc<H>,
    /// The confirm prompt. It waits its turn in the daemon's prompt
    /// queue, so only one prompt is on screen at a time, the unlock
    /// prompt (`Unlock::unlock`) included.
    confirm_prompt: Prompt<ConfirmAnswer>,
    /// Where the public-key cache lives, `None` without a cache directory.
    cache_dir: Option<PathBuf>,
    /// OpenSSH's known-hosts file, for naming a prompt's destination.
    known_hosts: Option<PathBuf>,
    /// How long a cancelled or timed-out prompt holds this database's
    /// prompts back (`docs/ssh-agent.md` § 6.6).
    backoff: Duration,
    /// One per database, held by the one signature that is asking about it
    /// (`prompts`). The others wait on it, then look again.
    turns: HashMap<String, Mutex<()>>,
}

impl<H: SshHost> Agent<H> {
    pub fn new(
        host: Arc<H>,
        confirm_prompt: Prompt<ConfirmAnswer>,
        backoff: Duration,
        paths: &Paths,
    ) -> Agent<H> {
        let turns = host
            .databases()
            .iter()
            .map(|cfg| (cfg.name.clone(), Mutex::new(())))
            .collect();
        Agent {
            host,
            confirm_prompt,
            cache_dir: keys::cache_dir(paths),
            known_hosts: paths.known_hosts.clone(),
            backoff,
            turns,
        }
    }
}

impl<H: SshHost> SshSign for Agent<H> {
    fn ssh_identities(&self, class: &ConnectionClass, requester: &Requester) -> Vec<Identity> {
        identities::identities(
            self.host.as_ref(),
            self.cache_dir.as_deref(),
            class,
            requester,
        )
    }

    fn ssh_sign(
        &self,
        class: &ConnectionClass,
        request: &SignRequest,
        login_session_id: Option<&[u8]>,
        requester: &Requester,
    ) -> AgentResponse {
        self.sign(class, request, login_session_id, requester)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::fake::{FakeHost, requester};
    use super::*;
    use crate::prompt::{PromptQueue, Scripted};
    use crate::ssh::testing::{database, test_key};

    /// The agent lists through its host, and finds the cache where `paths`
    /// puts it.
    #[test]
    fn the_agent_lists_cached_keys_from_its_cache_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = Paths {
            cache_dir: Some(dir.path().to_path_buf()),
            ..Paths::default()
        };
        let key = test_key(1);
        let cache = keys::cache_dir(&paths).expect("cache dir");
        keys::write_cache(&cache, "personal", &[key.public_key().clone()]).expect("write cache");
        let host = Arc::new(FakeHost::locked(vec![database("personal", vec![])]));
        let confirm_prompt = Prompt::new(
            Arc::new(PromptQueue::new()),
            Scripted::new(),
            Duration::from_secs(60),
        );
        let agent = Agent::new(host, confirm_prompt, Duration::from_secs(120), &paths);

        assert_eq!(
            agent
                .ssh_identities(&ConnectionClass::LocalUnbound, &requester())
                .len(),
            1
        );
    }
}
