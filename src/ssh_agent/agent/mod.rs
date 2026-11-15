//! The agent's own logic (`docs/ssh-agent.md` § 6): the per-database key
//! state, the scan at unlock, identity listing, and the sign flow.
//!
//! - [`SshHost`]: what the agent needs from the daemon that hosts it, and
//!   [`SlotView`], one database's slot as the agent sees it.
//! - [`SshSlot`]: the agent's per-database state, which the host keeps in
//!   each slot and locks with it.
//! - `identities`: which keys a connection sees, and which key a request
//!   names.
//! - `sign`: the sign flow, with `message` for what the approval prompt
//!   says and `signer` for the signature itself.
//! - [`Agent`]: all of it behind [`SshSign`], the interface
//!   [`serve`](super::serve) speaks.
//!
//! It reaches the daemon only through [`SshHost`] and the prompt queue the
//! daemon hands it; nothing here names `server`.

#[cfg(test)]
mod fake;
mod host;
mod identities;
mod message;
mod sign;
mod signer;
mod state;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

pub use host::{SlotView, SshHost};
pub use state::SshSlot;

use super::bind::ConnectionClass;
use super::keys;
use super::serve::SshSign;
use super::wire::{AgentResponse, Identity, SignRequest};
use crate::origin::{Origin, PeerOrigin};
use crate::paths::Paths;
use crate::prompt::PromptQueue;

/// The SSH agent for one host: what [`serve`](super::serve::serve) runs.
pub struct Agent<H> {
    host: Arc<H>,
    /// Where approval prompts are raised: the daemon's own queue, so only
    /// one prompt is on screen at a time, unlock's included.
    prompts: Arc<PromptQueue>,
    /// Where the public-key cache lives, `None` without a cache directory.
    cache_dir: Option<PathBuf>,
    /// OpenSSH's known-hosts file, for naming an approval prompt's
    /// destination.
    known_hosts: Option<PathBuf>,
}

impl<H: SshHost> Agent<H> {
    pub fn new(host: Arc<H>, prompts: Arc<PromptQueue>, paths: &Paths) -> Agent<H> {
        Agent {
            host,
            prompts,
            cache_dir: keys::cache_dir(paths),
            known_hosts: paths.known_hosts.clone(),
        }
    }
}

impl<H: SshHost> PeerOrigin for Agent<H> {
    fn origin_of(&self, stream: &UnixStream, owner: u32) -> Origin {
        self.host.origin_of(stream, owner)
    }
}

impl<H: SshHost> SshSign for Agent<H> {
    fn ssh_identities(&self, class: &ConnectionClass, _origin: Origin) -> Vec<Identity> {
        identities::identities(self.host.as_ref(), self.cache_dir.as_deref(), class)
    }

    fn ssh_sign(
        &self,
        class: &ConnectionClass,
        request: &SignRequest,
        login_session_id: Option<&[u8]>,
        origin: Origin,
    ) -> AgentResponse {
        self.sign(class, request, login_session_id, origin)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::fake::FakeHost;
    use super::*;
    use crate::prompt::Scripted;
    use crate::ssh_agent::testing::{database, test_key};

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
        let prompts = Arc::new(PromptQueue::new(Scripted::new(), Duration::from_secs(60)));
        let agent = Agent::new(host, prompts, &paths);

        assert_eq!(
            agent
                .ssh_identities(&ConnectionClass::LocalUnbound, Origin::Desktop)
                .len(),
            1
        );
    }
}
