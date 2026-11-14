//! The agent's own logic (`docs/ssh-agent.md` § 6): the per-database key
//! state, the scan at unlock, and identity listing.
//!
//! - [`SshHost`]: what the agent needs from the daemon that hosts it, and
//!   [`SlotView`], one database's slot as the agent sees it.
//! - [`SshSlot`]: the agent's per-database state, which the host keeps in
//!   each slot and resets on lock.
//! - `identities`: which keys a connection sees.
//! - [`Agent`]: all of it behind [`SshSign`], the interface
//!   [`serve`](super::serve) speaks.
//!
//! It reaches the daemon only through [`SshHost`]; nothing here names
//! `server`.

#[cfg(test)]
mod fake;
mod host;
mod identities;
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

/// The SSH agent for one host: what [`serve`](super::serve::serve) runs.
pub struct Agent<H> {
    host: Arc<H>,
    /// Where the public-key cache lives, `None` without a cache directory.
    cache_dir: Option<PathBuf>,
}

impl<H: SshHost> Agent<H> {
    pub fn new(host: Arc<H>, paths: &Paths) -> Agent<H> {
        Agent {
            host,
            cache_dir: keys::cache_dir(paths),
        }
    }
}

impl<H: SshHost> PeerOrigin for Agent<H> {
    fn origin_of(&self, stream: &UnixStream, owner: u32) -> Origin {
        self.host.origin_of(stream, owner)
    }
}

impl<H: SshHost> SshSign for Agent<H> {
    fn ssh_identities(&self, class: &ConnectionClass) -> Vec<Identity> {
        identities::identities(self.host.as_ref(), self.cache_dir.as_deref(), class)
    }

    /// Refuses every request: this agent lists keys but doesn't sign yet.
    fn ssh_sign(
        &self,
        _class: &ConnectionClass,
        _request: &SignRequest,
        _login_session_id: Option<&[u8]>,
        _origin: Origin,
    ) -> AgentResponse {
        AgentResponse::Failure
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeHost;
    use super::*;
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
        let agent = Agent::new(
            Arc::new(FakeHost::locked(vec![database("personal", vec![])])),
            &paths,
        );

        assert_eq!(
            agent.ssh_identities(&ConnectionClass::LocalUnbound).len(),
            1
        );
    }
}
