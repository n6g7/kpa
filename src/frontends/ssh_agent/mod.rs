//! kpa's SSH agent (`docs/ssh-agent.md`).
//!
//! [`wire`] frames and parses the agent protocol itself, [`classify`] says
//! what a signature request is actually for, and [`bind`] verifies
//! `session-bind@openssh.com` and tracks what it means for a connection —
//! none of the three touches a socket, a vault or a config file.
//! `ssh::keys` is where that wiring starts: config, key discovery and the key
//! cache.
//! [`authz`] decides what a signature request needs, and `ssh::approvals`
//! holds the approvals that cover it. [`serve`] is the
//! socket: it accepts connections and answers each request through
//! [`serve::SshSign`], the interface it defines for whatever lists and
//! signs.
//!
//! `agent/` holds the agent's own logic. It is in the tree and not compiled
//! until it runs on the core.

pub mod authz;
pub mod bind;
pub mod classify;
pub mod serve;
#[cfg(test)]
pub(crate) mod testing;
pub mod wire;
