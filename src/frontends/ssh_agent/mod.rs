//! kpa's SSH agent (`docs/ssh-agent.md`).
//!
//! [`wire`] frames and parses the agent protocol itself, [`classify`] says
//! what a signature request is actually for, and [`bind`] verifies
//! `session-bind@openssh.com` and tracks what it means for a connection —
//! none of the three touches a socket, a vault or a config file.
//! `ssh::keys` is where that wiring starts: config, key discovery and the key
//! cache.
//! `authz` decides what a signature request needs, and `ssh::approvals`
//! holds the approvals that cover it. [`serve`](fn@serve) is the socket: it accepts
//! connections and answers each request through the [`Agent`], which holds
//! the databases, [`SshState`], the approvals and the prompts, and is the
//! sign flow.

mod agent;
mod authz;
pub mod bind;
pub mod classify;
mod serve;
#[cfg(test)]
mod testing;
pub mod wire;

pub use agent::{Agent, SshState};
pub use serve::serve;
