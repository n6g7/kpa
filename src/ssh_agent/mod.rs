//! kpa's SSH agent (`docs/ssh-agent.md`).
//!
//! [`wire`] frames and parses the agent protocol itself, [`classify`] says
//! what a signature request is actually for, and [`bind`] verifies
//! `session-bind@openssh.com` and tracks what it means for a connection —
//! none of the three touches a socket, a vault or a config file. [`keys`]
//! is where that wiring starts: config, key discovery and the key cache.
//! [`policy`] decides what a signature request may do, and [`approve`]
//! holds the approvals and pending requests it consults. [`serve`] is the
//! socket: it accepts connections and answers each request through
//! [`serve::SshSign`], the interface it defines for whatever lists and
//! signs.

pub mod approve;
pub mod bind;
pub mod classify;
pub mod keys;
pub mod policy;
pub mod serve;
#[cfg(test)]
mod testing;
pub mod wire;
