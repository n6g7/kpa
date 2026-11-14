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
//!
//! `agent` is the agent's own logic, crate-private: an `Agent` over an
//! `SshHost`, the small interface the daemon implements. The daemon
//! runs it through `server::serve_ssh_agent`; this module never names
//! `server`.

mod agent;
pub mod approve;
pub mod bind;
pub mod classify;
pub mod keys;
pub mod policy;
pub mod serve;
#[cfg(test)]
pub(crate) mod testing;
pub mod wire;

pub(crate) use agent::{Agent, SlotView, SshHost, SshSlot};
