//! kpa's SSH agent (`docs/ssh-agent.md`).
//!
//! [`wire`] frames and parses the agent protocol itself, [`classify`] says
//! what a signature request is actually for, and [`bind`] verifies
//! `session-bind@openssh.com` and tracks what it means for a connection —
//! none of the three touches a socket, a vault or a config file. [`keys`]
//! is where that wiring starts: config, key discovery and the key cache.

pub mod bind;
pub mod classify;
pub mod keys;
pub mod wire;
