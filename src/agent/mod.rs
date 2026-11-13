//! kpa's SSH agent: the pure protocol layer (`docs/ssh-agent.md` § 11).
//!
//! [`wire`] frames and parses the agent protocol itself, [`classify`] says
//! what a signature request is actually for, and [`bind`] verifies
//! `session-bind@openssh.com` and tracks what it means for a connection.
//! None of the three touches a socket, a vault or a config file — that
//! wiring lives in later modules of this directory.

pub mod bind;
pub mod classify;
pub mod wire;
