//! swayshare - temporary, peer-scoped remote desktop access for Sway.
//!
//! wayvnc performs the screen sharing on a Unix socket that has no network
//! presence; swayshare owns the only path to it and admits exactly one
//! authorised peer at a time.
//!
//! The crate is a library so the access gate can be exercised by integration
//! tests, and so a future tray front-end can reuse the same core.

pub mod cli;
pub mod config;
pub mod daemon;
pub mod gate;
pub mod identity;
pub mod invite;
pub mod ipc;
pub mod notify;
pub mod paths;
pub mod secret;
pub mod wayvnc;
