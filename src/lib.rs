//! DataSentinel library: local sensitive-data discovery, detection, storage,
//! desktop notification and cross-platform autostart.
//!
//! The `sentinel` binary is a thin CLI wrapper around these modules; exposing
//! them as a library keeps the detection engine testable and reusable (e.g. a
//! future tray/GUI front-end).

#![allow(clippy::manual_is_multiple_of)]

pub mod autostart;
pub mod cli;
pub mod config;
pub mod detect;
pub mod model;
pub mod notify;
pub mod report;
pub mod rules;
pub mod scan;
pub mod store;
pub mod util;
pub mod watch;
pub mod webui;
