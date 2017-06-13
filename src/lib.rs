#[cfg(any(target_os = "linux", target_os = "macos"))]
#[macro_use]
extern crate nix;

#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "linux"))]
#[path="linux/mod.rs"]
pub mod platform;

#[cfg(any(target_os = "macos"))]
extern crate core_foundation_sys;
#[cfg(any(target_os = "macos"))]
extern crate mach;

#[cfg(any(target_os = "macos"))]
#[path="macos/mod.rs"]
pub mod platform;

#[cfg(any(target_os = "windows"))]
#[path="windows/mod.rs"]
pub mod platform;

#[macro_use] extern crate log;
extern crate rand;
extern crate libc;

mod consts;
mod manager;
mod runloop;
pub mod u2fprotocol;

pub use u2fprotocol::*;
pub use manager::U2FManager as U2FManager;
