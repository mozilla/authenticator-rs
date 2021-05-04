#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub mod hidproto;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
pub mod platform;

#[cfg(target_os = "freebsd")]
#[path = "freebsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "netbsd")]
#[path = "netbsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "openbsd")]
#[path = "openbsd/mod.rs"]
pub mod platform;

#[cfg(target_os = "macos")]
#[path = "macos/mod.rs"]
pub mod platform;

#[cfg(target_os = "windows")]
#[path = "windows/mod.rs"]
pub mod platform;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "windows"
)))]
#[path = "stub/mod.rs"]
pub mod platform;
