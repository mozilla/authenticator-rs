#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "linux"))]
#[path="linux/mod.rs"]
pub mod platform;

#[cfg(any(target_os = "macos"))]
extern crate core_foundation_sys;

#[cfg(any(target_os = "macos"))]
#[path="macos/mod.rs"]
pub mod platform;

#[cfg(any(target_os = "windows"))]
#[path="windows/mod.rs"]
pub mod platform;

#[macro_use] extern crate log;
extern crate rand;
extern crate libc;
extern crate boxfnonce;

// TODO
use std::io;
use boxfnonce::SendBoxFnOnce;
use std::sync::{Arc,Mutex};

type Callback = SendBoxFnOnce<(io::Result<Vec<u8>>,)>;

// TODO move this somewhere else?
pub struct OnceCallback {
    callback: Arc<Mutex<Option<Callback>>>
}

impl OnceCallback {
    fn new<F>(cb: F) -> Self
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        let cb = Some(SendBoxFnOnce::from(cb));
        Self { callback: Arc::new(Mutex::new(cb)) }
    }

    fn call(&self, rv: io::Result<Vec<u8>>) {
        if let Ok(mut cb) = self.callback.lock() {
            if let Some(cb) = cb.take() {
                cb.call(rv);
            }
        }
    }
}

impl Clone for OnceCallback {
    fn clone(&self) -> Self {
        Self { callback: self.callback.clone() }
    }
}

mod consts;
mod manager;
mod runloop;
pub mod u2fprotocol;

pub use u2fprotocol::*;
pub use manager::U2FManager as U2FManager;

mod capi;
pub use capi::*;
