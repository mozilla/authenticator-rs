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

use std::ptr;

pub use u2fprotocol::*;
pub use manager::U2FManager as U2FManager;

#[no_mangle]
pub extern "C" fn rust_u2f_mgr_new() -> *mut U2FManager {
    let manager = U2FManager::new();
    Box::into_raw(Box::new(manager))
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_free(ptr: *mut U2FManager) {
    if !ptr.is_null() {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_register(ptr: *mut U2FManager,
                                               timeout: u64,
                                               challenge_ptr: *const u8,
                                               challenge_len: usize,
                                               application_ptr: *const u8,
                                               application_len: usize,
                                               registration_ptr: *mut u8,
                                               registration_len: *mut usize,
                                               max_registration_len: usize) {
    if ptr.is_null() {
        return; // TODO error
    }

    let mut mgr = Box::from_raw(ptr);
    let challenge = std::slice::from_raw_parts(challenge_ptr, challenge_len);
    let application = std::slice::from_raw_parts(application_ptr, application_len);

    let res = mgr.register(timeout, challenge.to_vec(), application.to_vec());
    let _ = Box::into_raw(mgr);

    let res = match res {
        Ok(rv) => rv,
        _ => return // TODO error
    };

    if res.len() > max_registration_len {
      return; // TODO error
    }

    *registration_len = res.len();
    ptr::copy_nonoverlapping(res.as_ptr(), registration_ptr, res.len());
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_sign(ptr: *mut U2FManager,
                                           timeout: u64,
                                           challenge_ptr: *const u8,
                                           challenge_len: usize,
                                           application_ptr: *const u8,
                                           application_len: usize,
                                           key_handle_ptr: *const u8,
                                           key_handle_len: usize,
                                           signature_ptr: *mut u8,
                                           signature_len: *mut usize,
                                           max_signature_len: usize) {
    if ptr.is_null() {
        return; // TODO error
    }

    let mut mgr = Box::from_raw(ptr);
    let challenge = std::slice::from_raw_parts(challenge_ptr, challenge_len);
    let application = std::slice::from_raw_parts(application_ptr, application_len);
    let key_handle = std::slice::from_raw_parts(key_handle_ptr, key_handle_len);

    let sig = mgr.sign(timeout, challenge.to_vec(), application.to_vec(), key_handle.to_vec());
    let _ = Box::into_raw(mgr);

    let sig = match sig {
        Ok(rv) => rv,
        _ => return // TODO error
    };

    if sig.len() > max_signature_len {
      return; // TODO error
    }

    *signature_len = sig.len();
    ptr::copy_nonoverlapping(sig.as_ptr(), signature_ptr, sig.len());
}
