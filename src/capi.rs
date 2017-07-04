use libc::size_t;
use std::collections::HashMap;
use std::{ptr, slice};

use ::U2FManager;

type U2FResult = HashMap<u8, Vec<u8>>;
type U2FCallback = extern "C" fn (u64, *mut U2FResult);

const RESBUF_ID_REGISTRATION : u8 = 0;
const RESBUF_ID_KEYHANDLE : u8 = 1;
const RESBUF_ID_SIGNATURE : u8 = 2;

unsafe fn from_raw(ptr: *const u8, len: usize) -> Vec<u8> {
    slice::from_raw_parts(ptr, len).to_vec()
}

#[no_mangle]
pub extern "C" fn rust_u2f_mgr_new() -> *mut U2FManager
{
    if let Ok(mgr) = U2FManager::new() {
        Box::into_raw(Box::new(mgr))
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_free(mgr: *mut U2FManager)
{
    if !mgr.is_null() {
        Box::from_raw(mgr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_resbuf_length(res: *const U2FResult,
                                                bid: u8,
                                                len: *mut size_t) -> bool
{
    if res.is_null() {
        return false;
    }

    if let Some(buf) = (*res).get(&bid) {
        *len = buf.len();
        return true;
    }

    false
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_resbuf_copy(res: *const U2FResult,
                                              bid: u8,
                                              dst: *mut u8) -> bool
{
    if res.is_null() {
        return false;
    }

    if let Some(buf) = (*res).get(&bid) {
        ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len());
        return true;
    }

    false
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_res_free(res: *mut U2FResult)
{
    if !res.is_null() {
        Box::from_raw(res);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_register(mgr: *mut U2FManager,
                                               tid: u64,
                                               timeout: u64,
                                               callback: U2FCallback,
                                               challenge_ptr: *const u8,
                                               challenge_len: usize,
                                               application_ptr: *const u8,
                                               application_len: usize) -> bool
{
    if mgr.is_null() {
        return false;
    }

    let challenge = from_raw(challenge_ptr, challenge_len);
    let application = from_raw(application_ptr, application_len);

    let res = (*mgr).register(timeout, challenge, application, move |rv| {
        if let Ok(registration) = rv {
            let mut result = U2FResult::new();
            result.insert(RESBUF_ID_REGISTRATION, registration);
            callback(tid, Box::into_raw(Box::new(result)));
        } else {
            callback(tid, ptr::null_mut());
        };
    });

    res.is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_sign(mgr: *mut U2FManager,
                                           tid: u64,
                                           timeout: u64,
                                           callback: U2FCallback,
                                           challenge_ptr: *const u8,
                                           challenge_len: usize,
                                           application_ptr: *const u8,
                                           application_len: usize,
                                           key_handle_ptr: *const u8,
                                           key_handle_len: usize) -> bool
{
    if mgr.is_null() {
        return false;
    }

    let challenge = from_raw(challenge_ptr, challenge_len);
    let application = from_raw(application_ptr, application_len);
    let key_handle = from_raw(key_handle_ptr, key_handle_len);

    // TODO no need to clone as soon as sign() returns the chosen key handle
    let res = (*mgr).sign(timeout, challenge, application, key_handle.clone(), move |rv| {
        if let Ok(signature) = rv {
            let mut result = U2FResult::new();
            result.insert(RESBUF_ID_KEYHANDLE, key_handle);
            result.insert(RESBUF_ID_SIGNATURE, signature);
            callback(tid, Box::into_raw(Box::new(result)));
        } else {
            callback(tid, ptr::null_mut());
        };
    });

    res.is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_cancel(mgr: *mut U2FManager)
{
    if !mgr.is_null() {
        // Ignore return value.
        let _ = (*mgr).cancel();
    }
}
