/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::authenticatorservice::{
    AuthenticatorService, CtapVersion, RegisterArgsCtap1, RegisterArgsCtap2, SignArgsCtap1,
    SignArgsCtap2,
};
use crate::ctap2::attestation::AttestationStatement;
use crate::ctap2::commands::make_credentials::MakeCredentialsOptions;
use crate::ctap2::server::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, RelyingParty, User,
};
use crate::errors;
use crate::statecallback::StateCallback;
use crate::Pin;
use crate::{RegisterResult, SignResult};
use libc::size_t;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::mpsc::channel;
use std::thread;
use std::{ptr, slice};

type U2FAppIds = Vec<crate::AppId>;
type U2FKeyHandles = Vec<crate::KeyHandle>;
type U2FCallback = extern "C" fn(u64, *mut U2FResult);

pub enum U2FResult {
    Success(HashMap<u8, Vec<u8>>),
    Error(errors::AuthenticatorError),
}

const RESBUF_ID_REGISTRATION: u8 = 0;
const RESBUF_ID_KEYHANDLE: u8 = 1;
const RESBUF_ID_SIGNATURE: u8 = 2;
const RESBUF_ID_APPID: u8 = 3;
const RESBUF_ID_VENDOR_NAME: u8 = 4;
const RESBUF_ID_DEVICE_NAME: u8 = 5;
const RESBUF_ID_FIRMWARE_MAJOR: u8 = 6;
const RESBUF_ID_FIRMWARE_MINOR: u8 = 7;
const RESBUF_ID_FIRMWARE_BUILD: u8 = 8;
const RESBUF_ID_CTAP20_INDICATOR: u8 = 9;
const RESBUF_ID_ATTESTATION_STATEMENT_ALGORITHM: u8 = 10;
const RESBUF_ID_ATTESTATION_STATEMENT_SIGNATURE: u8 = 11;
const RESBUF_ID_ATTESTATION_STATEMENT_CERTIFICATE: u8 = 12;
const RESBUF_ID_ATTESTATION_STATEMENT_UNPARSED: u8 = 13;
const RESBUF_ID_AUTHENTICATOR_DATA: u8 = 14;
const RESBUF_ID_CLIENT_DATA: u8 = 15;

// Generates a new 64-bit transaction id with collision probability 2^-32.
fn new_tid() -> u64 {
    thread_rng().gen::<u64>()
}

unsafe fn from_raw(ptr: *const u8, len: usize) -> Vec<u8> {
    slice::from_raw_parts(ptr, len).to_vec()
}

/// # Safety
///
/// The handle returned by this method must be freed by the caller.
#[no_mangle]
pub extern "C" fn rust_u2f_mgr_new() -> *mut AuthenticatorService {
    if let Ok(mut mgr) = AuthenticatorService::new(CtapVersion::CTAP1) {
        mgr.add_detected_transports();
        Box::into_raw(Box::new(mgr))
    } else {
        ptr::null_mut()
    }
}

/// # Safety
///
/// This method must not be called on a handle twice, and the handle is unusable
/// after.
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_free(mgr: *mut AuthenticatorService) {
    if !mgr.is_null() {
        Box::from_raw(mgr);
    }
}

/// # Safety
///
/// The handle returned by this method must be freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_app_ids_new() -> *mut U2FAppIds {
    Box::into_raw(Box::new(vec![]))
}

/// # Safety
///
/// This method must be used on an actual U2FAppIds handle
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_app_ids_add(
    ids: *mut U2FAppIds,
    id_ptr: *const u8,
    id_len: usize,
) {
    (*ids).push(from_raw(id_ptr, id_len));
}

/// # Safety
///
/// This method must not be called on a handle twice, and the handle is unusable
/// after.
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_app_ids_free(ids: *mut U2FAppIds) {
    if !ids.is_null() {
        Box::from_raw(ids);
    }
}

/// # Safety
///
/// The handle returned by this method must be freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_khs_new() -> *mut U2FKeyHandles {
    Box::into_raw(Box::new(vec![]))
}

/// # Safety
///
/// This method must be used on an actual U2FKeyHandles handle
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_khs_add(
    khs: *mut U2FKeyHandles,
    key_handle_ptr: *const u8,
    key_handle_len: usize,
    transports: u8,
) {
    (*khs).push(crate::KeyHandle {
        credential: from_raw(key_handle_ptr, key_handle_len),
        transports: crate::AuthenticatorTransports::from_bits_truncate(transports),
    });
}

/// # Safety
///
/// This method must not be called on a handle twice, and the handle is unusable
/// after.
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_khs_free(khs: *mut U2FKeyHandles) {
    if !khs.is_null() {
        Box::from_raw(khs);
    }
}

/// # Safety
///
/// This method must be used on an actual U2FResult handle
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_result_error(res: *const U2FResult) -> u8 {
    if res.is_null() {
        return errors::U2FTokenError::Unknown as u8;
    }

    if let U2FResult::Error(ref err) = *res {
        return err.as_u2f_errorcode();
    }

    0 /* No error, the request succeeded. */
}

/// # Safety
///
/// This method must be used before rust_u2f_resbuf_copy
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_resbuf_contains(res: *const U2FResult, bid: u8) -> bool {
    if res.is_null() {
        return false;
    }

    if let U2FResult::Success(ref bufs) = *res {
        return bufs.contains_key(&bid);
    }

    false
}

/// # Safety
///
/// This method must be used before rust_u2f_resbuf_copy
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_resbuf_length(
    res: *const U2FResult,
    bid: u8,
    len: *mut size_t,
) -> bool {
    if res.is_null() {
        return false;
    }

    if let U2FResult::Success(ref bufs) = *res {
        if let Some(buf) = bufs.get(&bid) {
            *len = buf.len();
            return true;
        }
    }

    false
}

/// # Safety
///
/// This method does not ensure anything about dst before copying, so
/// ensure it is long enough (using rust_u2f_resbuf_length)
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_resbuf_copy(
    res: *const U2FResult,
    bid: u8,
    dst: *mut u8,
) -> bool {
    if res.is_null() {
        return false;
    }

    if let U2FResult::Success(ref bufs) = *res {
        if let Some(buf) = bufs.get(&bid) {
            ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len());
            return true;
        }
    }

    false
}

/// # Safety
///
/// This method should not be called on U2FResult handles after they've been
/// freed or a double-free will occur
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_res_free(res: *mut U2FResult) {
    if !res.is_null() {
        Box::from_raw(res);
    }
}

/// # Safety
///
/// This method should not be called on AuthenticatorService handles after
/// they've been freed
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_register(
    mgr: *mut AuthenticatorService,
    flags: u64,
    timeout: u64,
    callback: U2FCallback,
    challenge_ptr: *const u8,
    challenge_len: usize,
    application_ptr: *const u8,
    application_len: usize,
    khs: *const U2FKeyHandles,
) -> u64 {
    if mgr.is_null() {
        return 0;
    }

    // Check buffers.
    if challenge_ptr.is_null() || application_ptr.is_null() {
        return 0;
    }

    let flags = crate::RegisterFlags::from_bits_truncate(flags);
    let challenge = from_raw(challenge_ptr, challenge_len);
    let application = from_raw(application_ptr, application_len);
    let key_handles = (*khs).clone();

    let (status_tx, status_rx) = channel::<crate::StatusUpdate>();
    thread::spawn(move || loop {
        // Issue https://github.com/mozilla/authenticator-rs/issues/132 will
        // plumb the status channel through to the actual C API signatures
        match status_rx.recv() {
            Ok(_) => {}
            Err(_recv_error) => return,
        }
    });

    let tid = new_tid();

    let state_callback = StateCallback::<crate::Result<RegisterResult>>::new(Box::new(move |rv| {
        let result = match rv {
            Ok(RegisterResult::CTAP1(registration, dev_info)) => {
                let mut bufs = HashMap::new();
                bufs.insert(RESBUF_ID_REGISTRATION, registration);
                bufs.insert(RESBUF_ID_VENDOR_NAME, dev_info.vendor_name);
                bufs.insert(RESBUF_ID_DEVICE_NAME, dev_info.device_name);
                bufs.insert(RESBUF_ID_FIRMWARE_MAJOR, vec![dev_info.version_major]);
                bufs.insert(RESBUF_ID_FIRMWARE_MINOR, vec![dev_info.version_minor]);
                bufs.insert(RESBUF_ID_FIRMWARE_BUILD, vec![dev_info.version_build]);
                U2FResult::Success(bufs)
            }
            Ok(RegisterResult::CTAP2(..)) => U2FResult::Error(
                errors::AuthenticatorError::VersionMismatch("rust_u2f_mgr_register", 1),
            ),
            Err(e) => U2FResult::Error(e),
        };

        callback(tid, Box::into_raw(Box::new(result)));
    }));
    let ctap_args = RegisterArgsCtap1 {
        flags,
        challenge,
        application,
        key_handles,
    };

    let res = (*mgr).register(timeout, ctap_args.into(), status_tx, state_callback);

    if res.is_ok() {
        tid
    } else {
        0
    }
}

/// # Safety
///
/// This method should not be called on AuthenticatorService handles after
/// they've been freed
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_sign(
    mgr: *mut AuthenticatorService,
    flags: u64,
    timeout: u64,
    callback: U2FCallback,
    challenge_ptr: *const u8,
    challenge_len: usize,
    app_ids: *const U2FAppIds,
    khs: *const U2FKeyHandles,
) -> u64 {
    if mgr.is_null() || khs.is_null() {
        return 0;
    }

    // Check buffers.
    if challenge_ptr.is_null() {
        return 0;
    }

    // Need at least one app_id.
    if (*app_ids).is_empty() {
        return 0;
    }

    let flags = crate::SignFlags::from_bits_truncate(flags);
    let challenge = from_raw(challenge_ptr, challenge_len);
    let app_ids = (*app_ids).clone();
    let key_handles = (*khs).clone();

    let (status_tx, status_rx) = channel::<crate::StatusUpdate>();
    thread::spawn(move || loop {
        // Issue https://github.com/mozilla/authenticator-rs/issues/132 will
        // plumb the status channel through to the actual C API signatures
        match status_rx.recv() {
            Ok(_) => {}
            Err(_recv_error) => return,
        }
    });

    let tid = new_tid();
    let state_callback = StateCallback::<crate::Result<SignResult>>::new(Box::new(move |rv| {
        let result = match rv {
            Ok(SignResult::CTAP1(app_id, key_handle, signature, dev_info)) => {
                let mut bufs = HashMap::new();
                bufs.insert(RESBUF_ID_KEYHANDLE, key_handle);
                bufs.insert(RESBUF_ID_SIGNATURE, signature);
                bufs.insert(RESBUF_ID_APPID, app_id);
                bufs.insert(RESBUF_ID_VENDOR_NAME, dev_info.vendor_name);
                bufs.insert(RESBUF_ID_DEVICE_NAME, dev_info.device_name);
                bufs.insert(RESBUF_ID_FIRMWARE_MAJOR, vec![dev_info.version_major]);
                bufs.insert(RESBUF_ID_FIRMWARE_MINOR, vec![dev_info.version_minor]);
                bufs.insert(RESBUF_ID_FIRMWARE_BUILD, vec![dev_info.version_build]);
                U2FResult::Success(bufs)
            }
            Ok(SignResult::CTAP2(..)) => U2FResult::Error(
                errors::AuthenticatorError::VersionMismatch("rust_u2f_mgr_sign", 1),
            ),
            Err(e) => U2FResult::Error(e),
        };

        callback(tid, Box::into_raw(Box::new(result)));
    }));

    let res = (*mgr).sign(
        timeout,
        SignArgsCtap1 {
            flags,
            challenge,
            app_ids,
            key_handles,
        }
        .into(),
        status_tx,
        state_callback,
    );

    if res.is_ok() {
        tid
    } else {
        0
    }
}

/// # Safety
///
/// This method should not be called AuthenticatorService handles after they've
/// been freed
#[no_mangle]
pub unsafe extern "C" fn rust_u2f_mgr_cancel(mgr: *mut AuthenticatorService) {
    if !mgr.is_null() {
        // Ignore return value.
        let _ = (*mgr).cancel();
    }
}

/// # Safety
///
/// The handle returned by this method must be freed by the caller.
/// The returned handle can be used with all rust_u2f_mgr_*-functions as well
/// but uses CTAP2 as the underlying protocol. CTAP1 requests will be repackaged
/// into CTAP2 (if the device supports it)
#[no_mangle]
pub extern "C" fn rust_ctap2_mgr_new() -> *mut AuthenticatorService {
    if let Ok(mut mgr) = AuthenticatorService::new(CtapVersion::CTAP2) {
        mgr.add_detected_transports();
        Box::into_raw(Box::new(mgr))
    } else {
        ptr::null_mut()
    }
}

#[repr(C)]
pub struct RegisterArgsUser {
    id_ptr: *const u8,
    id_len: usize,
    name: *const c_char,
}

#[repr(C)]
pub struct RegisterArgsChallenge {
    ptr: *const u8,
    len: usize,
}

#[repr(C)]
pub struct RegisterArgsPubCred {
    ptr: *const i32,
    len: usize,
}

#[repr(C)]
pub struct RegisterArgsOptions {
    resident_key: bool,
    user_verification: bool,
}
/// # Safety
///
/// This method should not be called on AuthenticatorService handles after
/// they've been freed
/// All input is copied and it is the callers responsibility to free appropriately.
/// Note: `KeyHandles` are used as `PublicKeyCredentialDescriptor`s for the exclude_list
///       to keep the API smaller, as they are essentially the same thing.
///       `PublicKeyCredentialParameters` in pub_cred_params are represented as i32 with
///       their COSE value (see: https://www.iana.org/assignments/cose/cose.xhtml#table-algorithms)
#[no_mangle]
pub unsafe extern "C" fn rust_ctap2_mgr_register(
    mgr: *mut AuthenticatorService,
    timeout: u64,
    callback: U2FCallback,
    challenge: RegisterArgsChallenge,
    relying_party_id: *const c_char,
    origin_ptr: *const c_char,
    user: RegisterArgsUser,
    pub_cred_params: RegisterArgsPubCred,
    exclude_list: *const U2FKeyHandles,
    options: RegisterArgsOptions,
    pin_ptr: *const c_char,
) -> u64 {
    if mgr.is_null() {
        return 0;
    }

    // Check buffers.
    if challenge.ptr.is_null()
        || origin_ptr.is_null()
        || relying_party_id.is_null()
        || user.id_ptr.is_null()
        || user.name.is_null()
        || exclude_list.is_null()
    {
        return 0;
    }

    let pub_cred_params = slice::from_raw_parts(pub_cred_params.ptr, pub_cred_params.len)
        .iter()
        .map(|x| PublicKeyCredentialParameters::from(*x))
        .collect();
    let pin = if pin_ptr.is_null() {
        None
    } else {
        Some(Pin::new(&CStr::from_ptr(pin_ptr).to_string_lossy()))
    };
    let user = User {
        id: from_raw(user.id_ptr, user.id_len),
        name: CStr::from_ptr(user.name).to_string_lossy().to_string(), // TODO(MS): Use to_str() and error out on failure?
        display_name: None,
        icon: None,
    };
    let rp = RelyingParty {
        id: CStr::from_ptr(relying_party_id)
            .to_string_lossy()
            .to_string(),
        name: None,
        icon: None,
    };
    let origin = CStr::from_ptr(origin_ptr).to_string_lossy().to_string();
    let challenge = from_raw(challenge.ptr, challenge.len);
    let exclude_list = (*exclude_list)
        .clone()
        .iter()
        .map(|x| PublicKeyCredentialDescriptor::from(x))
        .collect();

    let (status_tx, status_rx) = channel::<crate::StatusUpdate>();
    thread::spawn(move || loop {
        // Issue https://github.com/mozilla/authenticator-rs/issues/132 will
        // plumb the status channel through to the actual C API signatures
        match status_rx.recv() {
            Ok(_) => {}
            Err(_recv_error) => return,
        }
    });

    let tid = new_tid();

    let state_callback = StateCallback::<crate::Result<RegisterResult>>::new(Box::new(move |rv| {
        let result = match rv {
            Ok(RegisterResult::CTAP1(..)) => U2FResult::Error(
                errors::AuthenticatorError::VersionMismatch("rust_u2f_mgr_sign", 2),
            ),
            Ok(RegisterResult::CTAP2(attestation_object, client_data)) => {
                let mut bufs = HashMap::new();
                bufs.insert(RESBUF_ID_CTAP20_INDICATOR, Vec::new());
                if let Some(cred_data) = &attestation_object.auth_data.credential_data {
                    bufs.insert(RESBUF_ID_KEYHANDLE, cred_data.credential_id.clone());
                }

                let auth_data = attestation_object.auth_data.to_vec();
                bufs.insert(RESBUF_ID_AUTHENTICATOR_DATA, auth_data);

                let client_data = serde_json::to_vec(&client_data).unwrap(); // TODO(MS)
                bufs.insert(RESBUF_ID_CLIENT_DATA, client_data);

                match attestation_object.att_statement {
                    AttestationStatement::None => { /* TODO(MS): What to do here?*/ }
                    AttestationStatement::Packed(att) => {
                        let alg_id: i64 = att.alg.into();
                        bufs.insert(
                            RESBUF_ID_ATTESTATION_STATEMENT_ALGORITHM,
                            alg_id.to_ne_bytes().to_vec(),
                        );

                        bufs.insert(
                            RESBUF_ID_ATTESTATION_STATEMENT_SIGNATURE,
                            att.sig.as_ref().to_vec(),
                        );
                        bufs.insert(
                            RESBUF_ID_ATTESTATION_STATEMENT_CERTIFICATE,
                            att.attestation_cert
                                .iter()
                                .map(|x| x.0.clone())
                                .flatten()
                                .collect::<Vec<u8>>(), // TODO(MS): FF can only handle cert-chain of length 1
                        );
                    }
                    AttestationStatement::FidoU2F(att) => {
                        bufs.insert(
                            RESBUF_ID_ATTESTATION_STATEMENT_SIGNATURE,
                            att.sig.as_ref().to_vec(),
                        );
                        bufs.insert(
                            RESBUF_ID_ATTESTATION_STATEMENT_CERTIFICATE,
                            att.attestation_cert
                                .iter()
                                .map(|x| x.0.clone())
                                .flatten()
                                .collect::<Vec<u8>>(), // TODO(MS): FF can only handle cert-chain of length 1
                        );
                    }
                    AttestationStatement::Unparsed(att) => {
                        bufs.insert(RESBUF_ID_ATTESTATION_STATEMENT_UNPARSED, att.clone());
                    }
                }

                U2FResult::Success(bufs)
            }
            Err(e) => U2FResult::Error(e),
        };

        callback(tid, Box::into_raw(Box::new(result)));
    }));

    let ctap_args = RegisterArgsCtap2 {
        challenge,
        relying_party: rp,
        origin,
        user,
        pub_cred_params,
        exclude_list,
        options: MakeCredentialsOptions {
            resident_key: options.resident_key.then(|| true),
            user_verification: options.user_verification.then(|| true),
        },
        pin,
    };

    let res = (*mgr).register(timeout, ctap_args.into(), status_tx, state_callback);

    if res.is_ok() {
        tid
    } else {
        0
    }
}

/// # Safety
///
/// This method should not be called on AuthenticatorService handles after
/// they've been freed
/// Note: `KeyHandles` are used as `PublicKeyCredentialDescriptor`s for the exclude_list
///       to keep the API smaller, as they are essentially the same thing.
///       `PublicKeyCredentialParameters` in pub_cred_params are represented as i32 with
///       their COSE value (see: https://www.iana.org/assignments/cose/cose.xhtml#table-algorithms)
#[no_mangle]
pub unsafe extern "C" fn rust_ctap2_mgr_sign(
    mgr: *mut AuthenticatorService,
    timeout: u64,
    callback: U2FCallback,
    flags: u64,
    challenge_ptr: *const u8,
    challenge_len: usize,
    relying_party_id: *const c_char,
    origin_ptr: *const c_char,
    allow_list: *const U2FKeyHandles,
    pin_ptr: *const c_char,
) -> u64 {
    if mgr.is_null() {
        return 0;
    }

    // Check buffers.
    if challenge_ptr.is_null()
        || origin_ptr.is_null()
        || relying_party_id.is_null()
        || allow_list.is_null()
    {
        return 0;
    }

    let flags = crate::SignFlags::from_bits_truncate(flags);
    let pin = if pin_ptr.is_null() {
        None
    } else {
        Some(Pin::new(&CStr::from_ptr(pin_ptr).to_string_lossy()))
    };
    let rpid = CStr::from_ptr(relying_party_id)
        .to_string_lossy()
        .to_string();
    let origin = CStr::from_ptr(origin_ptr).to_string_lossy().to_string();
    let challenge = from_raw(challenge_ptr, challenge_len);
    let allow_list: Vec<_> = (*allow_list)
        .clone()
        .iter()
        .map(|x| PublicKeyCredentialDescriptor::from(x))
        .collect();

    let (status_tx, status_rx) = channel::<crate::StatusUpdate>();
    thread::spawn(move || loop {
        // Issue https://github.com/mozilla/authenticator-rs/issues/132 will
        // plumb the status channel through to the actual C API signatures
        match status_rx.recv() {
            Ok(_) => {}
            Err(_recv_error) => return,
        }
    });

    let single_key_handle = if allow_list.len() == 1 {
        Some(allow_list.first().unwrap().id.clone())
    } else {
        None
    };

    let tid = new_tid();
    let state_callback = StateCallback::<crate::Result<SignResult>>::new(Box::new(move |rv| {
        let result = match rv {
            Ok(SignResult::CTAP1(..)) => U2FResult::Error(
                errors::AuthenticatorError::VersionMismatch("rust_u2f_mgr_sign", 1),
            ),
            Ok(SignResult::CTAP2(assertion_object, client_data)) => {
                // We can only handle length 1 assertion chains at the moment
                let assertion = assertion_object.0.first().unwrap(); // TODO(MS)!
                let mut bufs = HashMap::new();
                bufs.insert(RESBUF_ID_CTAP20_INDICATOR, Vec::new());
                bufs.insert(RESBUF_ID_SIGNATURE, assertion.signature.clone());

                // Credential data can be omitted by the token, if allow-list has length of 1
                if let Some(cred_data) = &assertion.auth_data.credential_data {
                    bufs.insert(RESBUF_ID_KEYHANDLE, cred_data.credential_id.clone());
                } else if let Some(key_handle) = &single_key_handle {
                    bufs.insert(RESBUF_ID_KEYHANDLE, key_handle.to_vec());
                }

                let auth_data = assertion.auth_data.to_vec();
                bufs.insert(RESBUF_ID_AUTHENTICATOR_DATA, auth_data);

                let client_data = serde_json::to_vec(&client_data).unwrap(); // TODO(MS)
                bufs.insert(RESBUF_ID_CLIENT_DATA, client_data);

                if let Some(user) = &assertion.user {
                    bufs.insert(RESBUF_ID_APPID, user.id.clone()); // Misusing AppID for this
                }
                U2FResult::Success(bufs)
            }
            Err(e) => U2FResult::Error(e),
        };

        callback(tid, Box::into_raw(Box::new(result)));
    }));

    let res = (*mgr).sign(
        timeout,
        SignArgsCtap2 {
            flags,
            challenge,
            origin,
            relying_party_id: rpid,
            allow_list,
            pin,
        }
        .into(),
        status_tx,
        state_callback,
    );

    if res.is_ok() {
        tid
    } else {
        0
    }
}
