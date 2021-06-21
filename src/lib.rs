/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
mod util;

#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "freebsd"))]
extern crate devd_rs;

#[cfg(any(target_os = "macos"))]
extern crate core_foundation;

extern crate libc;
#[macro_use]
extern crate log;
extern crate rand;
extern crate runloop;

#[macro_use]
extern crate bitflags;

pub mod authenticatorservice;
mod consts;
mod statemachine;
mod u2fprotocol;
mod u2ftypes;

mod manager;
pub use crate::manager::U2FManager;

mod capi;
pub use crate::capi::*;

pub mod ctap2;
pub use ctap2::attestation::AttestationObject;
pub use ctap2::client_data::CollectedClientData;
pub use ctap2::AssertionObject;

pub mod errors;
pub mod statecallback;
mod transport;
mod virtualdevices;

// Keep this in sync with the constants in u2fhid-capi.h.
bitflags! {
    pub struct RegisterFlags: u64 {
        const REQUIRE_RESIDENT_KEY        = 1;
        const REQUIRE_USER_VERIFICATION   = 2;
        const REQUIRE_PLATFORM_ATTACHMENT = 4;
    }
}
bitflags! {
    pub struct SignFlags: u64 {
        const REQUIRE_USER_VERIFICATION = 1;
    }
}
bitflags! {
    pub struct AuthenticatorTransports: u8 {
        const USB = 1;
        const NFC = 2;
        const BLE = 4;
    }
}

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub credential: Vec<u8>,
    pub transports: AuthenticatorTransports,
}

pub type AppId = Vec<u8>;

pub enum RegisterResult {
    CTAP1(Vec<u8>, u2ftypes::U2FDeviceInfo),
    CTAP2(AttestationObject, CollectedClientData),
}

pub enum SignResult {
    CTAP1(AppId, Vec<u8>, Vec<u8>, u2ftypes::U2FDeviceInfo),
    CTAP2(AssertionObject),
}

pub type Result<T> = std::result::Result<T, errors::AuthenticatorError>;

#[derive(Debug, Clone)]
pub enum StatusUpdate {
    DeviceAvailable { dev_info: u2ftypes::U2FDeviceInfo },
    DeviceUnavailable { dev_info: u2ftypes::U2FDeviceInfo },
    Success { dev_info: u2ftypes::U2FDeviceInfo },
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(fuzzing)]
pub use consts::*;
#[cfg(fuzzing)]
pub use u2fprotocol::*;
#[cfg(fuzzing)]
pub use u2ftypes::*;
