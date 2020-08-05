/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub enum TestWireProtocol {
    CTAP1,
    CTAP2,
}

pub struct TestToken {
    pub id: u64,
    pub protocol: TestWireProtocol,
    pub is_user_consenting: bool,
    pub has_user_verification: bool,
    pub is_user_verified: bool,
    pub has_resident_key: bool,
}

impl TestToken {
    pub fn register(&self) -> Result<crate::RegisterResult, crate::Error> {
        Ok((vec![0u8; 16], self.dev_info()))
    }
    pub fn sign(&self) -> Result<crate::SignResult, crate::Error> {
        Ok((vec![0u8; 0], vec![0u8; 0], vec![0u8; 0], self.dev_info()))
    }
    pub fn dev_info(&self) -> crate::u2ftypes::U2FDeviceInfo {
        crate::u2ftypes::U2FDeviceInfo {
            vendor_name: String::from("Mozilla").into_bytes(),
            device_name: String::from("Authenticator Webdriver Token").into_bytes(),
            version_interface: 0,
            version_major: 1,
            version_minor: 2,
            version_build: 3,
            cap_flags: 0,
        }
    }
}
