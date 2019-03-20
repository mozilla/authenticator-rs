/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use std::io;
use std::io::{Read, Write};

use super::TestCase;
use consts::CID_BROADCAST;
use ctap2::commands::{AuthenticatorInfo, ECDHSecret};
use transport::hid::{Cid, DeviceVersion, HIDDevice};
use transport::{Capability, Error};

#[derive(Debug)]
pub struct Device {
    test_case: TestCase,
    initialized: bool,
    cid: Cid,
    u2fhid_version: u8,
    device_version: DeviceVersion,
    capability: Capability,
    authenticator_info: Option<AuthenticatorInfo>,
    shared_secret: Option<ECDHSecret>,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.test_case == other.test_case
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("writing to device {:?}: {:?}", self.test_case, buf);
        Ok(buf.len())
    }
}

impl Write for Device {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl HIDDevice for Device {
    type BuildParameters = TestCase;
    type Id = TestCase;

    fn new(test_case: TestCase) -> Result<Self, Error> {
        Ok(Self {
            test_case,
            initialized: false,
            cid: CID_BROADCAST,
            u2fhid_version: 0,
            device_version: [0u8; 3],
            capability: Capability::empty(),
            authenticator_info: None,
            shared_secret: None,
        })
    }

    fn id(&self) -> Self::Id {
        self.test_case
    }

    fn initialized(&self) -> bool {
        self.initialized
    }

    fn initialize(&mut self) {
        self.initialized = true;
    }

    fn cid(&self) -> &Cid {
        &self.cid
    }

    fn set_cid(&mut self, cid: Cid) {
        self.cid = cid;
    }

    fn u2fhid_version(&self) -> u8 {
        self.u2fhid_version
    }

    fn set_u2fhid_version(&mut self, version: u8) {
        self.u2fhid_version = version;
    }

    fn device_version(&self) -> &DeviceVersion {
        &self.device_version
    }

    fn set_device_version(&mut self, device_version: DeviceVersion) {
        self.device_version = device_version;
    }

    fn capabilities(&self) -> Capability {
        self.capability
    }

    fn set_capabilities(&mut self, capabilities: Capability) {
        self.capability = capabilities;
    }

    fn shared_secret(&self) -> Option<&ECDHSecret> {
        self.shared_secret.as_ref()
    }
    fn set_shared_secret(&mut self, secret: ECDHSecret) {
        self.shared_secret = Some(secret)
    }

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }
    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        self.authenticator_info = Some(authenticator_info)
    }
}
