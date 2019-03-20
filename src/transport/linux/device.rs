/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use super::hidraw;
use crate::ctap2::commands::{AuthenticatorInfo, ECDHSecret};
use consts::CID_BROADCAST;
use transport::hid::{Capability, Cid, DeviceVersion, HIDDevice};
use transport::Error;

#[derive(Debug)]
pub struct Device {
    path: PathBuf,
    fd: File,
    initialized: bool,
    cid: Cid,
    u2fhid_version: u8,
    device_version: DeviceVersion,
    capability: Capability,
    secret: Option<ECDHSecret>,
    authenticator_info: Option<AuthenticatorInfo>,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.path == other.path
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
}

impl HIDDevice for Device {
    type BuildParameters = PathBuf;
    type Id = PathBuf;

    fn new(path: PathBuf) -> Result<Self, Error> {
        debug!("Opening device {:?}", path);
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.clone())
            .map_err(|e| Error::IO(Some(path.clone()), e))?;

        if hidraw::is_u2f_device(fd.as_raw_fd()) {
            info!("new device {:?}", path);
            Ok(Self {
                path,
                fd,
                initialized: false,
                cid: CID_BROADCAST,
                u2fhid_version: 0,
                device_version: [0u8; 3],
                capability: Capability::empty(),
                secret: None,
                authenticator_info: None,
            })
        } else {
            Err(Error::DeviceNotSupported)
        }
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

    fn id(&self) -> Self::Id {
        self.path.clone()
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
        self.secret.as_ref()
    }

    fn set_shared_secret(&mut self, secret: ECDHSecret) {
        self.secret = Some(secret);
    }

    fn authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        self.authenticator_info = Some(authenticator_info);
    }
}
