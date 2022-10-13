/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;
use crate::consts::CID_BROADCAST;
use crate::transport::hid::HIDDevice;
use crate::transport::platform::{hidraw, monitor};
use crate::transport::{AuthenticatorInfo, ECDHSecret, FidoDevice, HIDError};
use crate::u2ftypes::{U2FDevice, U2FDeviceInfo};
use crate::util::from_unix_result;
use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Device {
    path: PathBuf,
    fd: std::fs::File,
    in_rpt_size: usize,
    out_rpt_size: usize,
    cid: [u8; 4],
    dev_info: Option<U2FDeviceInfo>,
    secret: Option<ECDHSecret>,
    authenticator_info: Option<AuthenticatorInfo>,
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        // The path should be the only identifying member for a device
        // If the path is the same, its the same device
        self.path == other.path
    }
}

impl Eq for Device {}

impl Hash for Device {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // The path should be the only identifying member for a device
        // If the path is the same, its the same device
        self.path.hash(state);
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bufp = buf.as_mut_ptr() as *mut libc::c_void;
        let rv = unsafe { libc::read(self.fd.as_raw_fd(), bufp, buf.len()) };
        from_unix_result(rv as usize)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bufp = buf.as_ptr() as *const libc::c_void;
        let rv = unsafe { libc::write(self.fd.as_raw_fd(), bufp, buf.len()) };
        from_unix_result(rv as usize)
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl U2FDevice for Device {
    fn get_cid(&self) -> &[u8; 4] {
        &self.cid
    }

    fn set_cid(&mut self, cid: [u8; 4]) {
        self.cid = cid;
    }

    fn in_rpt_size(&self) -> usize {
        self.in_rpt_size
    }

    fn out_rpt_size(&self) -> usize {
        self.out_rpt_size
    }

    fn get_property(&self, prop_name: &str) -> io::Result<String> {
        monitor::get_property_linux(&self.path, prop_name)
    }

    fn get_device_info(&self) -> U2FDeviceInfo {
        // unwrap is okay, as dev_info must have already been set, else
        // a programmer error
        self.dev_info.clone().unwrap()
    }

    fn set_device_info(&mut self, dev_info: U2FDeviceInfo) {
        self.dev_info = Some(dev_info);
    }
}

impl HIDDevice for Device {
    type BuildParameters = PathBuf;
    type Id = PathBuf;

    fn new(path: PathBuf) -> Result<Self, (HIDError, Self::Id)> {
        debug!("Opening device {:?}", path);
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| (HIDError::IO(Some(path.clone()), e), path.clone()))?;
        let (in_rpt_size, out_rpt_size) = hidraw::read_hid_rpt_sizes_or_defaults(fd.as_raw_fd());
        let res = Self {
            path,
            fd,
            in_rpt_size,
            out_rpt_size,
            cid: CID_BROADCAST,
            dev_info: None,
            secret: None,
            authenticator_info: None,
        };
        if res.is_u2f() {
            info!("new device {:?}", res.path);
            Ok(res)
        } else {
            Err((HIDError::DeviceNotSupported, res.path.clone()))
        }
    }

    fn initialized(&self) -> bool {
        // During successful init, the broadcast channel id gets repplaced by an actual one
        self.cid != CID_BROADCAST
    }

    fn id(&self) -> Self::Id {
        self.path.clone()
    }

    fn is_u2f(&self) -> bool {
        hidraw::is_u2f_device(self.fd.as_raw_fd())
    }

    fn get_shared_secret(&self) -> Option<&ECDHSecret> {
        self.secret.as_ref()
    }

    fn set_shared_secret(&mut self, secret: ECDHSecret) {
        self.secret = Some(secret);
    }

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        self.authenticator_info = Some(authenticator_info);
    }

    /// This is used for cancellation of blocking read()-requests.
    /// With this, we can clone the Device, pass it to another thread and call "cancel()" on that.
    fn clone_device_as_write_only(&self) -> Result<Self, HIDError> {
        let fd = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| (HIDError::IO(Some(self.path.clone()), e)))?;

        Ok(Self {
            path: self.path.clone(),
            fd,
            in_rpt_size: self.in_rpt_size,
            out_rpt_size: self.out_rpt_size,
            cid: self.cid,
            dev_info: self.dev_info.clone(),
            secret: self.secret.clone(),
            authenticator_info: self.authenticator_info.clone(),
        })
    }
}

impl FidoDevice for Device {}
