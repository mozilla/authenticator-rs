/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;
use crate::consts::{CID_BROADCAST, MAX_HID_RPT_SIZE};
use crate::transport::hid::HIDDevice;
use crate::transport::platform::fd::Fd;
use crate::transport::platform::monitor::WrappedOpenDevice;
use crate::transport::platform::uhid;
use crate::transport::{AuthenticatorInfo, ECDHSecret, FidoDevice, HIDError};
use crate::u2ftypes::{U2FDevice, U2FDeviceInfo};
use crate::util::io_err;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::mem;

#[derive(Debug)]
pub struct Device {
    path: OsString,
    fd: Fd,
    cid: [u8; 4],
    dev_info: Option<U2FDeviceInfo>,
    secret: Option<ECDHSecret>,
    authenticator_info: Option<AuthenticatorInfo>,
}

impl Device {
    fn ping(&mut self) -> io::Result<()> {
        for i in 0..10 {
            let mut buf = vec![0u8; 1 + MAX_HID_RPT_SIZE];

            buf[0] = 0; // report number
            buf[1] = 0xff; // CID_BROADCAST
            buf[2] = 0xff;
            buf[3] = 0xff;
            buf[4] = 0xff;
            buf[5] = 0x81; // ping
            buf[6] = 0;
            buf[7] = 1; // one byte

            self.write(&buf[..])?;

            // Wait for response
            let mut pfd: libc::pollfd = unsafe { mem::zeroed() };
            pfd.fd = self.fd.fileno;
            pfd.events = libc::POLLIN;
            let nfds = unsafe { libc::poll(&mut pfd, 1, 100) };
            if nfds == -1 {
                return Err(io::Error::last_os_error());
            }
            if nfds == 0 {
                debug!("device timeout {}", i);
                continue;
            }

            // Read response
            self.read(&mut buf[..])?;

            return Ok(());
        }

        Err(io_err("no response from device"))
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.fd == other.fd
    }
}

impl Eq for Device {}

impl Hash for Device {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fd.hash(state);
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bufp = buf.as_mut_ptr() as *mut libc::c_void;
        let nread = unsafe { libc::read(self.fd.fileno, bufp, buf.len()) };
        if nread == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(nread as usize)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Always skip the first byte (report number)
        let data = &buf[1..];
        let data_ptr = data.as_ptr() as *const libc::c_void;
        let nwrit = unsafe { libc::write(self.fd.fileno, data_ptr, data.len()) };
        if nwrit == -1 {
            return Err(io::Error::last_os_error());
        }
        // Pretend we wrote the report number byte
        Ok(nwrit as usize + 1)
    }

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
        MAX_HID_RPT_SIZE
    }

    fn out_rpt_size(&self) -> usize {
        MAX_HID_RPT_SIZE
    }

    fn get_property(&self, _prop_name: &str) -> io::Result<String> {
        Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
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
    type BuildParameters = WrappedOpenDevice;
    type Id = OsString;

    fn new(fido: WrappedOpenDevice) -> Result<Self, (HIDError, Self::Id)> {
        debug!("device found: {:?}", fido);
        let mut res = Self {
            path: fido.os_path,
            fd: fido.fd,
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

    fn is_u2f(&mut self) -> bool {
        if !uhid::is_u2f_device(&self.fd) {
            return false;
        }
        // This step is not strictly necessary -- NetBSD puts fido
        // devices into raw mode automatically by default, but in
        // principle that might change, and this serves as a test to
        // verify that we're running on a kernel with support for raw
        // mode at all so we don't get confused issuing writes that try
        // to set the report descriptor rather than transfer data on
        // the output interrupt pipe as we need.
        match uhid::hid_set_raw(&self.fd, true) {
            Ok(_) => (),
            Err(_) => return false,
        }
        if let Err(_) = self.ping() {
            return false;
        }
        true
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
        // Try to open the device.
        let fd = Fd::open(&self.path, libc::O_WRONLY)?;
        Ok(Self {
            path: self.path.clone(),
            fd,
            cid: self.cid,
            dev_info: self.dev_info.clone(),
            secret: self.secret.clone(),
            authenticator_info: self.authenticator_info.clone(),
        })
    }
}

impl FidoDevice for Device {}
