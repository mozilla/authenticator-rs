extern crate libc;
extern crate log;

use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use consts::HID_RPT_SIZE;
use core_foundation_sys::base::*;
use u2ftypes::U2FDevice;

use super::iokit::*;

const READ_TIMEOUT: u64 = 15;

pub struct Report {
    pub data: [u8; HID_RPT_SIZE],
    pub len: usize,
}

unsafe impl Send for Report {}
unsafe impl Sync for Report {}

pub struct Device {
    pub device_ref: IOHIDDeviceRef,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
    pub report_recv: Receiver<Report>,
    pub report_send_void: *mut libc::c_void,
}

impl Drop for Device {
    fn drop(&mut self) {
        debug!("Dropping U2F device {}", self);
        // Re-allocate this raw pointer for destruction
        let _ = unsafe { Box::from_raw(self.report_send_void) };
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "InternalDevice(ref:{:?}, cid: {:02x}{:02x}{:02x}{:02x})",
            self.device_ref,
            self.cid[0],
            self.cid[1],
            self.cid[2],
            self.cid[3]
        )
    }
}

impl PartialEq for Device {
    fn eq(&self, other_device: &Device) -> bool {
        self.device_ref == other_device.device_ref
    }
}

impl Read for Device {
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        let timeout = Duration::from_secs(READ_TIMEOUT);
        let report_data = match self.report_recv.recv_timeout(timeout) {
            Ok(v) => v,
            Err(e) if e == RecvTimeoutError::Timeout => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, e));
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, e));
            }
        };
        bytes.write(&report_data.data[..report_data.len])
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() == HID_RPT_SIZE + 1);

        let report_id = bytes[0] as i64;
        // Skip report number when not using numbered reports.
        let start = if report_id == 0x0 { 1 } else { 0 };
        let data = &bytes[start..];

        let result = unsafe {
            IOHIDDeviceSetReport(
                self.device_ref,
                kIOHIDReportTypeOutput,
                report_id,
                data.as_ptr(),
                data.len() as CFIndex,
            )
        };
        if result != 0 {
            warn!("set_report sending failure = {0:X}", result);
            return Err(io::Error::from_raw_os_error(result));
        }
        trace!("set_report sending success = {0:X}", result);

        Ok(bytes.len())
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl U2FDevice for Device {
    fn get_cid<'a>(&'a self) -> &'a [u8; 4] {
        &self.cid
    }

    fn set_cid(&mut self, cid: [u8; 4]) {
        self.cid = cid;
    }
}
