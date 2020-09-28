/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate authenticator;

use std::{cmp, io};

use authenticator::{sendrecv, U2FDevice, U2FDeviceInfo, U2FInfoQueryable};
use authenticator::{CID_BROADCAST, MAX_HID_RPT_SIZE};

struct TestDevice {
    cid: [u8; 4],
    data: Vec<u8>,
    dev_info: Option<U2FDeviceInfo>,
}

impl TestDevice {
    pub fn new() -> TestDevice {
        TestDevice {
            cid: CID_BROADCAST,
            data: vec![],
            dev_info: None,
        }
    }
}

impl io::Read for TestDevice {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(bytes.len() == MAX_HID_RPT_SIZE);
        let max = cmp::min(self.data.len(), MAX_HID_RPT_SIZE);
        bytes[..max].copy_from_slice(&self.data[..max]);
        self.data = self.data[max..].to_vec();
        Ok(max)
    }
}

impl io::Write for TestDevice {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() == MAX_HID_RPT_SIZE + 1);
        self.data.extend_from_slice(&bytes[1..]);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl U2FDevice for TestDevice {
    fn get_cid<'a>(&'a self) -> &'a [u8; 4] {
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

    fn set_device_info(&mut self, dev_info: U2FDeviceInfo) {
        self.dev_info = Some(dev_info);
    }
}

impl U2FInfoQueryable for TestDevice {
    fn get_device_info(&self) -> U2FDeviceInfo {
        // unwrap is okay, as dev_info must have already been set, else
        // a programmer error
        self.dev_info.clone().unwrap()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 0 {
        let cmd = data[0];
        let data = &data[1..];
        let mut dev = TestDevice::new();
        let res = sendrecv(&mut dev, cmd, data);
        assert_eq!(data, &res.unwrap()[..]);
    }
});
