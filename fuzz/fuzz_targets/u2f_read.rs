/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate authenticator;

use std::{cmp, io};

use authenticator::{sendrecv, U2FDevice};
use authenticator::{CID_BROADCAST, MAX_HID_RPT_SIZE};

struct TestDevice<'a> {
    cid: [u8; 4],
    data: &'a [u8],
}

impl<'a> TestDevice<'a> {
    pub fn new(data: &'a [u8]) -> TestDevice {
        TestDevice {
            cid: CID_BROADCAST,
            data,
        }
    }
}

impl<'a> io::Read for TestDevice<'a> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(bytes.len() == MAX_HID_RPT_SIZE);
        let max = cmp::min(self.data.len(), MAX_HID_RPT_SIZE);
        bytes[..max].copy_from_slice(&self.data[..max]);
        self.data = &self.data[max..];
        Ok(max)
    }
}

impl<'a> io::Write for TestDevice<'a> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() == MAX_HID_RPT_SIZE + 1);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> U2FDevice for TestDevice<'a> {
    fn get_cid<'b>(&'b self) -> &'b [u8; 4] {
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
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 0 {
        let cmd = data[0];
        let data = &data[1..];
        let mut dev = TestDevice::new(data);
        let _ = sendrecv(&mut dev, cmd, data);
    }
});
