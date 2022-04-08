/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use crate::consts::CID_BROADCAST;
use crate::crypto::ECDHSecret;
use crate::ctap2::commands::get_info::AuthenticatorInfo;
use crate::transport::device_selector::DeviceCommand;
use crate::transport::{hid::HIDDevice, FidoDevice, HIDError};
use crate::u2ftypes::{U2FDevice, U2FDeviceInfo};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::sync::mpsc::{channel, Receiver, Sender};

pub(crate) const IN_HID_RPT_SIZE: usize = 64;
const OUT_HID_RPT_SIZE: usize = 64;

#[derive(Debug)]
pub struct Device {
    pub id: String,
    pub cid: [u8; 4],
    pub reads: Vec<[u8; IN_HID_RPT_SIZE]>,
    pub writes: Vec<[u8; OUT_HID_RPT_SIZE + 1]>,
    pub dev_info: Option<U2FDeviceInfo>,
    pub authenticator_info: Option<AuthenticatorInfo>,
    pub sender: Option<Sender<DeviceCommand>>,
    pub receiver: Option<Receiver<DeviceCommand>>,
}

impl Device {
    pub fn add_write(&mut self, packet: &[u8], fill_value: u8) {
        // Add one to deal with record index check
        let mut write = [fill_value; OUT_HID_RPT_SIZE + 1];
        // Make sure we start with a 0, for HID record index
        write[0] = 0;
        // Clone packet data in at 1, since front is padded with HID record index
        write[1..=packet.len()].clone_from_slice(packet);
        self.writes.push(write);
    }

    pub fn add_read(&mut self, packet: &[u8], fill_value: u8) {
        let mut read = [fill_value; IN_HID_RPT_SIZE];
        read[..packet.len()].clone_from_slice(packet);
        self.reads.push(read);
    }

    pub fn create_channel(&mut self) {
        let (tx, rx) = channel();
        self.sender = Some(tx);
        self.receiver = Some(rx);
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Pop a vector from the expected writes, check for quality
        // against bytes array.
        assert!(
            !self.writes.is_empty(),
            "Ran out of expected write values! Wanted to write {:?}",
            bytes
        );
        let check = self.writes.remove(0);
        assert_eq!(check.len(), bytes.len());
        assert_eq!(&check, bytes);
        Ok(bytes.len())
    }

    // nop
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Device {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(!self.reads.is_empty(), "Ran out of read values!");
        let check = self.reads.remove(0);
        assert_eq!(check.len(), bytes.len());
        bytes.clone_from_slice(&check);
        Ok(check.len())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.reads.is_empty());
            assert!(self.writes.is_empty());
        }
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.id == other.id
    }
}

impl Eq for Device {}

impl Hash for Device {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl U2FDevice for Device {
    fn get_cid<'a>(&'a self) -> &'a [u8; 4] {
        &self.cid
    }

    fn set_cid(&mut self, cid: [u8; 4]) {
        self.cid = cid;
    }

    fn in_rpt_size(&self) -> usize {
        IN_HID_RPT_SIZE
    }

    fn out_rpt_size(&self) -> usize {
        OUT_HID_RPT_SIZE
    }

    fn get_property(&self, prop_name: &str) -> io::Result<String> {
        Ok(format!("{} not implemented", prop_name))
    }
    fn get_device_info(&self) -> U2FDeviceInfo {
        self.dev_info.clone().unwrap()
    }

    fn set_device_info(&mut self, dev_info: U2FDeviceInfo) {
        self.dev_info = Some(dev_info);
    }
}

impl HIDDevice for Device {
    type Id = String;
    type BuildParameters = &'static str; // None used

    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.authenticator_info.as_ref()
    }

    fn set_authenticator_info(&mut self, authenticator_info: AuthenticatorInfo) {
        self.authenticator_info = Some(authenticator_info);
    }

    fn set_shared_secret(&mut self, _: ECDHSecret) {
        // Nothing
    }
    fn get_shared_secret(&self) -> std::option::Option<&ECDHSecret> {
        None
    }

    fn new(id: Self::BuildParameters) -> Result<Self, (HIDError, Self::Id)> {
        Ok(Device {
            id: id.to_string(),
            cid: CID_BROADCAST,
            reads: vec![],
            writes: vec![],
            dev_info: None,
            authenticator_info: None,
            sender: None,
            receiver: None,
        })
    }

    fn initialized(&self) -> bool {
        self.get_cid() != &CID_BROADCAST
    }

    fn id(&self) -> Self::Id {
        self.id.clone()
    }

    fn clone_device_as_write_only(&self) -> Result<Self, HIDError> {
        Ok(Device {
            id: self.id.clone(),
            cid: self.cid,
            reads: self.reads.clone(),
            writes: self.writes.clone(),
            dev_info: self.dev_info.clone(),
            authenticator_info: self.authenticator_info.clone(),
            sender: self.sender.clone(),
            receiver: None,
        })
    }

    fn is_u2f(&self) -> bool {
        self.sender.is_some()
    }
}

impl FidoDevice for Device {}
