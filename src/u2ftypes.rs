use std::io;

use consts::*;
use util::io_err;

// Trait for representing U2F HID Devices. Requires getters/setters for the
// channel ID, created during device initialization.
pub trait U2FDevice {
    fn get_cid(&self) -> [u8; 4];
    fn set_cid(&mut self, cid: &[u8; 4]);
}

// Init structure for U2F Communications. Tells the receiver what channel
// communication is happening on, what command is running, and how much data to
// expect to receive over all.
//
// Spec at https://fidoalliance.org/specs/fido-u2f-v1.
// 0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.html#message--and-packet-structure
pub struct U2FHIDInit {
    // U2F Channel ID
    cid: [u8; 4],
    // U2F Command
    cmd: u8,
    // High byte of 16-bit data size
    bcnth: u8,
    // Low byte of 16-bit data size
    bcntl: u8,
    // Packet data
    data: [u8; INIT_DATA_SIZE],
}

impl U2FHIDInit {
    pub fn new<T>(dev: &T, cmd: u8, bcnt: usize, init_data: &[u8]) -> Self
    where
        T: U2FDevice,
    {
        let len = init_data.len();
        let mut data = [0u8; INIT_DATA_SIZE];
        data[..len].copy_from_slice(&init_data[..len]);

        Self {
            cid: dev.get_cid(),
            cmd,
            bcnth: (bcnt >> 8) as u8,
            bcntl: bcnt as u8,
            data,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() != HID_RPT_SIZE {
            return Err(io_err("invalid init packet"));
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&buf[..4]);

        let mut data = [0u8; INIT_DATA_SIZE];
        data.copy_from_slice(&buf[7..]);

        Ok(Self {
            cid,
            cmd: buf[4],
            bcnth: buf[5],
            bcntl: buf[6],
            data,
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        assert!(buf.len() == HID_RPT_SIZE);

        buf[..4].copy_from_slice(&self.cid);
        buf[4] = self.cmd;
        buf[5] = self.bcnth;
        buf[6] = self.bcntl;
        buf[7..].copy_from_slice(&self.data);
    }

    pub fn bcnt(&self) -> usize {
        (self.bcnth as usize) << 8 | (self.bcntl as usize)
    }

    pub fn data<'a>(&'a self) -> &'a [u8] {
        &self.data
    }
}

// Continuation structure for U2F Communications. After an Init structure is
// sent, continuation structures are used to transmit all extra data that
// wouldn't fit in the initial packet. The sequence number increases with every
// packet, until all data is received.
//
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.
// html#message--and-packet-structure
pub struct U2FHIDCont {
    // U2F Channel ID
    cid: [u8; 4],
    // Continuation Sequence Number
    seq: u8,
    // Packet Data
    data: [u8; CONT_DATA_SIZE],
}

impl U2FHIDCont {
    pub fn new<T>(dev: &T, seq: u8, cont_data: &[u8]) -> Self
    where
        T: U2FDevice,
    {
        let len = cont_data.len();
        let mut data = [0u8; CONT_DATA_SIZE];
        data[..len].copy_from_slice(&cont_data[..len]);

        Self {
            cid: dev.get_cid(),
            seq,
            data,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() != HID_RPT_SIZE {
            return Err(io_err("invalid cont packet"));
        }

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&buf[..4]);

        let mut data = [0u8; CONT_DATA_SIZE];
        data.copy_from_slice(&buf[5..]);

        Ok(Self {
            cid,
            seq: buf[4],
            data,
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        assert!(buf.len() == HID_RPT_SIZE);

        buf[..4].copy_from_slice(&self.cid);
        buf[4] = self.seq;
        buf[5..].copy_from_slice(&self.data);
    }

    pub fn cid<'a>(&'a self) -> &'a [u8] {
        &self.cid
    }

    pub fn sequence(&self) -> u8 {
        self.seq
    }

    pub fn data<'a>(&'a self) -> &'a [u8] {
        &self.data
    }
}


// Reply sent after initialization command. Contains information about U2F USB
// Key versioning, as well as the communication channel to be used for all
// further requests.
//
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.
// html#u2fhid_init
#[derive(Debug)]
pub struct U2FHIDInitResp {
    nonce: [u8; INIT_NONCE_SIZE],
    cid: [u8; 4],
    version_interface: u8,
    version_major: u8,
    version_minor: u8,
    version_build: u8,
    cap_flags: u8,
}

impl U2FHIDInitResp {
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() != INIT_NONCE_SIZE + 9 {
            return Err(io_err("invalid init response"));
        }

        let mut nonce = [0u8; INIT_NONCE_SIZE];
        nonce.copy_from_slice(&buf[..INIT_NONCE_SIZE]);

        let mut cid = [0u8; 4];
        cid.copy_from_slice(&buf[INIT_NONCE_SIZE..INIT_NONCE_SIZE + 4]);

        Ok(Self {
            nonce,
            cid,
            version_interface: buf[INIT_NONCE_SIZE + 4],
            version_major: buf[INIT_NONCE_SIZE + 5],
            version_minor: buf[INIT_NONCE_SIZE + 6],
            version_build: buf[INIT_NONCE_SIZE + 7],
            cap_flags: buf[INIT_NONCE_SIZE + 8],
        })
    }

    pub fn nonce<'a>(&'a self) -> &'a [u8] {
        &self.nonce
    }

    pub fn cid<'a>(&'a self) -> &'a [u8; 4] {
        &self.cid
    }
}

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
// https://fidoalliance.org/specs/fido-u2f-v1.
// 0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#u2f-message-framing
pub struct U2FAPDUHeader {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    lc: [u8; 3],
}

impl U2FAPDUHeader {
    pub fn new(ins: u8, p1: u8, lc: usize) -> Self {
        Self {
            cla: 0,
            ins,
            p1,
            p2: 0, // p2 is always 0, at least, for our requirements.
            lc: [
                0, // lc[0] should always be 0
                (lc >> 8) as u8,
                (lc & 0xff) as u8,
            ],
        }
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        assert!(buf.len() == U2FAPDUHEADER_SIZE);

        buf[0] = self.cla;
        buf[1] = self.ins;
        buf[2] = self.p1;
        buf[3] = self.p2;
        buf[4..].copy_from_slice(&self.lc);
    }
}
