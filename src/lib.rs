#[cfg(any(target_os = "linux", target_os = "macos"))]
#[macro_use]
extern crate nix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern crate libc;

#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "linux"))]
#[path="linux/mod.rs"]
pub mod platform;

#[cfg(any(target_os = "macos"))]
extern crate core_foundation_sys;
#[cfg(any(target_os = "macos"))]
extern crate mach;

extern crate rand;

#[cfg(any(target_os = "macos"))]
#[path="macos/mod.rs"]
pub mod platform;

mod consts;
mod runloop;

use consts::*;
use rand::{thread_rng, Rng};
use std::{ffi, mem, io, slice};
use std::io::{Read, Write};
use std::ffi::CString;

// Trait for representing U2F HID Devices. Requires getters/setters for the
// channel ID, created during device initialization.
pub trait U2FDevice {
    fn get_cid(&self) -> [u8; 4];
    fn set_cid(&mut self, cid: &[u8; 4]);
}

// Size of data chunk expected in U2F Init USB HID Packets
const INIT_DATA_SIZE : usize = HID_RPT_SIZE - 7;
// Size of data chunk expected in U2F Cont USB HID Packets
const CONT_DATA_SIZE : usize = HID_RPT_SIZE - 5;

// Init structure for U2F Communications. Tells the receiver what channel
// communication is happening on, what command is running, and how much data to
// expect to receive over all.
//
// Spec at https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.html#message--and-packet-structure
#[repr(packed)]
#[allow(dead_code)]
struct U2FHIDInit {
    // U2F Channel ID
    cid: [u8; 4],
    // U2F Command
    cmd: u8,
    // High byte of 16-bit data size
    bcnth: u8,
    // Low byte of 16-bit data size
    bcntl: u8,
    // Packet data
    pub data: [u8; INIT_DATA_SIZE]
}

// Continuation structure for U2F Communications. After an Init structure is
// sent, continuation structures are used to transmit all extra data that
// wouldn't fit in the initial packet. The sequence number increases with every
// packet, until all data is received.
//
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.html#message--and-packet-structure
#[repr(packed)]
struct U2FHIDCont {
    // U2F Channel ID
    cid: [u8; 4],
    // Continuation Sequence Number
    seq: u8,
    // Packet Data
    pub data: [u8; CONT_DATA_SIZE]
}

// Reply sent after initialization command. Contains information about U2F USB
// Key versioning, as well as the communication channel to be used for all
// further requests.
//
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-hid-protocol.html#u2fhid_init
#[repr(packed)]
#[derive(Debug)]
struct U2FHIDInitResp {
    nonce: [u8; INIT_NONCE_SIZE],
    cid: [u8; 4],
    version_interface: u8,
    version_major: u8,
    version_minor: u8,
    version_build: u8,
    cap_flags: u8
}

////////////////////////////////////////////////////////////////////////
// Utility Functions
////////////////////////////////////////////////////////////////////////

fn to_u8_array<T>(non_ptr: &T) -> &[u8] {
    unsafe {
        slice::from_raw_parts(non_ptr as *const T as *const u8,
                              mem::size_of::<T>())
    }
}

fn from_u8_array<T>(arr: &[u8]) -> &T {
    unsafe { &*(arr.as_ptr() as *const T) }
}

pub fn set_data(data: &mut [u8], itr: &mut std::slice::Iter<u8>, max: usize)
{
    let take_amount;
    let count = itr.size_hint().0;
    if max < count {
        take_amount = max;
    } else {
        take_amount = count;
    }
    // TODO There is a better way to do this :|
    for i in 0..take_amount {
        data[i] = *itr.next().unwrap();
    }
}

////////////////////////////////////////////////////////////////////////
// Device Commands
////////////////////////////////////////////////////////////////////////

pub fn init_device<T>(dev: &mut T) -> io::Result<()>
    where T: U2FDevice + Read + Write
{
    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);
    let raw = sendrecv(dev, U2FHID_INIT, &nonce)?;

    let r : &U2FHIDInitResp = from_u8_array(&raw);
    if r.nonce != nonce {
        return Err(io::Error::new(io::ErrorKind::Other, "Nonces do not match!"));
    }

    dev.set_cid(&r.cid);
    Ok(())
}

pub fn ping_device<T>(dev: &mut T) -> io::Result<()>
    where T: U2FDevice + Read + Write
{
    let mut random = [0u8; 8];
    thread_rng().fill_bytes(&mut random);

    if sendrecv(dev, U2FHID_PING, &random)? != random {
        return Err(io::Error::new(io::ErrorKind::Other, "Ping was corrupted!"));
    }

    Ok(())
}

fn status_word_to_error(status_word_high: u8, status_word_low: u8) -> Option<io::Error>
{
    let status_word = [status_word_high, status_word_low];

    match status_word {
        SW_NO_ERROR => None,
        SW_WRONG_LENGTH => Some(io::Error::new(io::ErrorKind::InvalidInput, "Wrong Length")),
        SW_WRONG_DATA => Some(io::Error::new(io::ErrorKind::InvalidData, "Wrong Data")),
        SW_CONDITIONS_NOT_SATISFIED => Some(io::Error::new(io::ErrorKind::TimedOut, "Conditions not satisfied")),
        _ => Some(io::Error::new(io::ErrorKind::Other, format!("Problem Status: {:?}", status_word))),
    }
}

pub fn u2f_version<T>(dev: &mut T) -> io::Result<std::ffi::CString>
    where T: U2FDevice + Read + Write
{
    let mut version_resp = try!(send_apdu(dev, U2F_VERSION, 0x00, &vec![]));
    let sw_low = version_resp.pop().unwrap();
    let sw_high = version_resp.pop().unwrap();

    match status_word_to_error(sw_high, sw_low) {
        None => Ok(try!(CString::new(version_resp))),
        Some(e) => Err(e),
    }
}

pub fn u2f_version_is_v2<T>(dev: &mut T) -> io::Result<()>
    where T: U2FDevice + Read + Write
{
    let version_string = try!(u2f_version(dev));

    if version_string != try!(ffi::CString::new("U2F_V2")) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unexpected U2F Version"));
    }
    Ok(())
}

pub fn u2f_register<T>(dev: &mut T, challenge: &Vec<u8>, application: &Vec<u8>) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
    }

    let flags = 0x00;

    let mut register_data = Vec::with_capacity(2 * PARAMETER_SIZE);
    register_data.extend(challenge);
    register_data.extend(application);

    let register_resp = try!(send_apdu(dev, U2F_REGISTER, flags | U2F_REQUEST_USER_PRESENCE, &register_data));

    if register_resp.len() != 2 {
        // Real data, we're done
        return Ok(register_resp)
    }

    match status_word_to_error(register_resp[0], register_resp[1]) {
        None => Ok(Vec::new()),
        Some(e) => Err(e),
    }
}

pub fn u2f_sign<T>(dev: &mut T, challenge: &Vec<u8>, application: &Vec<u8>, key_handle: &Vec<u8>) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key handle too large"));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_REQUEST_USER_PRESENCE;
    let sign_resp = send_apdu(dev, U2F_AUTHENTICATE, flags, &sign_data)?;

    if sign_resp.len() != 2 {
        // Real data, let's bail out here
        return Ok(sign_resp)
    }

    match status_word_to_error(sign_resp[0], sign_resp[1]) {
        None => Ok(Vec::new()),
        Some(e) => Err(e),
    }
}

pub fn u2f_is_keyhandle_valid<T>(dev: &mut T, challenge: &Vec<u8>, application: &Vec<u8>, key_handle: &Vec<u8>) -> io::Result<bool>
    where T: U2FDevice + Read + Write
{
    if challenge.len() != PARAMETER_SIZE ||
       application.len() != PARAMETER_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
    }

    if key_handle.len() > 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key handle too large"));
    }

    let mut sign_data = Vec::with_capacity(2 * PARAMETER_SIZE + 1 + key_handle.len());
    sign_data.extend(challenge);
    sign_data.extend(application);
    sign_data.push(key_handle.len() as u8);
    sign_data.extend(key_handle);

    let flags = U2F_CHECK_IS_REGISTERED;
    let sign_resp = send_apdu(dev, U2F_AUTHENTICATE, flags, &sign_data)?;

    // Need to use `&sign_resp[0..2]` here due to a compiler bug.
    // https://github.com/rust-lang/rust/issues/42031
    Ok(&sign_resp[0..2] == SW_CONDITIONS_NOT_SATISFIED)
}

////////////////////////////////////////////////////////////////////////
// Device Communication Functions
////////////////////////////////////////////////////////////////////////

pub fn sendrecv<T>(dev: &mut T,
                   cmd: u8,
                   send: &[u8]) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    let mut sequence: u8 = 0; // Start at 0
    let mut data_itr = send.into_iter();
    let mut init_sent = false;
    // Write Data.
    while data_itr.size_hint().0 != 0 {
        // Add 1 to HID_RPT_SIZE since we need to prefix this with a record
        // index.
        let mut frame : [u8; HID_RPT_SIZE + 1] = [0; HID_RPT_SIZE + 1];
        if !init_sent {
            let mut uf = U2FHIDInit {
                cid: dev.get_cid(),
                cmd: cmd,
                bcnth: (send.len() >> 8) as u8,
                bcntl: send.len() as u8,
                data: [0; INIT_DATA_SIZE]
            };
            set_data(&mut uf.data, &mut data_itr, INIT_DATA_SIZE);
            frame[1..].clone_from_slice(to_u8_array(&uf));
            init_sent = true;
        } else {
            let mut uf = U2FHIDCont {
                cid: dev.get_cid(),
                seq: sequence,
                data: [0; CONT_DATA_SIZE]
            };
            set_data(&mut uf.data, &mut data_itr, CONT_DATA_SIZE);
            sequence += 1;
            frame[1..].clone_from_slice(to_u8_array(&uf));
        }

        print!("USB send: ");
        for &byte in frame.iter() {
            print!("{:02x}", byte);
        }
        println!();

        if let Err(er) = dev.write(&frame) {
            return Err(er);
        };
    }

    // Now we read. This happens in 2 chunks: The initial packet, which has the
    // size we expect overall, then continuation packets, which will fill in
    // data until we have everything.
    let mut frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
    let datalen: usize;
    let mut data : Vec<u8>;

    // TODO Check the status of the read, figure out how we'll deal with timeouts.
    dev.read(&mut frame)?;
    let mut recvlen = INIT_DATA_SIZE;

    // We'll get an init packet back from USB, open it to see how much we'll be
    // reading overall. (should unpack to an init struct). Scope this to deal
    // with the lifetime of the frame borrow in from_u8_array.
    {
        let info_frame : &U2FHIDInit = from_u8_array(&frame);

        // Read until we've exhausted the total read amount or error out
        datalen = (info_frame.bcnth as usize) << 8 | (info_frame.bcntl as usize);
        data = Vec::with_capacity(datalen);

        let clone_len : usize;
        if datalen < recvlen {
            clone_len = datalen;
        } else {
            clone_len = recvlen;
        }
        data.extend(info_frame.data[0..clone_len].iter().cloned());
    }
    sequence = 0;
    while recvlen < datalen {
        // Reset frame value
        frame = [0u8; HID_RPT_SIZE];
        dev.read(&mut frame)?;
        let cont_frame : &U2FHIDCont;
        cont_frame = from_u8_array(&frame);
        if cont_frame.cid != dev.get_cid() {
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong CID!"));
        }
        if cont_frame.seq != sequence {
            return Err(io::Error::new(io::ErrorKind::Other, "Sequence numbers out of order!"));
        }
        sequence = cont_frame.seq + 1;
        if (recvlen + CONT_DATA_SIZE) > datalen {
            data.extend(cont_frame.data[0..(datalen-recvlen)].iter().cloned());
        } else {
            data.extend(cont_frame.data.iter().cloned());
        }
        recvlen += CONT_DATA_SIZE;
    }
    Ok(data)
}

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
// https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#u2f-message-framing
#[repr(packed)]
#[allow(dead_code)]
struct U2FAPDUHeader {
    cla : u8,
    ins : u8,
    p1 : u8,
    p2 : u8,
    lc : [u8; 3]
}

pub fn send_apdu<T>(dev: &mut T,
                    cmd: u8,
                    p1: u8,
                    send: &Vec<u8>) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    // TODO: Check send length to make sure it's < 2^16
    let header = U2FAPDUHeader {
        cla: 0,
        ins: cmd,
        p1: p1,
        p2: 0, // p2 is always 0, at least, for our requirements.
        lc: [0, // lc[0] should always be 0
             (send.len() >> 8) as u8,
             (send.len() & 0xff) as u8]
    };
    // Size of header, plus data, plus 2 0 bytes at the end for maximum return
    // size.
    let mut data_vec : Vec<u8> = vec![0; std::mem::size_of::<U2FAPDUHeader>() + send.len() + 2];
    let header_raw : &[u8] = to_u8_array(&header);
    data_vec[0..U2FAPDUHEADER_SIZE].clone_from_slice(&header_raw);
    data_vec[U2FAPDUHEADER_SIZE..(send.len() + U2FAPDUHEADER_SIZE)].clone_from_slice(&send);
    sendrecv(dev, U2FHID_MSG, &data_vec)
}

#[cfg(test)]
    mod tests {
    use ::{U2FDevice, init_device, sendrecv, send_apdu};
    use std::error::Error;
    use consts::{U2FHID_PING, U2FHID_MSG, U2FAPDUHEADER_SIZE};
    mod platform {
        use consts::{CID_BROADCAST, HID_RPT_SIZE};
        use U2FDevice;
        use std::io;
        use std::io::{Read, Write};

        pub struct TestDevice {
            pub cid: [u8; 4],
            pub expected_reads: Vec<[u8; HID_RPT_SIZE]>,
            pub expected_writes: Vec<[u8; HID_RPT_SIZE + 1]>,
        }

        impl TestDevice {
            pub fn new() -> TestDevice {
                TestDevice {
                    cid: CID_BROADCAST,
                    expected_reads: Vec::new(),
                    expected_writes: Vec::new()
                }
            }
            pub fn add_write(&mut self, packet: &[u8], fill_value: u8) {
                // Add one to deal with record index check
                let mut write : [u8; HID_RPT_SIZE + 1] = [fill_value; HID_RPT_SIZE + 1];
                // Make sure we start with a 0, for HID record index
                write[0] = 0;
                // Clone packet data in at 1, since front is padded with HID record index
                write[1..packet.len() + 1].clone_from_slice(&packet);
                self.expected_writes.push(write);
            }
            pub fn add_read(&mut self, packet: &[u8], fill_value: u8) {
                let mut read : [u8; HID_RPT_SIZE] = [fill_value; HID_RPT_SIZE];
                read[0..packet.len()].clone_from_slice(&packet);
                self.expected_reads.push(read);
            }
        }

        impl Write for TestDevice {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                // Pop a vector from the expected writes, check for quality
                // against bytes array.
                assert!(self.expected_writes.len() > 0, "Ran out of expected write values!");
                let check = self.expected_writes.remove(0);
                assert_eq!(check.len(), bytes.len());
                assert_eq!(&check[..], bytes);
                Ok(bytes.len())
            }
            // nop
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Read for TestDevice {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                // Pop a vector from the expected writes, check for quality
                // against bytes array.
                assert!(self.expected_reads.len() > 0, "Ran out of expected read values!");
                let check = self.expected_reads.remove(0);
                bytes.clone_from_slice(&check[..]);
                Ok(check.len())
            }
        }
        impl U2FDevice for TestDevice {
            fn get_cid(&self) -> [u8; 4] {
                return self.cid.clone();
            }
            fn set_cid(&mut self, cid: &[u8; 4]) {
                self.cid = cid.clone();
            }
        }
    }

    #[test]
    fn test_init_device() {
        let mut device = platform::TestDevice::new();
        device.add_write(&vec![0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08, 0x08,
                               0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
                         0);
        device.add_read(&vec![0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x11, 0x08,
                              0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
                              0x03, 0x00, 0x14, 0x02, 0x04, 0x01, 0x08, 0x01],
                        0);
        if let Err(e) = init_device(&mut device) {
            assert!(true, format!("Init device returned an error! {:?}", e.description()));
        }
        assert_eq!(device.get_cid(), [0x00, 0x03, 0x00, 0x14]);
    }

    #[test]
    fn test_sendrecv_multiple() {
        let mut device = platform::TestDevice::new();
        device.set_cid(&[1, 2, 3, 4]);
        device.add_write(&vec![0x01, 0x02, 0x03, 0x04, U2FHID_PING, 0x00, 0xe4], 1);
        // Need CID and sequence number for CONT packets
        device.add_write(&vec![0x01, 0x02, 0x03, 0x04, 0x00], 1);
        device.add_write(&vec![0x01, 0x02, 0x03, 0x04, 0x01], 1);
        device.add_write(&vec![0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                               0x01, 0x01], 0);
        device.add_read(&vec![0x01, 0x02, 0x03, 0x04, U2FHID_PING, 0x00, 0xe4], 1);
        // Need CID and sequence number for CONT packets
        device.add_read(&vec![0x01, 0x02, 0x03, 0x04, 0x00], 1);
        device.add_read(&vec![0x01, 0x02, 0x03, 0x04, 0x01], 1);
        device.add_read(&vec![0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                              0x01, 0x01], 0);

        let d = match sendrecv(&mut device, U2FHID_PING, &vec![1 as u8; 0xe4]) {
            Ok(c) => c,
            Err(e) => panic!(format!("Init device returned an error! {:?}", e.description()))
        };
        assert_eq!(d.len(), 0xe4);
        assert_eq!(d, vec![1 as u8; 0xe4]);
    }

    #[test]
    fn test_sendapdu() {
        let mut device = platform::TestDevice::new();
        device.set_cid(&[1, 2, 3, 4]);
        device.add_write(&vec![// sendrecv header
                               0x01, 0x02, 0x03, 0x04, U2FHID_MSG, 0x00, 0x0e,
                               // apdu header
                               0x00, U2FHID_PING, 0xaa, 0x00, 0x00, 0x00, 0x05,
                               // apdu data
                               0x01, 0x02, 0x03, 0x04, 0x05], 0);
        // Only expect data from APDU back
        device.add_read(&vec![0x01, 0x02, 0x03, 0x04, U2FHID_MSG, 0x00, 0x05,
                              0x01, 0x02, 0x03, 0x04, 0x05], 0);
        send_apdu(&mut device, U2FHID_PING, 0xaa, &vec![1, 2, 3, 4, 5]);
    }
}
