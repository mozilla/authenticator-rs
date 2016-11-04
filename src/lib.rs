#[cfg(any(target_os = "linux"))]
#[macro_use]
extern crate nix;
#[cfg(any(target_os = "linux"))]
#[macro_use]
extern crate libc;
#[cfg(any(target_os = "linux"))]
extern crate libudev;

#[cfg(any(target_os = "linux"))]
#[path="linux/mod.rs"]
pub mod platform;

use std::{mem, io, slice};
use std::io::{Read,Write};

const HID_RPT_SIZE : usize = 64;
const CID_BROADCAST : [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const TYPE_MASK : u8 = 0x80;
const TYPE_INIT : u8 = 0x80;
const TYPE_CONT : u8 = 0x80;

const FIDO_USAGE_PAGE     : u16 =    0xf1d0;	// FIDO alliance HID usage page
const FIDO_USAGE_U2FHID   : u8  =   0x01;	// U2FHID usage for top-level collection
const FIDO_USAGE_DATA_IN  : u8  =   0x20;	// Raw IN data report
const FIDO_USAGE_DATA_OUT : u8  =   0x21;	// Raw OUT data report

// General constants

const U2FHID_IF_VERSION    : u32 =  2;	// Current interface implementation version
const U2FHID_FRAME_TIMEOUT : u32 =  500;	// Default frame timeout in ms
const U2FHID_TRANS_TIMEOUT : u32 =  3000;	// Default message timeout in ms

// U2FHID native commands

const U2FHID_PING         : u8 = (TYPE_INIT | 0x01);	// Echo data through local processor only
const U2FHID_MSG          : u8 = (TYPE_INIT | 0x03);	// Send U2F message frame
const U2FHID_LOCK         : u8 = (TYPE_INIT | 0x04);	// Send lock channel command
const U2FHID_INIT         : u8 = (TYPE_INIT | 0x06);	// Channel initialization
const U2FHID_WINK         : u8 = (TYPE_INIT | 0x08);	// Send device identification wink
const U2FHID_ERROR        : u8 = (TYPE_INIT | 0x3f);	// Error response
const U2FHID_VENDOR_FIRST : u8 = (TYPE_INIT | 0x40);	// First vendor defined command
const U2FHID_VENDOR_LAST  : u8 = (TYPE_INIT | 0x7f);	// Last vendor defined command

// U2FHID_INIT command defines

const INIT_NONCE_SIZE     : usize =    8;	// Size of channel initialization challenge
const CAPFLAG_WINK        : u8 =    0x01;	// Device supports WINK command
const CAPFLAG_LOCK        : u8 =    0x02;	// Device supports LOCK command

// Low-level error codes. Return as negatives.

const ERR_NONE            : u8 =    0x00;	// No error
const ERR_INVALID_CMD     : u8 =    0x01;	// Invalid command
const ERR_INVALID_PAR     : u8 =    0x02;	// Invalid parameter
const ERR_INVALID_LEN     : u8 =    0x03;	// Invalid message length
const ERR_INVALID_SEQ     : u8 =    0x04;	// Invalid message sequencing
const ERR_MSG_TIMEOUT     : u8 =    0x05;	// Message has timed out
const ERR_CHANNEL_BUSY    : u8 =    0x06;	// Channel busy
const ERR_LOCK_REQUIRED   : u8 =    0x0a;	// Command requires channel lock
const ERR_INVALID_CID     : u8 =    0x0b;	// Command not allowed on this cid
const ERR_OTHER           : u8 =    0x7f;	// Other unspecified error

pub trait U2FDevice {
    fn get_cid(&self) -> [u8; 4];
    fn set_cid(&mut self, cid: &[u8; 4]);
}

#[repr(packed)]
struct U2FHIDInitReq {
    nonce: [u8; INIT_NONCE_SIZE]
}

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

const INIT_DATA_SIZE : usize = HID_RPT_SIZE - 7;
const CONT_DATA_SIZE : usize = HID_RPT_SIZE - 5;

#[repr(packed)]
struct U2FHIDInit {
    cid: [u8; 4],
    cmd: u8,
    bcnth: u8,
    bcntl: u8,
    pub data: [u8; INIT_DATA_SIZE]
}

pub fn to_u8_array<T>(non_ptr: &T) -> &[u8] {
    unsafe {
        slice::from_raw_parts(non_ptr as *const T as *const u8,
                              mem::size_of::<T>())
    }
}

pub fn from_u8_array<T>(arr: &[u8]) -> &T {
    unsafe { &*(arr.as_ptr() as *const T) }
}

#[repr(packed)]
struct U2FHIDCont {
    cid: [u8; 4],
    seq: u8,
    pub data: [u8; CONT_DATA_SIZE]
}

fn print_array(arr: &[u8]) {
    let mut i = 0;
    while i < arr.len() {
        print!("0x{:02x}, ", arr[i]);
        i += 1;
        if i % 8 == 0 {
            println!();
        }
    }
}

pub fn init_device<T>(dev: &mut T) -> io::Result<()>
    where T: U2FDevice + Read + Write
{
    // TODO This is not a nonce. This is the opposite of a nonce.
    let nonce = vec![0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1];
    let raw : Vec<u8>;

    match sendrecv(dev, U2FHID_INIT, &nonce) {
        Ok(st) => raw = st,
        Err(e) => {
            return Err(e);
        }
    }
    let ptr: *const u8 = raw.as_slice().as_ptr();
    let ptr: *const U2FHIDInitResp = ptr as *const U2FHIDInitResp;
    let r : &U2FHIDInitResp = unsafe { &*ptr };
    if nonce != r.nonce {
        return Err(io::Error::new(io::ErrorKind::Other, "Nonces do not match!"));
    }
    dev.set_cid(&r.cid);
    Ok(())
}

// pub fn wink_device<T>(dev: &mut T) -> io::Result<()>
//     where T: U2FDevice + Read + Write
// {
// }

pub fn sendrecv<T>(dev: &mut T,
                   cmd: u8,
                   send: &Vec<u8>) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    let mut data_sent: usize = 0;
    let mut sequence: u8 = 0;

    // Write Data.
    while send.len() > data_sent {
        let mut frame : [u8; HID_RPT_SIZE] = [0; HID_RPT_SIZE];
        let data_buf_size;
        if data_sent == 0 {
            let mut uf = U2FHIDInit {
                cid: dev.get_cid(),
                cmd: cmd,
                bcnth: (send.len() >> 8) as u8,
                bcntl: send.len() as u8,
                data: [0; INIT_DATA_SIZE]
            };
            data_buf_size = INIT_DATA_SIZE;
            let send_length : usize;
            if (send.len() - data_sent) > data_buf_size {
                send_length = data_sent + data_buf_size;
            } else {
                send_length = send.len();
            }
            // clone_from_slice panics if src/dst sizes don't match.
            uf.data[data_sent..send_length].clone_from_slice(&send[data_sent..send_length]);
            frame.clone_from_slice(to_u8_array(&uf));
        } else {
            let mut uf = U2FHIDCont {
                cid: dev.get_cid(),
                seq: sequence,
                data: [0; CONT_DATA_SIZE]
            };
            data_buf_size = CONT_DATA_SIZE;
            let send_length : usize;
            if (send.len() - data_sent) > data_buf_size {
                send_length = data_buf_size;
            } else {
                send_length = send.len() - data_sent;
            }
            uf.data[0..send_length].clone_from_slice(&send[data_sent..send_length + data_sent]);
            frame.clone_from_slice(to_u8_array(&uf));
        }
        print_array(&frame);
        sequence += 1;
        // TODO Figure out nicer way to prepend record number
        let mut frame_data : [u8; HID_RPT_SIZE + 1] = [0u8; HID_RPT_SIZE + 1];
        frame_data[0] = 0;
        frame_data[1..].clone_from_slice(&frame);
        match dev.write(&frame_data) {
            Ok(n) => data_sent += data_buf_size,
            Err(er) => return Err(er)
        };
    }

    // Now we read. This happens in 2 chunks: The initial packet, which has the
    // size we expect overall, then continuation packets, which will fill in
    // data until we have everything.
    let mut raw_frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];

    // TODO Check the status of the read, figure out how we'll deal with timeouts.
    dev.read(&mut raw_frame).unwrap();
    let mut recvlen = INIT_DATA_SIZE;
    // We'll get an init packet back from USB, open it to see how much we'll be
    // reading overall. (should unpack to an init struct)
    let mut info_frame : &U2FHIDInit = from_u8_array(&raw_frame);

    // Read until we've exhausted the total read amount or error out
    let datalen : usize = (info_frame.bcnth as usize) << 8 | (info_frame.bcntl as usize);
    let mut data : Vec<u8> = Vec::with_capacity(datalen);

    let clone_len : usize;
    if datalen < recvlen {
        clone_len = datalen;
    } else {
        clone_len = recvlen;
    }
    data.extend(info_frame.data[0..clone_len].iter().cloned());
    println!("{:?}", data);
    println!("{:?}", datalen);
    sequence = 0;
    while recvlen < datalen {
        println!("{:?}", recvlen);
        println!("trying to get more data?");
        let mut frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
        dev.read(&mut frame).unwrap();
        let mut cont_frame : &U2FHIDCont;
        cont_frame = from_u8_array(&frame);
        if cont_frame.cid != dev.get_cid() {
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong CID!"));
        }
        if cont_frame.seq != sequence + 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "Sequence numbers out of order!"));
        }
        sequence = cont_frame.seq;
        if (recvlen + CONT_DATA_SIZE) > datalen {
            println!("Last packet! {}", datalen-recvlen);
            println!("{:?}", cont_frame.data[0..(datalen-recvlen)].iter());
            data.extend(cont_frame.data[0..(datalen-recvlen)].iter().cloned());
        } else {
            data.extend(cont_frame.data.iter().cloned());
        }
        recvlen += CONT_DATA_SIZE;
    }
    Ok(data)
}

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
const U2FAPDUHEADER_SIZE : usize = 7;
#[repr(packed)]
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
                    send: &Vec<u8>,
                    recv: &mut Vec<u8>) -> io::Result<()>
    where T: U2FDevice + Read + Write
{
    // TODO: Check send length to make sure it's < 2^16
    let header = U2FAPDUHeader {
        cla: 0,
        ins: cmd,
        p1: p1,
        p2: 0,
        lc: [0, // lc[0] should always be 0
             (send.len() & 0xff) as u8,
             (send.len() >> 8) as u8]
    };
    // Size of header, plus data, plus 2 0 bytes at the end for maximum return
    // size.
    let mut data_vec : Vec<u8> = vec![0; std::mem::size_of::<U2FAPDUHeader>() + send.len() + 2];
    let header_raw : [u8; U2FAPDUHEADER_SIZE];
    unsafe {
        header_raw = mem::transmute(header);
    }
    data_vec[0..U2FAPDUHEADER_SIZE].clone_from_slice(&header_raw);
    data_vec[U2FAPDUHEADER_SIZE..(send.len() + U2FAPDUHEADER_SIZE)].clone_from_slice(&send);
    let mut base_recv = vec![0 as u8; 65536];
    //sendrecv(dev, U2FHID_MSG, &data_vec, &mut base_recv);
    Ok(())
}

#[cfg(test)]
    mod tests {
    use ::{U2FDevice, init_device, sendrecv, U2FHID_PING, print_array};
    use std::error::Error;
    mod platform {
        use ::{CID_BROADCAST, print_array};
        use U2FDevice;
        use std::io;
        use std::io::{Read, Write};

        pub struct TestDevice {
            pub cid: [u8; 4],
            pub expected_reads: Vec<Vec<u8>>,
            pub expected_writes: Vec<Vec<u8>>,
        }

        impl TestDevice {
            pub fn new() -> TestDevice {
                TestDevice {
                    cid: CID_BROADCAST,
                    expected_reads: Vec::new(),
                    expected_writes: Vec::new()
                }
            }
        }

        impl Write for TestDevice {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                // Pop a vector from the expected writes, check for quality
                // against bytes array.
                assert!(self.expected_writes.len() > 0, "Ran out of expected write values!");
                let check = self.expected_writes.remove(0);
                println!("Expecting:");
                print_array(&bytes[1..]);
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
                println!("Setting CID to {:?}", cid);
                self.cid = cid.clone();
            }
        }
    }

    #[test]
    fn test_init_device() {
        let mut device = platform::TestDevice::new();
        device.expected_writes.push(vec![0x00, //record index
                                         // data
                                         0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08, 0x08,
                                         0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        device.expected_reads.push(vec![0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x11, 0x08,
                                        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
                                        0x03, 0x00, 0x14, 0x02, 0x04, 0x01, 0x08, 0x01,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        if let Err(e) = init_device(&mut device) {
            assert!(true, format!("Init device returned an error! {:?}", e.description()));
        }
        assert_eq!(device.get_cid(), [0x00, 0x03, 0x00, 0x14]);
    }

    #[test]
    fn test_sendrecv_multiple() {
        let mut device = platform::TestDevice::new();
        device.set_cid(&[1, 2, 3, 4]);
        device.expected_writes.push(vec![0x00, //record index
                                         // data
                                         0x01, 0x02, 0x03, 0x04, U2FHID_PING, 0x00, 0xe4, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_writes.push(vec![0x00, //record index
                                         // data
                                         0x01, 0x02, 0x03, 0x04, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_writes.push(vec![0x00, //record index
                                         // data
                                         0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_writes.push(vec![0x00,
                                         0x01, 0x02, 0x03, 0x04, 0x03, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                         0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        device.expected_reads.push(vec![0x01, 0x02, 0x03, 0x04, U2FHID_PING, 0x00, 0xe4, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_reads.push(vec![0x01, 0x02, 0x03, 0x04, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_reads.push(vec![0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        device.expected_reads.push(vec![0x01, 0x02, 0x03, 0x04, 0x03, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let d = match sendrecv(&mut device, U2FHID_PING, &vec![1 as u8; 0xe4]) {
            Ok(c) => c,
            Err(e) => panic!(format!("Init device returned an error! {:?}", e.description()))
        };
        assert_eq!(d.len(), 0xe4);
        assert_eq!(d, vec![1 as u8; 0xe4]);
    }

    #[test]
    fn test_sendapdu() {
    }
}
