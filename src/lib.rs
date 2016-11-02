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

use std::mem;
use std::io;
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

#[repr(packed)]
struct U2FHIDInit {
    cid: [u8; 4],
    cmd: u8,
    bcnth: u8,
    bcntl: u8,
    pub data: [u8; HID_RPT_SIZE - 7]
}

#[repr(packed)]
struct U2FHIDCont {
    cid: [u8; 4],
    seq: u8,
    pub data: [u8; HID_RPT_SIZE - 5]
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
    println!("Initing device!");
    // TODO This is not a nonce. This is the opposite of a nonce.
    let nonce = vec![0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1];
    let r : U2FHIDInitResp;
    match sendrecv(dev, U2FHID_INIT, &nonce) {
        Ok(st) => r = st,
        Err(e) => {
            return Err(e);
        }
    }
    println!("{:?}", r);
    if nonce != r.nonce {
        return Err(io::Error::new(io::ErrorKind::Other, "Nonces do not match!"));
    }
    dev.set_cid(&r.cid);
    Ok(())
}

pub fn sendrecv<T, R>(dev: &mut T,
                      cmd: u8,
                      send: &Vec<u8>) -> io::Result<R>
    where T: U2FDevice + Read + Write
{
    let mut data_sent: usize = 0;
    let mut sequence: u8 = 0;

    println!("Sending data!");
    // Write Data.
    while send.len() > data_sent {
        let frame : [u8; HID_RPT_SIZE];

        if data_sent == 0 {
            let mut uf = U2FHIDInit {
                cid: dev.get_cid(),
                cmd: cmd,
                bcnth: (send.len() >> 8) as u8,
                bcntl: send.len() as u8,
                data: [0; HID_RPT_SIZE - 7]
            };
            // clone_from_slice panics if src/dst sizes don't match.
            // TODO This isn't subdividing large datasets correctly.
            uf.data[0..send.len()].clone_from_slice(send);
            unsafe {
                frame = mem::transmute(uf);
            }
        } else {
            let mut uf = U2FHIDCont {
                cid: dev.get_cid(),
                seq: sequence,
                data: [0; HID_RPT_SIZE - 5]
            };
            // TODO This isn't subdividing large datasets correctly.
            uf.data[0..send.len()].clone_from_slice(send);
            unsafe {
                frame = mem::transmute(uf);
            }
        }
        print_array(&frame);
        sequence += 1;
        // TODO Figure out nicer way to prepend record number
        let mut frame_data : [u8; HID_RPT_SIZE + 1] = [0u8; HID_RPT_SIZE + 1];
        frame_data[0] = 0;
        frame_data[1..].clone_from_slice(&frame);
        match dev.write(&frame_data) {
            Ok(n) => data_sent += n,
            Err(er) => {
                println!("Write fucked up! {:?}", er);
                return Err(io::Error::new(io::ErrorKind::Other, "WRITING FUCKED UP"));
            }
        };
        println!("Sent data!");
        // TODO Take care of result
    }
    println!("Receiving data!");
    // Now we read. This happens in 2 chunks: The initial packet, which has the
    // size we expect overall, then continuation packets, which will fill in
    // data until we have everything.
    let mut raw_frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];

    // TODO Check the status of the read, figure out how we'll deal with timeouts.
    let recvlen = dev.read(&mut raw_frame).unwrap();
    // We'll get an init packet back from USB, open it to see how much we'll be
    // reading overall. (should unpack to an init struct)
    let mut info_frame : U2FHIDInit;
    unsafe {
        info_frame = mem::transmute(raw_frame);
    }
    print_array(&raw_frame);
    // Read until we've exhausted the total read amount or error out
    let datalen : usize = (info_frame.bcnth as usize) << 8 | (info_frame.bcntl as usize);
    //let recvlen : u16 = 0;
    sequence = 0;
    println!("Expecting data length: {:?}", datalen);
    println!("Receiving even more data!");
    while recvlen < datalen {
        let mut frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
        println!("Got more data! {:?}", dev.read(&mut frame));
        print_array(&frame);
        let mut cont_frame : U2FHIDCont;
        unsafe {
            cont_frame = mem::transmute(frame);
        }
        if cont_frame.seq != sequence + 1 {
            println!("Error in sequence number!");
            // TODO: This should be an error.
            return Err(io::Error::new(io::ErrorKind::Other, "Sequence numbers out of order!"));
        }
        sequence = cont_frame.seq;
    }
    println!("Finished receiving data!");
    let ret : R;
    unsafe {
        // TODO Just make this a bounded transmute with a size check before it.
        ret = std::mem::transmute_copy(&info_frame.data);
    }
    // Return the read data buffer.
    Ok(ret)
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
    let mut header = U2FAPDUHeader {
        cla: 0,
        ins: cmd,
        p1: p1,
        p2: 0,
        lc: [0; 3]
    };
    // lc[0] should always be 0
    header.lc[1] = (send.len() & 0xff) as u8;
    header.lc[2] = (send.len() >> 8) as u8;
    // Size of header, plus data, plus 2 0 bytes at the end for maximum return
    // size.
    let mut data_vec : Vec<u8> = vec![0; std::mem::size_of::<U2FAPDUHeader>() + send.len() + 2];
    let header_raw : [u8; U2FAPDUHEADER_SIZE];
    unsafe {
        header_raw = mem::transmute(header);
    }
    data_vec[0..U2FAPDUHEADER_SIZE].clone_from_slice(&header_raw);
    data_vec[U2FAPDUHEADER_SIZE..send.len() + U2FAPDUHEADER_SIZE].clone_from_slice(&send);
    let mut base_recv = vec![0 as u8; 65536];
    //sendrecv(dev, U2FHID_MSG, &data_vec, &mut base_recv);
    Ok(())
}

#[cfg(test)]
    mod tests {
    use ::{U2FDevice, init_device};
    use std::error::Error;
    mod platform {
        use ::CID_BROADCAST;
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
                let check = match self.expected_writes.pop() {
                    Some(c) => c,
                    None => panic!("Ran out of expected reads!")
                };
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
                let check = match self.expected_reads.pop() {
                    Some(c) => c,
                    None => panic!("Ran out of expected reads!")
                };
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
    }

    #[test]
    fn test_sendapdu() {
    }
}
