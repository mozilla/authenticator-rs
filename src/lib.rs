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

const HID_RPT_SIZE : usize = 64;
const CID_BROADCAST : u32 = 0xffffffff;
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

#[repr(packed)]
struct U2FHIDInitReq {
    nonce: [u8; INIT_NONCE_SIZE]
}

#[repr(packed)]
struct U2FHIDInitResp {
    nonce: [u8; INIT_NONCE_SIZE],
    cid: u32,
    version_interface: u8,
    version_major: u8,
    version_minor: u8,
    version_build: u8,
    cap_flags: u8
}

#[repr(packed)]
struct U2FHIDInit {
    cid: u32,
    cmd: u8,
    bcnth: u8,
    bcntl: u8,
    data: [u8; HID_RPT_SIZE - 7]
}

#[repr(packed)]
struct U2FHIDCont {
    cid: u32,
    seq: u8,
    data: [u8; HID_RPT_SIZE - 5]
}

pub fn init_device(dev: &mut platform::Device) {
    println!("Initing device!");
    let nonce = vec![0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1];
    let mut recv : Vec<u8> = Vec::new();
    sendrecv(dev, U2FHID_INIT, &nonce, &mut recv);
}

pub fn sendrecv(dev: &mut platform::Device, cmd: u8, send: &Vec<u8>, recv: &mut Vec<u8>) -> io::Result<()> {
    let mut data_sent: usize = 0;
    let mut sequence: u8 = 0;

    println!("Sending data!");
    // Write Data.
    while send.len() > data_sent {
        let frame : [u8; HID_RPT_SIZE];

        if data_sent == 0 {
            let mut uf = U2FHIDInit {
                cid: dev.cid,
                cmd: cmd,
                bcnth: (send.len() >> 8) as u8,
                bcntl: send.len() as u8,
                data: [0; HID_RPT_SIZE - 7]
            };
            // clone_from_slice panics if src/dst sizes don't match.
            uf.data[0..send.len()].clone_from_slice(send);
            unsafe {
                frame = mem::transmute(uf);
            }
        } else {
            let uf = U2FHIDCont {
                cid: dev.cid,
                seq: sequence,
                data: [0; HID_RPT_SIZE - 5]
            }
            uf.data[0..send.len()].clone_from_slice(send);
            unsafe {
                frame = mem::transmute(uf);
            }
        }

        sequence += 1;
        // TODO Figure out nicer way to prepend record number
        let mut frame_data : [u8; HID_RPT_SIZE + 1] = [0u8; HID_RPT_SIZE + 1];
        frame_data[0] = 0;
        frame_data[1..].clone_from_slice(&frame);

        match platform::write(dev, &frame_data) {
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
    let recvlen = platform::read(dev, &mut raw_frame).unwrap();
    println!("Read! {:?}", recvlen);
    for x in 0..64 {
        println!("{:?}", raw_frame[x]);
    }
    // We'll get an init packet back from USB, open it to see how much we'll be
    // reading overall. (should unpack to an init struct)
    let mut info_frame : U2FHIDInit;
    unsafe {
        info_frame = mem::transmute(raw_frame);
    }

    // Read until we've exhausted the total read amount or error out
    let datalen : usize = (info_frame.bcnth as usize) << 8 | (info_frame.bcntl as usize);
    //let recvlen : u16 = 0;
    sequence = 0;
    println!("Expecting data length: {:?}", datalen);
    println!("Receiving even more data!");
    while recvlen < datalen {
        let mut frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
        println!("Got more data! {:?}", platform::read(dev, &mut frame));

        let mut cont_frame : U2FHIDCont;
        unsafe {
            cont_frame = mem::transmute(frame);
        }
        if cont_frame.seq != sequence + 1 {
            println!("Error in sequence number!");
            // TODO: This should be an error.
            return Ok(());
        }
        sequence = cont_frame.seq;
    }
    println!("Finished receiving data!");
    // Return the read data buffer.
    Ok(())
}
