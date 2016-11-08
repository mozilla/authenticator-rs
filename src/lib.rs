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
mod consts;

use consts::*;
use std::{mem, io, slice};
use std::io::{Read, Write};

pub trait U2FDevice {
    fn get_cid(&self) -> [u8; 4];
    fn set_cid(&mut self, cid: &[u8; 4]);
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
#[allow(dead_code)]
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

#[repr(packed)]
struct U2FHIDCont {
    cid: [u8; 4],
    seq: u8,
    pub data: [u8; CONT_DATA_SIZE]
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

pub fn sendrecv<T>(dev: &mut T,
                   cmd: u8,
                   send: &Vec<u8>) -> io::Result<Vec<u8>>
    where T: U2FDevice + Read + Write
{
    let mut sequence: u8 = 1;
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
        if let Err(er) = dev.write(&frame) {
            return Err(er);
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
    let info_frame : &U2FHIDInit = from_u8_array(&raw_frame);

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
    sequence = 0;
    while recvlen < datalen {
        let mut frame : [u8; HID_RPT_SIZE] = [0u8; HID_RPT_SIZE];
        dev.read(&mut frame).unwrap();
        let cont_frame : &U2FHIDCont;
        cont_frame = from_u8_array(&frame);
        if cont_frame.cid != dev.get_cid() {
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong CID!"));
        }
        if cont_frame.seq != sequence + 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "Sequence numbers out of order!"));
        }
        sequence = cont_frame.seq;
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
    println!("{:?}", header_raw);
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
        use consts::{CID_BROADCAST};
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
        let mut device = platform::TestDevice::new();
        device.set_cid(&[1, 2, 3, 4]);
        let mut r = vec![0x00,
                     // sendrecv header
                     0x01, 0x02, 0x03, 0x04, U2FHID_MSG, 0x00, 0x0e,
                     // apdu header
                     0x00, U2FHID_PING, 0xaa, 0x00, 0x00, 0x00, 0x05,
                     // apdu data
                     0x01, 0x02, 0x03, 0x04, 0x05];
        r.extend([0x0 as u8; 45].iter());
        device.expected_writes.push(r);
        let mut ret = vec![0x01, 0x02, 0x03, 0x04, U2FHID_MSG, 0x00, 0x05,
                           0x01, 0x02, 0x03, 0x04, 0x05];
        ret.extend([0x0 as u8; 52].iter());
        device.expected_reads.push(ret);
        send_apdu(&mut device, U2FHID_PING, 0xaa, &vec![1, 2, 3, 4, 5]);
    }
}
