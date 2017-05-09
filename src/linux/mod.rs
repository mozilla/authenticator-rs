use libudev;
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::os::unix::io::RawFd;
use std::io;
use std::io::{Read, Write};
use ::consts::{CID_BROADCAST, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};
use U2FDevice;

////////////////////////////////////////////////////////////////////////
// USB and HID Device Structs
////////////////////////////////////////////////////////////////////////

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct hidraw_report_descriptor {
    size: ::libc::c_int,
    value: [u8; 4096]
}

impl hidraw_report_descriptor {
    fn new() -> hidraw_report_descriptor  {
        hidraw_report_descriptor {
            size: 0,
            value: [0; 4096]
        }
    }
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h
ioctl!(read hidiocgrdescsize with b'H', 0x01; ::libc::c_int);
ioctl!(read hidiocgrdesc with b'H', 0x02; /*struct*/ hidraw_report_descriptor);

// Struct representing a USB HID device on Linux, via hidraw API
#[derive(Debug)]
pub struct Device {
    pub devnode: PathBuf,
    // hidraw device file handle
    pub device: RawFd,
    // Stores whether or not the device uses numbered reports
    // TODO: Needs implementation
    pub uses_numbered_reports: bool,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.devnode == other.devnode
    }
}

impl Read for Device {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.device == 0 {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"));
        }

        from_nix_result(::nix::unistd::read(self.device, bytes))
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.device == 0 {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"));
        }

        from_nix_result(::nix::unistd::write(self.device, bytes))
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        if self.device == 0 {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"));
        }

        Ok(())
    }
}

impl U2FDevice for Device {
    fn get_cid(&self) -> [u8; 4] {
        return self.cid.clone();
    }
    fn set_cid(&mut self, cid: &[u8; 4]) {
        self.cid.clone_from(cid);
    }
}

////////////////////////////////////////////////////////////////////////
// Utility Functions
////////////////////////////////////////////////////////////////////////

fn from_nix_error(err: ::nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno() as i32)
}

fn from_nix_result<T>(res: ::nix::Result<T>) -> io::Result<T> {
    match res {
        Ok(r) => Ok(r),
        Err(err) => Err(from_nix_error(err)),
    }
}

////////////////////////////////////////////////////////////////////////
// HID Usage Page Functions
////////////////////////////////////////////////////////////////////////

fn read_report_descriptor(dev: &libudev::Device, desc: &mut hidraw_report_descriptor) -> io::Result<()> {
    let path = dev.devnode().unwrap();
    let opts = ::nix::fcntl::O_RDONLY;
    let mode = ::nix::sys::stat::Mode::empty();

    // Open the file and read the report descriptor.
    let fd = try!(from_nix_result(::nix::fcntl::open(path, opts, mode)));

    try!(from_nix_result(unsafe { hidiocgrdescsize(fd, &mut desc.size) }));
    try!(from_nix_result(unsafe { hidiocgrdesc(fd, desc) }));
    try!(from_nix_result(::nix::unistd::close(fd)));

    Ok(())
}

fn read_uint_le(buf: &[u8]) -> u32 {
    assert!(buf.len() <= 4);
    // Parse the number in little endian byte order.
    buf.iter().rev().fold(0, |num, b| (num << 8) | (*b as u32))
}

fn has_fido_usage(desc: &hidraw_report_descriptor) -> bool {
    let desc = &desc.value[..];
    let mut usage_page = None;
    let mut usage = None;
    let mut i = 0;

    while i < desc.len() {
        let key = desc[i];
        let cmd = key & 0xfc;

        if key & 0xf0 == 0xf0 {
            break; // Invalid data.
        }

        // Determine length.
        let data_len = match key & 0x3 {
            s @ 0 ... 2 => s as usize,
            _ => 4 /* key & 0x3 == 3 */
        };

        if i + data_len >= desc.len() {
            break; // Invalid data.
        }

        let data = &desc[i+1..i+1+data_len];

        // Read value.
        if cmd == 0x4 {
            usage_page = Some(read_uint_le(data));
        } else if cmd == 0x8 {
            usage = Some(read_uint_le(data));
        }

        // Check the values we found.
        if let (Some(usage_page), Some(usage)) = (usage_page, usage) {
            return usage_page == FIDO_USAGE_PAGE as u32 &&
                   usage == FIDO_USAGE_U2FHID as u32;
        }

        // Next byte.
        i += data_len + 1;
    }

    false
}

fn is_u2f_device(dev: &libudev::Device) -> bool {
    if dev.subsystem().to_str() != Some("hidraw") {
        return false;
    }

    if dev.devnode().is_none() {
        return false;
    }

    let mut desc = hidraw_report_descriptor::new();
    match read_report_descriptor(&dev, &mut desc) {
        Ok(_) => has_fido_usage(&desc),
        Err(_) => false // Upon failure, just say it's not a U2F device.
    }
}

////////////////////////////////////////////////////////////////////////
// Publicly Exposed Device Functions
////////////////////////////////////////////////////////////////////////

fn create_device(dev: &libudev::Device) -> io::Result<Device> {
    let devnode = match dev.devnode() {
        Some(n) => n,
        None => return Err(io::Error::new(io::ErrorKind::Other, "No devnode for device!"))
    };
    Ok(Device {
        devnode: devnode.to_owned(),
        device: 0,
        // TODO Actually check the usage report here
        uses_numbered_reports: true,
        // Start device with CID_BROADCAST as a cid, we'll get the actual CID on
        // device init.
        cid: CID_BROADCAST
    })
}

pub fn open_device(dev: &mut Device) -> io::Result<()> {
    let path = &dev.devnode;
    let opts = ::nix::fcntl::O_RDWR;
    let mode = ::nix::sys::stat::Mode::empty();
    dev.device = try!(from_nix_result(::nix::fcntl::open(path, opts, mode)));

    Ok(())
}

pub fn find_keys() -> io::Result<Vec<Device>> {
    let context = libudev::Context::new().unwrap();
    let mut enumerator = try!(libudev::Enumerator::new(&context));
    let mut devices = vec![];

    // udev's enumerator returns an internally allocated linked list, not an
    // iterator, so we can't use filter on it.
    for device in try!(enumerator.scan_devices()) {
        if is_u2f_device(&device) {
            devices.push(try!(create_device(&device)));
        }
    }

    Ok(devices)
}
