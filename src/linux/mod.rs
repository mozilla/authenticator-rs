use libudev;
use byteorder::{ByteOrder, LittleEndian};
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
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

// Taken from ioctl crate, but it doesn't look like they're alive anymore?
ioctl!(read hidiocgrdescsize with b'H', 0x01; ::libc::c_int);
ioctl!(read hidiocgrdesc with b'H', 0x02; /*struct*/ hidraw_report_descriptor);

// Struct representing a USB HID device on Linux, via hidraw API
#[derive(Debug)]
pub struct Device {
    pub devnode: PathBuf,
    // hidraw device file handle
    pub device: Option<File>,
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
        if let Some(ref mut d) = self.device {
            d.read(bytes)
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"))
        }
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(ref mut d) = self.device {
            d.write(bytes)
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"))
        }
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref d) = self.device {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "Device not opened!"))
        }
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

fn has_fido_usage(desc: &hidraw_report_descriptor) -> bool {
    let desc = &desc.value[..];
    let mut usage_page = None;
    let mut usage = None;
    let mut i = 0;

    while i < desc.len() {
        let key = desc[i];
        let cmd = key & 0xfc;
        let data = &desc[i+1..];

        if key & 0xf0 == 0xf0 {
            break; // Invalid data.
        }

        // Determine length.
        let data_len = match key & 0x3 {
            s @ 0 ... 2 => s as usize,
            _ => 4 /* key & 0x3 == 3 */
        };

        if data_len > data.len() {
            break; // Invalid data.
        }

        // Read value.
        if cmd == 0x4 {
            usage_page = Some(LittleEndian::read_uint(data, data_len));
        } else if cmd == 0x8 {
            usage = Some(LittleEndian::read_uint(data, data_len));
        }

        // Check the values we found.
        if let (Some(usage_page), Some(usage)) = (usage_page, usage) {
            return usage_page == FIDO_USAGE_PAGE as u64 &&
                   usage == FIDO_USAGE_U2FHID as u64;
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
        device: None,
        // TODO Actually check the usage report here
        uses_numbered_reports: true,
        // Start device with CID_BROADCAST as a cid, we'll get the actual CID on
        // device init.
        cid: CID_BROADCAST
    })
}

pub fn open_device(dev: &mut Device) -> io::Result<()> {
    dev.device = match OpenOptions::new().write(true).read(true).open(&dev.devnode) {
        Ok(f) => Some(f),
        Err(er) => return Err(er)
    };
    Ok(())
}

pub fn find_keys() -> io::Result<Vec<Device>> {
    let context = libudev::Context::new().unwrap();
    let mut enumerator = try!(libudev::Enumerator::new(&context));
    let mut devices : Vec<Device> = vec![];

    // udev's enumerator returns an internally allocated linked list, not an
    // iterator, so we can't use filter on it.
    for device in try!(enumerator.scan_devices()) {
        if is_u2f_device(&device) {
            match create_device(&device) {
                Ok(d) => devices.push(d),
                Err(e) => return Err(e)
            }
        }
    }

    Ok(devices)
}
