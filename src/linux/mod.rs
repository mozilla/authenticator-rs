use libudev;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::io;
use std::io::{Read, Write};
use ::{init_device, ping_device};
use ::consts::{CID_BROADCAST, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};
use U2FDevice;

////////////////////////////////////////////////////////////////////////
// USB and HID Device Structs
////////////////////////////////////////////////////////////////////////

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct hidraw_report_descriptor {
    pub size: u32,
    pub value: [u8;4096]
}

impl hidraw_report_descriptor {
    pub fn new(s: u32) -> hidraw_report_descriptor  {
        hidraw_report_descriptor {
            size: s,
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

#[derive(Debug, Clone)]
struct DeviceUsage {
    pub usage: u16,
    pub usage_page: u16
}

impl DeviceUsage {
    pub fn new() -> DeviceUsage {
        DeviceUsage {
            usage: 0,
            usage_page: 0
        }
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

fn get_bytes(desc: &[u8], num_bytes: usize, cur: usize) -> u32 {
    /* Return if there aren't enough bytes. */
    if cur + num_bytes >= desc.len() {
        return 0;
    }

    if num_bytes == 0 {
        return 0;
    }
    else if num_bytes == 1 {
        return desc[cur + 1] as u32;
    }
    else if num_bytes == 2 {
        return ((desc[cur + 2] as u32) << 8) + (desc[cur + 1] as u32);
    }
    0
}

fn get_usage(desc: &[u8]) -> Result<Vec<DeviceUsage>, ()> {

    let mut usages : Vec<DeviceUsage> = vec![];
    let mut du : DeviceUsage = DeviceUsage::new();
    let mut size_code: u8;
    let mut data_len: usize;
    let mut key_size: i32;
    let mut usage_found: bool = false;
    let mut usage_page_found: bool = false;
    let mut i: usize = 0;
    while i < desc.len() {
        let key = desc[i];
        let key_cmd = key & 0xfc;
        if key & 0xf0 == 0xf0 {
            return Err(());
        }
        size_code = (key & 0x3) as u8;
        match size_code
	      {
	          0 => data_len = size_code as usize,
            1 => data_len = size_code as usize,
            2 => data_len = size_code as usize,
            3 => data_len = 4,
            _ => data_len = 0
	      };
        key_size = 1;
        let mut du : DeviceUsage = DeviceUsage::new();
        if key_cmd == 0x4
        {
            du.usage_page = get_bytes(desc, data_len, i) as u16;
            usage_page_found = true;
        }
        if key_cmd == 0x8
        {
            du.usage = get_bytes(desc, data_len, i) as u16;
            usage_found = true;
        }

        if usage_page_found && usage_found {
            usage_page_found = false;
            usage_found = false;
            usages.push(du.clone());
            du = DeviceUsage::new();
        }
        i += data_len + (key_size as usize);
    }
    Ok(usages)
}

fn get_usages(dev : &libudev::Device) -> io::Result<Vec<DeviceUsage>> {
    let mut desc_size: i32 = 0;
    let fname = match dev.devnode() {
        Some(n) => n,
        None => return Err(io::Error::new(io::ErrorKind::Other, "No devnode!"))
    };
    let fd = match File::open(fname) {
        Ok(f) => AsRawFd::as_raw_fd(&f),
        Err(e) => return Err(e)
    };
    if let Err(e) = from_nix_result(unsafe { hidiocgrdescsize(fd, &mut desc_size) }) {
        return Err(e);
    }
    let mut rpt_desc: hidraw_report_descriptor = hidraw_report_descriptor::new(desc_size as u32);
    if let Err(e) = from_nix_result(unsafe { hidiocgrdesc(fd, &mut rpt_desc) }) {
        return Err(e);
    }
    match get_usage(&rpt_desc.value[0..(desc_size as usize)]) {
        Ok(v) => Ok(v),
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Can't get descriptor!"))
    }
}

fn is_u2f_device(device: &libudev::Device) -> bool {
    match get_usages(&device) {
        Ok(usages) => {
            usages.iter()
                .any(|ref x| {
                    x.usage_page == FIDO_USAGE_PAGE && x.usage == FIDO_USAGE_U2FHID
                })
        },
        // If we error out while finding usage pages, just say we're not a U2F
        // device.
        Err(_) => false
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
