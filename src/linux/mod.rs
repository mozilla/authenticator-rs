use libudev;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::io;
use std::io::{Read, Write};
use ::{init_device};
use ::consts::CID_BROADCAST;
use U2FDevice;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct hidraw_report_descriptor {
    pub size: u32,
    pub value: [u8;4096]
}

// Taken from ioctl crate, but it doesn't look like they're alive anymore?
ioctl!(read hidiocgrdescsize with b'H', 0x01; ::libc::c_int);
ioctl!(read hidiocgrdesc with b'H', 0x02; /*struct*/ hidraw_report_descriptor);

#[derive(Debug)]
pub struct Device {
    // TODO: Does this need a lifetime?
    pub device: File,
    pub blocking: bool,
    pub uses_numbered_reports: bool,
    pub cid: [u8; 4],
}

#[derive(Debug)]
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

impl hidraw_report_descriptor {
    pub fn new(s: u32) -> hidraw_report_descriptor  {
        hidraw_report_descriptor {
            size: s,
            value: [0; 4096]
        }
    }
}

fn from_nix_error(err: ::nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno() as i32)
}

fn from_nix_result<T>(res: ::nix::Result<T>) -> io::Result<T> {
    match res {
        Ok(r) => Ok(r),
        Err(err) => Err(from_nix_error(err)),
    }
}

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

fn get_usage(desc: &[u8]) -> Result<DeviceUsage, ()> {
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
        println!("start: {0}, len: {1}", i, data_len);
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
            // TODO: Hack to make sure we only access Yubikey
            if du.usage == 1 {
                return Ok(du);		/* success */
            }
            return Err(());
        }
        i += data_len + (key_size as usize);
    }

    return Err(())
}

fn get_usages(dev : &libudev::Device) -> io::Result<()> {
    let mut desc_size: i32 = 0;
    let fd;
    let fname;
    match dev.devnode() {
        Some(n) => fname = n,
        None => return Err(io::Error::new(io::ErrorKind::Other, "No devnode!"))
    }
    let f = try!(File::open(fname));
    fd = AsRawFd::as_raw_fd(&f);
    match from_nix_result(unsafe { hidiocgrdescsize(fd, &mut desc_size) }) {
        Ok(_) => println!("Descriptor size: {:?}", desc_size),
        Err(e) => return Err(e)
    }
    println!("{:?} {:?}", dev.devnode(), dev.sysname());
    let mut rpt_desc: hidraw_report_descriptor = hidraw_report_descriptor::new(desc_size as u32);
    match from_nix_result(unsafe { hidiocgrdesc(fd, &mut rpt_desc) }) {
        Ok(_) => println!("Descriptor size: {:?}", desc_size),
        Err(e) => return Err(e)
    }
    match get_usage(&rpt_desc.value[0..(desc_size as usize)]) {
        Ok(_) => Ok(()),
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Can't get descriptor!"))
    }
}

pub fn open_device(fname: &Path) -> io::Result<Device> {
    println!("opening device!");
    let d = match OpenOptions::new().write(true).read(true).open(fname) {
        Ok(f) => f,
        Err(er) => { println!("{:?}", er); return Err(io::Error::new(io::ErrorKind::Other, "Can't open!")); }
    };
    println!("Opened device! {:?}", d);
    let mut device = Device {
        device: d,
        blocking: true,
        // TODO Actually check the usage report here
        uses_numbered_reports: true,
        // Start device with CID_BROADCAST as a cid, we'll get the actual CID on
        // device init.
        cid: CID_BROADCAST
    };
    println!("Trying to init device!");
    init_device(&mut device);
    Ok(device)
}

pub fn find_keys() -> io::Result<()> {
    let context = libudev::Context::new().unwrap();
    let mut enumerator = try!(libudev::Enumerator::new(&context));

    for device in try!(enumerator.scan_devices()) {
        //let u;
        match get_usages(&device) {
            Ok(usage) => {
                println!("{:?}", usage);
                match device.devnode() {
                    Some(n) => { open_device(n); },
                    None => println!("Can't open!")
                };
            },
            Err(_) => continue
        };
    }

    Ok(())
}

impl Read for Device {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.device.read(bytes)
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        println!("writing to device! {:?}", self.device);
        self.device.write(bytes)
    }

    // nop
    fn flush(&mut self) -> io::Result<()> {
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
