use libudev;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::io;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct hidraw_report_descriptor {
    pub size: u32,
    pub value: [u8;4096]
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
struct hidraw_devinfo {
    __bustype: u32,
    __vendor: i16,
    __product: i16
}

ioctl!(read hidiocgrdescsize with b'H', 0x01; ::libc::c_int);
ioctl!(read hidiocgrdesc with b'H', 0x02; /*struct*/ hidraw_report_descriptor);

struct Device {
    device_handle: i32,
    blocking: bool,
    uses_numbered_reports: bool
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
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, "Can't get descriptor!"))
    }
    let mut rpt_desc: hidraw_report_descriptor = hidraw_report_descriptor::new(desc_size as u32);
    match from_nix_result(unsafe { hidiocgrdesc(fd, &mut rpt_desc) }) {
        Ok(_) => println!("Descriptor size: {:?}", desc_size),
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, "Can't get descriptor!"))
    }
    Ok(())
}

pub fn find_keys() -> io::Result<()> {
    let context = libudev::Context::new().unwrap();
    let mut enumerator = try!(libudev::Enumerator::new(&context));

    for device in try!(enumerator.scan_devices()) {
        let u;
        match get_usages(&device) {
            Ok(usage) => u = usage,
            Err(_) => continue
        }
    }

    Ok(())
}
