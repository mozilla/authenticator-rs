use nix::sys::ioctl;

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
struct hidraw_report_descriptor {
    size: u32;
    value: [u8;4096];
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(C)]
struct hidraw_devinfo {
    __bustype: u32,
    __vendor: i16,
    __product: i16
}
