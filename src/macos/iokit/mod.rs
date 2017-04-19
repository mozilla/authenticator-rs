#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate core_foundation_sys;
extern crate libc;
extern crate mach;

pub use self::hiddevice::*;
pub use self::hidmanager::*;
pub use self::ioreturn::*;

mod ioreturn;
mod hiddevice;
mod hidmanager;

use libc::c_char;

pub type IOOptionBits = u32;

// exports from <IOKit/usb/IOUSBLib.h>
pub fn kIOUSBDeviceClassName() -> *const c_char {
    b"IOUSBDevice\0".as_ptr() as *const c_char
}
pub fn kIOUSBInterfaceClassName() -> *const c_char {
    b"IOUSBInterface\0".as_ptr() as *const c_char
}

// exports from <IOHIDFamily/IOHIDKeys.h>
pub fn kIOHIDDeviceUsageKey() -> *const c_char {
    b"DeviceUsage\0".as_ptr() as *const c_char
}
pub fn kIOHIDDeviceUsagePageKey() -> *const c_char {
    b"DeviceUsagePage\0".as_ptr() as *const c_char
}
pub fn kIOHIDPrimaryUsageKey() -> *const c_char {
    b"PrimaryUsage\0".as_ptr() as *const c_char
}
pub fn kIOHIDPrimaryUsagePageKey() -> *const c_char {
    b"PrimaryUsagePage\0".as_ptr() as *const c_char
}
pub fn kIOHIDVendorIDKey() -> *const c_char {
    b"VendorID\0".as_ptr() as *const c_char
}
pub fn kIOHIDProductIDKey() -> *const c_char {
    b"Product\0".as_ptr() as *const c_char
}
