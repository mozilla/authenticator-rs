#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate core_foundation_sys;
extern crate libc;

use libc::c_void;
use core_foundation_sys::base::{CFIndex, CFTypeRef};
use core_foundation_sys::string::CFStringRef;
use core_foundation_sys::runloop::CFRunLoopRef;

use platform::iokit::ioreturn::IOReturn;
use platform::iokit::IOOptionBits;

pub type IOHIDReportType = IOOptionBits;
pub const kIOHIDReportTypeInput: IOHIDReportType   = 0;
pub const kIOHIDReportTypeOutput: IOHIDReportType  = 1;
pub const kIOHIDReportTypeFeature: IOHIDReportType = 2;
pub const kIOHIDReportTypeCount: IOHIDReportType   = 3;

#[doc(hidden)]
#[repr(C)]
pub struct __IOHIDDevice {
    __private: c_void,
}

pub type IOHIDDeviceRef = *const __IOHIDDevice;

pub type IOHIDDeviceCallback = extern fn(context: *mut c_void, result: IOReturn, sender: *mut c_void, device: IOHIDDeviceRef);

pub type IOHIDReportCallback = extern fn(context: *mut c_void, result: IOReturn, sender: *mut c_void, report_type: IOHIDReportType,
                                         report_id: u32, report: *mut u8, report_len: CFIndex);

pub type IOHIDCallback = extern fn(context: *mut c_void, result: IOReturn, sender: *mut c_void);

extern "C" {
    pub fn IOHIDDeviceGetProperty(device: IOHIDDeviceRef, key: CFStringRef) -> CFTypeRef;
    pub fn IOHIDDeviceScheduleWithRunLoop(device: IOHIDDeviceRef, runLoop: CFRunLoopRef, runLoopMode: CFStringRef);
    pub fn IOHIDDeviceSetReport(device: IOHIDDeviceRef, reportType: IOHIDReportType, reportID: CFIndex, report: *const u8, reportLength: CFIndex) -> IOReturn;
    pub fn IOHIDDeviceRegisterInputReportCallback(device: IOHIDDeviceRef, report: *const u8, reportLength: CFIndex, callback: IOHIDReportCallback, context: *mut c_void);
    pub fn IOHIDDeviceRegisterRemovalCallback(device: IOHIDDeviceRef, callback: IOHIDCallback, context: *mut c_void);
}

