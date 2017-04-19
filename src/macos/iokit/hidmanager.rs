#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use libc::c_void;
use core_foundation_sys::base::CFAllocatorRef;
use core_foundation_sys::set::CFSetRef;
use core_foundation_sys::string::CFStringRef;
use core_foundation_sys::runloop::CFRunLoopRef;
use core_foundation_sys::dictionary::CFDictionaryRef;

use platform::iokit::ioreturn::IOReturn;
use platform::iokit::hiddevice::{IOHIDDeviceCallback, IOHIDReportCallback};
use platform::iokit::IOOptionBits;

pub type IOHIDManagerOptions = IOOptionBits;
pub const kIOHIDManagerOptionNone: IOHIDManagerOptions                    = 0;
pub const kIOHIDManagerOptionUsePersistentProperties: IOHIDManagerOptions = 1;
pub const kIOHIDManagerOptionDoNotLoadProperties: IOHIDManagerOptions     = 2;
pub const kIOHIDManagerOptionDoNotSaveProperties: IOHIDManagerOptions     = 4;

#[doc(hidden)]
#[repr(C)]
pub struct __IOHIDManager {
    __private: c_void,
}

pub type IOHIDManagerRef = *mut __IOHIDManager;

extern "C" {
    pub fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: IOHIDManagerOptions) -> IOHIDManagerRef;
    pub fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: CFDictionaryRef);
    pub fn IOHIDManagerRegisterDeviceMatchingCallback(manager: IOHIDManagerRef, callback: IOHIDDeviceCallback, context: *mut c_void);
    pub fn IOHIDManagerRegisterDeviceRemovalCallback(manager: IOHIDManagerRef, callback: IOHIDDeviceCallback, context: *mut c_void);
    pub fn IOHIDManagerRegisterInputReportCallback(manager: IOHIDManagerRef, callback: IOHIDReportCallback, context: *mut c_void);
    pub fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    pub fn IOHIDManagerClose(manager: IOHIDManagerRef, options: IOHIDManagerOptions) -> IOReturn;
    pub fn IOHIDManagerCopyDevices(manager: IOHIDManagerRef) -> CFSetRef;
    pub fn IOHIDManagerScheduleWithRunLoop(manager: IOHIDManagerRef, runLoop: CFRunLoopRef, runLoopMode: CFStringRef);
}