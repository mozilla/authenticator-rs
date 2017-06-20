use std::io;

use super::iokit::*;
use core_foundation_sys::base::*;
use core_foundation_sys::dictionary::*;
use core_foundation_sys::number::*;
use core_foundation_sys::runloop::*;
use core_foundation_sys::string::*;

extern crate log;
extern crate libc;

use ::consts::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};

pub struct IOHIDDeviceID {
    pub device_id: u64 // TODO: Does this work on non-64-bit systems?
}

impl IOHIDDeviceID {
    pub fn from_ref(device_ref: IOHIDDeviceRef) -> IOHIDDeviceID {
        IOHIDDeviceID{ device_id: device_ref as u64 }
    }

    pub fn as_ref(&self) -> IOHIDDeviceRef {
        self.device_id as IOHIDDeviceRef
    }
}

pub struct IOHIDDeviceMatcher {
    dict: CFDictionaryRef,
    keys: Vec<CFStringRef>,
    values: Vec<CFNumberRef>
}

impl IOHIDDeviceMatcher {
    pub fn new() -> Self {
        let keys = vec!(
            IOHIDDeviceMatcher::cf_string("DeviceUsage"),
            IOHIDDeviceMatcher::cf_string("DeviceUsagePage")
        );

        let values = vec!(
            IOHIDDeviceMatcher::cf_number(FIDO_USAGE_U2FHID as i32),
            IOHIDDeviceMatcher::cf_number(FIDO_USAGE_PAGE as i32)
        );

        let dict = unsafe {
              CFDictionaryCreate(kCFAllocatorDefault,
                                 keys.as_ptr() as *const *const libc::c_void,
                                 values.as_ptr() as *const *const libc::c_void,
                                 keys.len() as CFIndex,
                                 &kCFTypeDictionaryKeyCallBacks,
                                 &kCFTypeDictionaryValueCallBacks) };

        Self { dict, keys, values }
    }

    fn cf_number(number: i32) -> CFNumberRef {
        let nbox = Box::new(number);
        let nptr = Box::into_raw(nbox) as *mut libc::c_void;

        unsafe {
            // Drop when out of scope.
            let _num = Box::from_raw(nptr);
            CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, nptr)
        }
    }

    fn cf_string(string: &str) -> CFStringRef {
        unsafe { CFStringCreateWithBytes(kCFAllocatorDefault,
                                         string.as_ptr(),
                                         string.len() as CFIndex,
                                         kCFStringEncodingUTF8,
                                         false as Boolean,
                                         kCFAllocatorNull) }
    }

    pub fn get(&self) -> CFDictionaryRef {
        self.dict
    }
}

impl Drop for IOHIDDeviceMatcher {
    fn drop(&mut self) {
        unsafe { CFRelease(self.dict as *mut libc::c_void) };

        for key in &self.keys {
            unsafe { CFRelease(*key as *mut libc::c_void) };
        }

        for value in &self.values {
            unsafe { CFRelease(*value as *mut libc::c_void) };
        }
    }
}

pub struct IOHIDManager {
    manager: IOHIDManagerRef
}

impl IOHIDManager {
    pub fn new() -> io::Result<Self> {
        let manager = unsafe { IOHIDManagerCreate(kCFAllocatorDefault,
                                                  kIOHIDManagerOptionNone) };

        let rv = unsafe { IOHIDManagerOpen(manager, kIOHIDManagerOptionNone) };
        if rv != 0 {
            return Err(io::Error::new(io::ErrorKind::Other,
                                      "Couldn't open HID Manager"));
        }

        unsafe { IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetCurrent(),
                                                 kCFRunLoopDefaultMode) };

        Ok(Self { manager })
    }

    pub fn get(&self) -> IOHIDManagerRef {
        self.manager
    }
}

impl Drop for IOHIDManager {
    fn drop(&mut self) {
        let rv = unsafe { IOHIDManagerClose(self.manager,
                                            kIOHIDManagerOptionNone) };
        if rv != 0 {
            warn!("Couldn't close the HID Manager");
        }
    }
}
