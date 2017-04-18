extern crate libc;
extern crate mach;

pub use self::iokit::*;
mod iokit;

use std::ffi::{CString, CStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::io;
use std::fmt;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Barrier};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::time::Duration;

use libc::{c_char, c_void};

// use mach::port::{mach_port_t,MACH_PORT_NULL};
use mach::kern_return::KERN_SUCCESS;

use core_foundation_sys::base::*;
use core_foundation_sys::string::*;
use core_foundation_sys::number::*;
use core_foundation_sys::set::*;
use core_foundation_sys::runloop::*;
use core_foundation_sys::dictionary::*;

use {init_device, ping_device};
use consts::{CID_BROADCAST, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID, HID_RPT_SIZE};
use U2FDevice;
pub struct Report {
    pub data: [u8; HID_RPT_SIZE],
}
unsafe impl Send for Report {}
unsafe impl Sync for Report {}

pub struct Device {
    pub name: String,
    pub deviceRef: IOHIDDeviceRef,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
    pub report_send: Sender<Report>,
    pub report_recv: Receiver<Report>,
    pub thread: Option<thread::JoinHandle<()>>,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Device({}, ptr:{:?}, cid: {:02x}{:02x}{:02x}{:02x})", self.name, self.deviceRef,
               self.cid[0], self.cid[1], self.cid[2], self.cid[3])
    }
}

fn create_device(dev: IOHIDDeviceRef, name: String) -> Device {
    let (mut tx, rx) = channel();

    let mut device = Device {
        name: name.clone(),
        deviceRef: dev,
        cid: CID_BROADCAST,
        report_send: tx.clone(),
        report_recv: rx,
        thread: None,
    };


    // Use a barrier to block this function until the thread is ready
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();

    // Use a refcounted clone
    // let tx_clone = tx.clone();

    // Super, super sketchy, but we can't Send a libc::c_void to the thread, yet OSX wants us to do
    // just that. An alternative way to accomplish this might be to come up with enough information
    // for the thread to re-enumerate this device.
    let device_raw_handle : u64 = unsafe { ::std::mem::transmute(dev) };

    device.thread = match thread::Builder::new().name(name).spawn(move || {
      unsafe {
          let device_handle : IOHIDDeviceRef = unsafe { ::std::mem::transmute(device_raw_handle) };
          let tx_ptr: *mut libc::c_void = &mut tx as *mut _ as *mut libc::c_void;
          let scratch_buf = [0; HID_RPT_SIZE];

          IOHIDDeviceRegisterInputReportCallback(device_handle, scratch_buf.as_ptr(),
                                                 scratch_buf.len() as CFIndex,
                                                 read_new_data_cb, tx_ptr);

          IOHIDDeviceScheduleWithRunLoop(device_handle, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

          barrier_clone.wait();

          // Run the Event Loop. CFRunLoopRunInMode() will dispatch HID input reports into the
          // read_new_data_cb() callback.
          while true {
            println!("Run loop running, deviceRef={:?}", device_handle);
            match CFRunLoopRunInMode(kCFRunLoopDefaultMode, 2.0, 0) {
              kCFRunLoopRunFinished => {
                println!("Device disconnected.");
                return;
              },
              kCFRunLoopRunStopped => {
                println!("Device stopped.");
                return;
              },
              _ => {},
            }
          }
      }

    }) {
      Ok(t) => Some(t),
      Err(e) => panic!("Unable to start thread"),
    };

    barrier.wait();

    device
}

impl Read for Device {
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        println!("Reading");
        let report_data = match self.report_recv.recv() {
            Ok(v) => v,
            Err(e) => panic!("Couldn't read data: {}", e),
        };
        let len = bytes.write(&report_data.data).unwrap();
        Ok(len)
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        unsafe { set_report(self.deviceRef, kIOHIDReportTypeOutput, bytes) }
    }

    // USB HID writes don't buffer, so this will be a nop.
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

pub struct U2FManager {
    pub hid_manager: IOHIDManagerRef,
}

pub fn open_u2f_hid_manager() -> io::Result<U2FManager> {
    unsafe {
        let hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
        IOHIDManagerSetDeviceMatching(hid_manager, ptr::null());

        // Start the manager
        IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

        let result = IOHIDManagerOpen(hid_manager, kIOHIDManagerOptionNone);
        if result != KERN_SUCCESS {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(U2FManager { hid_manager: hid_manager })
    }
}

impl U2FManager {
    pub fn close(&self) {
        unsafe {
            let result = IOHIDManagerClose(self.hid_manager, kIOHIDManagerOptionNone);
            if result != KERN_SUCCESS {
                panic!("ERROR: {}", result);
            }
        }
        println!("U2FManager closing...");
    }

    pub fn find_keys(&self) -> io::Result<Vec<Device>> {
        println!("Finding ... ");
        let mut devices: Vec<Device> = vec![];
        unsafe {
            println!("Device counting...");
            let device_set = IOHIDManagerCopyDevices(self.hid_manager);
            if device_set.is_null() {
                panic!("Could not get the set of devices");
            }

            println!("Device set...");
            // let count = CFSetGetCount(device_set);
            // println!("Device count: {}", count);

            // The OSX System call can take a void pointer _context, which we will use
            // for the out variable, devices.
            let devices_ptr: *mut libc::c_void = &mut devices as *mut _ as *mut libc::c_void;
            CFSetApplyFunction(device_set, locate_hid_devices_cb, devices_ptr);
        }

        Ok(devices)
    }
}

unsafe fn set_report(device_ref: IOHIDDeviceRef,
                     report_type: IOHIDReportType,
                     bytes: &[u8])
                     -> io::Result<usize> {
    let report_id = bytes[0] as i64;
    let mut data = bytes.as_ptr();
    let mut length = bytes.len() as CFIndex;

    if report_id == 0x0 {
        // Not using numbered reports, so don't send the report number
        length = length - 1;
        data = data.offset(1);
    }

    let result = IOHIDDeviceSetReport(device_ref, report_type, report_id, data, length);
    if result != KERN_SUCCESS {
        println!("Sending failure = {0:X}", result);

        return Err(io::Error::from_raw_os_error(result));
    }
    println!("Sending success? = {0:X}", result);

    Ok(length as usize)
}


unsafe fn get_int_property(device_ref: IOHIDDeviceRef, property_name: *const c_char) -> i32 {
    let mut result: i32 = 0;
    let key = CFStringCreateWithCString(kCFAllocatorDefault, property_name, kCFStringEncodingUTF8);
    if key.is_null() {
        panic!("failed to allocate key string");
    }

    let numberRef = IOHIDDeviceGetProperty(device_ref, key);
    if numberRef.is_null() {
        result = -1
    } else {
        if CFGetTypeID(numberRef) == CFNumberGetTypeID() {
            CFNumberGetValue(numberRef as CFNumberRef,
                             kCFNumberSInt32Type,
                             mem::transmute(&mut result));
        }
    }
    result
}

unsafe fn get_usage(device_ref: IOHIDDeviceRef) -> i32 {
    let mut device_usage = get_int_property(device_ref, kIOHIDDeviceUsageKey());
    if device_usage == -1 {
        device_usage = get_int_property(device_ref, kIOHIDPrimaryUsageKey());
    }
    device_usage
}

unsafe fn get_usage_page(device_ref: IOHIDDeviceRef) -> i32 {
    let mut device_usage_page = get_int_property(device_ref, kIOHIDDeviceUsagePageKey());
    if device_usage_page == -1 {
        device_usage_page = get_int_property(device_ref, kIOHIDPrimaryUsagePageKey());
    }
    device_usage_page
}

unsafe fn is_u2f_device(device_ref: IOHIDDeviceRef) -> bool {
    let device_usage = get_usage(device_ref);
    let device_usage_page = get_usage_page(device_ref);

    let is_u2f = device_usage == FIDO_USAGE_U2FHID as i32 &&
                 device_usage_page == FIDO_USAGE_PAGE as i32;
    is_u2f
}

// This is called from the RunLoop thread
extern "C" fn read_new_data_cb(context: *mut c_void,
                               result: IOReturn,
                               sender: *mut c_void,
                               report_type: IOHIDReportType,
                               report_id: u32,
                               report: *mut u8,
                               report_len: CFIndex) {
    unsafe {
        let tx: &mut Sender<Report> = &mut *(context as *mut Sender<Report>);

        println!("read_new_data_cb type={} id={} report={:?} len={}",
                 report_type,
                 report_id,
                 report,
                 report_len);

        let mut report_obj = Report { data: [0; HID_RPT_SIZE] };

        if report_len as usize <= HID_RPT_SIZE {
            ptr::copy(report, report_obj.data.as_mut_ptr(), report_len as usize);
        } else {
            println!("read_new_data_cb got too much data! {} > {}",
                     report_len,
                     HID_RPT_SIZE);
        }

        tx.send(report_obj);
    }
}

// This is called from the RunLoop thread
extern "C" fn device_unregistered_cb(void_ref: CFTypeRef, context: *const c_void) {
    unsafe {
        // context contains a Device which we populate as the out variable
        let device: &mut Device = &mut *(context as *mut Device);

        let device_ref = void_ref as IOHIDDeviceRef;
        println!("device_unregistered_cb = {}", device);
    }
}

// This method is called in the same thread
extern "C" fn locate_hid_devices_cb(void_ref: CFTypeRef, context: *const c_void) {
    unsafe {
        // context contains a Vec<Device> which we populate as the out variable
        let devices: &mut Vec<Device> = &mut *(context as *mut Vec<Device>);

        let device_ref = void_ref as IOHIDDeviceRef;

        if is_u2f_device(device_ref) {
            let vendor_id = get_int_property(device_ref, kIOHIDVendorIDKey());
            let product_id = get_int_property(device_ref, kIOHIDProductIDKey());
            let device_usage = get_usage(device_ref);
            let device_usage_page = get_usage_page(device_ref);

            let name = format!("Vendor={} Product={} Page={} Usage={}",
                     vendor_id, product_id, device_usage_page, device_usage);

            println!("FIDO-compliant Device Found: {}", name);

            devices.push(create_device(device_ref, name));
        }
    }
}
