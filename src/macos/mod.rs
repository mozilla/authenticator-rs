extern crate libc;
extern crate mach;

pub use self::iokit::*;
mod iokit;

use std::io::{Read, Write};
use std::io;
use std::fmt;
use std::mem;
use std::ptr;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock};
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
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

use consts::{CID_BROADCAST, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID, HID_RPT_SIZE};
use U2FDevice;

const READ_TIMEOUT: u64 = 15;

pub struct Report {
    pub data: [u8; HID_RPT_SIZE],
}
unsafe impl Send for Report {}
unsafe impl Sync for Report {}

pub struct InternalDevice {
    pub name: String,
    pub device_ref: IOHIDDeviceRef,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
    pub report_recv: Receiver<Report>,
    pub report_send: Sender<Report>,
}

impl fmt::Display for InternalDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InternalDevice({}, ref:{:?}, cid: {:02x}{:02x}{:02x}{:02x})", self.name, self.device_ref,
               self.cid[0], self.cid[1], self.cid[2], self.cid[3])
    }
}

struct AddedDevice {
    pub raw_handle: u64,
    pub report_tx: Sender<Report>,
    pub is_started: Arc<(Mutex<bool>, Condvar)>,
}

#[derive(Clone)]
pub struct Device {
    pub device: Arc<RwLock<InternalDevice>>,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let int_device = self.device.read().unwrap();
        write!(f, "Device({})", *int_device)
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        let int_device = self.device.read().unwrap();
        let other_device = other.device.read().unwrap();
        int_device.device_ref == other_device.device_ref
    }
}

impl Read for Device {
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        let int_device = self.device.write().unwrap();
        println!("Reading {}", *int_device);
        let timeout = Duration::from_secs(READ_TIMEOUT);
        let report_data = match int_device.report_recv.recv_timeout(timeout) {
            Ok(v) => v,
            Err(e) => {
                if e == RecvTimeoutError::Timeout {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, e));
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, e));
            },
        };
        let len = bytes.write(&report_data.data).unwrap();
        Ok(len)
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let int_device = self.device.write().unwrap();
        println!("Sending on {}", *int_device);
        unsafe { set_report(int_device.device_ref, kIOHIDReportTypeOutput, bytes) }
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl U2FDevice for Device {
    fn get_cid(&self) -> [u8; 4] {
        let int_device = self.device.read().unwrap();
        return int_device.cid.clone();
    }
    fn set_cid(&mut self, cid: &[u8; 4]) {
        let mut int_device = self.device.write().unwrap();
        int_device.cid.clone_from(cid);
    }
}

pub struct PlatformManager {
    pub hid_manager: IOHIDManagerRef,
    device_added: Sender<AddedDevice>,
    known_devices: Vec<Device>,
}

pub fn open_platform_manager() -> io::Result<PlatformManager> {
    let (mut added_tx, added_rx) = channel::<AddedDevice>();

    let hid_manager: IOHIDManagerRef;
    unsafe {
        hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
        IOHIDManagerSetDeviceMatching(hid_manager, ptr::null());

        let result = IOHIDManagerOpen(hid_manager, kIOHIDManagerOptionNone);
        if result != KERN_SUCCESS {
            return Err(io::Error::from_raw_os_error(result));
        }
    }

    let hid_manager_ptr: u64 = unsafe { ::std::mem::transmute(hid_manager) };
    let thread = match thread::Builder::new().name("HID Runloop".to_string()).spawn(move || {
    unsafe {
        let (mut removal_tx, removal_rx) = channel::<IOHIDDeviceRef>();

        let hid_manager: IOHIDManagerRef = ::std::mem::transmute(hid_manager_ptr);
        let removal_tx_ptr: *mut libc::c_void = &mut removal_tx as *mut _ as *mut libc::c_void;
        IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, device_unregistered_cb, removal_tx_ptr);

        // Start the manager
        IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

        // Run the Event Loop. CFRunLoopRunInMode() will dispatch HID input reports into the
        // read_new_data_cb() callback.
        loop {
            println!("Run loop running, handle={:?}", thread::current());

            #[allow(non_upper_case_globals)]
            match CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, 0) {
                kCFRunLoopRunStopped => {
                    println!("Device stopped.");
                    return;
                },
                _ => {},
            }
        }
    }}) {
        Ok(t) => Some(t),
        Err(e) => return Err(e),
    };

    println!("Finding ... ");
    let mut device_refs: Vec<IOHIDDeviceRef> = Vec::new();
    unsafe {
        let device_set = IOHIDManagerCopyDevices(hid_manager);
        if device_set.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Could not get the set of devices"));
        }

        // The OSX System call can take a void pointer _context, which we will use
        // for the out variable, devices.
        let devices_ptr: *mut libc::c_void = &mut device_refs as *mut _ as *mut libc::c_void;
        CFSetApplyFunction(device_set, locate_hid_devices_cb, devices_ptr);
    }

    let scratch_buf = [0; HID_RPT_SIZE];

    let mut devices: Vec<Device> = Vec::new();
    for device_ref in device_refs {
        let (mut report_tx, report_rx) = channel::<Report>();

        let started_conditon = Arc::new((Mutex::new(false), Condvar::new()));

        let int_device = InternalDevice {
            name: get_name(device_ref),
            device_ref: device_ref,
            cid: CID_BROADCAST,
            report_send: report_tx,
            report_recv: report_rx,
        };

        let device = Device {
            device: Arc::new(RwLock::new(int_device)),
        };

        let report_tx_ptr: *mut libc::c_void = unsafe { &mut device.device.read().unwrap().report_send.clone() as *mut _ as *mut libc::c_void };

        unsafe {
            IOHIDDeviceRegisterInputReportCallback(device_ref, scratch_buf.as_ptr(),
                                                   scratch_buf.len() as CFIndex,
                                                   read_new_data_cb, report_tx_ptr);
        }

        println!("Readied {}", device);
        devices.push(device);
    }

    Ok(PlatformManager {
        hid_manager: hid_manager,
        device_added: added_tx,
        known_devices: devices,
    })
}

impl PlatformManager {
    pub fn close(&self) {
        unsafe {
            let result = IOHIDManagerClose(self.hid_manager, kIOHIDManagerOptionNone);
            if result != KERN_SUCCESS {
                panic!("ERROR: {}", result);
            }
        }
        println!("U2FManager closing...");
    }

    pub fn find_keys(&self) -> io::Result<Vec<Device>>
    {
        Ok(self.known_devices.clone())
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

    let number_ref = IOHIDDeviceGetProperty(device_ref, key);
    if number_ref.is_null() {
        result = -1
    } else {
        if CFGetTypeID(number_ref) == CFNumberGetTypeID() {
            CFNumberGetValue(number_ref as CFNumberRef,
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

fn get_name(device_ref: IOHIDDeviceRef) -> String {
    unsafe {
        let vendor_id = get_int_property(device_ref, kIOHIDVendorIDKey());
        let product_id = get_int_property(device_ref, kIOHIDProductIDKey());
        let device_usage = get_usage(device_ref);
        let device_usage_page = get_usage_page(device_ref);

        format!("Vendor={} Product={} Page={} Usage={}", vendor_id, product_id,
                device_usage_page, device_usage)
    }
}

// This is called from the RunLoop thread
extern "C" fn read_new_data_cb(context: *mut c_void,
                               _: IOReturn,
                               _: *mut c_void,
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

        if let Err(e) = tx.send(report_obj) {
            // TOOD: This happens when the channel closes before this thread
            // does. This is pretty common, but let's deal with stopping
            // properly later.
            println!("Problem returning read_new_data_cb data for thread: {}", e);
        };
    }
}

// This is called from the RunLoop thread
extern "C" fn device_unregistered_cb(context: *mut c_void,
                                     result: IOReturn,
                                     _: *mut c_void,
                                     device: IOHIDDeviceRef) {
    unsafe {
        let tx: &mut Sender<IOHIDDeviceRef> = &mut *(context as *mut Sender<IOHIDDeviceRef>);

        // context contains a Device which we populate as the out variable
        // let device: &mut Device = &mut *(context as *mut Device);

        // let device_ref = void_ref as IOHIDDeviceRef;
        println!("{:?} device_unregistered_cb context={:?} result={:?} device_ref={:?}",
                 thread::current(), context, result, device);

        if let Err(e) = tx.send(device) {
            // TOOD: This happens when the channel closes before this thread
            // does. This is pretty common, but let's deal with stopping
            // properly later.
            println!("Problem returning device_unregistered_cb data for thread: {}", e);
        };
    }
}

// This method is called in the same thread
extern "C" fn locate_hid_devices_cb(void_ref: CFTypeRef, context: *const c_void) {
    unsafe {
        // context contains a Vec<Device> which we populate as the out variable
        let devices: &mut Vec<IOHIDDeviceRef> = &mut *(context as *mut Vec<IOHIDDeviceRef>);

        let device_ref = void_ref as IOHIDDeviceRef;

        if is_u2f_device(device_ref) {
            println!("Found U2F Device, passing it back...");
            devices.push(device_ref);
        }
    }
}
