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
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use libc::{c_char, c_void};

use mach::kern_return::KERN_SUCCESS;

use core_foundation_sys::base::*;
use core_foundation_sys::string::*;
use core_foundation_sys::number::*;
use core_foundation_sys::set::*;
use core_foundation_sys::runloop::*;

mod monitor;
use self::monitor::Monitor;
use std::collections::HashMap;

use consts::{CID_BROADCAST, FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID, HID_RPT_SIZE};
use U2FDevice;

const READ_TIMEOUT: u64 = 15;

pub struct Report {
    pub data: [u8; HID_RPT_SIZE],
}
unsafe impl Send for Report {}
unsafe impl Sync for Report {}

pub struct Device {
    pub name: String,
    pub device_ref: IOHIDDeviceRef,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
    pub report_recv: Receiver<Report>,
    pub report_send_void: *mut libc::c_void,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InternalDevice({}, ref:{:?}, cid: {:02x}{:02x}{:02x}{:02x})", self.name,
               self.device_ref, self.cid[0], self.cid[1], self.cid[2], self.cid[3])
    }
}

impl PartialEq for Device {
    fn eq(&self, other_device: &Device) -> bool {
        self.device_ref == other_device.device_ref
    }
}

impl Read for Device {
    fn read(&mut self, mut bytes: &mut [u8]) -> io::Result<usize> {
        let timeout = Duration::from_secs(READ_TIMEOUT);
        let report_data = match self.report_recv.recv_timeout(timeout) {
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
        println!("Sending on {}", self);
        unsafe { set_report(self.device_ref, kIOHIDReportTypeOutput, bytes) }
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

pub struct PlatformManager {
  // Send 'stop' commands to the thread.
  tx: Option<Sender<()>>
}

impl PlatformManager {
    pub fn new() -> Self {
        Self { tx: None }
    }

    // Can block
    pub fn cancel(&self) {
        self.tx.as_ref().expect("Should be already running").send(());
    }

    // Non-blocking, must return data on the provided channel
    pub fn register(&mut self, timeout: Duration, challenge: Vec<u8>, application: Vec<u8>) -> io::Result<Vec<u8>> {
        self.run_and_block(timeout, challenge, application, None)
    }

    // Non-blocking, must return data on the provided channel
    pub fn sign(&mut self, timeout: Duration, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>) -> io::Result<Vec<u8>> {
        self.run_and_block(timeout, challenge, application, Some(key_handle))
    }

    fn run_and_block(&mut self, timeout: Duration, challenge: Vec<u8>, application: Vec<u8>, key_handle: Option<Vec<u8>>) -> io::Result<Vec<u8>> {
        let mut monitor = Monitor::new();
        let mut devices = HashMap::new();

        let start_time = Instant::now();

        let (tx, stop_rx) = channel();
        self.tx = Some(tx);

        monitor.start()?;
        while start_time.elapsed() < timeout {
            if let Ok(_) = stop_rx.try_recv() {
                monitor.stop();
                return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled"));
            }

            for event in monitor.events() {
                process_event(&mut devices, event);
            }

            for device in devices.values_mut() {
                if key_handle.as_ref().is_some() {
                    // Caller gave us a key handle, so we want to sign.
                    let key = key_handle.as_ref().unwrap();

                    // Determine if this key handle belongs to this token
                    let is_valid = match super::u2f_is_keyhandle_valid(device, key) {
                        Err(_) => continue,
                        Ok(result) => result,
                    };

                    if is_valid {
                        // It does, we can sign
                        if let Ok(bytes) = super::u2f_sign(device, &challenge, &application, key) {
                            monitor.stop();
                            return Ok(bytes);
                        }
                    } else {
                        // If doesn't, so blink anyway
                        // TODO: transmit garbage challenge and application
                        if let Ok(bytes) = super::u2f_register(device, &challenge, &application) {
                            monitor.stop();
                            // If the user selects this token that can't satisfy, it's an error
                            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "User chose invalid key"));
                        }
                    }
                } else {
                    // Caller asked us to register, so the first token that does wins
                    if let Ok(bytes) = super::u2f_register(device, &challenge, &application) {
                        monitor.stop();
                        return Ok(bytes);
                    }
                }
            }

            thread::sleep(Duration::from_millis(100));
        }

        monitor.stop();
        Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"))
    }
}

fn maybe_add_device(devs: &mut HashMap<IOHIDDeviceRef, Device>, device_ref: IOHIDDeviceRef) {
    if devs.contains_key(&device_ref) {
        return;
    }

    unsafe {
        if is_u2f_device(device_ref) {
            let scratch_buf = [0; HID_RPT_SIZE];
            let (mut report_tx, report_rx) = channel::<Report>();

            let boxed_report_tx = Box::new(report_tx);
            let report_tx_ptr: *mut libc::c_void = unsafe { Box::into_raw(boxed_report_tx) as *mut libc::c_void };

            let mut dev = Device {
                name: get_name(device_ref),
                device_ref: device_ref,
                cid: CID_BROADCAST,
                report_recv: report_rx,
                report_send_void: report_tx_ptr,
            };

            IOHIDDeviceRegisterInputReportCallback(device_ref, scratch_buf.as_ptr(),
                                                   scratch_buf.len() as CFIndex,
                                                   read_new_data_cb, report_tx_ptr);

            if let Err(_) = super::init_device(&mut dev) {
                return;
            }
            if let Err(_) = super::ping_device(&mut dev) {
                return;
            }
            if let Err(_) = super::u2f_version_is_v2(&mut dev) {
                return;
            }

            println!("added U2F device {}", dev);
            devs.insert(device_ref, dev);
        } else {
            println!("ignored non-U2F device {:?}", device_ref);
        }
    }
}

fn maybe_remove_device(devs: &mut HashMap<IOHIDDeviceRef, Device>, device_ref: IOHIDDeviceRef) {
    // TODO: When we deregister a device, also drop the report_send_void
    match devs.remove(&device_ref) {
        Some(dev) => { println!("removing U2F device {}", dev); },
        None => { println!("Couldn't remove {:?}", device_ref); },
    }
}

fn process_event(devs: &mut HashMap<IOHIDDeviceRef, Device>, event: monitor::Event) {
    match event {
        monitor::Event::Add { device_id } => maybe_add_device(devs, device_id.as_ref()),
        monitor::Event::Remove { device_id } => maybe_remove_device(devs, device_id.as_ref()),
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

