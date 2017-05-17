extern crate libc;
extern crate mach;

pub use self::iokit::*;
mod iokit;
mod iohid;

use rand::{thread_rng, Rng};
use std::fmt;
use std::io::{Read, Write};
use std::io;
use std::ptr;
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use libc::c_void;

use mach::kern_return::KERN_SUCCESS;

use core_foundation_sys::base::*;

mod monitor;
use self::monitor::Monitor;
use std::collections::HashMap;
use runloop::RunLoop;

use consts::{CID_BROADCAST, HID_RPT_SIZE, PARAMETER_SIZE};
use U2FDevice;

const READ_TIMEOUT: u64 = 15;

pub struct Report {
    pub data: [u8; HID_RPT_SIZE],
}
unsafe impl Send for Report {}
unsafe impl Sync for Report {}

pub struct Device {
    pub device_ref: IOHIDDeviceRef,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
    pub report_recv: Receiver<Report>,
    pub report_send_void: *mut libc::c_void,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InternalDevice(ref:{:?}, cid: {:02x}{:02x}{:02x}{:02x})",
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
  // Handle to the thread loop.
  thread: Option<RunLoop>
}

impl PlatformManager {
    pub fn new() -> Self {
        Self { thread: None }
    }

    // Non-blocking
    pub fn register<F>(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        self.run_thread(timeout, challenge, application, None, callback)
    }


    // Non-blocking
    pub fn sign<F>(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        self.run_thread(timeout, challenge, application, Some(key_handle), callback)
    }

    // Can block
    pub fn cancel(&mut self) {
        if let Some(mut thread) = self.thread.take() {
            thread.cancel();
        }
    }

    fn run_thread<F>(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, key_handle: Option<Vec<u8>>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        // Abort any prior register/sign calls.
        self.cancel();

        self.thread = Some(RunLoop::new(move |alive| {
            let mut monitor = Monitor::new()?;
            let mut devices = HashMap::new();

            // Helper to stop monitor and call back.
            let complete = |monitor: &mut Monitor, rv| {
                monitor.stop();
                callback(rv);
                Ok(())
            };

            'top: while alive() {
                for event in monitor.events() {
                    process_event(&mut devices, event);
                }

                for device in devices.values_mut() {
                    // Check to see if monitor.events has any hotplug events that we'll need to handle
                    if monitor.events().size_hint().0 > 0 {
                        println!("Hotplug event; restarting loop");
                        continue 'top;
                    }

                    if let Some(ref key) = key_handle {
                        // Determine if this key handle belongs to this token
                        let is_valid = match super::u2f_is_keyhandle_valid(device, &challenge, &application, key) {
                            Err(_) => continue,
                            Ok(result) => result,
                        };

                        if is_valid {
                            // It does, we can sign
                            if let Ok(bytes) = super::u2f_sign(device, &challenge, &application, key) {
                                return complete(&mut monitor, Ok(bytes));
                            }
                        } else {
                            // If doesn't, so blink anyway (using bogus data)
                            let blank = vec![0u8; PARAMETER_SIZE];

                            if let Ok(_) = super::u2f_register(device, &blank, &blank) {
                                // If the user selects this token that can't satisfy, it's an error
                                return complete(&mut monitor, Err(io::Error::new(io::ErrorKind::ConnectionRefused, "User chose invalid key")));
                            }
                        }
                    } else {
                        // Caller asked us to register, so the first token that does wins
                        if let Ok(bytes) = super::u2f_register(device, &challenge, &application) {
                            return complete(&mut monitor, Ok(bytes));
                        }
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }

            complete(&mut monitor, Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")))
        }, timeout)?);

        Ok(())
    }
}

fn maybe_add_device(devs: &mut HashMap<IOHIDDeviceRef, Device>, device_ref: IOHIDDeviceRef) {
    if devs.contains_key(&device_ref) {
        return;
    }

    let scratch_buf = [0; HID_RPT_SIZE];
    let (report_tx, report_rx) = channel::<Report>();

    let boxed_report_tx = Box::new(report_tx);
    // report_tx_ptr is deallocated by maybe_remove_device
    let report_tx_ptr = Box::into_raw(boxed_report_tx) as *mut libc::c_void;

    let mut dev = Device {
        device_ref: device_ref,
        cid: CID_BROADCAST,
        report_recv: report_rx,
        report_send_void: report_tx_ptr,
    };

    unsafe { IOHIDDeviceRegisterInputReportCallback(device_ref,
                                                    scratch_buf.as_ptr(),
                                                    scratch_buf.len() as CFIndex,
                                                    read_new_data_cb,
                                                    report_tx_ptr) };

    let mut nonce = [0u8; 8];
    thread_rng().fill_bytes(&mut nonce);
    if let Err(_) = super::init_device(&mut dev, nonce) {
        return;
    }

    let mut random = [0u8; 8];
    thread_rng().fill_bytes(&mut random);
    if let Err(_) = super::ping_device(&mut dev, random) {
        return;
    }
    if let Err(_) = super::u2f_version_is_v2(&mut dev) {
        return;
    }

    println!("added U2F device {}", dev);
    devs.insert(device_ref, dev);
}

fn maybe_remove_device(devs: &mut HashMap<IOHIDDeviceRef, Device>, device_ref: IOHIDDeviceRef) {
    match devs.remove(&device_ref) {
        Some(dev) => {
            println!("removing U2F device {}", dev);
            // Re-allocate this raw pointer for destruction
            let _ = unsafe { Box::from_raw(dev.report_send_void) };
        },
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

