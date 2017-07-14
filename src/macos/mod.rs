extern crate log;
extern crate libc;


use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::ptr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

use libc::c_void;
use core_foundation_sys::base::*;

mod device;
mod iokit;
mod iohid;
mod monitor;

use self::iokit::*;
use self::device::{Device, Report};
use self::monitor::Monitor;

use consts::{CID_BROADCAST, HID_RPT_SIZE, PARAMETER_SIZE};
use runloop::RunLoop;
use util::{io_err, OnceCallback};
use u2fprotocol::{u2f_register, u2f_sign, u2f_is_keyhandle_valid};
use u2fprotocol::{init_device, ping_device, u2f_version_is_v2};

pub struct PlatformManager {
  // Handle to the thread loop.
  thread: Option<RunLoop>
}

impl PlatformManager {
    pub fn new() -> Self {
        Self { thread: None }
    }

    pub fn register(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, callback: OnceCallback<Vec<u8>>)
    {
        // Abort any prior register/sign calls.
        self.cancel();

        let cbc = callback.clone();

        let thread = RunLoop::new(move |alive| {
            let mut devices = HashMap::new();
            let monitor = try_or!(Monitor::new(), |e| {
                callback.call(Err(e));
            });

            'top: while alive() && monitor.alive() {
                for event in monitor.events() {
                    process_event(&mut devices, event);
                }

                for device in devices.values_mut() {
                    // Caller asked us to register, so the first token that does wins
                    if let Ok(bytes) = u2f_register(device, &challenge, &application) {
                        callback.call(Ok(bytes));
                        return;
                    }

                    // Check to see if monitor.events has any hotplug events that we'll need to handle
                    if monitor.events().size_hint().0 > 0 {
                        debug!("Hotplug event; restarting loop");
                        continue 'top;
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }

            callback.call(Err(io_err("aborted or timed out")));
        }, timeout);

        self.thread = Some(try_or!(thread, |_| {
            cbc.call(Err(io_err("couldn't create runloop")))
        }));
    }


    pub fn sign(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, key_handles: Vec<Vec<u8>>, callback: OnceCallback<(Vec<u8>,Vec<u8>)>)
    {
        // Abort any prior register/sign calls.
        self.cancel();

        let cbc = callback.clone();

        let thread = RunLoop::new(move |alive| {
            let mut devices = HashMap::new();
            let monitor = try_or!(Monitor::new(), |e| {
                callback.call(Err(e));
            });

            'top: while alive() && monitor.alive() {
                for event in monitor.events() {
                    process_event(&mut devices, event);
                }

                for key_handle in &key_handles {
                    for device in devices.values_mut() {
                        // Determine if this key handle belongs to this token
                        let is_valid = match u2f_is_keyhandle_valid(device, &challenge, &application, key_handle) {
                            Ok(result) => result,
                            Err(_) => continue // Skip this device for now.
                        };

                        if is_valid {
                            // It does, we can sign
                            if let Ok(bytes) = u2f_sign(device, &challenge, &application, key_handle) {
                                callback.call(Ok((key_handle.clone(), bytes)));
                                return;
                            }
                        } else {
                            // If doesn't, so blink anyway (using bogus data)
                            let blank = vec![0u8; PARAMETER_SIZE];

                            if let Ok(_) = u2f_register(device, &blank, &blank) {
                                // If the user selects this token that can't satisfy, it's an error
                                callback.call(Err(io_err("invalid key")));
                                return;
                            }
                        }

                        // Check to see if monitor.events has any hotplug events that we'll need to handle
                        if monitor.events().size_hint().0 > 0 {
                            debug!("Hotplug event; restarting loop");
                            continue 'top;
                        }
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }

            callback.call(Err(io_err("aborted or timed out")));
        }, timeout);

        self.thread = Some(try_or!(thread, |_| {
            cbc.call(Err(io_err("couldn't create runloop")))
        }));
    }

    pub fn cancel(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.cancel();
        }
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
    if let Err(_) = init_device(&mut dev, nonce) {
        return;
    }

    let mut random = [0u8; 8];
    thread_rng().fill_bytes(&mut random);
    if let Err(_) = ping_device(&mut dev, random) {
        return;
    }
    if let Err(_) = u2f_version_is_v2(&mut dev) {
        return;
    }

    debug!("added U2F device {}", dev);
    devs.insert(device_ref, dev);
}

fn maybe_remove_device(devs: &mut HashMap<IOHIDDeviceRef, Device>, device_ref: IOHIDDeviceRef) {
    match devs.remove(&device_ref) {
        Some(dev) => {
            debug!("removing U2F device {}", dev);
            // Re-allocate this raw pointer for destruction
            let _ = unsafe { Box::from_raw(dev.report_send_void) };
        },
        None => { warn!("Couldn't remove {:?}", device_ref); },
    }
}

fn process_event(devs: &mut HashMap<IOHIDDeviceRef, Device>, event: monitor::Event) {
    match event {
        monitor::Event::Add(device_id) => maybe_add_device(devs, device_id.as_ref()),
        monitor::Event::Remove(device_id) => maybe_remove_device(devs, device_id.as_ref()),
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

        trace!("read_new_data_cb type={} id={} report={:?} len={}",
                 report_type,
                 report_id,
                 report,
                 report_len);

        let mut report_obj = Report { data: [0; HID_RPT_SIZE] };

        if report_len as usize <= HID_RPT_SIZE {
            ptr::copy(report, report_obj.data.as_mut_ptr(), report_len as usize);
        } else {
            warn!("read_new_data_cb got too much data! {} > {}",
                     report_len,
                     HID_RPT_SIZE);
        }

        if let Err(e) = tx.send(report_obj) {
            // TOOD: This happens when the channel closes before this thread
            // does. This is pretty common, but let's deal with stopping
            // properly later.
            warn!("Problem returning read_new_data_cb data for thread: {}", e);
        };
    }
}

