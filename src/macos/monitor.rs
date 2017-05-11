use std::io;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender, Receiver, TryIter, TryRecvError, RecvTimeoutError};
use std::thread::JoinHandle;
use std::thread;

use super::iokit::*;
use core_foundation_sys::base::*;
use core_foundation_sys::runloop::*;

extern crate libc;
use libc::c_void;

extern crate mach;
use mach::kern_return::KERN_SUCCESS;

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

pub enum Event {
    Add { device_id: IOHIDDeviceID },
    Remove { device_id: IOHIDDeviceID },
}

pub struct Monitor {
  // Receive events from the thread.
  rx: Option<Receiver<Event>>,
  // Send 'stop' commands to the thread.
  tx: Option<Sender<()>>,
  // Handle to the polling thread.
  thread: Option<JoinHandle<io::Result<()>>>,
  // Stop condition,
  stop: Arc<(Mutex<bool>, Condvar)>,
}

impl Monitor {
    pub fn new() -> Self {
        Monitor {
            rx: None, tx: None, thread: None,
            stop: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn stop(&mut self) {
        self.tx.as_ref().expect("Should be already running").send(());

        // Block waiting on the thead to finish
        let &(ref lock, ref cvar) = &*self.stop;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = cvar.wait(started).unwrap();
        }
    }

    pub fn start(&mut self) -> io::Result<()> {
        assert!(self.thread.is_none(), "monitor is already running");

        // A channel to notify the controlling thread.
        let (thread_tx, rx) = channel();
        self.rx = Some(rx);

        // A channel the controlling thread uses to stop polling.
        let (tx, thread_rx) = channel();
        self.tx = Some(tx);

        let thread_stop = self.stop.clone();

        thread::Builder::new().name("Monitor HID Runloop".to_string()).spawn(move ||
        unsafe {
            let (mut removal_tx, removal_rx) = channel::<IOHIDDeviceRef>();
            let (mut added_tx, added_rx) = channel::<IOHIDDeviceRef>();

            let hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
            IOHIDManagerSetDeviceMatching(hid_manager, ptr::null());

            if IOHIDManagerOpen(hid_manager, kIOHIDManagerOptionNone) != KERN_SUCCESS {
                panic!("Couldn't open a HID Manager");
            }

            let boxed_removal_tx = Box::new(removal_tx);
            let removal_tx_ptr: *mut libc::c_void = Box::into_raw(boxed_removal_tx) as *mut libc::c_void;
            IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, device_register_cb, removal_tx_ptr);

            let boxed_added_tx = Box::new(added_tx);
            let added_tx_ptr: *mut libc::c_void = Box::into_raw(boxed_added_tx) as *mut libc::c_void;
            IOHIDManagerRegisterDeviceMatchingCallback(hid_manager, device_register_cb, added_tx_ptr);

            IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

            // Run the Event Loop. CFRunLoopRunInMode() will dispatch HID input reports into the
            // various call
            loop {
                println!("Run loop running, handle={:?}", thread::current());

                for device_ref in added_rx.try_iter() {
                    thread_tx.send(Event::Add { device_id: IOHIDDeviceID::from_ref(device_ref) });
                }
                for device_ref in removal_rx.try_iter() {
                    thread_tx.send(Event::Remove { device_id: IOHIDDeviceID::from_ref(device_ref) });
                }
                if let Ok(_) = thread_rx.try_recv() {
                    // Stop received
                    break;
                }

                #[allow(non_upper_case_globals)]
                match CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, 0) {
                    kCFRunLoopRunStopped => {
                        println!("Device stopped.");
                        // TODO: drop the removal_tx_ptr
                        break;
                    },
                    _ => {},
                }
            }

            if IOHIDManagerClose(hid_manager, kIOHIDManagerOptionNone) != KERN_SUCCESS {
                panic!("Couldn't close the HID Manager");
            }

            // Notify the stop() method
            let &(ref lock, ref cvar) = &*thread_stop;
            let mut started = lock.lock().unwrap();
            *started = true;
            cvar.notify_all();
        });

        Ok(())
    }

    pub fn events<'a>(&'a self) -> TryIter<'a, Event> {
        self.rx.as_ref().expect("monitor is not running").try_iter()
    }
}

// This is called from the RunLoop thread
extern "C" fn device_register_cb(context: *mut c_void,
                                 result: IOReturn,
                                 _: *mut c_void,
                                 device: IOHIDDeviceRef) {
    unsafe {
        let tx: &mut Sender<IOHIDDeviceRef> = &mut *(context as *mut Sender<IOHIDDeviceRef>);

        // context contains a Device which we populate as the out variable
        // let device: &mut Device = &mut *(context as *mut Device);

        // let device_ref = void_ref as IOHIDDeviceRef;
        println!("{:?} device_register_cb context={:?} result={:?} device_ref={:?}",
                 thread::current(), context, result, device);

        if let Err(e) = tx.send(device) {
            // TOOD: This happens when the channel closes before this thread
            // does. This is pretty common, but let's deal with stopping
            // properly later.
            println!("Problem returning device_register_cb data for thread: {}", e);
        };
    }
}

