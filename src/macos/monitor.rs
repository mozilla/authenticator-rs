use std::io;
use std::ptr;
use std::sync::mpsc::{channel, Sender, Receiver, TryIter};
use std::thread;

use super::iokit::*;
use core_foundation_sys::base::*;
use core_foundation_sys::runloop::*;
use runloop::RunLoop;

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
    rx: Receiver<Event>,
    // Handle to the thread loop.
    thread: RunLoop
}

impl Monitor {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = channel();

        let thread = RunLoop::new(move |alive| {
            let (removal_tx, removal_rx) = channel::<IOHIDDeviceRef>();
            let (added_tx, added_rx) = channel::<IOHIDDeviceRef>();

            let hid_manager = unsafe {
                let hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
                IOHIDManagerSetDeviceMatching(hid_manager, ptr::null());
                if IOHIDManagerOpen(hid_manager, kIOHIDManagerOptionNone) != KERN_SUCCESS {
                    panic!("Couldn't open a HID Manager");
                }
                hid_manager
            };

            let boxed_added_tx = Box::new(added_tx);
            let added_tx_ptr = Box::into_raw(boxed_added_tx) as *mut libc::c_void;
            let boxed_removal_tx = Box::new(removal_tx);
            let removal_tx_ptr = Box::into_raw(boxed_removal_tx) as *mut libc::c_void;

            unsafe {
                IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, device_register_cb, removal_tx_ptr);
                IOHIDManagerRegisterDeviceMatchingCallback(hid_manager, device_register_cb, added_tx_ptr);
                IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
            }

            // Run the Event Loop. CFRunLoopRunInMode() will dispatch HID input reports into the
            // various call
            while alive() {
                println!("Run loop running, handle={:?}", thread::current());

                for device_ref in added_rx.try_iter() {
                    tx.send(Event::Add { device_id: IOHIDDeviceID::from_ref(device_ref) });
                }
                for device_ref in removal_rx.try_iter() {
                    tx.send(Event::Remove { device_id: IOHIDDeviceID::from_ref(device_ref) });
                }

                #[allow(non_upper_case_globals)]
                match unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, 0) } {
                    kCFRunLoopRunStopped => {
                        println!("Device stopped.");
                        // TODO: drop the removal_tx_ptr
                        break;
                    },
                    _ => {},
                }
            }

            if unsafe { IOHIDManagerClose(hid_manager, kIOHIDManagerOptionNone) } != KERN_SUCCESS {
                panic!("Couldn't close the HID Manager");
            }

            Ok(())
        }, 0 /* no timeout */)?;

        Ok(Self { rx, thread })
    }

    pub fn events<'a>(&'a self) -> TryIter<'a, Event> {
        self.rx.try_iter()
    }

    // This might block.
    pub fn stop(&mut self) {
        self.thread.cancel();
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
