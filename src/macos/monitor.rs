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

struct IOHIDManager {
    manager: IOHIDManagerRef
}

impl IOHIDManager {
    pub fn new(tx_ptr: *mut libc::c_void) -> io::Result<Self> {
        let manager = unsafe { IOHIDManagerCreate(kCFAllocatorDefault,
                                                  kIOHIDManagerOptionNone) };

        // TODO we should probably set up proper device matching
        unsafe { IOHIDManagerSetDeviceMatching(manager, ptr::null()) };

        if unsafe { IOHIDManagerOpen(manager, kIOHIDManagerOptionNone) } != KERN_SUCCESS {
            return Err(io::Error::new(io::ErrorKind::Other, "Couldn't open HID Manager"));
        }

        unsafe {
            IOHIDManagerRegisterDeviceMatchingCallback(
                manager, IOHIDManager::device_add_cb, tx_ptr);
            IOHIDManagerRegisterDeviceRemovalCallback(
                manager, IOHIDManager::device_remove_cb, tx_ptr);
            IOHIDManagerScheduleWithRunLoop(
                manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        }

        Ok(Self { manager })
    }

    extern "C" fn device_add_cb(context: *mut c_void, _: IOReturn,
                                _: *mut c_void, device: IOHIDDeviceRef) {
        let tx = unsafe { &*(context as *mut Sender<Event>) };
        IOHIDManager::send_device_event(tx, Event::Add {
            device_id: IOHIDDeviceID::from_ref(device)
        });
    }

    extern "C" fn device_remove_cb(context: *mut c_void, _: IOReturn,
                                   _: *mut c_void, device: IOHIDDeviceRef) {
        let tx = unsafe { &*(context as *mut Sender<Event>) };
        IOHIDManager::send_device_event(tx, Event::Remove {
            device_id: IOHIDDeviceID::from_ref(device)
        });
    }

    fn send_device_event(tx: &Sender<Event>, event: Event) {
        if let Err(e) = tx.send(event) {
            // TOOD: This happens when the channel closes before this thread
            // does. This is pretty common, but let's deal with stopping
            // properly later.
            println!("Problem returning device_register_cb data for thread: {}", e);
        }
    }
}

impl Drop for IOHIDManager {
    fn drop(&mut self) {
        if unsafe { IOHIDManagerClose(self.manager, kIOHIDManagerOptionNone) } != KERN_SUCCESS {
            println!("Couldn't close the HID Manager");
        }
    }
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
            let tx_box = Box::new(tx);
            let tx_ptr = Box::into_raw(tx_box) as *mut libc::c_void;

            // This will keep `tx` alive only for the scope.
            let _tx = unsafe { Box::from_raw(tx_ptr) };

            // Create and initialize a scoped HID manager.
            let _manager = IOHIDManager::new(tx_ptr)?;

            // Run the Event Loop. CFRunLoopRunInMode() will dispatch HID
            // input reports into the various callbacks
            while alive() {
                println!("Run loop running, handle={:?}", thread::current());

                if unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, 0) } == kCFRunLoopRunStopped {
                    println!("Device stopped.");
                    break;
                }
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
