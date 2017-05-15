use std::io;
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::thread;

mod device;
mod devicemap;
mod hidraw;
mod monitor;
mod runloop;
mod util;

use self::devicemap::DeviceMap;
use self::monitor::Monitor;
use self::runloop::RunLoop;

pub struct PlatformManager {
    // Handle to the thread loop.
    thread: Option<RunLoop>
}

impl PlatformManager {
    pub fn new() -> Self {
        Self { thread: None }
    }

    pub fn register(&mut self, challenge: Vec<u8>, application: Vec<u8>, tx: Sender<io::Result<Vec<u8>>>) -> io::Result<()> {
        assert!(self.thread.is_none(), "thread is already running");

        self.thread = Some(RunLoop::new(move |alive| {
            let mut monitor = Monitor::new()?;
            let mut devices = DeviceMap::new();

            while alive() {
                // Add/remove devices.
                for event in monitor.events() {
                    devices.process_event(event);
                }

                // Try to register each device.
                for device in devices.values_mut() {
                    if let Ok(bytes) = super::u2f_register(device, &challenge, &application) {
                        monitor.stop();
                        tx.send(Ok(bytes)).unwrap();
                        return Ok(()); // TODO
                    }
                }

                // Wait a little before trying again.
                thread::sleep(Duration::from_millis(10));
            }

            // TODO
            monitor.stop();
            let _ = tx.send(Err(util::io_err("thread cancelled")));
            Ok(()) // TODO
        }, 10 /* TODO */)?);

        Ok(())
    }

    pub fn sign(&mut self) {
    }

    // This might block.
    pub fn cancel(&mut self) {
        if let Some(mut thread) = self.thread.take() {
            thread.cancel();
        }
    }
}
