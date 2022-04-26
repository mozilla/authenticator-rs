/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::transport::device_selector::DeviceSelectorEvent;
use crate::transport::platform::winapi::DeviceInfoSet;
use runloop::RunLoop;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::iter::FromIterator;
use std::sync::{mpsc::Sender, Arc};
use std::thread;
use std::time::Duration;

pub struct Monitor<F>
where
    F: Fn(String, Sender<DeviceSelectorEvent>, Sender<crate::StatusUpdate>, &dyn Fn() -> bool)
        + Sync,
{
    runloops: HashMap<String, RunLoop>,
    new_device_cb: Arc<F>,
    selector_sender: Sender<DeviceSelectorEvent>,
    status_sender: Sender<crate::StatusUpdate>,
}

impl<F> Monitor<F>
where
    F: Fn(String, Sender<DeviceSelectorEvent>, Sender<crate::StatusUpdate>, &dyn Fn() -> bool)
        + Send
        + Sync
        + 'static,
{
    pub fn new(
        new_device_cb: F,
        selector_sender: Sender<DeviceSelectorEvent>,
        status_sender: Sender<crate::StatusUpdate>,
    ) -> Self {
        Self {
            runloops: HashMap::new(),
            new_device_cb: Arc::new(new_device_cb),
            selector_sender,
            status_sender,
        }
    }

    pub fn run(&mut self, alive: &dyn Fn() -> bool) -> Result<(), Box<dyn Error>> {
        let mut stored = HashSet::new();

        while alive() {
            let device_info_set = DeviceInfoSet::new()?;
            let devices = HashSet::from_iter(device_info_set.devices());

            // Remove devices that are gone.
            for path in stored.difference(&devices) {
                self.remove_device(path);
            }

            let paths: Vec<_> = devices.difference(&stored).cloned().collect();
            self.selector_sender
                .send(DeviceSelectorEvent::DevicesAdded(paths.clone()))?;
            // Add devices that were plugged in.
            for path in paths {
                self.add_device(&path);
            }

            // Remember the new set.
            stored = devices;

            // Wait a little before looking for devices again.
            thread::sleep(Duration::from_millis(100));
        }

        // Remove all tracked devices.
        self.remove_all_devices();

        Ok(())
    }

    fn add_device(&mut self, path: &String) {
        let f = self.new_device_cb.clone();
        let path = path.clone();
        let key = path.clone();
        let selector_sender = self.selector_sender.clone();
        let status_sender = self.status_sender.clone();
        debug!("Adding device {}", path);

        let runloop = RunLoop::new(move |alive| {
            if alive() {
                f(path, selector_sender, status_sender, alive);
            }
        });

        if let Ok(runloop) = runloop {
            self.runloops.insert(key, runloop);
        }
    }

    fn remove_device(&mut self, path: &String) {
        let _ = self
            .selector_sender
            .send(DeviceSelectorEvent::DeviceRemoved(path.clone()));

        debug!("Removing device {}", path);
        if let Some(runloop) = self.runloops.remove(path) {
            runloop.cancel();
        }
    }

    fn remove_all_devices(&mut self) {
        while !self.runloops.is_empty() {
            let path = self.runloops.keys().next().unwrap().clone();
            self.remove_device(&path);
        }
    }
}
