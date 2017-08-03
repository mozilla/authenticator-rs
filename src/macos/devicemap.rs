use rand::{thread_rng, Rng};
use std::collections::hash_map::ValuesMut;
use std::collections::HashMap;

use u2fprotocol::{init_device, ping_device, u2f_version_is_v2};

use platform::monitor::Event;
use platform::device::Device;
use platform::iokit::*;

pub struct DeviceMap {
    map: HashMap<IOHIDDeviceRef, Device>,
}

impl DeviceMap {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn values_mut(&mut self) -> ValuesMut<IOHIDDeviceRef, Device> {
        self.map.values_mut()
    }

    pub fn process_event(&mut self, event: Event) {
        match event {
            Event::Add(dev) => self.add(dev),
            Event::Remove(dev) => self.remove(dev),
        }
    }

    fn add(&mut self, device_ref: IOHIDDeviceRef) {
        if self.map.contains_key(&device_ref) {
            return;
        }

        // Create the device.
        let mut dev = Device::new(device_ref);

        // Do a few U2F device checks.
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

        self.map.insert(device_ref, dev);
    }

    fn remove(&mut self, device_ref: IOHIDDeviceRef) {
        // Ignore errors.
        let _ = self.map.remove(&device_ref);
    }
}
