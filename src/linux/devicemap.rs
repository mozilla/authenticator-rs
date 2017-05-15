use std::collections::HashMap;
use std::collections::hash_map::ValuesMut;
use std::path::PathBuf;

use ::platform::device::Device;
use ::platform::monitor::Event;

pub struct DeviceMap {
    map: HashMap<PathBuf, Device>
}

impl DeviceMap {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn values_mut(&mut self) -> ValuesMut<PathBuf, Device> {
        self.map.values_mut()
    }

    pub fn process_event(&mut self, event: Event) {
        match event {
            Event::Add { path } => self.add(path),
            Event::Remove { path } => self.remove(path)
        }
    }

    fn add(&mut self, path: PathBuf) {
        if self.map.contains_key(&path) {
            return;
        }

        // Create and try to open the device.
        if let Ok(mut dev) = Device::new(path.clone()) {
            if !dev.is_u2f() {
                return;
            }

            // Do a few U2F device checks.
            if let Err(_) = ::init_device(&mut dev) {
                return;
            }
            if let Err(_) = ::ping_device(&mut dev) {
                return;
            }
            if let Err(_) = ::u2f_version_is_v2(&mut dev) {
                return;
            }

            self.map.insert(path, dev);
        }
    }

    fn remove(&mut self, path: PathBuf) {
        // Ignore errors.
        let _ = self.map.remove(&path);
    }
}
