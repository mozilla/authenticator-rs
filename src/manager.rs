use std::io;

use consts::PARAMETER_SIZE;
use platform::PlatformManager;

pub struct U2FManager {
    platform: PlatformManager
}

impl U2FManager {
    pub fn new() -> Self {
        Self { platform: PlatformManager::new() }
    }

    // Cannot block.
    pub fn register<F>(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE ||
           application.len() != PARAMETER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
        }

        self.platform.register(timeout, challenge, application, callback)
    }

    // Cannot block.
    pub fn sign<F>(&mut self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE ||
           application.len() != PARAMETER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
        }

        if key_handle.len() > 256 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key handle too large"));
        }

        self.platform.sign(timeout, challenge, application, key_handle, callback)
    }

    // Cannot block. Cancels a single operation.
    pub fn cancel<F>(&mut self) {
        self.platform.cancel();
    }
}
