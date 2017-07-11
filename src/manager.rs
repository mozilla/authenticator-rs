use std::io;
use std::sync::mpsc::{channel, Sender, RecvTimeoutError};
use std::time::Duration;

use consts::PARAMETER_SIZE;
use platform::PlatformManager;
use runloop::RunLoop;
use util::{to_io_err, OnceCallback};

pub enum QueueAction {
  Register {
    timeout: u64,
    challenge: Vec<u8>,
    application: Vec<u8>,
    callback: OnceCallback
  },
  Sign {
    timeout: u64,
    challenge: Vec<u8>,
    application: Vec<u8>,
    key_handle: Vec<u8>,
    callback: OnceCallback
  },
  Cancel
}

pub struct U2FManager {
    queue: RunLoop,
    tx: Sender<QueueAction>
}

impl U2FManager {
    pub fn new() -> io::Result<Self> {
        let (tx, rx) = channel();

        // Start a new work queue thread.
        let queue = try!(RunLoop::new(move |alive| {
            let mut pm = PlatformManager::new();

            while alive() {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(QueueAction::Register{timeout, challenge, application, callback}) => {
                        // This must not block, otherwise we can't cancel.
                        pm.register(timeout, challenge, application, callback);
                    }
                    Ok(QueueAction::Sign{timeout, challenge, application, key_handle, callback}) => {
                        // This must not block, otherwise we can't cancel.
                        pm.sign(timeout, challenge, application, key_handle, callback);
                    }
                    Ok(QueueAction::Cancel) => {
                        // Cancelling must block so that we don't start a new
                        // polling thread before the old one has shut down.
                        pm.cancel();
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                    _ => { /* continue */ }
                }
            }

            // Cancel any ongoing activity.
            pm.cancel();
        }, 0 /* no timeout */));

        Ok(Self { queue, tx })
    }

    pub fn register<F>(&self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE ||
           application.len() != PARAMETER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
        }

        let callback = OnceCallback::new(callback);
        let action = QueueAction::Register { timeout, challenge, application, callback };
        self.tx.send(action).map_err(to_io_err)
    }

    pub fn sign<F>(&self, timeout: u64, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F) -> io::Result<()>
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE ||
           application.len() != PARAMETER_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes"));
        }

        if key_handle.len() > 256 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Key handle too large"));
        }

        let callback = OnceCallback::new(callback);
        let action = QueueAction::Sign { timeout, challenge, application, key_handle, callback };
        self.tx.send(action).map_err(to_io_err)
    }

    pub fn cancel(&self) -> io::Result<()> {
        self.tx.send(QueueAction::Cancel).map_err(to_io_err)
    }
}

impl Drop for U2FManager {
    fn drop(&mut self) {
        self.queue.cancel();
    }
}
