use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

struct Canary {
    alive: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>
}

impl Canary {
    fn new() -> Self {
        Self { alive: AtomicBool::new(true), thread: Mutex::new(None) }
    }
}

pub struct RunLoop {
    flag: Weak<Canary>
}

impl RunLoop {
    pub fn new<F,T>(fun: F, timeout: u64) -> io::Result<Self>
        where F: FnOnce(&Fn() -> bool) -> T, F: Send + 'static
    {
        let flag = Arc::new(Canary::new());
        let flag_ = flag.clone();

        // Spawn the run loop thread.
        let thread = thread::Builder::new().spawn(move || {
            let start = Instant::now();

            // A callback to determine whether the thread should terminate.
            let still_alive = || {
                // `flag.alive` will be false after cancel() was called.
                flag.alive.load(Ordering::Relaxed) &&
                // If a timeout was provided, we'll check that too.
                (timeout == 0 || start.elapsed().as_secs() < timeout)
            };

            // Ignore errors.
            let _ = fun(&still_alive);
        })?;

        // We really should never fail to lock here.
        let mut guard = (*flag_).thread.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "failed to lock")
        })?;

        // Store the thread handle so we can join later.
        *guard = Some(thread);

        Ok(Self { flag: Arc::downgrade(&flag_) })
    }

    // Cancels the run loop and waits for the thread to terminate.
    // This is a potentially BLOCKING operation.
    pub fn cancel(&self) {
        // If thread still exists...
        if let Some(flag) = self.flag.upgrade() {
            // ...let the run loop terminate.
            flag.alive.store(false, Ordering::Relaxed);

            // Locking should never fail here either.
            if let Ok(mut guard) = flag.thread.lock() {
                // This really can't fail.
                if let Some(handle) = (*guard).take() {
                    // This might fail, ignore.
                    let _ = handle.join();
                }
            }
        }
    }
}
