extern crate libc;

use std::error::Error;
use std::io;
use std::sync::{Arc,Mutex};

use boxfnonce::SendBoxFnOnce;

macro_rules! try_or {
    ($val:expr, $or:expr) => {
        match $val {
            Ok(v) => { v }
            Err(e) => { return $or(e); }
        }
    }
}

pub trait Signed {
    fn is_negative(&self) -> bool;
}

impl Signed for i32 {
    fn is_negative(&self) -> bool {
        *self < (0 as i32)
    }
}

impl Signed for usize {
    fn is_negative(&self) -> bool {
        (*self as isize) < (0 as isize)
    }
}

#[cfg(any(target_os = "linux"))]
pub fn from_unix_result<T: Signed>(rv: T) -> io::Result<T> {
    if rv.is_negative() {
        let errno = unsafe { *libc::__errno_location() };
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(rv)
    }
}

pub fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn to_io_err<T: Error>(err: T) -> io::Error {
    io_err(err.description())
}

type Callback = SendBoxFnOnce<(io::Result<Vec<u8>>,)>;

pub struct OnceCallback {
    callback: Arc<Mutex<Option<Callback>>>
}

impl OnceCallback {
    pub fn new<F>(cb: F) -> Self
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        let cb = Some(SendBoxFnOnce::from(cb));
        Self { callback: Arc::new(Mutex::new(cb)) }
    }

    pub fn call(&self, rv: io::Result<Vec<u8>>) {
        if let Ok(mut cb) = self.callback.lock() {
            if let Some(cb) = cb.take() {
                cb.call(rv);
            }
        }
    }
}

impl Clone for OnceCallback {
    fn clone(&self) -> Self {
        Self { callback: self.callback.clone() }
    }
}
