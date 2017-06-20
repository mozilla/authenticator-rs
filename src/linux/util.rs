extern crate libc;

use std::error::Error;
use std::io;

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
