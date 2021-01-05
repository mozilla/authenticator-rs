/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use sha2::Digest;
use std::io;
use std::ops::Deref;

use crate::AppId;

macro_rules! try_or {
    ($val:expr, $or:expr) => {
        match $val {
            Ok(v) => v,
            Err(e) => {
                return $or(e);
            }
        }
    };
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

#[cfg(any(target_os = "freebsd"))]
pub fn from_unix_result<T: Signed>(rv: T) -> io::Result<T> {
    if rv.is_negative() {
        let errno = unsafe { *libc::__error() };
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(rv)
    }
}

#[cfg(any(target_os = "openbsd"))]
pub fn from_unix_result<T: Signed>(rv: T) -> io::Result<T> {
    if rv.is_negative() {
        Err(io::Error::last_os_error())
    } else {
        Ok(rv)
    }
}

pub fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

impl AppId {
    pub fn to_u2f(&self) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::default();
        sha256.input(&self.0);
        sha256.result().to_vec()
    }
}

impl Deref for AppId {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<Vec<u8>> for AppId {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}
