/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use std::io;
use std::sync::{Arc, Mutex};

use boxfnonce::SendBoxFnOnce;

use log;

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

#[cfg(all(target_os = "linux", not(test)))]
pub fn from_unix_result<T: Signed>(rv: T) -> io::Result<T> {
    if rv.is_negative() {
        let errno = unsafe { *libc::__errno_location() };
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(rv)
    }
}

#[cfg(all(target_os = "freebsd", not(test)))]
pub fn from_unix_result<T: Signed>(rv: T) -> io::Result<T> {
    if rv.is_negative() {
        let errno = unsafe { *libc::__error() };
        Err(io::Error::from_raw_os_error(errno))
    } else {
        Ok(rv)
    }
}

pub fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub struct OnceCallback<T> {
    callback: Arc<Mutex<Option<SendBoxFnOnce<(Result<T, ::Error>,)>>>>,
}

impl<T> OnceCallback<T> {
    pub fn new<F>(cb: F) -> Self
    where
        F: FnOnce(Result<T, ::Error>),
        F: Send + 'static,
    {
        let cb = Some(SendBoxFnOnce::from(cb));
        Self {
            callback: Arc::new(Mutex::new(cb)),
        }
    }

    // Note(baloo): this map does not allow composition, but this is not something I did care about
    // in this usecase. This should ultimately disappear (I think).
    pub fn map<F, U>(&self, f: F) -> OnceCallbackMap<U, T>
    where
        F: (FnOnce(U) -> T),
        F: Send + 'static,
    {
        let callback = self.clone();
        let map = Arc::new(Mutex::new(Some(SendBoxFnOnce::from(f))));
        OnceCallbackMap { callback, map }
    }
}

impl<T> Clone for OnceCallback<T> {
    fn clone(&self) -> Self {
        Self {
            callback: self.callback.clone(),
        }
    }
}

pub struct OnceCallbackMap<U, T> {
    callback: OnceCallback<T>,
    map: Arc<Mutex<Option<SendBoxFnOnce<(U,), T>>>>,
}

impl<U, T> Clone for OnceCallbackMap<U, T> {
    fn clone(&self) -> Self {
        Self {
            callback: self.callback.clone(),
            map: self.map.clone(),
        }
    }
}

pub trait Callback {
    type Input;
    fn call(&self, input: Result<Self::Input, ::Error>);
}

impl<U, T> Callback for OnceCallbackMap<U, T> {
    type Input = U;

    fn call(&self, rv: Result<U, ::Error>) {
        if let Ok(mut map) = self.map.lock() {
            if let Some(map) = map.take() {
                match rv {
                    Ok(v) => self.callback.call(Ok(map.call(v))),
                    Err(e) => self.callback.call(Err(e)),
                }
            }
        }
    }
}
impl<T> Callback for OnceCallback<T> {
    type Input = T;
    fn call(&self, rv: Result<T, ::Error>) {
        if let Ok(mut cb) = self.callback.lock() {
            if let Some(cb) = cb.take() {
                cb.call(rv);
            }
        }
    }
}

pub trait ErrorCallback {
    fn errcall(&self, e: ::Error);
}

impl<T> ErrorCallback for T
where
    T: Callback,
{
    fn errcall(&self, e: ::Error) {
        self.call(Err(e))
    }
}

pub fn trace_hex(data: &[u8]) {
    if log_enabled!(log::Level::Trace) {
        let parts: Vec<String> = data.iter().map(|byte| format!("{:02x}", byte)).collect();
        trace!("USB send: {}", parts.join(""));
    }
}
