/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;

use std::io;

macro_rules! try_or {
    ($val:expr, $or:expr) => {
        match $val {
            Ok(v) => v,
            Err(e) => {
                #[allow(clippy::redundant_closure_call)]
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
        *self < 0
    }
}

impl Signed for usize {
    fn is_negative(&self) -> bool {
        (*self as isize) < 0
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

#[cfg(all(target_os = "openbsd", not(test)))]
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

#[cfg(all(test, not(feature = "crypto_dummy")))]
pub fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Serialize a heterogeneous map with optional entries in the order they appear.
///
/// The macro automatically calculates the number of entries to allocate in the
/// map, and closes the map.
///
/// Arguments:
/// - An expression of type [serde::Serializer]. This expression will be bound
///   to a local variable and thus evaluated only once.
/// - 0 or more entries of the form `$key => $value,`, where `$key` is any
///   expression and `$value` is an expression of type [Option<T>]. The entry
///   will be included in the map if and only if the `$value` is [Some].
macro_rules! serialize_map_optional {
    (
        $serializer:expr,
        $( $key:expr => $value:expr , )*
    ) => {
        {
            let serializer = $serializer;
            let map_len = 0usize $(+ if $value.is_some() { 1usize } else { 0usize })*;
            let mut map = serializer.serialize_map(core::option::Option::Some(map_len))?;
            $(
                if let core::option::Option::Some(v) = $value {
                    map.serialize_entry($key, &v)?;
                }
            )*
            map.end()
        }
    };
}

/// Like [serialize_map_optional], but all values are wrapped in [Some].
macro_rules! serialize_map {
    (
        $serializer:expr,
        $( $key:expr => $value:expr , )*
    ) => {
        {
            serialize_map_optional!($serializer, $( $key => Some($value) , )*)
        }
    };
}
