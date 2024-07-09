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

#[cfg(test)]
pub fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Serialize a heterogeneous map with optional entries in the order they appear.
///
/// The macro automatically calculates the number of entries to allocate in the
/// map, and closes the map. Each key and value expression is evaluated only
/// once.
///
/// Arguments:
/// - An expression of type [serde::Serializer]. This expression will be bound
///   to a local variable and thus evaluated only once.
/// - 0 or more entries of the form `$ident: $key => $value,`, where `$ident` is
///   an arbitrary identifier, `$key` is any expression and `$value` is an
///   expression of type [Option<T>]. The entry will be included in the map if
///   and only if the `$value` is [Some].
///
///   The `$ident` is needed in order to bind each `$value` as a local variable,
///   in order to evaluate each expression only once. Recommended use is to
///   simply set `$ident` to `v1`, `v2`, ..., or possibly some descriptive
///   label.
macro_rules! serialize_map_optional {
    (
        $serializer:expr,
        $( $value_ident:ident : $key:expr => $value:expr , )*
    ) => {
        {
            let serializer = $serializer;

            $(
                let $value_ident = $value;
            )*

            let map_len = 0usize $(+ if ::core::option::Option::is_some(&$value_ident) { 1usize } else { 0usize })*;
            let mut map = ::serde::ser::Serializer::serialize_map(serializer, ::core::option::Option::Some(map_len))?;
            $(
                if let ::core::option::Option::Some(v) = $value_ident {
                    ::serde::ser::SerializeMap::serialize_entry(&mut map, $key, &v)?;
                }
            )*
            ::serde::ser::SerializeMap::end(map)
        }
    };
}

/// Serialize a heterogeneous map in the order that entries appear.
///
/// The macro automatically calculates the number of entries to allocate in the
/// map, and closes the map.
///
/// Arguments:
/// - An expression of type [serde::Serializer]. This expression will be bound
///   to a local variable and thus evaluated only once.
/// - 0 or more entries of the form `$key => $value,`, where `$key` and `$value`
/// are both expressions. Each expression is evaluated only once.
macro_rules! serialize_map {
    (@count_entry $value:expr) => { () };
    (
        $serializer:expr,
        $( $key:expr => $value:expr , )*
    ) => {
        {
            let serializer = $serializer;
            const MAP_LEN: usize = [$( serialize_map!(@count_entry $value) ),*].len();
            let mut map = ::serde::ser::Serializer::serialize_map(serializer, ::core::option::Option::Some(MAP_LEN))?;
            $(
                ::serde::ser::SerializeMap::serialize_entry(&mut map, $key, $value)?;
            )*
            ::serde::ser::SerializeMap::end(map)
        }
    };
}
