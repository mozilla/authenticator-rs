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

#[cfg(test)]
mod tests {
    mod serialize_map_optional {
        //! Test cases generated using the following Python snippet:
        //! ```python
        //! from fido2 import cbor
        //! cbor._sort_keys = lambda entry: 0  # Disable canonical CBOR map sorting
        //! c = cbor.encode({
        //!   0x00: "a",
        //!   "a" : 0x01,
        //!   ("b",) : ["c"],
        //!   ("c", "d") : ["d", "e"],
        //!   -0x04 : "e",
        //!   0xff : "f",
        //!   0xffff : "g",
        //!   0xffffff : "h",
        //!   0xffffffff : "i",
        //!   0xffffffffffffffff : "i",
        //!   0x0a : -1337,
        //!   0x0b : 0xffffffffffffffff,
        //! })
        //! print(c.hex())
        //! ```

        use super::super::decode_hex;
        use serde::{Serialize, Serializer};

        #[test]
        fn serialize_map_optional_1() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                    )
                }
            }
            assert_eq!(serde_cbor::to_vec(&Foo).unwrap(), decode_hex("a1006161"));
        }

        #[test]
        fn serialize_map_optional_2() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a2006161616101")
            );
        }

        #[test]
        fn serialize_map_optional_3() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a3006161616101816162816163")
            );
        }

        #[test]
        fn serialize_map_optional_4() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a400616161610181616281616382616361648261646165")
            );
        }

        #[test]
        fn serialize_map_optional_5() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a500616161610181616281616382616361648261646165236165")
            );
        }

        #[test]
        fn serialize_map_optional_6() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a60061616161018161628161638261636164826164616523616518ff6166")
            );
        }

        #[test]
        fn serialize_map_optional_7() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex(
                    "a70061616161018161628161638261636164826164616523616518ff616619ffff6167"
                )
            );
        }

        #[test]
        fn serialize_map_optional_8() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                        v7: &0xffffff => Some("h"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a80061616161018161628161638261636164826164616523616518ff616619ffff61671a00ffffff6168")
            );
        }

        #[test]
        fn serialize_map_optional_9() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                        v7: &0xffffff => Some("h"),
                        v8: &0xffffffffu32 => Some("i"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("a90061616161018161628161638261636164826164616523616518ff616619ffff61671a00ffffff61681affffffff6169")
            );
        }

        #[test]
        fn serialize_map_optional_10() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                        v7: &0xffffff => Some("h"),
                        v8: &0xffffffffu32 => Some("i"),
                        v9: &0xffffffffffffffffu64 => Some("i"),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("aa0061616161018161628161638261636164826164616523616518ff616619ffff61671a00ffffff61681affffffff61691bffffffffffffffff6169")
            );
        }

        #[test]
        fn serialize_map_optional_11() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                        v7: &0xffffff => Some("h"),
                        v8: &0xffffffffu32 => Some("i"),
                        v9: &0xffffffffffffffffu64 => Some("i"),
                        va: &0x0a => Some(-1337),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("ab0061616161018161628161638261636164826164616523616518ff616619ffff61671a00ffffff61681affffffff61691bffffffffffffffff61690a390538")
            );
        }

        #[test]
        fn serialize_map_optional_12() {
            struct Foo;
            impl Serialize for Foo {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serialize_map_optional!(
                        serializer,
                        v0: &0x00 => Some("a"),
                        v1: &"a" => Some(0x01),
                        v2: &["b"] => Some(["c"]),
                        v3: &["c", "d"] => Some(["d", "e"]),
                        v4: &-0x04 => Some("e"),
                        v5: &0xff => Some("f"),
                        v6: &0xffff => Some("g"),
                        v7: &0xffffff => Some("h"),
                        v8: &0xffffffffu32 => Some("i"),
                        v9: &0xffffffffffffffffu64 => Some("i"),
                        va: &0x0a => Some(-1337),
                        vb: &0x0b => Some(0xffffffffffffffffu64),
                    )
                }
            }
            assert_eq!(
                serde_cbor::to_vec(&Foo).unwrap(),
                decode_hex("ac0061616161018161628161638261636164826164616523616518ff616619ffff61671a00ffffff61681affffffff61691bffffffffffffffff61690a3905380b1bffffffffffffffff")
            );
        }
    }
}
