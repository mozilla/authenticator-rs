/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::Result;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto_ring")] {
        #[path = "ring.rs"]
        pub mod imp;
    } else if #[cfg(feature = "crypto_openssl")] {
        #[path = "openssl.rs"]
        pub mod imp;
    } else {
        #[path = "nss.rs"]
        pub mod imp;
    }
}

pub use imp::*;

pub trait CryptoProvider {
    fn new_key(&self) -> Result<Box<dyn Key>>;
    fn random_bytes(&self, destination: &mut [u8]) -> Result<()>;
}

pub trait Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public(&self) -> Vec<u8>;
}
