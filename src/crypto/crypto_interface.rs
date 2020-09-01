/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::error;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub trait WebAuthnCrypto {
    fn sign(data: &[u8], key: &[u8]) -> Result<Vec<u8>>;
    fn encrypt(&self, input: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
}
