/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "local-biometric")]
pub(crate) type Secret<T> = zeroize::Zeroizing<T>;
#[cfg(not(feature = "local-biometric"))]
pub(crate) type Secret<T> = T;

#[cfg(feature = "local-biometric")]
pub(crate) fn protect<T: zeroize::Zeroize>(value: T) -> Secret<T> {
    zeroize::Zeroizing::new(value)
}
#[cfg(not(feature = "local-biometric"))]
pub(crate) fn protect<T>(value: T) -> Secret<T> {
    value
}

#[cfg(feature = "local-biometric")]
pub(crate) fn wipe<T: zeroize::Zeroize + ?Sized>(value: &mut T) {
    zeroize::Zeroize::zeroize(value);
}
#[cfg(not(feature = "local-biometric"))]
pub(crate) fn wipe<T: ?Sized>(_value: &mut T) {}

#[cfg(feature = "local-biometric")]
#[cfg(feature = "crypto_openssl")]
pub(crate) fn unprotect(mut value: Secret<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *value)
}
#[cfg(not(feature = "local-biometric"))]
#[cfg(feature = "crypto_openssl")]
pub(crate) fn unprotect(value: Vec<u8>) -> Vec<u8> {
    value
}
