/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, WriteBytesExt};

use crate::crypto::{CryptoProvider, Key};
use crate::errors::{self, AuthenticatorError, U2FTokenError};
use crate::u2ftypes::U2FDeviceInfo;
use crate::{AppId, KeyHandle, RegisterFlags, RegisterResult, Result, SignFlags, SignResult};

struct SoftwareU2FKey {
    key_handle: Box<dyn Key>,
    app_id: AppId,
}

impl SoftwareU2FKey {
    fn new(key_handle: Box<dyn Key>, app_id: AppId) -> SoftwareU2FKey {
        SoftwareU2FKey { key_handle, app_id }
    }
}

pub struct SoftwareU2FToken {
    crypto_provider: Box<dyn CryptoProvider>,
    keys: Vec<SoftwareU2FKey>,
    counter: u32,
}

// This is simply for platforms that aren't using the U2F Token, usually for builds
// without --feature webdriver
#[allow(dead_code)]

#[rustfmt::skip]
const TBS_CERTIFICATE_BEFORE_SERIAL_NUMBER: &'static [u8] = &[
    0x30, 0x81, 0xE0, // SEQUENCE of length 224
          0xA0, 0x03, // [0]
                0x02, 0x01, 0x02, // INTEGER (2)
          0x02, 0x14, ]; // INTEGER of length 20
                         // serialNumber goes here (must be 20 bytes, MSB of 0th bit must not be set, 0th byte must not be 0)

#[rustfmt::skip]
const TBS_CERTIFICATE_BEFORE_VALIDITY: &'static [u8] = &[
    0x30, 0x0A, // SEQUENCE of length 10
          0x06, 0x08, // OBJECT IDENTIFIER of length 8
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, // 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
    0x30, 0x1B, // SEQUENCE of length 27
          0x31, 0x19, // SET of length 25
                0x30, 0x17, // SEQUENCE of length 23
                      0x06, 0x03, // OBJECT identifier of length 3
                            0x55, 0x04, 0x03, // 2.5.4.3 = id-at-commonName
                      0x0C, 0x10, // UTF8String of length 16
                            0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x55, 0x32, 0x46, 0x54, 0x6f, 0x6b, 0x65, 0x6e, // "SoftwareU2FToken"
    0x30, 0x22, ]; // SEQUENCE of length 22
                   // validity goes here (two GENERALIZED TIME, each of the form YYYYMMDDHHmmssZ)

const GENERALIZED_TIME_PREFIX: &'static [u8] = &[0x18, 0x0F]; // GENERALIZED TIME of length 15

#[rustfmt::skip]
const TBS_CERTIFICATE_BEFORE_SPKI: &'static [u8] = &[
    0x30, 0x1B, // SEQUENCE of length 27
          0x31, 0x19, // SET of length 25
                0x30, 0x17, // SEQUENCE of length 23
                      0x06, 0x03, // OBJECT identifier of length 3
                            0x55, 0x04, 0x03, // 2.5.4.3 = id-at-commonName
                      0x0C, 0x10, // UTF8String of length 16
                            0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x55, 0x32, 0x46, 0x54, 0x6f, 0x6b, 0x65, 0x6e, // "SoftwareU2FToken"
    0x30, 0x59, // SEQUENCE of length 89
          0x30, 0x13, // SEQUENCE of length 19
                0x06, 0x07, // OBJECT IDENTIFIER of length 7
                      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // 1.2.840.10045.2.1 = id-ecPublicKey
                0x06, 0x08, // OBJECT IDENTIFIER of length 8
                      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // 1.2.840.10045.3.1.7 = secp256r1
          0x03, 0x42, // BIT STRING of length 66
                0x00, ]; // 0 unused bits
                         // public key goes here (65 bytes, uncompressed EC point representation)

#[rustfmt::skip]
const SIGNATURE_ALGORITHM: &'static [u8] = &[
    0x30, 0x0A, // SEQUENCE of length 10
          0x06, 0x08, // OBJECT IDENTIFIER of length 8
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, ]; // 1.2.840.10045.4.3.2 = ecdsa-with-SHA256

impl SoftwareU2FToken {
    pub fn new(crypto_provider: Box<dyn CryptoProvider>) -> SoftwareU2FToken {
        Self {
            crypto_provider,
            keys: Vec::new(),
            counter: 0,
        }
    }

    pub fn register(
        &mut self,
        _flags: RegisterFlags,
        _timeout: u64,
        challenge: Vec<u8>,
        application: AppId,
        key_handles: Vec<KeyHandle>,
    ) -> Result<RegisterResult> {
        for key_handle in key_handles {
            for key in &self.keys {
                // TODO: is credential what I think it is?
                if key_handle.credential == key.key_handle.public() && application == key.app_id {
                    // A key has already been registered for this application.
                    return Err(AuthenticatorError::U2FToken(U2FTokenError::NotAllowed));
                }
            }
        }
        // The bytes returned consist of:
        // Bytes  Value
        // 1      0x05 (reserved value)
        // 65     public key (uncompressed representation of public key)
        // 1      key handle length
        // *      key handle
        // ASN.1  attestation X509 certificate
        // *      attestation signature (ANSI X9.62 with P-256/SHA-256) over the following:
        //    Bytes  Value
        //    1      0x00 (reserved value)
        //    32     application parameter
        //    32     challenge parameter
        //    *      key handle
        //    65     public key
        let key = self.crypto_provider.new_key()?;
        let public_key = key.public();
        let mut to_sign = vec![0];
        to_sign.extend_from_slice(&application);
        to_sign.extend_from_slice(&challenge);
        to_sign.extend_from_slice(&public_key);
        to_sign.extend_from_slice(&public_key);
        let signature = key.sign(&to_sign)?;
        let mut to_return = vec![5];
        to_return.extend_from_slice(&public_key);
        if public_key.len() > 256 {
            return Err(errors::AuthenticatorError::CryptoError);
        }
        to_return.push(public_key.len() as u8);
        to_return.extend_from_slice(&public_key);
        let mut certificate = self.make_certificate(key.as_ref())?;
        to_return.append(&mut certificate);
        to_return.extend_from_slice(signature.as_ref());
        self.keys.push(SoftwareU2FKey::new(key, application));
        Ok((to_return, self.dev_info()))
    }

    fn make_certificate(&self, key: &dyn Key) -> Result<Vec<u8>> {
        let mut tbs_certificate = Vec::with_capacity(256);
        tbs_certificate.extend_from_slice(TBS_CERTIFICATE_BEFORE_SERIAL_NUMBER);
        let mut serial_number = vec![0; 20];
        self.crypto_provider.random_bytes(&mut serial_number)?;
        serial_number[0] &= 0x7f; // unset the MSB
        serial_number[0] |= 0x40; // ensure that at least one other bit is set
        tbs_certificate.append(&mut serial_number);
        tbs_certificate.extend_from_slice(TBS_CERTIFICATE_BEFORE_VALIDITY);

        tbs_certificate.extend_from_slice(GENERALIZED_TIME_PREFIX);
        let not_before = chrono::Utc::now() - chrono::Duration::days(1);
        let mut not_before_bytes = not_before.format("%Y%m%d000000Z").to_string().into_bytes();
        tbs_certificate.append(&mut not_before_bytes);
        tbs_certificate.extend_from_slice(GENERALIZED_TIME_PREFIX);
        let not_after = chrono::Utc::now() + chrono::Duration::days(1);
        let mut not_after_bytes = not_after.format("%Y%m%d000000Z").to_string().into_bytes();
        tbs_certificate.append(&mut not_after_bytes);

        tbs_certificate.extend_from_slice(TBS_CERTIFICATE_BEFORE_SPKI);
        tbs_certificate.extend_from_slice(&key.public());
        let mut signature = key.sign(&tbs_certificate)?;
        let mut certificate = Vec::with_capacity(400);
        // The + 3 here is due to two bytes for the tag and length of
        // tbs_certificate and one byte for the "zero unused bits" byte in the
        // signature.
        let inner_length = tbs_certificate.len() + SIGNATURE_ALGORITHM.len() + signature.len() + 3;
        if inner_length < 256 || inner_length > 65535 {
            return Err(errors::AuthenticatorError::CryptoError);
        }
        let length_byte_1 = (inner_length / 256) as u8;
        let length_byte_2 = (inner_length % 256) as u8;
        certificate.extend_from_slice(&[0x30, 0x82, length_byte_1, length_byte_2]);
        certificate.append(&mut tbs_certificate);
        certificate.extend_from_slice(SIGNATURE_ALGORITHM);
        let signature_length_byte = if signature.len() < 127 {
            signature.len() as u8
        } else {
            return Err(errors::AuthenticatorError::CryptoError);
        };
        // BIT STRING of length <signature_length_byte> + 1 with zero unused bits
        certificate.extend_from_slice(&[0x03, signature_length_byte + 1, 0x00]);
        certificate.append(&mut signature);
        Ok(certificate)
    }

    /// The implementation of this method must return quickly and should
    /// report its status via the status and callback methods
    pub fn sign(
        &mut self,
        _flags: SignFlags,
        _timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<AppId>,
        key_handles: Vec<KeyHandle>,
    ) -> Result<SignResult> {
        let key = match self.get_key(&key_handles, &app_ids) {
            Some(key) => key,
            None => return Err(AuthenticatorError::U2FToken(U2FTokenError::InvalidState)), // not registered
        };
        let user_presence_byte = 0;
        // The bytes returned consist of:
        // Bytes  Value
        // 1      user presence byte (...)
        // 4      counter (big-endian representation of the number of authentications performed)
        // *      signature (ANSI X9.62 with P-256/SHA-256) over the following:
        //    Bytes  Value
        //    32     application parameter
        //    1      user presence byte
        //    4      counter
        //    32     challenge parameter
        let mut to_sign = Vec::with_capacity(69);
        to_sign.extend_from_slice(&key.app_id);
        to_sign.push(user_presence_byte);
        let mut counter_bytes = self.get_counter_bytes()?;
        to_sign.extend_from_slice(&counter_bytes);
        to_sign.extend_from_slice(&challenge);
        let signature = key.key_handle.sign(&to_sign)?;
        let mut to_return = Vec::with_capacity(100);
        to_return.push(user_presence_byte);
        to_return.append(&mut counter_bytes);
        to_return.extend_from_slice(&signature);
        let app_id_used = key.app_id.clone();
        self.increment_counter();
        // TODO: what are we even returning here
        Ok((app_id_used, to_return, signature, self.dev_info()))
    }

    fn get_key(&self, key_handles: &[KeyHandle], app_ids: &[AppId]) -> Option<&SoftwareU2FKey> {
        // TODO: this triple-loop is paaaaaainful
        for key_handle in key_handles {
            for key in &self.keys {
                // TODO: is this the right field?
                if key.key_handle.public() == key_handle.credential {
                    for app_id in app_ids {
                        if &key.app_id == app_id {
                            return Some(key);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn dev_info(&self) -> U2FDeviceInfo {
        U2FDeviceInfo {
            vendor_name: b"Mozilla".to_vec(),
            device_name: b"Authenticator Webdriver Token".to_vec(),
            version_interface: 0,
            version_major: 1,
            version_minor: 2,
            version_build: 3,
            cap_flags: 0,
        }
    }

    fn get_counter_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = Vec::with_capacity(4);
        writer
            .write_u32::<BigEndian>(self.counter)
            .map_err(|_| AuthenticatorError::InternalError("write_u32 failed?".to_string()))?;
        Ok(writer)
    }

    fn increment_counter(&mut self) {
        // TODO: is this per-key or per-authenticator?
        self.counter += 1;
    }
}

////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::SoftwareU2FToken;
    use crate::crypto::RingCryptoProvider;
    use crate::{AuthenticatorTransports, KeyHandle, RegisterFlags, SignFlags};

    #[test]
    fn test_register_and_sign() {
        let mut software_token = SoftwareU2FToken::new(Box::new(RingCryptoProvider::new()));
        let register_result = software_token.register(
            RegisterFlags::empty(),
            10_000,
            vec![0; 32],
            vec![0; 32],
            vec![],
        );
        assert!(register_result.is_ok());
        let register_result = register_result.unwrap().0;
        assert!(register_result.len() > 67);
        let key_handle_length = register_result[66] as usize;
        assert!(register_result.len() > 67 + key_handle_length);
        let key_handle = &register_result[67..67 + key_handle_length];
        let sign_result = software_token.sign(
            SignFlags::empty(),
            10_000,
            vec![0; 32],
            vec![vec![0; 32]],
            vec![KeyHandle {
                credential: key_handle.to_vec(),
                transports: AuthenticatorTransports::empty(),
            }],
        );
        assert!(sign_result.is_ok());
    }
}
