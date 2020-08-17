/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::authenticatorservice::AuthenticatorTransport;
use crate::statecallback::StateCallback;
use crate::virtualdevices::software_u2f::SoftwareU2FToken;
use crate::{AppId, KeyHandle, RegisterFlags, RegisterResult, SignFlags, SignResult, StatusUpdate};
use base64;
use keychain_services::*;
use rand::{thread_rng, RngCore};
use std::sync::mpsc::Sender;
use std::{io, thread};

const TOUCHID_APP_TAG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

pub struct TouchIDToken {
    pub u2f_impl: SoftwareU2FToken,
    // pub secret: PasswordData,
}

fn map_to_ioerr<T, U>(x: Result<T, U>) -> Result<T, io::Error>
where
    U: std::fmt::Display,
{
    x.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
}

impl TouchIDToken {
    pub fn new() -> io::Result<Self> {
        let service = "example.com";
        let account = "example";

        let keychain = map_to_ioerr(Keychain::find_default())?;

        let mut flags = AccessControlFlags::new();
        flags.add(AccessConstraint::BiometryCurrentSet);
        flags.add(AccessOption::PrivateKeyUsage);

        let ac = map_to_ioerr(AccessControl::create_with_flags(
            AttrAccessible::WhenPasscodeSetThisDeviceOnly,
            flags,
        ))?;

        let params = KeyPairGenerateParams::new(AttrKeyType::EcSecPrimeRandom, 256)
            .application_tag(AttrApplicationTag::new(&TOUCHID_APP_TAG))
            .access_control(&ac)
            .token_id(AttrTokenId::SecureEnclave)
            // .permanent(true)
            ;

        let keypair = KeyPair::generate(params).unwrap();

        let public_key_bytes = keypair.public_key.to_external_representation().unwrap();
        println!("pubkey: {}", &base64::encode(&public_key_bytes));

        // let secret = match GenericPassword::find(&keychain, &service, &account) {
        //     Ok(recovered_secret) => recovered_secret,
        //     Err(_) => {
        //         let mut keymat = [0u8; 32];
        //         thread_rng().fill_bytes(&mut keymat);
        //         map_to_ioerr(GenericPassword::create(&keychain, &service, &account, &base64::encode(&keymat)))?
        //     }
        // };

        // println!("password: {}", &base64::encode(&map_to_ioerr(secret.password())?));

        Ok(Self {
            u2f_impl: SoftwareU2FToken::new(),
            // secret: map_to_ioerr(secret.password())?,
        })
    }
}

impl AuthenticatorTransport for TouchIDToken {
    fn register(
        &mut self,
        flags: RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: AppId,
        key_handles: Vec<KeyHandle>,
        status: Sender<StatusUpdate>,
        callback: StateCallback<Result<RegisterResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        let result = self
            .u2f_impl
            .register(flags, timeout, challenge, application, key_handles);
        status
            .send(StatusUpdate::Success {
                dev_info: self.u2f_impl.dev_info(),
            })
            .map_err(|_| crate::Error::Unknown)?;
        thread::spawn(move || {
            callback.call(result);
        });
        Ok(())
    }

    fn sign(
        &mut self,
        flags: SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<AppId>,
        key_handles: Vec<KeyHandle>,
        status: Sender<StatusUpdate>,
        callback: StateCallback<Result<SignResult, crate::Error>>,
    ) -> Result<(), crate::Error> {
        let result = self
            .u2f_impl
            .sign(flags, timeout, challenge, app_ids, key_handles);
        status
            .send(StatusUpdate::Success {
                dev_info: self.u2f_impl.dev_info(),
            })
            .map_err(|_| crate::Error::Unknown)?;
        thread::spawn(move || {
            callback.call(result);
        });
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), crate::Error> {
        Ok(())
    }
}
