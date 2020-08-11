/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::virtualdevices::software_u2f::SoftwareU2FToken;
use crate::{Error, RegisterFlags, RegisterResult, SignFlags, SignResult};

pub enum TestWireProtocol {
    CTAP1,
    CTAP2,
}

pub struct TestToken {
    pub id: u64,
    pub protocol: TestWireProtocol,
    pub is_user_consenting: bool,
    pub has_user_verification: bool,
    pub is_user_verified: bool,
    pub has_resident_key: bool,
    pub u2f_impl: Option<SoftwareU2FToken>,
}

impl TestToken {
    pub fn new(
        id: u64,
        protocol: TestWireProtocol,
        is_user_consenting: bool,
        has_user_verification: bool,
        is_user_verified: bool,
        has_resident_key: bool,
    ) -> TestToken {
        match protocol {
            TestWireProtocol::CTAP1 => {
                return Self {
                    id,
                    protocol,
                    is_user_consenting,
                    has_user_verification,
                    is_user_verified,
                    has_resident_key,
                    u2f_impl: Some(SoftwareU2FToken::new()),
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn register(&self) -> Result<RegisterResult, Error> {
        if self.u2f_impl.is_some() {
            return self.u2f_impl.as_ref().unwrap().register(
                RegisterFlags::empty(),
                10_000,
                vec![0; 32],
                vec![0; 32],
                vec![],
            );
        }
        Err(Error::Unknown)
    }

    pub fn sign(&self) -> Result<SignResult, Error> {
        if self.u2f_impl.is_some() {
            return self.u2f_impl.as_ref().unwrap().sign(
                SignFlags::empty(),
                10_000,
                vec![0; 32],
                vec![vec![0; 32]],
                vec![],
            );
        }
        Err(Error::Unknown)
    }
}
