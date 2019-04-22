/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod commands;
pub mod crypto;
pub mod device;
pub mod transaction;

use std::cell::RefCell;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum TestCase {
    WriteError,
    Fido2Simple,
}

impl TestCase {
    pub fn activate(value: TestCase) {
        // ENABLED_TEST will return older value in error side of a result, just
        // ignore it.
        debug!(
            "enabling test_case={:?} in {:?}",
            value,
            std::thread::current().id()
        );
        ENABLED_TEST.with(|v| v.replace(value));
    }

    pub fn active() -> TestCase {
        let value = ENABLED_TEST.with(|v| v.clone().into_inner());
        debug!(
            "enabling test_case={:?} in {:?}",
            value,
            std::thread::current().id()
        );
        value
    }
}

impl Default for TestCase {
    fn default() -> Self {
        TestCase::Fido2Simple
    }
}

thread_local! {
    static ENABLED_TEST: RefCell<TestCase> = RefCell::new(TestCase::default());
}
