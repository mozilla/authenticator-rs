/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io;
use std::sync::{mpsc::Sender, Arc, Mutex};

use crate::consts::PARAMETER_SIZE;
use crate::util::StateCallback;

pub trait AuthenticatorTransport {
    /// The implementation of this method must return quickly and should
    /// report its status via the status and callback methods
    fn register(
        &mut self,
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<Result<crate::RegisterResult, crate::Error>>,
    ) -> Result<(), crate::Error>;

    /// The implementation of this method must return quickly and should
    /// report its status via the status and callback methods
    fn sign(
        &mut self,
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: StateCallback<Result<crate::SignResult, crate::Error>>,
    ) -> Result<(), crate::Error>;

    fn cancel(&mut self) -> Result<(), crate::Error>;
}

pub struct AuthenticatorService {
    transports: Vec<Arc<Mutex<Box<dyn AuthenticatorTransport + Send>>>>,
}

fn clone_and_configure_cancellation_callback<T>(
    callback: &StateCallback<T>,
    transports_to_cancel: Vec<Arc<Mutex<Box<dyn AuthenticatorTransport + Send>>>>,
) -> StateCallback<T> {
    let mut callback = callback.clone();
    callback.add_uncloneable_observer(Box::new(move || {
        debug!(
            "Callback observer is running, cancelling \
             {} unchosen transports...",
            transports_to_cancel.len()
        );
        for transport_mutex in &transports_to_cancel {
            if let Err(e) = transport_mutex.lock().unwrap().cancel() {
                error!("Cancellation failed: {:?}", e);
            }
        }
    }));
    callback
}

impl AuthenticatorService {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            transports: Vec::new(),
        })
    }

    /// Add any detected platform transports
    pub fn add_detected_transports(&mut self) {
        self.add_u2f_usb_hid_platform_transports();

        #[cfg(target_os = "macos")]
        self.add_macos_touchid_virtual_device();
    }

    fn add_transport(&mut self, boxed_token: Box<dyn AuthenticatorTransport + Send>) {
        self.transports.push(Arc::new(Mutex::new(boxed_token)))
    }

    pub fn add_u2f_usb_hid_platform_transports(&mut self) {
        match crate::U2FManager::new() {
            Ok(token) => self.add_transport(Box::new(token)),
            Err(e) => error!("Could not add U2F HID transport: {}", e),
        }
    }

    #[cfg(target_os = "macos")]
    pub fn add_macos_touchid_virtual_device(&mut self) {
        match crate::virtualdevices::macos_touchid::TouchIDToken::new() {
            Ok(token) => self.add_transport(Box::new(token)),
            Err(e) => error!("Could not add MacOS TouchID virtual device: {}", e),
        }
    }

    #[cfg(feature = "webdriver")]
    pub fn add_webdriver_virtual_bus(&mut self) {
        match crate::virtualdevices::webdriver::VirtualManager::new() {
            Ok(token) => {
                println!("WebDriver ready, listening at {}", &token.url());
                self.add_transport(Box::new(token));
            }
            Err(e) => error!("Could not add WebDriver virtual bus: {}", e),
        }
    }

    pub fn register<F>(
        &mut self,
        flags: crate::RegisterFlags,
        timeout: u64,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: F,
    ) -> Result<(), crate::Error>
    where
        F: Fn(Result<crate::RegisterResult, crate::Error>),
        F: Send + 'static,
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            return Err(crate::Error::Unknown);
        }

        for key_handle in &key_handles {
            if key_handle.credential.len() > 256 {
                return Err(crate::Error::Unknown);
            }
        }

        let iterable_transports = self.transports.clone();
        if iterable_transports.is_empty() {
            return Err(crate::Error::NotSupported);
        }

        let callback = StateCallback::new(Box::new(callback));

        for (idx, transport_mutex) in iterable_transports.iter().enumerate() {
            let mut transports_to_cancel = iterable_transports.clone();
            transports_to_cancel.remove(idx);

            transport_mutex.lock().unwrap().register(
                flags.clone(),
                timeout,
                challenge.clone(),
                application.clone(),
                key_handles.clone(),
                status.clone(),
                clone_and_configure_cancellation_callback(&callback, transports_to_cancel),
            )?;
        }

        Ok(())
    }

    pub fn sign<F>(
        &mut self,
        flags: crate::SignFlags,
        timeout: u64,
        challenge: Vec<u8>,
        app_ids: Vec<crate::AppId>,
        key_handles: Vec<crate::KeyHandle>,
        status: Sender<crate::StatusUpdate>,
        callback: F,
    ) -> Result<(), crate::Error>
    where
        F: Fn(Result<crate::SignResult, crate::Error>),
        F: Send + 'static,
    {
        if challenge.len() != PARAMETER_SIZE {
            return Err(crate::Error::Unknown);
        }

        if app_ids.is_empty() {
            return Err(crate::Error::Unknown);
        }

        for app_id in &app_ids {
            if app_id.len() != PARAMETER_SIZE {
                return Err(crate::Error::Unknown);
            }
        }

        for key_handle in &key_handles {
            if key_handle.credential.len() > 256 {
                return Err(crate::Error::Unknown);
            }
        }

        let iterable_transports = self.transports.clone();
        if iterable_transports.is_empty() {
            return Err(crate::Error::NotSupported);
        }

        let callback = StateCallback::new(Box::new(callback));

        for (idx, transport_mutex) in iterable_transports.iter().enumerate() {
            let mut transports_to_cancel = iterable_transports.clone();
            transports_to_cancel.remove(idx);

            transport_mutex.lock().unwrap().sign(
                flags.clone(),
                timeout,
                challenge.clone(),
                app_ids.clone(),
                key_handles.clone(),
                status.clone(),
                clone_and_configure_cancellation_callback(&callback, transports_to_cancel),
            )?;
        }

        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), crate::Error> {
        if self.transports.is_empty() {
            return Err(crate::Error::NotSupported);
        }

        for transport_mutex in &mut self.transports {
            transport_mutex.lock().unwrap().cancel()?;
        }

        Ok(())
    }
}
