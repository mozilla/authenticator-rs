/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use zbus::{dbus_proxy, Result};
use zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::errors;
use crate::{RegisterResult, SignResult};

#[dbus_proxy(
    interface = "org.freedesktop.fido2.Device",
    default_service = "org.freedesktop.fido2"
)]
trait Device {
    fn make_credential(
        &self,
        sign_type: &str,
        client_data_hash: &[u8],
        rp: &str,
        user_id: &[u8],
        user: &str,
        options: HashMap<&str, &Value>,
    ) -> Result<OwnedObjectPath>;

    fn get_assertion(
        &self,
        client_data_hash: &[u8],
        rp: &str,
        key_handle: &[u8],
        options: HashMap<&str, &Value>,
    ) -> Result<OwnedObjectPath>;
}

#[dbus_proxy(
    interface = "org.freedesktop.fido2.Request",
    default_service = "org.freedesktop.fido2"
)]
trait Request {
    fn cancel(&self) -> Result<()>;

    #[dbus_proxy(signal)]
    fn error(&self, code: u32, cause: &str) -> Result<()>;

    #[dbus_proxy(signal)]
    fn completed(&self, options: HashMap<&str, Value>) -> Result<()>;
}

pub struct Device<'c>(DeviceProxy<'c>);

pub struct DeviceManagerState<'c> {
    pub devices: Vec<Device<'c>>,
}

impl<'c> DeviceManagerState<'c> {
    pub fn new() -> Arc<Mutex<DeviceManagerState<'c>>> {
        Arc::new(Mutex::new(DeviceManagerState { devices: vec![] }))
    }
}

pub fn serve(
    state: Arc<Mutex<DeviceManagerState<'static>>>,
    connection: zbus::Connection,
) -> Result<()> {
    let object_manager_connection = zbus::Connection::new_session()?;

    let object_manager = zbus::fdo::ObjectManagerProxy::new_for(
        &object_manager_connection,
        "org.freedesktop.fido2",
        "/org/freedesktop/fido2/Device",
    )?;

    let connectionclone = connection.clone();
    let stateclone = state.clone();

    object_manager.connect_interfaces_added(move |object_path, _| {
        let device = DeviceProxy::new_for_owned_path(
            connectionclone.clone(),
            object_path.as_str().to_string(),
        )?;
        let mut lock = stateclone.lock().unwrap();
        lock.devices.push(Device(device));
        Ok(())
    })?;

    let stateclone = state.clone();

    object_manager.connect_interfaces_removed(move |object_path, _| {
        let mut lock = stateclone.lock().unwrap();
        if let Some(index) = lock
            .devices
            .iter()
            .position(|device| device.0.path() == object_path.as_str())
        {
            lock.devices.remove(index);
        }
        Ok(())
    })?;

    let objects = object_manager.get_managed_objects()?;
    for object_path in objects.keys().next() {
        let device =
            DeviceProxy::new_for_owned_path(connection.clone(), object_path.as_str().to_string())?;

        let mut lock = state.lock().unwrap();
        lock.devices.push(Device(device));
    }

    loop {
        object_manager.next_signal()?;
    }
}

fn array_to_vec<'a, T>(value: &'a Value) -> Vec<T>
where
    T: TryFrom<Value<'a>>,
{
    let array: &zvariant::Array = value.downcast_ref().unwrap();
    <Vec<T>>::try_from(array.clone()).unwrap()
}

impl<'c> Device<'c> {
    pub fn register(
        &self,
        challenge: Vec<u8>,
        application: crate::AppId,
    ) -> crate::Result<RegisterResult> {
        // rp must be in valid UTF-8
        let rp = std::str::from_utf8(&*application)
            .map_err(|_| errors::AuthenticatorError::InvalidRelyingPartyInput)?;

        // Forcibly use CTAP1 to avoid PIN requirement
        let mut options = HashMap::new();
        let force_u2f = Value::new(true);
        options.insert("forceU2F", &force_u2f);

        // Require user presence
        let up = Value::new(true);
        options.insert("up", &up);

        if let Ok(request_path) = self.0.make_credential(
            "es256",
            &challenge.as_slice(),
            rp,
            "user".as_bytes(),
            &"user",
            options,
        ) {
            if let Ok(request) =
                RequestProxy::new_for_path(self.0.connection(), request_path.as_str())
            {
                let (register_tx, register_rx) = channel();

                let register_tx_clone = register_tx.clone();
                request
                    .connect_error(move |_, _| {
                        register_tx_clone
                            .send(Err(errors::AuthenticatorError::U2FToken(
                                errors::U2FTokenError::Unknown,
                            )))
                            .map_err(|_| zbus::Error::Io(io::ErrorKind::Other.into()))
                    })
                    .unwrap();

                let register_tx_clone = register_tx.clone();
                request
                    .connect_completed(move |options| {
                        let mut public_key = array_to_vec(options.get("publicKey").unwrap());
                        let mut key_handle = array_to_vec(options.get("credentialID").unwrap());
                        let mut certificate = array_to_vec(options.get("x5c").unwrap());
                        let mut signature = array_to_vec(options.get("signature").unwrap());

                        let mut response = Vec::new();
                        response.push(0x05u8);
                        // Indicate the public key is in the ANSI X9.62
                        // uncompressed format.
                        response.push(0x04u8);
                        response.append(&mut public_key);
                        response.push(key_handle.len() as u8);
                        response.append(&mut key_handle);
                        response.append(&mut certificate);
                        response.append(&mut signature);

                        register_tx_clone
                            .send(Ok(response))
                            .map_err(|_| zbus::Error::Io(io::ErrorKind::Other.into()))
                    })
                    .unwrap();

                loop {
                    match request.next_signal() {
                        Ok(None) => break,
                        Ok(_) => {}
                        _ => {
                            return Err(errors::AuthenticatorError::U2FToken(
                                errors::U2FTokenError::Unknown,
                            ))
                        }
                    }
                }

                if let Ok(Ok(response)) = register_rx.recv() {
                    Ok((response, self.dev_info()))
                } else {
                    Err(errors::AuthenticatorError::U2FToken(
                        errors::U2FTokenError::Unknown,
                    ))
                }
            } else {
                Err(errors::AuthenticatorError::U2FToken(
                    errors::U2FTokenError::Unknown,
                ))
            }
        } else {
            Err(errors::AuthenticatorError::U2FToken(
                errors::U2FTokenError::Unknown,
            ))
        }
    }

    pub fn sign(
        &self,
        challenge: Vec<u8>,
        application: crate::AppId,
        key_handle: Vec<u8>,
    ) -> crate::Result<SignResult> {
        // rp must be in valid UTF-8
        let rp = std::str::from_utf8(&*application)
            .map_err(|_| errors::AuthenticatorError::InvalidRelyingPartyInput)?;

        // Forcibly use CTAP1 to avoid PIN requirement
        let mut options = HashMap::new();
        let force_u2f = Value::new(true);
        options.insert("forceU2F", &force_u2f);

        // Require user presence
        let up = Value::new(true);
        options.insert("up", &up);

        if let Ok(request_path) =
            self.0
                .get_assertion(&challenge.as_slice(), rp, &key_handle.as_slice(), options)
        {
            if let Ok(request) =
                RequestProxy::new_for_path(self.0.connection(), request_path.as_str())
            {
                let (sign_tx, sign_rx) = channel();

                let sign_tx_clone = sign_tx.clone();
                request
                    .connect_error(move |_, _| {
                        sign_tx_clone
                            .send(Err(errors::AuthenticatorError::U2FToken(
                                errors::U2FTokenError::Unknown,
                            )))
                            .map_err(|_| zbus::Error::Io(io::ErrorKind::Other.into()))
                    })
                    .unwrap();

                let sign_tx_clone = sign_tx.clone();
                request
                    .connect_completed(move |options| {
                        // FIXME: The server actually sends an array of
                        // assertions, though zbus seems to pick only the first
                        // assertion.
                        let value = options.get("assertions").unwrap();
                        let assertion: &zvariant::Dict = value.downcast_ref().unwrap();
                        let assertion =
                            <HashMap<String, OwnedValue>>::try_from(assertion.clone()).unwrap();

                        let value = assertion.get("sigCount").unwrap();
                        let mut counter = u32::try_from(&*value)
                            .and_then(|value| Ok(value.to_be_bytes().to_vec()))
                            .map_err(|_| zbus::Error::Io(io::ErrorKind::Other.into()))?;

                        let mut signature = array_to_vec(assertion.get("signature").unwrap());

                        let mut response = Vec::new();
                        response.push(0x01u8); // user presense
                        response.append(&mut counter);
                        response.append(&mut signature);

                        sign_tx_clone
                            .send(Ok(response))
                            .map_err(|_| zbus::Error::Io(io::ErrorKind::Other.into()))
                    })
                    .unwrap();

                loop {
                    match request.next_signal() {
                        Ok(None) => break,
                        Ok(_) => {}
                        _ => {
                            return Err(errors::AuthenticatorError::U2FToken(
                                errors::U2FTokenError::Unknown,
                            ))
                        }
                    }
                }

                if let Ok(Ok(response)) = sign_rx.recv() {
                    Ok((
                        application.clone(),
                        key_handle.clone(),
                        response,
                        self.dev_info(),
                    ))
                } else {
                    Err(errors::AuthenticatorError::U2FToken(
                        errors::U2FTokenError::Unknown,
                    ))
                }
            } else {
                Err(errors::AuthenticatorError::U2FToken(
                    errors::U2FTokenError::Unknown,
                ))
            }
        } else {
            Err(errors::AuthenticatorError::U2FToken(
                errors::U2FTokenError::Unknown,
            ))
        }
    }

    // FIXME: add a method to the protocol that retrieves actual device
    // information.
    fn dev_info(&self) -> crate::u2ftypes::U2FDeviceInfo {
        crate::u2ftypes::U2FDeviceInfo {
            vendor_name: b"Mozilla".to_vec(),
            device_name: b"Authenticator D-Bus Token".to_vec(),
            version_interface: 0,
            version_major: 1,
            version_minor: 2,
            version_build: 3,
            cap_flags: 0,
        }
    }
}
