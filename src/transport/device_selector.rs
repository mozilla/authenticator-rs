use crate::send_status;
pub use crate::transport::platform::device::Device;
use crate::transport::{hid::HIDDevice, FidoDevice};
use runloop::RunLoop;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

pub type DeviceID = <Device as HIDDevice>::Id;
pub type DeviceBuildParameters = <Device as HIDDevice>::BuildParameters;

trait DeviceSelectorEventMarker {}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlinkResult {
    DeviceSelected,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceCommand {
    Blink,
    Continue,
    Removed,
}

#[derive(Debug)]
pub enum DeviceSelectorEvent {
    Timeout,
    DevicesAdded(Vec<DeviceID>),
    DeviceRemoved(DeviceID),
    NotAToken(DeviceID),
    ImAToken((Device, Sender<DeviceCommand>)),
    SelectedToken(DeviceID),
}

pub struct DeviceSelector {
    /// How to send a message to the event loop
    sender: Sender<DeviceSelectorEvent>,
    /// Thread of the event loop
    runloop: RunLoop,
}

impl DeviceSelector {
    pub fn run(status: Sender<crate::StatusUpdate>) -> Self {
        let (selector_send, selector_rec) = channel();
        // let new_device_callback = Arc::new(new_device_cb);
        let runloop = RunLoop::new(move |alive| {
            let mut blinking = false;
            // Device was added, but we wait for its response, if it is a token or not
            // We save both a write-only copy of the device (for cancellation) and it's thread
            let mut waiting_for_response = HashSet::new();
            // All devices that responded with "ImAToken"
            let mut tokens = HashMap::new();
            while alive() {
                let d = Duration::from_secs(100);
                let res = match selector_rec.recv_timeout(d) {
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => DeviceSelectorEvent::Timeout,
                    Ok(res) => res,
                };

                match res {
                    DeviceSelectorEvent::Timeout => {
                        /* TODO */
                        Self::cancel_all(tokens, None);
                        break;
                    }
                    DeviceSelectorEvent::SelectedToken(dev) => {
                        Self::cancel_all(tokens, Some(&dev));
                        break; // We are done here. The selected device continues without us.
                    }
                    DeviceSelectorEvent::DevicesAdded(ids) => {
                        for id in ids {
                            println!("Device added event: {:?}", id);
                            waiting_for_response.insert(id);
                        }
                        continue;
                    }
                    DeviceSelectorEvent::DeviceRemoved(id) => {
                        println!("Device removed event: {:?}", id);
                        if !waiting_for_response.remove(&id) {
                            // Note: We _could_ check here if we had multiple tokens and are already blinking
                            //       and the removal of this one leads to only one token left. So we could in theory
                            //       stop blinking and select it right away. At the moment, I think this is a
                            //       too surprising behavior and therefore, we let the remaining device keep on blinking
                            //       since the user could add yet another device, instead of using the remaining one.
                            tokens.iter().for_each(|(dev, send)| {
                                if dev.id() == id {
                                    let _ = send.send(DeviceCommand::Removed);
                                }
                            });
                            tokens.retain(|dev, _| dev.id() != id);
                            if tokens.is_empty() {
                                blinking = false;
                                continue;
                            }
                        }
                        // We are already blinking, so no need to run the code below this match
                        // that figures out if we should blink or not. In fact, currently, we do
                        // NOT want to run this code again, because if you have 2 blinking tokens
                        // and one got removed, we WANT the remaining one to continue blinking.
                        // This is a design choice, because I currently think it is the "less surprising"
                        // option to the user.
                        if blinking {
                            continue;
                        }
                    }
                    DeviceSelectorEvent::NotAToken(id) => {
                        println!("Device not a token event: {:?}", id);
                        waiting_for_response.remove(&id);
                    }
                    DeviceSelectorEvent::ImAToken((dev, tx)) => {
                        let id = dev.id();
                        let supports_uv = dev.supports_some_user_verification();
                        let _ = waiting_for_response.remove(&id);
                        tokens.insert(dev, tx.clone());
                        if blinking {
                            let cmd = if supports_uv {
                                DeviceCommand::Blink
                            } else {
                                DeviceCommand::Continue
                            };
                            // We are already blinking, so this new device should blink too.
                            if tx.send(cmd).is_err() {
                                // Device thread died in the meantime (which shouldn't happen)
                                tokens.retain(|dev, _| dev.id() != id);
                            }
                            continue;
                        }
                    }
                }

                // All known devices told us, whether they are tokens or not and we have at least one token
                if waiting_for_response.is_empty() && !tokens.is_empty() {
                    if tokens.len() == 1 {
                        let (dev, tx) = tokens.drain().next().unwrap(); // We just checked that it can't be empty
                        if tx.send(DeviceCommand::Continue).is_err() {
                            // Device thread died in the meantime (which shouldn't happen).
                            // Tokens is empty, so we just start over again
                            continue;
                        }
                        Self::cancel_all(tokens, Some(&dev.id()));
                        break; // We are done here
                    } else {
                        blinking = true;

                        tokens.iter().for_each(|(dev, tx)| {
                            // We send the add. blink-command only, if the token either has a PIN set or some other
                            // kind of user verification. If so, we can't send the request straight to them
                            // because that could result in PIN-prompts from multiple devices, so then they
                            // have to blink first.
                            // BUT if they are either CTAP1 tokens or CTAP2 without uv, we can send the normal
                            // request to them, and skip one additional user-interaction (touch).
                            let cmd = if dev.supports_some_user_verification() {
                                DeviceCommand::Blink
                            } else {
                                DeviceCommand::Continue
                            };
                            // A send operation can only fail if the receiving end of a channel is disconnected, implying that the data could never be received.
                            // We ignore errors here for now, but should probably remove the device in such a case (even though it theoretically can't happen)
                            let _ = tx.send(cmd);
                        });
                        send_status(&status, crate::StatusUpdate::SelectDeviceNotice);
                    }
                }
            }
        });
        Self {
            runloop: runloop.unwrap(), // TODO
            sender: selector_send,
        }
    }

    pub fn clone_sender(&self) -> Sender<DeviceSelectorEvent> {
        self.sender.clone()
    }

    fn cancel_all(tokens: HashMap<Device, Sender<DeviceCommand>>, exclude: Option<&DeviceID>) {
        tokens
            .into_keys()
            .filter(|x| exclude.map_or(true, |y| y != &x.id()))
            .for_each(|mut dev| dev.cancel().unwrap()); // TODO
    }

    pub fn stop(&mut self) {
        self.runloop.cancel();
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        ctap2::commands::get_info::{AuthenticatorInfo, AuthenticatorOptions},
        StatusUpdate,
    };

    use super::*;

    fn make_device_simple_u2f(dev: &mut Device) {
        dev.create_channel();
    }

    fn make_device_with_pin(dev: &mut Device) {
        dev.create_channel();
        let info = AuthenticatorInfo {
            options: AuthenticatorOptions {
                client_pin: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        dev.set_authenticator_info(info.clone());
    }

    fn send_i_am_token(dev: &Device, selector: &DeviceSelector) {
        selector
            .sender
            .send(DeviceSelectorEvent::ImAToken((
                dev.clone_device_as_write_only().unwrap(),
                dev.sender.clone().unwrap(),
            )))
            .unwrap();
    }

    fn send_no_token(dev: &Device, selector: &DeviceSelector) {
        selector
            .sender
            .send(DeviceSelectorEvent::NotAToken(dev.id()))
            .unwrap()
    }

    fn remove_device(dev: &Device, selector: &DeviceSelector) {
        selector
            .sender
            .send(DeviceSelectorEvent::DeviceRemoved(dev.id()))
            .unwrap();
        assert_eq!(
            dev.receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Removed
        );
    }

    fn add_devices<'a, T>(iter: T, selector: &DeviceSelector)
    where
        T: Iterator<Item = &'a Device>,
    {
        selector
            .sender
            .send(DeviceSelectorEvent::DevicesAdded(
                iter.map(|f| f.id()).collect(),
            ))
            .unwrap();
    }

    #[test]
    fn test_device_selector_one_token_no_late_adds() {
        let mut devices = vec![
            Device::new("device selector 1").unwrap(),
            Device::new("device selector 2").unwrap(),
            Device::new("device selector 3").unwrap(),
            Device::new("device selector 4").unwrap(),
        ];

        // Make those actual tokens. The rest is interpreted as non-u2f-devices
        make_device_with_pin(&mut devices[2]);

        let (status_tx, _status_rx) = channel();
        let selector = DeviceSelector::run(status_tx);

        // Adding all
        add_devices(devices.iter(), &selector);

        devices.iter().filter(|d| !d.is_u2f()).for_each(|d| {
            send_no_token(d, &selector);
        });

        send_i_am_token(&devices[2], &selector);

        assert_eq!(
            devices[2].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Continue
        );
    }

    #[test]
    fn test_device_selector_all_pins_with_late_add() {
        let mut devices = vec![
            Device::new("device selector 1").unwrap(),
            Device::new("device selector 2").unwrap(),
            Device::new("device selector 3").unwrap(),
            Device::new("device selector 4").unwrap(),
            Device::new("device selector 5").unwrap(),
            Device::new("device selector 6").unwrap(),
        ];

        // Make those actual tokens. The rest is interpreted as non-u2f-devices
        make_device_with_pin(&mut devices[2]);
        make_device_with_pin(&mut devices[4]);
        make_device_with_pin(&mut devices[5]);

        let (status_tx, status_rx) = channel();
        let selector = DeviceSelector::run(status_tx);

        // Adding all, except the last one (we simulate that this one is not yet plugged in)
        add_devices(devices.iter().take(5), &selector);

        // Interleave tokens and non-tokens
        send_i_am_token(&devices[2], &selector);

        devices.iter().filter(|d| !d.is_u2f()).for_each(|d| {
            send_no_token(d, &selector);
        });

        send_i_am_token(&devices[4], &selector);

        // We added 2 devices that are tokens. They should get the blink-command now
        assert_eq!(
            devices[2].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Blink
        );
        assert_eq!(
            devices[4].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Blink
        );
        assert!(matches!(
            status_rx.recv().unwrap(),
            StatusUpdate::SelectDeviceNotice
        ));

        // Plug in late device
        send_i_am_token(&devices[5], &selector);
        assert_eq!(
            devices[5].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Blink
        );
    }

    #[test]
    fn test_device_selector_no_pins_late_mixed_adds() {
        // Multiple tokes, none of them support a PIN, so we should get Continue-commands
        // for all of them
        let mut devices = vec![
            Device::new("device selector 1").unwrap(),
            Device::new("device selector 2").unwrap(),
            Device::new("device selector 3").unwrap(),
            Device::new("device selector 4").unwrap(),
            Device::new("device selector 5").unwrap(),
            Device::new("device selector 6").unwrap(),
            Device::new("device selector 7").unwrap(),
        ];

        // Make those actual tokens. The rest is interpreted as non-u2f-devices
        make_device_simple_u2f(&mut devices[2]);
        make_device_simple_u2f(&mut devices[4]);
        make_device_simple_u2f(&mut devices[5]);

        let (status_tx, status_rx) = channel();
        let selector = DeviceSelector::run(status_tx);

        // Adding all, except the last one (we simulate that this one is not yet plugged in)
        add_devices(devices.iter().take(5), &selector);

        // Interleave tokens and non-tokens
        send_i_am_token(&devices[2], &selector);

        devices.iter().filter(|d| !d.is_u2f()).for_each(|d| {
            send_no_token(d, &selector);
        });

        send_i_am_token(&devices[4], &selector);

        // We added 2 devices that are tokens. They should get the blink-command now
        assert_eq!(
            devices[2].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Continue
        );
        assert_eq!(
            devices[4].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Continue
        );
        assert!(matches!(
            status_rx.recv().unwrap(),
            StatusUpdate::SelectDeviceNotice
        ));

        // Plug in late device
        send_i_am_token(&devices[5], &selector);
        assert_eq!(
            devices[5].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Continue
        );
        // Remove device again
        remove_device(&devices[5], &selector);

        // Now we add a token that has a PIN, it should not get "Continue" but "Blink"
        make_device_with_pin(&mut devices[6]);
        send_i_am_token(&devices[6], &selector);
        assert_eq!(
            devices[6].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Blink
        );
    }

    #[test]
    fn test_device_selector_mixed_pins_remove_all() {
        // Multiple tokes, none of them support a PIN, so we should get Continue-commands
        // for all of them
        let mut devices = vec![
            Device::new("device selector 1").unwrap(),
            Device::new("device selector 2").unwrap(),
            Device::new("device selector 3").unwrap(),
            Device::new("device selector 4").unwrap(),
            Device::new("device selector 5").unwrap(),
            Device::new("device selector 6").unwrap(),
        ];

        // Make those actual tokens. The rest is interpreted as non-u2f-devices
        make_device_with_pin(&mut devices[2]);
        make_device_with_pin(&mut devices[4]);
        make_device_with_pin(&mut devices[5]);

        let (status_tx, status_rx) = channel();
        let selector = DeviceSelector::run(status_tx);

        // Adding all, except the last one (we simulate that this one is not yet plugged in)
        add_devices(devices.iter(), &selector);

        devices.iter().for_each(|d| {
            if d.is_u2f() {
                send_i_am_token(d, &selector);
            } else {
                send_no_token(d, &selector);
            }
        });

        for idx in [2, 4, 5] {
            assert_eq!(
                devices[idx].receiver.as_ref().unwrap().recv().unwrap(),
                DeviceCommand::Blink
            );
        }
        assert!(matches!(
            status_rx.recv().unwrap(),
            StatusUpdate::SelectDeviceNotice
        ));

        // Remove all tokens
        for idx in [2, 4, 5] {
            remove_device(&devices[idx], &selector);
        }

        // Adding one again
        send_i_am_token(&devices[4], &selector);

        // This should now get a "Continue" instead of "Blinking", because it's the only device
        assert_eq!(
            devices[4].receiver.as_ref().unwrap().recv().unwrap(),
            DeviceCommand::Continue
        );
    }
}
