use super::{u2ftypes, Pin};
use std::sync::mpsc::Sender;

#[derive(Debug)]
pub enum StatusPinUv {
    PinRequired(Sender<Pin>),
    InvalidPin(Sender<Pin>, Option<u8>),
    PinIsTooShort,
    PinIsTooLong(usize),
    InvalidUv(Option<u8>),
    // This SHOULD ever only happen for CTAP2.0 devices that
    // use internal UV (e.g. fingerprint sensors) and failed (e.g. wrong
    // finger used).
    // PinAuthInvalid, // Folded into InvalidUv
    PinAuthBlocked,
    PinBlocked,
    PinNotSet,
    UvBlocked,
}

#[derive(Debug)]
pub enum StatusUpdate {
    /// Device found
    DeviceAvailable { dev_info: u2ftypes::U2FDeviceInfo },
    /// Device got removed
    DeviceUnavailable { dev_info: u2ftypes::U2FDeviceInfo },
    /// We successfully finished the register or sign request
    Success { dev_info: u2ftypes::U2FDeviceInfo },
    /// Sent if a PIN is needed (or was wrong), or some other kind of PIN-related
    /// error occurred. The Sender is for sending back a PIN (if needed).
    PinUvError(StatusPinUv),
    /// Sent, if multiple devices are found and the user has to select one
    SelectDeviceNotice,
    /// Sent, once a device was selected (either automatically or by user-interaction)
    /// and the register or signing process continues with this device
    DeviceSelected(u2ftypes::U2FDeviceInfo),
}

pub(crate) fn send_status(status: &Sender<StatusUpdate>, msg: StatusUpdate) {
    match status.send(msg) {
        Ok(_) => {}
        Err(e) => error!("Couldn't send status: {:?}", e),
    };
}
