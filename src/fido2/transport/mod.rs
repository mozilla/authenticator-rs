mod hid;

use super::commands::{Request, Reply};

enum Error<DeviceError> {
    Timeout,
    Device(DeviceError),
}

pub trait Device {
    type DeviceError;

    fn send_msg<'msg, Req: Request>(&mut self, msg: &'msg Req) -> Result<Req::Reply, Self::DeviceError>;
}
