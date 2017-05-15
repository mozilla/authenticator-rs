use std::error::Error;
use std::io;

pub fn from_nix_error(err: ::nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno() as i32)
}

pub fn from_nix_result<T>(res: ::nix::Result<T>) -> io::Result<T> {
    match res {
        Ok(r) => Ok(r),
        Err(err) => Err(from_nix_error(err)),
    }
}

pub fn io_err(msg: &str) -> io::Error {
  io::Error::new(io::ErrorKind::Other, msg)
}

pub fn to_io_err<T: Error>(err: T) -> io::Error {
  io_err(err.description())
}
