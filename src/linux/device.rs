use std::path::PathBuf;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::RawFd;

use ::consts::CID_BROADCAST;
use ::platform::hidraw;
use ::platform::util::from_nix_result;

use U2FDevice;

#[derive(Debug)]
pub struct Device {
    pub path: PathBuf,
    // hidraw device file handle
    pub fd: RawFd,
    // Stores whether or not the device uses numbered reports
    // TODO: Needs implementation
    pub uses_numbered_reports: bool,
    // Channel ID for U2F HID communication. Needed to implement U2FDevice
    // trait.
    pub cid: [u8; 4],
}

impl Device {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        let opts = ::nix::fcntl::O_RDWR;
        let mode = ::nix::sys::stat::Mode::empty();
        let fd = from_nix_result(::nix::fcntl::open(&path, opts, mode))?;
        assert!(fd > 0);

        Ok(Self {
            path, fd,
            // TODO Actually check the usage report here
            uses_numbered_reports: true,
            // Start device with CID_BROADCAST as a cid,
            // we'll get the actual CID on device init.
            cid: CID_BROADCAST
        })
    }

    pub fn is_u2f(&self) -> bool {
        hidraw::is_u2f_device(self.fd)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Close the fd, ignore any errors.
        let _ = ::nix::unistd::close(self.fd);
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Device) -> bool {
        self.path == other.path
    }
}

impl Read for Device {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        from_nix_result(::nix::unistd::read(self.fd, bytes))
    }
}

impl Write for Device {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        from_nix_result(::nix::unistd::write(self.fd, bytes))
    }

    // USB HID writes don't buffer, so this will be a nop.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl U2FDevice for Device {
    fn get_cid(&self) -> [u8; 4] {
        self.cid.clone()
    }

    fn set_cid(&mut self, cid: &[u8; 4]) {
        self.cid.clone_from(cid);
    }
}
