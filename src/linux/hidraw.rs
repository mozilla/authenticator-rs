use std::io;
use std::os::unix::io::RawFd;

use ::consts::{FIDO_USAGE_PAGE, FIDO_USAGE_U2FHID};
use ::platform::util::from_nix_result;

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct ReportDescriptor {
    size: ::libc::c_int,
    value: [u8; 4096]
}

impl ReportDescriptor {
    fn iter(self) -> ReportDescriptorIterator {
        ReportDescriptorIterator::new(self)
    }
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h
ioctl!(read hidiocgrdescsize with b'H', 0x01; ::libc::c_int);
ioctl!(read hidiocgrdesc with b'H', 0x02; /*struct*/ ReportDescriptor);

enum Data {
    UsagePage { data: u32 },
    Usage { data: u32 }
}

struct ReportDescriptorIterator {
    desc: ReportDescriptor,
    pos: usize
}

impl ReportDescriptorIterator {
    fn new(desc: ReportDescriptor) -> Self {
        Self { desc, pos: 0 }
    }
}

impl Iterator for ReportDescriptorIterator {
    type Item = Data;

    fn next(&mut self) -> Option<Self::Item> {
        let value_len = self.desc.value.len();
        if self.pos >= value_len {
            return None;
        }

        let key = self.desc.value[self.pos];
        if key & 0xf0 == 0xf0 {
            self.pos = value_len;
            return None; // Invalid data.
        }

        // Determine length.
        let data_len = match key & 0x3 {
            s @ 0 ... 2 => s as usize,
            _ => 4 /* key & 0x3 == 3 */
        };

        if self.pos + data_len >= value_len {
            self.pos = value_len;
            return None; // Invalid data.
        }

        let range = self.pos+1..self.pos+1+data_len;
        let data = read_uint_le(&self.desc.value[range]);
        self.pos += 1 + data_len;

        match key & 0xfc {
            0x4 => Some(Data::UsagePage { data }),
            0x8 => Some(Data::Usage { data }),
            _ => self.next()
        }
    }
}

fn read_uint_le(buf: &[u8]) -> u32 {
    assert!(buf.len() <= 4);
    // Parse the number in little endian byte order.
    buf.iter().rev().fold(0, |num, b| (num << 8) | (*b as u32))
}

pub fn is_u2f_device(fd: RawFd) -> bool {
    match read_report_descriptor(fd) {
        Ok(desc) => has_fido_usage(desc),
        Err(_) => false // Upon failure, just say it's not a U2F device.
    }
}

fn read_report_descriptor(fd: RawFd) -> io::Result<ReportDescriptor> {
    let mut desc = ReportDescriptor { size: 0, value: [0; 4096] };
    from_nix_result(unsafe { hidiocgrdescsize(fd, &mut desc.size) })?;
    from_nix_result(unsafe { hidiocgrdesc(fd, &mut desc) })?;
    Ok(desc)
}

fn has_fido_usage(desc: ReportDescriptor) -> bool {
    let mut usage_page = None;
    let mut usage = None;

    for data in desc.iter() {
        match data {
            Data::UsagePage { data } => usage_page = Some(data),
            Data::Usage { data } => usage = Some(data)
        }

        // Check the values we found.
        if let (Some(usage_page), Some(usage)) = (usage_page, usage) {
            return usage_page == FIDO_USAGE_PAGE as u32 &&
                   usage == FIDO_USAGE_U2FHID as u32;
        }
    }

    false
}
