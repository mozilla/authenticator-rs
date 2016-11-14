// Allow dead code in this module, since it's all packet consts anyways.
#![allow(dead_code)]

pub const HID_RPT_SIZE : usize = 64;
pub const U2FAPDUHEADER_SIZE : usize = 7;
pub const CID_BROADCAST : [u8; 4] = [0xff, 0xff, 0xff, 0xff];
pub const TYPE_MASK : u8 = 0x80;
pub const TYPE_INIT : u8 = 0x80;
pub const TYPE_CONT : u8 = 0x80;

pub const FIDO_USAGE_PAGE     : u16 =    0xf1d0;	// FIDO alliance HID usage page
pub const FIDO_USAGE_U2FHID   : u16  =   0x01;	// U2FHID usage for top-level collection
pub const FIDO_USAGE_DATA_IN  : u8  =   0x20;	// Raw IN data report
pub const FIDO_USAGE_DATA_OUT : u8  =   0x21;	// Raw OUT data report

// General pub constants

pub const U2FHID_IF_VERSION    : u32 =  2;	// Current interface implementation version
pub const U2FHID_FRAME_TIMEOUT : u32 =  500;	// Default frame timeout in ms
pub const U2FHID_TRANS_TIMEOUT : u32 =  3000;	// Default message timeout in ms

// U2FHID native commands

pub const U2FHID_PING         : u8 = (TYPE_INIT | 0x01);	// Echo data through local processor only
pub const U2FHID_MSG          : u8 = (TYPE_INIT | 0x03);	// Send U2F message frame
pub const U2FHID_LOCK         : u8 = (TYPE_INIT | 0x04);	// Send lock channel command
pub const U2FHID_INIT         : u8 = (TYPE_INIT | 0x06);	// Channel initialization
pub const U2FHID_WINK         : u8 = (TYPE_INIT | 0x08);	// Send device identification wink
pub const U2FHID_ERROR        : u8 = (TYPE_INIT | 0x3f);	// Error response
pub const U2FHID_VENDOR_FIRST : u8 = (TYPE_INIT | 0x40);	// First vendor defined command
pub const U2FHID_VENDOR_LAST  : u8 = (TYPE_INIT | 0x7f);	// Last vendor defined command

// U2FHID_INIT command defines

pub const INIT_NONCE_SIZE     : usize =    8;	// Size of channel initialization challenge
pub const CAPFLAG_WINK        : u8 =    0x01;	// Device supports WINK command
pub const CAPFLAG_LOCK        : u8 =    0x02;	// Device supports LOCK command

// Low-level error codes. Return as negatives.

pub const ERR_NONE            : u8 =    0x00;	// No error
pub const ERR_INVALID_CMD     : u8 =    0x01;	// Invalid command
pub const ERR_INVALID_PAR     : u8 =    0x02;	// Invalid parameter
pub const ERR_INVALID_LEN     : u8 =    0x03;	// Invalid message length
pub const ERR_INVALID_SEQ     : u8 =    0x04;	// Invalid message sequencing
pub const ERR_MSG_TIMEOUT     : u8 =    0x05;	// Message has timed out
pub const ERR_CHANNEL_BUSY    : u8 =    0x06;	// Channel busy
pub const ERR_LOCK_REQUIRED   : u8 =    0x0a;	// Command requires channel lock
pub const ERR_INVALID_CID     : u8 =    0x0b;	// Command not allowed on this cid
pub const ERR_OTHER           : u8 =    0x7f;	// Other unspecified error
