//! Common items for the host controller interface
//!
//! This crate carries the parts of the HCI that are used by multiple HCI crates.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod events;
pub mod le;
pub mod opcodes;

use core::fmt;

/// The connection handle
///
/// This is used as an identifier of a connection by both the host and interface. Its created by the
/// controller when a connection is established between this device and another device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ConnectionHandle {
    handle: u16,
}

impl fmt::Display for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl fmt::Binary for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:b}", self.handle)
    }
}

impl fmt::LowerHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.handle)
    }
}

impl fmt::Octal for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:o}", self.handle)
    }
}

impl fmt::UpperHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self.handle)
    }
}

impl AsRef<u16> for ConnectionHandle {
    fn as_ref(&self) -> &u16 {
        &self.handle
    }
}

impl ConnectionHandle {
    pub const MAX: u16 = 0x0EFF;

    const ERROR: &'static str = "Raw connection handle value larger then the maximum (0x0EFF)";

    pub fn get_raw_handle(&self) -> u16 {
        self.handle
    }
}

impl TryFrom<u16> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        if raw <= ConnectionHandle::MAX {
            Ok(ConnectionHandle { handle: raw })
        } else {
            Err(Self::ERROR)
        }
    }
}

impl TryFrom<[u8; 2]> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: [u8; 2]) -> Result<Self, Self::Error> {
        let raw_val = <u16>::from_le_bytes(raw);

        core::convert::TryFrom::<u16>::try_from(raw_val)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Off,
    E0,
    AESCCM,
}

/// A matcher of events in response to a command
///
/// This is used for matching a HCI packet from the controller to the events [Command Complete] or
/// [Command Status]. Either one will match so long as the opcode within the event matches the
/// opcode within the `CommandEventMatcher`.
///
/// [Command Complete]: events::parameters::CommandCompleteData
/// [Command Status]: events::parameters::CommandStatusData
#[derive(Clone, Copy)]
pub struct CommandEventMatcher {
    op_code: opcodes::HCICommand,
    event: events::Events,
    get_op_code: for<'a> fn(&'a [u8]) -> Option<u16>,
}

impl CommandEventMatcher {
    /// Create a new `CommandEventMatcher` for the event `CommandComplete`
    fn new_command_complete(op_code: opcodes::HCICommand) -> Self {
        fn get_op_code(raw: &[u8]) -> Option<u16> {
            // bytes 3 and 4 are the opcode within an HCI event
            // packet containing a Command Complete event.

            let b1 = raw.get(3)?;
            let b2 = raw.get(4)?;

            Some(<u16>::from_le_bytes([*b1, *b2]))
        }

        Self {
            op_code,
            event: events::Events::CommandComplete,
            get_op_code,
        }
    }

    /// Create a new `CommandEventMatcher` for the event `CommandStatus`
    fn new_command_status(op_code: opcodes::HCICommand) -> Self {
        fn get_op_code(raw: &[u8]) -> Option<u16> {
            // bytes 4 and 5 are the opcode within an HCI event
            // packet containing a Command Status event.

            let b1 = raw.get(4)?;
            let b2 = raw.get(5)?;

            Some(<u16>::from_le_bytes([*b1, *b2]))
        }

        Self {
            op_code,
            event: events::Events::CommandStatus,
            get_op_code,
        }
    }
}
