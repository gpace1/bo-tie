//! A Bluetooth Library
//!
//! The primary purpose of bo-tie is to provide a middling layer between the architecture specific
//! and user friendly libraries for Bluetooth. bo-tie is also intended to be used in environments
//! where only [`core`](https://doc.rust-lang.org/core/) and
//! [`alloc`](https://doc.rust-lang.org/alloc/) are available.
//!
//! The primary way of interfacing to the controller is through the [`hci`] (Host Controller
//! Interface). All commands, events, *and* data (ACL, SCO/eSCO) go through this interface.

#![cfg_attr(test, feature(test))]
#![cfg_attr(not(test),no_std)]

// These crates are used all the time
extern crate alloc;
extern crate bincode as serializer;

// test related
#[cfg(test)]
extern crate test;

pub mod att;
pub mod gap;
pub mod gatt;
pub mod hci;
pub mod l2cap;
pub mod sm;
pub mod hci_transport;

pub type BluetoothDeviceAddress = [u8; 6];

pub fn bluetooth_address_from_string( addr: &str ) -> Result<BluetoothDeviceAddress, &'static str> {
    let mut address = BluetoothDeviceAddress::default();

    if let None = {
        let mut addr_itr = address.iter_mut();

        for val in addr.split(':').rev() {
            if let Some(byte) = addr_itr.next() {
                *byte = u8::from_str_radix(&val, 16).or(Err("Address contains invalid characters"))?;
            } else {
                return Err("Address contain too few bytes, all six are required");
            }
        }

        addr_itr.next()
    } {
        Ok(address)
    } else {
        Err("Address contains too many bytes, there are only six bytes in a bluetooth address")
    }
}

pub fn bluetooth_address_into_string( addr: BluetoothDeviceAddress ) -> alloc::string::String {
    alloc::format!("{}:{}:{}:{}:{}:{}", addr[5], addr[4], addr[3], addr[2], addr[1], addr[0])
}

/// Universally Unique Identifier
///
/// A UUID in bluetooth is used to identify a Service and is part of many different protocols
/// with bluetooth.
///
/// This structure always handles UUIDs in their 128 bit value form.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Hash,Default)]
pub struct UUID {
    base_uuid: u128,
}

impl UUID {
    /// See V 5.0 Vol 3 part B sec 2.5.1 for where this value comes from.
    /// This can also be found as the Bluetooth Base UUID in the assigned numbers document.
    const BLUETOOTH_BASE_UUID: u128 = 0x0000000000001000800000805F9B34FB;

    pub const fn from_u32(v: u32) -> Self {
        UUID {
            /// See V 5.0 Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) + Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u16(v: u16) -> Self {
        UUID {
            /// See V 5.0 Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) + Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u128(v: u128) -> Self {
        UUID {
            base_uuid: v,
        }
    }

    /// Get the UUID version
    ///
    /// Returns the UUID version if the version field is valid, otherwise returns an error to
    /// indicate that the version field is
    pub fn get_version(&self) -> Result<UUIDVersion, ()> {
        UUIDVersion::try_from_uuid(self)
    }
}

impl core::fmt::LowerHex for UUID {
    fn fmt(&self, f: &mut core::fmt::Formatter ) -> core::fmt::Result {
        match core::convert::TryInto::<u16>::try_into(*self) {
            Ok(val) => {
                core::fmt::LowerHex::fmt(&val, f)?;
                write!(f, " (16b)")
            },
            Err(_) => {
                core::fmt::LowerHex::fmt(&self.base_uuid, f)?;
                write!(f, " (128b)")
            },
        }
    }
}

impl core::fmt::UpperHex for UUID {
    fn fmt(&self, f: &mut core::fmt::Formatter ) -> core::fmt::Result {
        match core::convert::TryInto::<u16>::try_into(*self) {
            Ok(val) => {
                core::fmt::UpperHex::fmt(&val, f)
            },
            Err(_) => {
                core::fmt::UpperHex::fmt(&self.base_uuid, f)
            },
        }
    }
}

impl From<u128> for UUID {
    fn from(v: u128) -> UUID {
        Self::from_u128(v)
    }
}

impl From<u32> for UUID {
    fn from(v: u32) -> UUID {
        Self::from_u32(v)
    }
}

impl From<u16> for UUID {
    fn from(v: u16) -> UUID {
        Self::from_u16(v)
    }
}

impl From<uuid::Uuid> for UUID {
    /// Convert from the
    /// [uuid](https://crates.io/crates/uuid) crate implementation of UUID.
    fn from(uuid: uuid::Uuid) -> UUID {
        <u128>::from_be_bytes(uuid.as_bytes().clone()).into()
    }
}

impl From<UUID> for uuid::Uuid {
    /// Convert a UUID into the UUID from the crate
    /// [uuid](https://crates.io/crates/uuid)
    fn from(uuid: UUID) -> uuid::Uuid {
        uuid::Uuid::from_bytes(uuid.base_uuid.to_be_bytes())
    }
}

/// Create a UUID from a *little endian* ordered array
impl From<[u8;16]> for UUID {
    fn from(v: [u8;16]) -> UUID {
        Self::from_u128( <u128>::from_le_bytes(v) )
    }
}

#[derive(Clone,Copy,Debug)]
pub enum UUIDFormatError<'a> {
    IncorrectFieldLength(&'a str),
    IncorrectLength,
    IncorrectDigit(&'a str, &'a str),
}

impl<'a> core::fmt::Display for UUIDFormatError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self {
            UUIDFormatError::IncorrectFieldLength(field) =>
                write!(f, "Field with '{}' has an incorrect number of characters", field),
            UUIDFormatError::IncorrectLength =>
                write!(f, "Incorrect Length"),
            UUIDFormatError::IncorrectDigit(digits, field) =>
                write!(f, "Ditigts '{}' in field '{}' are not hexidecimal", digits, field),
        }
    }
}

/// Create a UUID from its formatted type
///
/// The format is a 16 octet UUID in the form of \[8\]-\[4\]-\[4\]-\[4\]-\[12\] where each number represents
/// the number of characters for the field. An example UUID would be
/// '68d82662-0305-4e6f-a679-6be1475f5e04'
impl<'a> core::convert::TryFrom<&'a str> for UUID {
    type Error = UUIDFormatError<'a>;

    fn try_from(v: &'a str) -> Result<Self, Self::Error> {

        let mut fields = v.split("-");

        // The format is naturally big-endian
        let mut bytes_be = [0u8; 16];

        macro_rules! parse_uuid_field {
            ( $bytes:expr) => {{
                let field = fields.next().ok_or( UUIDFormatError::IncorrectLength )?;
                let mut bytes = $bytes.iter_mut();

                let mut cnt = 0;

                while let Some(hex_str) = field.get( (cnt * 2)..(cnt * 2 + 2) ) {
                    cnt += 1;

                    *bytes.next().ok_or( UUIDFormatError::IncorrectFieldLength(field) )? =
                        <u8>::from_str_radix(hex_str, 16)
                            .or( Err(UUIDFormatError::IncorrectDigit(hex_str, field)) )?;
                }

                Ok(())
            }}
        }

        // Breaking the bytes into their respective fields
        parse_uuid_field!( bytes_be[0..4]  )?;
        parse_uuid_field!( bytes_be[4..6]  )?;
        parse_uuid_field!( bytes_be[6..8]  )?;
        parse_uuid_field!( bytes_be[8..10] )?;
        parse_uuid_field!( bytes_be[10..]  )?;

        Ok( UUID {
            base_uuid: <u128>::from_be_bytes(bytes_be)
        })
    }
}

impl From<UUID> for u128 {
    fn from(uuid: UUID) -> u128 {
        uuid.base_uuid
    }
}

impl core::convert::TryFrom<UUID> for u32 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (assigned number).
    fn try_from(uuid: UUID) -> Result<u32, ()> {
        match !(((!0u32) as u128) << 96) & uuid.base_uuid {
            UUID::BLUETOOTH_BASE_UUID => Ok((uuid.base_uuid >> 96) as u32),
            _ => Err(())
        }
    }
}

impl core::convert::TryFrom<UUID> for u16 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (assigned number).
    fn try_from(uuid: UUID) -> Result<u16, ()> {
        match !(((!0u16) as u128) << 96) & uuid.base_uuid {
            UUID::BLUETOOTH_BASE_UUID => Ok((uuid.base_uuid >> 96) as u16),
            _ => Err(())
        }
    }
}

/// Universially Unique Identifier Version
///
/// There are 4 UUID versions.
/// *
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum UUIDVersion {
    Time,
    NameMDA5,
    RandomNumber,
    NameSHA1,
}

impl UUIDVersion {
    fn try_from_uuid(uuid: &UUID) -> Result<Self, ()> {
        match ( uuid.base_uuid >> 76 ) & 0xF {
            1 => Ok( UUIDVersion::Time ),
            3 => Ok( UUIDVersion::NameMDA5 ),
            4 => Ok( UUIDVersion::RandomNumber ),
            5 => Ok( UUIDVersion::NameSHA1 ),
            _ => Err( () )
        }
    }
}

impl core::fmt::Display for UUIDVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            UUIDVersion::Time =>
                write!(f, "Time-based version"),
            UUIDVersion::NameMDA5 =>
                write!(f, "Name-based (with MD5 hash) version"),
            UUIDVersion::RandomNumber =>
                write!(f, "Random-number-based version"),
            UUIDVersion::NameSHA1 =>
                write!(f, "Name-based (with SHA-1 hash) version"),
        }
    }
}
