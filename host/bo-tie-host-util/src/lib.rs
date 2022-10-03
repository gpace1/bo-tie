//! Host items common between the host protocols
//!
//! Things that do not fit for a single protocol are put here. `host-util` is a base crate
//! for the other host protocol crates within `host`. Generally things within this lib are
//! re-exported by the crate using them.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

/// Universally Unique Identifier
///
/// A UUID in Bluetooth has some differences from the UUID of
/// [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122). They are still unique identifiers,
/// but to reduce the load of having to transfer 128-bits for commonly used identifiers, the
/// specification has mapped two ranges for shortened UUIDs. These shortened UUIDs are sized at 16
/// and 32 bit. A shortened UUID can always be converted into a larger UUID or full sized UUID.
///
/// ```
/// # use bo_tie_host_common::Uuid;
///
/// let uuid_16 = Uuid::from(123u16);
///
/// assert!(uuid_16.can_be_16_bit());
///
/// // The mapped region for shortened values does
/// // not begin a zero, so `123u128` cannot be a
/// // 16 bit sized UUID.
/// let uuid_128 = Uuid::from(123u128);
///
/// assert!(!uuid_128.can_be_16_bit());
/// ```
///
/// ## Conversion
/// A UUID can be converted to a [uuid::Uuid](https://github.com/uuid-rs/uuid) if the feature
/// `uuid-crate` is enabled.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uuid {
    base_uuid: u128,
}

impl Uuid {
    /// See Vol 3 part B sec 2.5.1 for where this value comes from.
    /// This can also be found as the Bluetooth Base UUID in the assigned numbers document.
    const BLUETOOTH_BASE_UUID: u128 = 0x0000000000001000800000805F9B34FB;

    pub const fn from_u32(v: u32) -> Self {
        Uuid {
            /// See Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) | Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u16(v: u16) -> Self {
        Uuid {
            /// See Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) | Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u128(v: u128) -> Self {
        Uuid { base_uuid: v }
    }

    /// Returns true if the UUID can be a 16 bit shortened UUID
    pub fn can_be_16_bit(&self) -> bool {
        !((!0u16 as u128) << 96) & self.base_uuid == Uuid::BLUETOOTH_BASE_UUID
    }

    /// Returns true if the UUID can be a 32 bit shortened UUID
    pub fn can_be_32_bit(&self) -> bool {
        !(((!0u32) as u128) << 96) & self.base_uuid == Uuid::BLUETOOTH_BASE_UUID
    }

    /// Get the UUID version
    ///
    /// Returns the UUID version if the version field is valid, otherwise returns an error to
    /// indicate that the version field is
    pub fn get_version(&self) -> Result<UuidVersion, ()> {
        UuidVersion::try_from_uuid(self)
    }

    /// Display format for UUID
    ///
    /// The display format for a UUID changes based on whether or not it is a 16 bit or 32 bit
    /// shortened UUID.
    fn display_type<F1, F2, F3>(
        &self,
        f: &mut core::fmt::Formatter,
        fn_16: F1,
        fn_32: F2,
        fn_128: F3,
    ) -> core::fmt::Result
    where
        F1: FnOnce(&u16, &mut core::fmt::Formatter) -> core::fmt::Result,
        F2: FnOnce(&u32, &mut core::fmt::Formatter) -> core::fmt::Result,
        F3: FnOnce(&u128, &mut core::fmt::Formatter) -> core::fmt::Result,
    {
        if let Ok(val) = <u16>::try_from(*self) {
            fn_16(&val, f)?;

            write!(f, " (16b)")
        } else if let Ok(val) = <u32>::try_from(*self) {
            fn_32(&val, f)?;

            write!(f, " (32b)")
        } else {
            fn_128(&self.base_uuid, f)?;

            write!(f, " (128b)")
        }
    }
}

impl core::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl core::fmt::LowerHex for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.display_type(
            f,
            |v, f| core::fmt::LowerHex::fmt(v, f),
            |v, f| core::fmt::LowerHex::fmt(v, f),
            |v, f| core::fmt::LowerHex::fmt(v, f),
        )
    }
}

impl core::fmt::UpperHex for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.display_type(
            f,
            |v, f| core::fmt::UpperHex::fmt(v, f),
            |v, f| core::fmt::UpperHex::fmt(v, f),
            |v, f| core::fmt::UpperHex::fmt(v, f),
        )
    }
}

impl From<u128> for Uuid {
    fn from(v: u128) -> Uuid {
        Self::from_u128(v)
    }
}

impl From<u32> for Uuid {
    fn from(v: u32) -> Uuid {
        Self::from_u32(v)
    }
}

impl From<u16> for Uuid {
    fn from(v: u16) -> Uuid {
        Self::from_u16(v)
    }
}

#[cfg(feature = "uuid-crate")]
impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Uuid {
        <u128>::from_be_bytes(uuid.as_bytes().clone()).into()
    }
}

#[cfg(feature = "uuid-crate")]
impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> uuid::Uuid {
        uuid::Uuid::from_bytes(uuid.base_uuid.to_be_bytes())
    }
}

/// Create a UUID from a *little endian* ordered array
impl From<[u8; 16]> for Uuid {
    fn from(v: [u8; 16]) -> Uuid {
        Self::from_u128(<u128>::from_le_bytes(v))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UuidFormatError<'a> {
    IncorrectFieldLength(&'a str),
    IncorrectLength,
    IncorrectDigit(&'a str, &'a str),
}

impl<'a> core::fmt::Display for UuidFormatError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self {
            UuidFormatError::IncorrectFieldLength(field) => {
                write!(f, "Field with '{}' has an incorrect number of characters", field)
            }
            UuidFormatError::IncorrectLength => write!(f, "Incorrect Length"),
            UuidFormatError::IncorrectDigit(digits, field) => {
                write!(f, "Digits '{}' in field '{}' are not hexadecimal", digits, field)
            }
        }
    }
}

/// Create a UUID from its formatted type
///
/// The format is a 16 octet UUID in the form of \[8\]-\[4\]-\[4\]-\[4\]-\[12\] where each number represents
/// the number of characters for the field. An example UUID would be
/// '68d82662-0305-4e6f-a679-6be1475f5e04'
impl<'a> TryFrom<&'a str> for Uuid {
    type Error = UuidFormatError<'a>;

    fn try_from(v: &'a str) -> Result<Self, Self::Error> {
        let mut fields = v.split("-");

        // The format is naturally big-endian
        let mut bytes_be = [0u8; 16];

        macro_rules! parse_uuid_field {
            ( $bytes:expr) => {{
                let field = fields.next().ok_or(UuidFormatError::IncorrectLength)?;
                let mut bytes = $bytes.iter_mut();

                let mut cnt = 0;

                while let Some(hex_str) = field.get((cnt * 2)..(cnt * 2 + 2)) {
                    cnt += 1;

                    *bytes.next().ok_or(UuidFormatError::IncorrectFieldLength(field))? =
                        <u8>::from_str_radix(hex_str, 16).or(Err(UuidFormatError::IncorrectDigit(hex_str, field)))?;
                }

                Ok(())
            }};
        }

        // Breaking the bytes into their respective fields
        parse_uuid_field!(bytes_be[0..4])?;
        parse_uuid_field!(bytes_be[4..6])?;
        parse_uuid_field!(bytes_be[6..8])?;
        parse_uuid_field!(bytes_be[8..10])?;
        parse_uuid_field!(bytes_be[10..])?;

        Ok(Uuid {
            base_uuid: <u128>::from_be_bytes(bytes_be),
        })
    }
}

impl From<Uuid> for u128 {
    fn from(uuid: Uuid) -> u128 {
        uuid.base_uuid
    }
}

impl TryFrom<Uuid> for u32 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (a.k.a. assigned number) from the Bluetooth SIG.
    fn try_from(uuid: Uuid) -> Result<u32, ()> {
        if uuid.can_be_32_bit() {
            Ok((uuid.base_uuid >> 96) as u32)
        } else {
            Err(())
        }
    }
}

impl TryFrom<Uuid> for u16 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (a.k.a. assigned number) from the Bluetooth SIG.
    fn try_from(uuid: Uuid) -> Result<u16, ()> {
        if uuid.can_be_16_bit() {
            Ok((uuid.base_uuid >> 96) as u16)
        } else {
            Err(())
        }
    }
}

/// Universally Unique Identifier Version
///
/// There are 4 UUID versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UuidVersion {
    Time,
    NameMDA5,
    RandomNumber,
    NameSHA1,
}

impl UuidVersion {
    fn try_from_uuid(uuid: &Uuid) -> Result<Self, ()> {
        match (uuid.base_uuid >> 76) & 0xF {
            1 => Ok(UuidVersion::Time),
            3 => Ok(UuidVersion::NameMDA5),
            4 => Ok(UuidVersion::RandomNumber),
            5 => Ok(UuidVersion::NameSHA1),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for UuidVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            UuidVersion::Time => write!(f, "Time-based version"),
            UuidVersion::NameMDA5 => write!(f, "Name-based (with MD5 hash) version"),
            UuidVersion::RandomNumber => write!(f, "Random-number-based version"),
            UuidVersion::NameSHA1 => write!(f, "Name-based (with SHA-1 hash) version"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_16_test() {
        // 16 bit shortened form
        let uuid_val = 0x1234;

        // expected full 128 bit form of uuid_val
        let uuid_128_val: u128 = 0x0000123400001000800000805F9B34FB;

        let uuid = Uuid::from_u16(uuid_val);

        let uuid_128 = Uuid::from_u128(uuid_128_val);

        let uuid_2 = Uuid::from_u16(0xabcd);

        assert!(uuid.can_be_16_bit());

        assert!(uuid.can_be_32_bit());

        assert_eq!(Ok(uuid_val), <u16>::try_from(uuid));

        assert_eq!(Ok(uuid_val as u32), <u32>::try_from(uuid));

        assert_eq!(uuid_128_val, uuid.base_uuid);

        assert_eq!(uuid_128_val, uuid.into());

        assert_eq!("1234 (16b)", format!("{:x}", uuid));

        assert_eq!("0x1234 (16b)", format!("{:#x}", uuid));

        assert_eq!(uuid, uuid_128);

        assert_eq!("ABCD (16b)", format!("{:X}", uuid_2));

        assert_eq!("0xABCD (16b)", format!("{:#X}", uuid_2));
    }

    #[test]
    fn uuid_32_test() {
        // 32 bit shortened form
        let uuid_val = 0x12345678;

        // expected full 128 bit form of uuid_val
        let uuid_128_val: u128 = 0x1234567800001000800000805F9B34FB;

        let uuid = Uuid::from_u32(uuid_val);

        let uuid_128 = Uuid::from_u128(uuid_128_val);

        let uuid_2 = Uuid::from_u32(0xabcdef);

        assert!(!uuid.can_be_16_bit());

        assert!(uuid.can_be_32_bit());

        assert_eq!(Err(()), <u16>::try_from(uuid));

        assert_eq!(Ok(uuid_val), <u32>::try_from(uuid));

        assert_eq!(uuid_128_val, uuid.base_uuid);

        assert_eq!(uuid_128_val, uuid.into());

        assert_eq!(uuid, uuid_128);

        assert_eq!("12345678 (32b)", format!("{:x}", uuid));

        assert_eq!("0x12345678 (32b)", format!("{:#x}", uuid));

        assert_eq!("ABCDEF (32b)", format!("{:X}", uuid_2));

        assert_eq!("0xABCDEF (32b)", format!("{:#X}", uuid_2));
    }

    #[test]
    fn uuid_128_test() {
        let uuid_val = 0x1234567890abcdef;

        let uuid = Uuid::from_u128(uuid_val);

        assert_eq!(uuid, Uuid::from(uuid_val));

        assert!(!uuid.can_be_16_bit());

        assert!(!uuid.can_be_32_bit());

        assert_eq!(Err(()), <u16>::try_from(uuid));

        assert_eq!(Err(()), <u32>::try_from(uuid));

        assert_eq!(uuid_val, uuid.base_uuid);

        assert_eq!("1234567890abcdef (128b)", format!("{:x}", uuid));

        assert_eq!("0x1234567890abcdef (128b)", format!("{:#x}", uuid));

        assert_eq!("1234567890ABCDEF (128b)", format!("{:X}", uuid));

        assert_eq!("0x1234567890ABCDEF (128b)", format!("{:#X}", uuid));
    }
}
