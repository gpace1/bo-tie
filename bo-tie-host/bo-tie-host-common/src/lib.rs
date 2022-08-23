//! Host items common between the host protocols
//!
//! Things that do not fit for a single protocol are put here. `bo-tie-host-common` is a base crate
//! for the other host protocol crates within `bo-tie-host`. Generally things within this lib are
//! re-exported by the crate using them.

/// Universally Unique Identifier
///
/// A UUID in Bluetooth has some differences from the UUID of
/// [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122). They are still unique identifiers,
/// but to reduce the load of having to transfer 128-bits for commonly used identifiers, the
/// specification has mapped two ranges for shortened UUIDs. These shortened UUIDs are sized at 16
/// and 32 bit. A shortened UUID can always be converted into a larger UUID or full sized UUID.
///
/// ```
/// # use bo_tie_host_common::UUID;
///
/// let uuid_16 = UUID::from(123u16);
///
/// assert!(uuid_16.can_be_16_bit());
///
/// // The mapped region for shortened values does
/// // not begin a zero, so `123u128` cannot be a
/// // 16 bit sized UUID.
/// let uuid_128 = UUID::from(123u128);
///
/// assert!(!uuid_128.can_be_16_bit());
/// ```
///
/// ## Conversion
/// A UUID can be converted to a [uuid::Uuid](https://github.com/uuid-rs/uuid) if the feature
/// `uuid-crate` is enabled.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UUID {
    base_uuid: u128,
}

impl UUID {
    /// See Vol 3 part B sec 2.5.1 for where this value comes from.
    /// This can also be found as the Bluetooth Base UUID in the assigned numbers document.
    const BLUETOOTH_BASE_UUID: u128 = 0x0000000000001000800000805F9B34FB;

    pub const fn from_u32(v: u32) -> Self {
        UUID {
            /// See Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) | Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u16(v: u16) -> Self {
        UUID {
            /// See Vol 3 part B sec 2.5.1 for this equation
            base_uuid: ((v as u128) << 96) | Self::BLUETOOTH_BASE_UUID,
        }
    }

    pub const fn from_u128(v: u128) -> Self {
        UUID { base_uuid: v }
    }

    /// Returns true if the UUID can be a 16 bit shortened UUID
    pub fn can_be_16_bit(&self) -> bool {
        !((!0u16 as u128) << 96) & self.base_uuid == UUID::BLUETOOTH_BASE_UUID
    }

    /// Returns true if the UUID can be a 32 bit shortened UUID
    pub fn can_be_32_bit(&self) -> bool {
        !(((!0u32) as u128) << 96) & self.base_uuid == UUID::BLUETOOTH_BASE_UUID
    }

    /// Get the UUID version
    ///
    /// Returns the UUID version if the version field is valid, otherwise returns an error to
    /// indicate that the version field is
    pub fn get_version(&self) -> Result<UUIDVersion, ()> {
        UUIDVersion::try_from_uuid(self)
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

impl core::fmt::Debug for UUID {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(self, f)
    }
}

impl core::fmt::LowerHex for UUID {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.display_type(
            f,
            |v, f| core::fmt::LowerHex::fmt(v, f),
            |v, f| core::fmt::LowerHex::fmt(v, f),
            |v, f| core::fmt::LowerHex::fmt(v, f),
        )
    }
}

impl core::fmt::UpperHex for UUID {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.display_type(
            f,
            |v, f| core::fmt::UpperHex::fmt(v, f),
            |v, f| core::fmt::UpperHex::fmt(v, f),
            |v, f| core::fmt::UpperHex::fmt(v, f),
        )
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

#[cfg(feature = "uuid-crate")]
impl From<uuid::Uuid> for UUID {
    fn from(uuid: uuid::Uuid) -> UUID {
        <u128>::from_be_bytes(uuid.as_bytes().clone()).into()
    }
}

#[cfg(feature = "uuid-crate")]
impl From<UUID> for uuid::Uuid {
    fn from(uuid: UUID) -> uuid::Uuid {
        uuid::Uuid::from_bytes(uuid.base_uuid.to_be_bytes())
    }
}

/// Create a UUID from a *little endian* ordered array
impl From<[u8; 16]> for UUID {
    fn from(v: [u8; 16]) -> UUID {
        Self::from_u128(<u128>::from_le_bytes(v))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UUIDFormatError<'a> {
    IncorrectFieldLength(&'a str),
    IncorrectLength,
    IncorrectDigit(&'a str, &'a str),
}

impl<'a> core::fmt::Display for UUIDFormatError<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self {
            UUIDFormatError::IncorrectFieldLength(field) => {
                write!(f, "Field with '{}' has an incorrect number of characters", field)
            }
            UUIDFormatError::IncorrectLength => write!(f, "Incorrect Length"),
            UUIDFormatError::IncorrectDigit(digits, field) => {
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
impl<'a> TryFrom<&'a str> for UUID {
    type Error = UUIDFormatError<'a>;

    fn try_from(v: &'a str) -> Result<Self, Self::Error> {
        let mut fields = v.split("-");

        // The format is naturally big-endian
        let mut bytes_be = [0u8; 16];

        macro_rules! parse_uuid_field {
            ( $bytes:expr) => {{
                let field = fields.next().ok_or(UUIDFormatError::IncorrectLength)?;
                let mut bytes = $bytes.iter_mut();

                let mut cnt = 0;

                while let Some(hex_str) = field.get((cnt * 2)..(cnt * 2 + 2)) {
                    cnt += 1;

                    *bytes.next().ok_or(UUIDFormatError::IncorrectFieldLength(field))? =
                        <u8>::from_str_radix(hex_str, 16).or(Err(UUIDFormatError::IncorrectDigit(hex_str, field)))?;
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

        Ok(UUID {
            base_uuid: <u128>::from_be_bytes(bytes_be),
        })
    }
}

impl From<UUID> for u128 {
    fn from(uuid: UUID) -> u128 {
        uuid.base_uuid
    }
}

impl TryFrom<UUID> for u32 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (a.k.a. assigned number) from the Bluetooth SIG.
    fn try_from(uuid: UUID) -> Result<u32, ()> {
        if uuid.can_be_32_bit() {
            Ok((uuid.base_uuid >> 96) as u32)
        } else {
            Err(())
        }
    }
}

impl TryFrom<UUID> for u16 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (a.k.a. assigned number) from the Bluetooth SIG.
    fn try_from(uuid: UUID) -> Result<u16, ()> {
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
/// *
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UUIDVersion {
    Time,
    NameMDA5,
    RandomNumber,
    NameSHA1,
}

impl UUIDVersion {
    fn try_from_uuid(uuid: &UUID) -> Result<Self, ()> {
        match (uuid.base_uuid >> 76) & 0xF {
            1 => Ok(UUIDVersion::Time),
            3 => Ok(UUIDVersion::NameMDA5),
            4 => Ok(UUIDVersion::RandomNumber),
            5 => Ok(UUIDVersion::NameSHA1),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for UUIDVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            UUIDVersion::Time => write!(f, "Time-based version"),
            UUIDVersion::NameMDA5 => write!(f, "Name-based (with MD5 hash) version"),
            UUIDVersion::RandomNumber => write!(f, "Random-number-based version"),
            UUIDVersion::NameSHA1 => write!(f, "Name-based (with SHA-1 hash) version"),
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

        let uuid = UUID::from_u16(uuid_val);

        let uuid_128 = UUID::from_u128(uuid_128_val);

        let uuid_2 = UUID::from_u16(0xabcd);

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

        let uuid = UUID::from_u32(uuid_val);

        let uuid_128 = UUID::from_u128(uuid_128_val);

        let uuid_2 = UUID::from_u32(0xabcdef);

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

        let uuid = UUID::from_u128(uuid_val);

        assert_eq!(uuid, UUID::from(uuid_val));

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
