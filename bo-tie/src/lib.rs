//! A Bluetooth Library
//!
//! The primary purpose of bo-tie is to provide a middling layer between the architecture specific
//! and user friendly libraries for Bluetooth. bo-tie is also intended to be used in environments
//! where only [`core`](https://doc.rust-lang.org/core/) and
//! [`alloc`](https://doc.rust-lang.org/alloc/) are available.
//!
//! The primary way of interfacing to the controller is through the [`hci`] (Host Controller
//! Interface). All commands, events, *and* data (ACL, SCO/eSCO) go through this interface.

#![feature(generic_associated_types)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(test, feature(test))]
#![cfg_attr(not(test), no_std)]

// These crates are used all the time
extern crate alloc;

// tests related
#[cfg(test)]
extern crate test;

pub mod att;
pub mod gap;
pub mod gatt;
pub mod hci;
pub mod l2cap;
pub mod sm;

pub type BluetoothDeviceAddress = [u8; 6];

pub fn bluetooth_address_from_string(addr: &str) -> Result<BluetoothDeviceAddress, &'static str> {
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

pub fn bluetooth_address_into_string(addr: &BluetoothDeviceAddress) -> alloc::string::String {
    alloc::format!(
        "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
        addr[5],
        addr[4],
        addr[3],
        addr[2],
        addr[1],
        addr[0]
    )
}

/// Create a static random address
pub fn new_static_random_bluetooth_address() -> BluetoothDeviceAddress {
    use rand_core::RngCore;

    let mut a = BluetoothDeviceAddress::default();

    rand_core::OsRng.fill_bytes(&mut a);

    // tag for static random in address is 11 in the most significant 2 bits
    a[5] |= 0b1100_0000;

    a
}

/// Create a non-resolvable private address
pub fn new_non_resolvable_private_address() -> BluetoothDeviceAddress {
    use rand_core::RngCore;

    let mut a = BluetoothDeviceAddress::default();

    loop {
        rand_core::OsRng.fill_bytes(&mut a);

        // Practically unnecessary, necessary check to validate the address not being all 0 or 1.
        // For a good rng there is only a 2 in 2^48 chance of this happening
        if ([0u8; 6] != a) && ([0xFF; 6] != a) {
            break;
        }
    }

    // tag for static random in address is 00 in most significant 2 bits
    a[5] &= 0b0011_1111;

    a
}

/// Create a resolvable private address
///
/// This requires an identity resolving key (`irk`) to generate the address from. Most controllers
/// will be able to handle both the generation and resolving of a resolvable private address (RPA).
/// However it can be setup for both the generation and resolving to be done in the host.
///
/// For more information on generating an IRK see the [security manager](crate::sm).
pub fn new_resolvable_private_address(irk: u128) -> BluetoothDeviceAddress {
    use rand_core::RngCore;

    let mut address = BluetoothDeviceAddress::default();

    let (hash, prand) = address.split_at_mut(3);

    loop {
        rand_core::OsRng.fill_bytes(prand);

        // Practically unnecessary, necessary check to validate the address not being all 0 or 1.
        // For a good rng there is only a 2 in 2^24 chance of this happening
        if (&[0u8; 3] != prand) && (&[0xFF, 3] != prand) {
            break;
        }
    }

    // tag for static random in address is 01 in the most significant 2 bits
    prand[2] = prand[2] & 0b0011_1111 | 0b0100_0000;

    hash.copy_from_slice(&sm::toolbox::ah(irk, [prand[0], prand[1], prand[2]]));

    address
}

/// Resolve a resolvable private address with `irk`
///
/// This function returns true if `address` is resolved with the provided `irk`
pub fn resolve_resolvable_private_address(irk: u128, address: BluetoothDeviceAddress) -> bool {
    let (peer_hash, prand) = address.split_at(3);

    let hash = sm::toolbox::ah(irk, [prand[0], prand[1], prand[2]]);

    // Check if the prand has the correct signature for a RPA (most significant 2 bits are 01) and
    // the hash matches
    (prand[2] & 0b1100_0000 == 0b0100_0000) && (peer_hash == hash)
}

/// Universally Unique Identifier
///
/// A UUID in bluetooth is used to identify a Service and is part of many different protocols
/// with bluetooth.
///
/// This structure always handles UUIDs in their 128 bit value form.
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
    pub fn is_16_bit(&self) -> bool {
        (!(((!0u16) as u128) << 96) & self.base_uuid) == UUID::BLUETOOTH_BASE_UUID
    }

    /// Returns true if the UUID can be a 32 bit shortened UUID
    pub fn is_32_bit(&self) -> bool {
        (!(((!0u32) as u128) << 96) & self.base_uuid) == UUID::BLUETOOTH_BASE_UUID
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
    /// Convert from the
    /// [uuid](https://crates.io/crates/uuid) crate implementation of UUID.
    fn from(uuid: uuid::Uuid) -> UUID {
        <u128>::from_be_bytes(uuid.as_bytes().clone()).into()
    }
}

#[cfg(feature = "uuid-crate")]
impl From<UUID> for uuid::Uuid {
    /// Convert a UUID into the UUID from the crate
    /// [uuid](https://crates.io/crates/uuid)
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
impl<'a> core::convert::TryFrom<&'a str> for UUID {
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

impl core::convert::TryFrom<UUID> for u32 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (assigned number).
    fn try_from(uuid: UUID) -> Result<u32, ()> {
        if uuid.is_32_bit() {
            Ok((uuid.base_uuid >> 96) as u32)
        } else {
            Err(())
        }
    }
}

impl core::convert::TryFrom<UUID> for u16 {
    type Error = ();

    /// Try to convert a UUID into its 32 bit shortened form. This doesn't check that the value is
    /// pre-allocated (assigned number).
    fn try_from(uuid: UUID) -> Result<u16, ()> {
        if uuid.is_16_bit() {
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

/// Try to extend a collection with an iterator
///
/// This is the try equivalent to [`Extend`](std::iter::Extend)
///
/// # Note
/// `TryExtend` is auto-implemented for anything that already implements
/// [`Extend`](core::iter::Extend)
pub trait TryExtend<A> {
    type Error;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>;

    fn try_extend_one(&mut self, item: A) -> Result<(), Self::Error> {
        self.try_extend(core::iter::once(item))
    }
}

impl<T> TryExtend<u8> for T
where
    T: Extend<u8>,
{
    type Error = core::convert::Infallible;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.extend(iter);

        Ok(())
    }
}

/// Try to remove items
///
/// This trait is used to remove items from the end of the collection and return them.
trait TryRemove<A> {
    type Error;
    type RemoveIter<'a>: Iterator<Item = A>
    where
        Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error>;

    fn try_pop(&mut self) -> Option<A> {
        self.try_remove(1).ok().and_then(|mut i| i.next())
    }
}

/// Try to extend the front of a collection with an iterator
trait TryFrontExtend<A> {
    type Error;

    /// Try to extend the collection by the iterator `iter`
    ///
    /// This will extend the front of the iterator by the contents produced by `iter`. The front of
    /// the collection is extended *in order* in which they are pushed to the front. This means that
    /// for something like a `Vec` this results in the items within `iter` being placed in reverse
    /// order at the front.
    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>;

    /// Reverses `iter` before extending the front of the collection
    ///
    /// This reverses the iterator `iter` before front extending the collection. The main purpose of
    /// this is to put items onto the front in the order in which they appear. In something like a
    /// `Vec` when calling `try_rev_front_extend` the first item in `iter` would become the first
    /// item in the vector.
    fn try_rev_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>,
        T::IntoIter: DoubleEndedIterator,
    {
        let iter = iter.into_iter();

        self.try_front_extend(iter.rev())
    }

    fn try_front_extend_one(&mut self, item: A) -> Result<(), Self::Error> {
        self.try_front_extend(core::iter::once(item))
    }
}

/// Try to remove items from the front of a collection
///
/// This is used for trying to removing items at the front of a collection. In order for a
/// collection to implement this trait it must have a capacity at the front. Removing items from the
/// front must also increase this capacity.
trait TryFrontRemove<A> {
    type Error;
    type FrontRemoveIter<'a>: Iterator<Item = A>
    where
        Self: 'a;

    /// Try to take a number of items from the front of the collection
    ///
    /// The return is an iterator over the items
    /// # Error
    /// `how_many` must not be larger than the length of the implementation.
    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error>;

    /// Try to pop the front item
    ///
    /// The first item is returned so long as the item is not empty.
    fn try_front_pop(&mut self) -> Option<A> {
        self.try_front_remove(1).ok()?.next()
    }
}

impl<A> TryRemove<A> for &'_ [A]
where
    A: Copy,
{
    type Error = BufferError;
    type RemoveIter<'a> = core::iter::Copied<core::slice::Iter<'a, A>> where Self: 'a, A: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let (new_this, to_iter) = self.split_at(self.len() - how_many);

            *self = new_this;

            Ok(to_iter.iter().copied())
        } else {
            Err(BufferError::LengthOfBuffer)
        }
    }
}

impl<A> TryFrontRemove<A> for &'_ [A]
where
    A: Copy,
{
    type Error = BufferError;
    type FrontRemoveIter<'a> = core::iter::Copied<core::slice::Iter<'a, A>> where Self: 'a, A: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let (to_iter, new_this) = self.split_at(how_many);

            *self = new_this;

            Ok(to_iter.iter().copied())
        } else {
            Err(BufferError::LengthOfBuffer)
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum BufferError {
    LengthOfBuffer,
    FrontReserveSize,
}

impl core::fmt::Display for BufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BufferError::LengthOfBuffer => f.write_str("buffer is too small"),
            BufferError::FrontReserveSize => f.write_str("front reserve is too small"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn rpa_test() {
        use rand_core::RngCore;

        let mut rand = [0u8; 16];

        rand_core::OsRng.fill_bytes(&mut rand);

        let irk = <u128>::from_le_bytes(rand);

        let rpa = super::new_resolvable_private_address(irk);

        assert!(super::resolve_resolvable_private_address(irk, rpa));
    }

    #[test]
    fn uuid_16_test() {
        // 16 bit shortened form
        let uuid_val = 0x1234;

        // expected full 128 bit form of uuid_val
        let uuid_128_val: u128 = 0x0000123400001000800000805F9B34FB;

        let uuid = UUID::from_u16(uuid_val);

        let uuid_128 = UUID::from_u128(uuid_128_val);

        let uuid_2 = UUID::from_u16(0xabcd);

        assert!(uuid.is_16_bit());

        assert!(uuid.is_32_bit());

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

        assert!(!uuid.is_16_bit());

        assert!(uuid.is_32_bit());

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

        assert!(!uuid.is_16_bit());

        assert!(!uuid.is_32_bit());

        assert_eq!(Err(()), <u16>::try_from(uuid));

        assert_eq!(Err(()), <u32>::try_from(uuid));

        assert_eq!(uuid_val, uuid.base_uuid);

        assert_eq!("1234567890abcdef (128b)", format!("{:x}", uuid));

        assert_eq!("0x1234567890abcdef (128b)", format!("{:#x}", uuid));

        assert_eq!("1234567890ABCDEF (128b)", format!("{:X}", uuid));

        assert_eq!("0x1234567890ABCDEF (128b)", format!("{:#X}", uuid));
    }
}
