//! Utilities for `bo-tie`
//!
//! These are things that are used throughout the other crates within the `bo-tie` workspace and are
//! collected here as a common place to put them.

#![feature(generic_associated_types)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod buffer;
#[cfg(feature = "cryptography")]
pub mod cryptography;
pub mod errors;

use core::fmt::{Display, Formatter, LowerHex, UpperHex};
use core::ops::{Deref, DerefMut};

/// A Bluetooth device address
///
/// This is a wrapper around a six byte array. The address shall always be represented in little
/// endian format within a `BluetoothDeviceAddress`.
///
/// # Address Types
/// A Bluetooth device address can either be a public address, a static device address, a
/// resolvable private address, or a non-resolvable private address. Bluetooth BR/EDR operation only
/// uses public addresses, but Bluetooth LE uses all four types of address.
///
/// A public address is the address is hardwired into the device. It must be retrieved from the
/// controller in order to be used by the host protocols. When using the host controller interface
/// implementation it can be acquired from the *Information Parameters* command *Read BR_ADDR*.
///
/// A static device address is generated by the host and set to a *LE* controller. It can be
/// any address so long as the random part (the least significant 46 bits) are not all either zero
/// or one. A static device address can act as an identity address (see the Security Manager
/// Protocol) but it must be saved by the host and resent upon controller reset.
///
/// A resolvable private address is *usually* a controller generated address for use in Bluetooth
/// *LE* privacy. Its main usage is for identifying a device through "resolving" an address using an
/// identity resolving key (resolving is essentially inputting the address and the identity
/// resolving key into a cypher function and seeing if the output is zero). The most common usage
/// of this is to re-establish encryption after reconnecting two LE devices.
///
/// A non-resolvable private address is a host generated address sent to the *LE* controller.
/// A non-resolvable private address is used where it is desired for the public or static device
/// address to not be known for privacy reasons, but a resolvable private address is not needed or
/// used.
///
/// # UI Representation
/// A `BluetoothDeviceAddress` can be created from the UI Rfepresentation form. This is a string
/// formatted as either twelve consecutive hexadecimals (`"XXXXXXXXXXXX"`) or separated at every
/// two by a colon (`"XX:XX:XX:XX:XX:XX").
///
/// A `BluetoothDeviceAddress` can be converted into the UI representation with colons through its
/// implementation of [`Display`](core::fmt::Display). If the format with just twelve hexidecimal
/// digits is desired, it can be done using either the implementation for
/// [`LowerHex`](core::fmt::LowerHex) or [`UpperHex`](core::fmt::UpperHex).
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct BluetoothDeviceAddress(pub [u8; 6]);

impl BluetoothDeviceAddress {
    /// Create a `BluetoothDeviceAddress` containing a randomly generated static device address
    #[cfg(feature = "sys-rand")]
    pub fn new_random_static() -> Self {
        use rand_core::RngCore;

        let mut a = [0u8; 6];

        loop {
            rand_core::OsRng.fill_bytes(&mut a);

            if let Ok(this) = Self::try_from_static(a) {
                return this;
            }
        }
    }

    /// Try to create a `BluetoothDeviceAddress` containing a static device address
    ///
    /// The returned `BluetoothDeviceAddress` will contain `addr` with the marker bits for a static
    /// device address. The only way this will fail in creating a `BluetoothDeviceAddress` is if
    /// input `addr` is equal to zero or all bits between position zero through forty-five are one.
    ///
    /// # Note
    /// The marker bits for a static device address do not need to be in `addr`. This method will
    /// add the bits to the address before returning a `BluetoothDeviceAddress`.
    pub fn try_from_static(mut addr: [u8; 6]) -> Result<Self, errors::StaticDeviceError> {
        // The tag for static device address is 0b11 in the
        // two most significant bits.
        addr[5] |= 0b1100_0000;

        if addr == [0xFF; 6] {
            Err(errors::StaticDeviceError::AddressIsAllOnes)
        } else if addr == [0, 0, 0, 0, 0, 0xC0] {
            Err(errors::StaticDeviceError::AddressIsZero)
        } else {
            Ok(Self(addr))
        }
    }

    /// Create a `BluetoothDeviceAddress` containing a non-resolvable private address
    #[cfg(feature = "sys-rand")]
    pub fn new_non_resolvable() -> Self {
        use rand_core::RngCore;

        let mut a = [0u8; 6];

        loop {
            rand_core::OsRng.fill_bytes(&mut a);

            if let Ok(this) = Self::try_from_non_resolvable(a) {
                return this;
            }
        }
    }

    /// Try to create a `BluetoothDeviceAddress` containing a non-resolvable private address
    ///
    /// The returned `BluetoothDeviceAddress` will contain `addr` with the marker bits for a
    /// non-resolvable private address. The only way this will fail in creating a
    /// `BluetoothDeviceAddress` is if input `addr` is equal to zero or all bits between position
    /// zero through forty-five are one.
    ///
    /// # Note
    /// The marker bits for a non-resolvable private address do not need to be in `addr`. This
    /// method will add the bits to the address before returning a `BluetoothDeviceAddress`.
    pub fn try_from_non_resolvable(mut addr: [u8; 6]) -> Result<Self, errors::NonResolvableError> {
        // The tag for a non resolvable private address is
        // 0b00 in the two most significant bits
        addr[5] &= 0b0011_1111;

        if [0u8; 6] == addr {
            Err(errors::NonResolvableError::AddressIsZero)
        } else if [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F] == addr {
            Err(errors::NonResolvableError::AddressIsAllOnes)
        } else {
            return Ok(Self(addr));
        }
    }

    /// Create a `BluetoothDeviceAddress` containing a resolvable private address
    ///
    /// The input is an identity resolving key (`irk`) that is used to generate the resolvable
    /// private address.
    ///
    /// # Note
    /// Most of the time this method is not needed as a resolvable private address is generated by
    /// the controller as part of the privacy process. See the Bluetooth Specification about the
    /// resolving list in the Bluetooth Low Energy Controller.
    #[cfg(all(feature = "sys-rand", feature = "cryptography"))]
    pub fn new_resolvable(irk: u128) -> Self {
        use rand_core::RngCore;

        let mut p_rand = [0u8; 3];

        loop {
            rand_core::OsRng.fill_bytes(&mut p_rand);

            if let Ok(this) = Self::try_from_resolvable(irk, p_rand) {
                return this;
            }
        }
    }

    /// Try to create a `BluetoothDeviceAddress` containing a resolvable private address
    ///
    /// This takes an identity resolving key (`irk`) and a randomly generated three byte number
    /// (`p_rand`). The first three bytes of a resolvable address is hash value that is generated
    /// from the `irk` and `p_rand`. The last three bytes of the address is `p_rand`. Input `irk` is
    /// a cryptographic key so it must stay private within the device and only given to other
    /// devices that should be able to resolve the address.
    ///
    /// Input `p_rand` cannot be zero or all ones within bits zero to twenty-two. The last two most
    /// significant bits are used to mark the address as a resolvable private address. This method
    /// will set those bits to `0b01`.
    #[cfg(feature = "cryptography")]
    pub fn try_from_resolvable(irk: u128, mut p_rand: [u8; 3]) -> Result<Self, errors::ResolvableError> {
        // The tag for a resolvable private address is 0b01
        // in the two most significant bits.
        //
        // `p_rand[2]` will become the most significant
        // byte of the resolvable private address.
        p_rand[2] = p_rand[2] & 0b0011_1111 | 0b0100_0000;

        if [0, 0, 0x40] == p_rand {
            Err(errors::ResolvableError::PRandIsZero)
        } else if [0xFF, 0xFF, 0x7F] == p_rand {
            Err(errors::ResolvableError::PRandIsAllOnes)
        } else {
            let mut address = [0, 0, 0, p_rand[0], p_rand[1], p_rand[2]];

            address[..3].copy_from_slice(&cryptography::ah(irk, p_rand));

            Ok(Self(address))
        }
    }

    /// Try to resolve this address
    ///
    /// This method should only be called if this address is a resolvable private address.
    ///
    /// `true` is returned if `irk` was the identity resolving key used to generate this Bluetooth
    /// address. `false` is returned  if `irk` was not the correct key or this address is not a
    /// resolvable private address.
    #[cfg(feature = "cryptography")]
    pub fn resolve(&self, irk: u128) -> bool {
        let (peer_hash, p_rand) = self.0.split_at(3);

        let hash = cryptography::ah(irk, [p_rand[0], p_rand[1], p_rand[2]]);

        // Check if p_rand has the correct signature for a resolvable private address
        // (the most significant two bits must be 0b01) and the hashes match.
        (p_rand[2] & 0b1100_0000 == 0b0100_0000) && (peer_hash == hash)
    }

    /// Create a `BluetoothDeviceAddress` containing all zeros
    ///
    /// An address with all zeros is an invalid address an cannot be used for Bluetooth operations.
    /// The bytes of the returned address should be modified after it is created.
    pub fn zeroed() -> Self {
        Self([0; 6])
    }

    //=============================================
    // Error returns for implementation of TryFrom
    //=============================================
    const TOO_FEW_CHARS: &'static str = "address contains too few digits";
    const TOO_MANY_CHARS: &'static str = "address contains too many digits";
    const INVALID_CHARS: &'static str = "address contains invalid characters";
    const REPEATED_COLONS: &'static str = "multiple consecutive colons separating characters";
    const COLON_AT_FRONT: &'static str = "colon in front of the address";
    const COLON_AT_BACK: &'static str = "colon at the end of the address";
}

impl Deref for BluetoothDeviceAddress {
    type Target = [u8; 6];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BluetoothDeviceAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<&str> for BluetoothDeviceAddress {
    type Error = &'static str;

    fn try_from(source: &str) -> Result<Self, Self::Error> {
        macro_rules! next_char {
            ($iter:expr) => {
                match $iter.next().ok_or(Self::TOO_FEW_CHARS)? {
                    ':' => match $iter.next().ok_or(Self::TOO_FEW_CHARS)? {
                        ':' => return Err(Self::REPEATED_COLONS)?,
                        c => c,
                    },
                    c => c,
                }
            };
        }

        if let ':' = source.chars().next().ok_or(Self::TOO_FEW_CHARS)? {
            return Err(Self::COLON_AT_FRONT);
        }

        if let Some(':') = source.chars().next_back() {
            return Err(Self::COLON_AT_BACK);
        }

        let mut address = [0u8; 6];

        let mut addr_chars_iter = source.chars().rev().fuse();

        for byte in address.iter_mut() {
            let mut src_buffer = [0u8; core::mem::size_of::<char>() * 2];

            let char_ms = next_char!(addr_chars_iter);

            let char_ls = next_char!(addr_chars_iter);

            let char_ms_len = char_ms.len_utf8();

            let char_ls_len = char_ls.len_utf8();

            let src_len = char_ms_len + char_ls_len;

            char_ls.encode_utf8(&mut src_buffer);

            char_ms.encode_utf8(&mut src_buffer[char_ls_len..]);

            let src = unsafe { core::str::from_utf8_unchecked(&src_buffer[..src_len]) };

            *byte = u8::from_str_radix(&src, 16).or(Err(Self::INVALID_CHARS))?;
        }

        match addr_chars_iter.next() {
            Some(_) => Err(Self::TOO_MANY_CHARS),
            None => Ok(Self(address)),
        }
    }
}

impl Display for BluetoothDeviceAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
            self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

impl LowerHex for BluetoothDeviceAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:x}{:x}{:x}{:x}{:x}{:x}",
            self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

impl UpperHex for BluetoothDeviceAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:X}{:X}{:X}{:X}{:X}{:X}",
            self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_static_device_address() {
        assert_eq!(
            Err(errors::StaticDeviceError::AddressIsZero),
            BluetoothDeviceAddress::try_from_static([0; 6])
        );

        assert_eq!(
            Err(errors::StaticDeviceError::AddressIsAllOnes),
            BluetoothDeviceAddress::try_from_static([0xFF; 6])
        );

        assert_eq!(
            Err(errors::StaticDeviceError::AddressIsAllOnes),
            BluetoothDeviceAddress::try_from_static([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F])
        )
    }

    #[test]
    fn invalid_non_resolvable_private_address() {
        assert_eq!(
            Err(errors::NonResolvableError::AddressIsZero),
            BluetoothDeviceAddress::try_from_non_resolvable([0; 6])
        );

        assert_eq!(
            Err(errors::NonResolvableError::AddressIsAllOnes),
            BluetoothDeviceAddress::try_from_non_resolvable([0xFF; 6])
        );

        assert_eq!(
            Err(errors::NonResolvableError::AddressIsAllOnes),
            BluetoothDeviceAddress::try_from_non_resolvable([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F])
        );
    }

    #[test]
    fn invalid_resolvable_private_address() {
        let irk = 1234u128;

        assert_eq!(
            Err(errors::ResolvableError::PRandIsZero),
            BluetoothDeviceAddress::try_from_resolvable(irk, [0; 3])
        );

        assert_eq!(
            Err(errors::ResolvableError::PRandIsAllOnes),
            BluetoothDeviceAddress::try_from_resolvable(irk, [0xFF; 3])
        );

        assert_eq!(
            Err(errors::ResolvableError::PRandIsAllOnes),
            BluetoothDeviceAddress::try_from_resolvable(irk, [0xFF, 0xFF, 0x3F])
        );
    }

    #[test]
    fn resolve_resolvable_private_address() {
        let irk = 123456u128;

        let p_rand = [0x12, 0x23, 0x34];

        let rpa = BluetoothDeviceAddress::try_from_resolvable(irk, p_rand).unwrap();

        assert!(rpa.resolve(irk));
    }

    #[test]
    fn bluetooth_addr_ui_representation() {
        assert_eq!(
            Ok(BluetoothDeviceAddress([0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12])),
            BluetoothDeviceAddress::try_from("123456789abc")
        );

        assert_eq!(
            Ok(BluetoothDeviceAddress([0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12])),
            BluetoothDeviceAddress::try_from("12:34:56:78:9a:bc")
        );

        // The Bluetooth Specification does not have a common format
        // when using colons to split an address into sub-slices. This
        // might be shown in a UI where the address is split into the
        // LAP, UAP, and NAP parts.
        assert_eq!(
            Ok(BluetoothDeviceAddress([0x56, 0x34, 0x12, 0xef, 0xcd, 0xab])),
            BluetoothDeviceAddress::try_from("abcdef:12:3456")
        );

        // Repetitions of colons are not allowed.
        assert_eq!(
            Err(BluetoothDeviceAddress::REPEATED_COLONS),
            BluetoothDeviceAddress::try_from("ab::cd::ef::12::34::56")
        );

        // Colon(s) at the front are not allowed
        assert_eq!(
            Err(BluetoothDeviceAddress::COLON_AT_FRONT),
            BluetoothDeviceAddress::try_from(":abcdef123456")
        );

        // Colon(s) at the back are not allowed
        assert_eq!(
            Err(BluetoothDeviceAddress::COLON_AT_BACK),
            BluetoothDeviceAddress::try_from("abcdef123456:")
        );

        assert_eq!(
            Err(BluetoothDeviceAddress::INVALID_CHARS),
            BluetoothDeviceAddress::try_from("hello_worlds")
        );

        assert_eq!(
            Err(BluetoothDeviceAddress::TOO_MANY_CHARS),
            BluetoothDeviceAddress::try_from("123456789abcd")
        );

        assert_eq!(
            Err(BluetoothDeviceAddress::TOO_FEW_CHARS),
            BluetoothDeviceAddress::try_from("123456789ab")
        );

        assert_eq!(
            Err(BluetoothDeviceAddress::TOO_FEW_CHARS),
            BluetoothDeviceAddress::try_from("123456789a")
        );
    }
}
