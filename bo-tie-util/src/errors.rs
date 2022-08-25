//! Errors for things in the crate root of `bo-tie-util`

use core::fmt::{Display, Formatter};

/// Generic error for invalid Bluetooth addresses
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressError {
    AddressIsZero,
    AddressIsAllOnes,
}

impl Display for AddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::AddressIsZero => f.write_str("the random part of the address is zero"),
            AddressError::AddressIsAllOnes => f.write_str("the random part of the address is all ones"),
        }
    }
}

/// Error type for
/// [BluetoothDeviceAddress::try_from_static](crate::BluetoothDeviceAddress::try_from_static)
pub type StaticDeviceError = AddressError;

/// Error type for
/// [BluetoothDeviceAddress::try_from_non_resolvable](crate::BluetoothDeviceAddress::try_from_non_resolvable)
pub type NonResolvableError = AddressError;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResolvableError {
    PRandIsZero,
    PRandIsAllOnes,
}

impl Display for ResolvableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolvableError::PRandIsZero => f.write_str("the random part of the prand is all zeros"),
            ResolvableError::PRandIsAllOnes => f.write_str("the random part of the prand is all ones"),
        }
    }
}
