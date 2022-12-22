//! Security Manager Out Of Band Pairing
//!
//! This contains the setup for enabling the usage of out of band pairing with the Security Manager
//! implementations in this library.

use bo_tie_gap::assigned::le_device_address::LeDeviceAddress;
use bo_tie_gap::assigned::le_role::LeRole;
use bo_tie_gap::assigned::sc_confirm_value::ScConfirmValue;
use bo_tie_gap::assigned::sc_random_value::ScRandomValue;
use bo_tie_gap::assigned::security_manager_tk_value::SecurityManagerTkValue;
use bo_tie_gap::assigned::{AssignedTypes, ConvertError, EirOrAdStruct, Sequence};
use bo_tie_util::buffer::stack::LinearBuffer;
use bo_tie_util::BluetoothDeviceAddress;

/// Direction of Out Of Band Data
///
/// OOB data can be sent from either both Security Managers or just one of them. This is used to
/// indicate the direction of which out of band data is sent between the two Security Managers.
#[derive(Debug, Clone, Copy)]
pub enum OobDirection {
    OnlyResponderSendsOob,
    OnlyInitiatorSendsOob,
    BothSendOob,
}

/// Required Out of Band data
///
/// This is data that is sent 'out of band' of the Bluetooth connection between two devices. In
/// order to ensure authentication, it must be sent over a channel that has sufficient man in the
/// middle protection.
pub(crate) enum RequiredOutOfBandData {
    // Right now (possibly never) the Security Managers of
    // bo-tie do not support legacy pairing.
    //
    // LeLegacy {
    //     tk: u128
    // },
    SecureConnections {
        address: BluetoothDeviceAddress,
        sc_random: u128,
        sc_confirm: u128,
    },
}

impl RequiredOutOfBandData {
    /// Create a new OutOfBandData for Secure Connections
    pub fn new_sc(address: BluetoothDeviceAddress, random: u128, confirm: u128) -> Self {
        let address = address.into();
        let sc_random = random.into();
        let sc_confirm = confirm.into();

        RequiredOutOfBandData::SecureConnections {
            address,
            sc_random,
            sc_confirm,
        }
    }

    /// Write to out of band data to `buffer`
    pub fn write_to(&self, buffer: &mut [u8]) -> Result<(), ConvertError> {
        let mut sequence = Sequence::new(buffer);

        if let Some(address) = self.address {
            let address = LeDeviceAddress::from(addres);

            sequence.try_add(&address)?;
        }

        if let Some(temp_key) = self.temp_key {
            let temp_key = SecurityManagerTkValue::new(temp_key);

            sequence.try_add(&temp_key)?;
        }

        if let Some(confirm) = self.sc_confirm {
            let sc_confirm = ScConfirmValue::new(confirm);

            sequence.try_add(&sc_confirm)?;
        }

        if let Some(random) = self.sc_random {
            let sc_random = ScRandomValue::new(random);

            sequence.try_add(&sc_random)?;
        }

        Ok(())
    }
}

impl OutOfBandData for RequiredOutOfBandData {
    fn append_to(&self, sequence: &mut Sequence) -> Result<(), ConvertError> {
        match self {
            RequiredOutOfBandData::SecureConnections {
                address,
                sc_random,
                sc_confirm,
            } => {
                let device_address = LeDeviceAddress::from(*address);
                let sc_confirm_value = ScConfirmValue::new(*sc_confirm);
                let sc_random_value = ScRandomValue::new(*sc_random);

                sequence.try_add(&device_address)?;
                sequence.try_add(&sc_confirm_value)?;
                sequence.try_add(&sc_random_value)?;

                Ok(())
            }
        }
    }
}

/// Trait for formulating out of band data
///
/// The library will give
pub trait OutOfBandData {
    fn append_to(&self, sequence: &mut Sequence) -> Result<(), ConvertError>;

    /// Write the out of band data to a buffer
    ///
    /// The return is a [`Sequence`] that owns the buffer. It can be used to add further AD
    /// structures to the buffer for out of band data.
    fn write_to<'a>(&self, buffer: &'a mut [u8]) -> Result<Sequence<'a>, ConvertError> {
        let mut sequence = Sequence::new(buffer);

        self.append_to(&mut sequence)?;

        Ok(sequence)
    }
}
