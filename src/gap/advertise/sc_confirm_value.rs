//! LE Secure Connection Confirmation Value
//!
//! This advertising data is sent as part of the secure simple pairing out of band (OOB) data block.
//! Its used by the OOB part of the secure connections pairing process to send the generated
//! confirmation value to the peer pairing device (Bluetooth Core Spec. v5.2 | Vol. 3, Part H |
//! Sec. 2.3.5.6.4).

use crate::gap::advertise::{new_raw_type, AssignedTypes, Error, IntoRaw, TryFromRaw};
use alloc::prelude::v1::Vec;

pub struct ScConfirmValue(u128);

impl ScConfirmValue {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::LESecureConnectionsConfirmationValue;

    /// Create a ScConfirmValue
    ///
    /// The input is the confirmation value as returned by the [`f4`](crate::sm::toolbox::f4)
    /// confirm value generation function.
    pub fn new(c: u128) -> Self {
        ScConfirmValue(c)
    }
}

impl IntoRaw for ScConfirmValue {
    fn into_raw(&self) -> Vec<u8> {
        let ad_type = Self::ASSIGNED_TYPE.val();

        let mut val = new_raw_type(ad_type);

        val.extend(&self.0.to_le_bytes());

        val
    }
}

impl TryFromRaw for ScConfirmValue {
    fn try_from_raw(raw: &[u8]) -> Result<Self, Error> {
        from_raw!(raw, Self::ASSIGNED_TYPE, {
            if raw.len() != 17 {
                return Err(Error::IncorrectLength);
            }

            let mut c_arr = [0; 16];

            c_arr.copy_from_slice(&raw[1..]);

            let c = <u128>::from_le_bytes(c_arr);

            ScConfirmValue::new(c)
        })
    }
}
