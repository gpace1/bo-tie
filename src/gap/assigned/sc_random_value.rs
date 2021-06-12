//! LE Secure Connection Random Value
//!
//! This advertising data is sent as part of the secure simple pairing out of band (OOB) data block.
//! Its used by the OOB part of the secure connections pairing process to send the generated
//! random value to the peer pairing device (Bluetooth Core Spec. v5.2 | Vol. 3, Part H | Sec.
//! 2.3.5.6.4).

use crate::gap::assigned::{new_raw_type, AssignedTypes, Error, IntoRaw, TryFromRaw};
use alloc::prelude::v1::Vec;

pub struct ScRandomValue(pub u128);

impl ScRandomValue {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::LESecureConnectionsRandomValue;

    /// Create a ScConfirmValue
    ///
    /// This is a random value
    pub fn new(r: u128) -> Self {
        ScRandomValue(r)
    }
}

impl IntoRaw for ScRandomValue {
    fn into_raw(&self) -> Vec<u8> {
        let ad_type = Self::ASSIGNED_TYPE.val();

        let mut val = new_raw_type(ad_type);

        val.extend(&self.0.to_le_bytes());

        val
    }
}

impl TryFromRaw for ScRandomValue {
    fn try_from_raw(raw: &[u8]) -> Result<Self, Error> {
        from_raw!(raw, Self::ASSIGNED_TYPE, {
            if raw.len() != 17 {
                return Err(Error::IncorrectLength);
            }

            let mut r_arr = [0; 16];

            r_arr.copy_from_slice(&raw[1..]);

            let r = <u128>::from_le_bytes(r_arr);

            ScRandomValue::new(r)
        })
    }
}
