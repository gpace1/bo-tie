//! LE Secure Connection Confirmation Value
//!
//! This advertising data is sent as part of the secure simple pairing out of band (OOB) data block
//! or OOB pairing with a security manager.
//!
//! Its used by the OOB part in the secure connections pairing process of the security manager to
//! send the generated confirmation value to the peer pairing device (Bluetooth Core Spec. v5.2 |
//! Vol. 3, Part H | Sec. 2.3.5.6.4).

use crate::gap::assigned::{AssignedTypes, EirOrAdStruct, Error, IntoStruct, StructIntermediate, TryFromStruct};

pub struct ScConfirmValue(pub u128);

impl ScConfirmValue {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::LESecureConnectionsConfirmationValue;

    /// Size of the EIR/AD struct
    pub const STRUCT_SIZE: usize = core::mem::size_of::<u128>() + super::HEADER_SIZE;

    /// Create a ScConfirmValue
    ///
    /// The input is the confirmation value as returned by the [`f4`](crate::sm::toolbox::f4)
    /// confirm value generation function.
    pub fn new(c: u128) -> Self {
        ScConfirmValue(c)
    }
}

impl IntoStruct for ScConfirmValue {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(core::mem::size_of::<u128>())
    }

    fn convert_into<'a>(&self, ad: &'a mut [u8]) -> Option<EirOrAdStruct<'a>> {
        const U128_SIZE: usize = core::mem::size_of::<u128>();

        if ad.len() > U128_SIZE + 2 {
            None
        } else {
            let mut interm = StructIntermediate::new(ad, Self::ASSIGNED_TYPE.val())?;

            self.0
                .to_le_bytes()
                .iter()
                .try_for_each(|b| interm.next().map(|r| *r = *b))?;

            interm.finish()
        }
    }
}

impl TryFromStruct<'_> for ScConfirmValue {
    fn try_from_struct(ad: EirOrAdStruct<'_>) -> Result<Self, Error> {
        if ad.get_type() == Self::ASSIGNED_TYPE.val() {
            if ad.get_data().len() == core::mem::size_of::<u128>() {
                let mut bytes = [0; 16];

                bytes.copy_from_slice(ad.get_data());

                let rand = <u128>::from_le_bytes(bytes);

                Ok(ScConfirmValue::new(rand))
            } else {
                Err(Error::IncorrectLength)
            }
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}
