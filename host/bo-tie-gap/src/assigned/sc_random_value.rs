//! LE Secure Connection Random Value
//!
//! This advertising data is sent as part of the secure simple pairing out of band (OOB) data.
//! Its used the secure connections OOB pairing process to contain the generated random value sent
//! to the peer device (Bluetooth Core Spec. v5.2 | Vol. 3, Part H | Sec. 2.3.5.6.4).

use crate::assigned::{
    AssignedTypes, ConvertError, EirOrAdStruct, Error, IntoStruct, StructIntermediate, TryFromStruct,
};

pub struct ScRandomValue(pub u128);

impl ScRandomValue {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::LESecureConnectionsRandomValue;

    /// Size of the EIR/AD struct
    pub const STRUCT_SIZE: usize = core::mem::size_of::<u128>() + super::HEADER_SIZE;

    /// Create a ScConfirmValue
    ///
    /// This is a random value
    pub fn new(r: u128) -> Self {
        ScRandomValue(r)
    }

    pub fn into_inner(self) -> u128 {
        self.0
    }
}

impl IntoStruct for ScRandomValue {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(core::mem::size_of::<u128>())
    }

    fn convert_into<'a>(&self, ad: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, super::ConvertError> {
        if ad.len() < Self::STRUCT_SIZE {
            Err(ConvertError {
                required: Self::STRUCT_SIZE,
                remaining: ad.len(),
            })
        } else {
            let mut interm = StructIntermediate::new(ad, Self::ASSIGNED_TYPE.val())?;

            self.0.to_le_bytes().iter().for_each(|b| *interm.next().unwrap() = *b);

            Ok(interm.finish())
        }
    }
}

impl TryFromStruct<'_> for ScRandomValue {
    fn try_from_struct(ad: EirOrAdStruct<'_>) -> Result<Self, Error> {
        if ad.get_type() == Self::ASSIGNED_TYPE.val() {
            if ad.get_data().len() == core::mem::size_of::<u128>() {
                let mut bytes = [0; 16];

                bytes.copy_from_slice(ad.get_data());

                let rand = <u128>::from_le_bytes(bytes);

                Ok(ScRandomValue::new(rand))
            } else {
                Err(Error::IncorrectLength)
            }
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}
