//! Security Manager TK Value
//!
//! This is the data type is sent as part of Out of Band data between two Security Managers
//! performing LE legacy pairing.

use crate::assigned::{
    AssignedTypes, ConvertError, EirOrAdStruct, Error, IntoStruct, StructIntermediate, TryFromStruct,
};

pub struct SecurityManagerTkValue(pub u128);

impl SecurityManagerTkValue {
    const ASSIGNED_TYPE: AssignedTypes = AssignedTypes::SecurityManagerTKValue;

    /// Size of the EIR/AD struct
    pub const STRUCT_SIZE: usize = core::mem::size_of::<u128>() + super::HEADER_SIZE;

    /// Create a ScConfirmValue
    ///
    /// This is a random value
    pub fn new(r: u128) -> Self {
        SecurityManagerTkValue(r)
    }
}

impl IntoStruct for SecurityManagerTkValue {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(core::mem::size_of::<u128>())
    }

    fn convert_into<'a>(&self, ad: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, super::ConvertError> {
        if ad.len() < Self::STRUCT_SIZE {
            Err(ConvertError::OutOfSpace {
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

impl TryFromStruct<'_> for SecurityManagerTkValue {
    fn try_from_struct(ad: EirOrAdStruct<'_>) -> Result<Self, Error> {
        if ad.get_type() == Self::ASSIGNED_TYPE.val() {
            if ad.get_data().len() == core::mem::size_of::<u128>() {
                let mut bytes = [0; 16];

                bytes.copy_from_slice(ad.get_data());

                let rand = <u128>::from_le_bytes(bytes);

                Ok(SecurityManagerTkValue::new(rand))
            } else {
                Err(Error::IncorrectLength)
            }
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}

impl IntoIterator for SecurityManagerTkValue {
    type Item = u8;
    type IntoIter = SecurityManagerTkValueStructIter;

    fn into_iter(self) -> Self::IntoIter {
        SecurityManagerTkValueStructIter(self, 0)
    }
}

/// Iterator over bytes of a [`SecurityManagerTkValue`] data structure
///
/// This can be created from the `IntoIterator` implementation of `SecurityManagerTkValue`
pub struct SecurityManagerTkValueStructIter(SecurityManagerTkValue, usize);

impl Iterator for SecurityManagerTkValueStructIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.1 += 1;

        match self.1 {
            1 => 16.into(),
            2 => SecurityManagerTkValue::ASSIGNED_TYPE.val().into(),
            i => self.0 .0.to_le_bytes().get(i - 3).copied(),
        }
    }
}
