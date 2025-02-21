use crate::assigned::{ConvertError, EirOrAdStruct, Error};

/// LE device role
///
/// Gives information on the roles the device can support with Bluetooth LE

pub enum LeRole {
    /// Only Peripheral role supported
    OnlyPeripheral,
    /// Only central role supported
    OnlyCentral,
    /// Peripheral and Central roles are supported, but the Peripheral role is preferred for
    /// connection establishment.
    PeripheralPreferred,
    /// Peripheral and Central roles are supported, but the Central is role is preferred for
    /// connection establishment.
    CentralPreferred,
}

impl LeRole {
    const ASSIGNED_TYPE: super::AssignedTypes = super::AssignedTypes::LERole;

    /// The size of the EIR/AD struct
    pub const STRUCT_SIZE: usize = 1 + super::HEADER_SIZE;

    fn val(&self) -> u8 {
        match self {
            LeRole::OnlyPeripheral => 0,
            LeRole::OnlyCentral => 1,
            LeRole::PeripheralPreferred => 2,
            LeRole::CentralPreferred => 3,
        }
    }

    fn try_from_val(val: u8) -> Result<Self, Error> {
        match val {
            1 => Ok(LeRole::OnlyPeripheral),
            2 => Ok(LeRole::OnlyCentral),
            3 => Ok(LeRole::PeripheralPreferred),
            4 => Ok(LeRole::CentralPreferred),
            _ => Err(Error::InvalidData),
        }
    }
}

impl super::IntoStruct for LeRole {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(1)
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, super::ConvertError> {
        if b.len() < Self::STRUCT_SIZE {
            Err(ConvertError::OutOfSpace {
                required: Self::STRUCT_SIZE,
                remaining: b.len(),
            })
        } else {
            let mut interm = super::StructIntermediate::new(b, Self::ASSIGNED_TYPE.val()).unwrap();

            *interm.next().unwrap() = self.val();

            Ok(interm.finish())
        }
    }
}

impl<'a> super::TryFromStruct<'a> for LeRole {
    fn try_from_struct(st: EirOrAdStruct<'a>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if st.get_type() != Self::ASSIGNED_TYPE.val() {
            return Err(Error::IncorrectAssignedType);
        };

        let data = st.get_data();

        if data.len() == 1 {
            LeRole::try_from_val(data[0])
        } else {
            Err(Error::IncorrectLength)
        }
    }
}

impl IntoIterator for LeRole {
    type Item = u8;

    type IntoIter = LeRoleStructIter;

    fn into_iter(self) -> Self::IntoIter {
        LeRoleStructIter(self, 0)
    }
}

/// Iterator over bytes of a [`LeRole`] data structure
///
/// This can be created from the `IntoIterator` implementation of `LeRole`
pub struct LeRoleStructIter(LeRole, usize);

impl Iterator for LeRoleStructIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.1 += 1;

        match self.1 {
            1 => 2.into(),
            2 => LeRole::ASSIGNED_TYPE.val().into(),
            3 => self.0.val().into(),
            _ => None,
        }
    }
}
