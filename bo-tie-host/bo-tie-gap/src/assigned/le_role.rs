use crate::assigned::{ConvertError, EirOrAdStruct};

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
}

impl super::IntoStruct for LeRole {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(1)
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, super::ConvertError> {
        if b.len() < Self::STRUCT_SIZE {
            Err(ConvertError {
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
