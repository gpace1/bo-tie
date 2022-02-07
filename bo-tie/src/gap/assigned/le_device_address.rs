use crate::gap::assigned::{EirOrAdStruct, Error};

/// LE Bluetooth Device Address

pub struct LeDeviceAddress(crate::BluetoothDeviceAddress);

impl LeDeviceAddress {
    const ASSIGNED_TYPE: super::AssignedTypes = super::AssignedTypes::LEBluetoothDeviceAddress;

    /// The size of the EIR/AD struct
    pub const STRUCT_SIZE: usize = 6 + super::HEADER_SIZE;

    pub fn into_inner(self) -> crate::BluetoothDeviceAddress {
        self.0
    }
}

impl From<crate::BluetoothDeviceAddress> for LeDeviceAddress {
    fn from(a: crate::BluetoothDeviceAddress) -> Self {
        LeDeviceAddress(a)
    }
}

impl core::ops::Deref for LeDeviceAddress {
    type Target = crate::BluetoothDeviceAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl super::IntoStruct for LeDeviceAddress {
    fn data_len(&self) -> Result<usize, usize> {
        Ok(6)
    }

    fn convert_into<'a>(&self, ad: &'a mut [u8]) -> Option<EirOrAdStruct<'a>> {
        let mut interm = super::StructIntermediate::new(ad, Self::ASSIGNED_TYPE.val())?;

        self.0.iter().try_for_each(|b| interm.next().map(|r| *r = *b))?;

        interm.finish()
    }
}

impl<'a> super::TryFromStruct<'a> for LeDeviceAddress {
    fn try_from_struct(st: EirOrAdStruct<'a>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if st.get_type() == Self::ASSIGNED_TYPE.val() {
            let data = st.get_data();

            if data.len() == 6 {
                let mut address = crate::BluetoothDeviceAddress::default();

                address.copy_from_slice(data);

                Ok(LeDeviceAddress(address))
            } else {
                Err(Error::IncorrectLength)
            }
        } else {
            Err(Error::IncorrectAssignedType)
        }
    }
}
