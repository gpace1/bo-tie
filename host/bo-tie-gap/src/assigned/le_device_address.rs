use crate::assigned::{EirOrAdStruct, Error};

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
        Ok(self.0.len())
    }

    fn convert_into<'a>(&self, ad: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, super::ConvertError> {
        if ad.len() < Self::STRUCT_SIZE {
            Err(super::ConvertError::OutOfSpace {
                required: Self::STRUCT_SIZE,
                remaining: ad.len(),
            })
        } else {
            let mut interm = super::StructIntermediate::new(ad, Self::ASSIGNED_TYPE.val()).unwrap();

            self.0.iter().for_each(|b| *interm.next().unwrap() = *b);

            Ok(interm.finish())
        }
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
                let mut address = crate::BluetoothDeviceAddress::zeroed();

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

impl IntoIterator for LeDeviceAddress {
    type Item = u8;
    type IntoIter = LeDeviceAddressStructIter;

    fn into_iter(self) -> Self::IntoIter {
        LeDeviceAddressStructIter(self, 0)
    }
}

/// Iterator over bytes of a [`LeDeviceAddress`] data structure
///
/// This can be created from the `IntoIterator` implementation of `LeDeviceAddress`
pub struct LeDeviceAddressStructIter(LeDeviceAddress, usize);

impl Iterator for LeDeviceAddressStructIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.1 += 1;

        match self.1 {
            1 => <u8>::try_from(self.0.len()).ok(),
            2 => LeDeviceAddress::ASSIGNED_TYPE.val().into(),
            i => self.0 .0.get(i - 3).copied(),
        }
    }
}
