//! Service Class UUID Data Type
//!
//! The struct Services is the data type for the list of service class UUIDs paired with
//! service data. It is implemented for the three types of UUIDs (16, 32, and 128 bit)
//! and to create an instance of it use the functions `new_16`, `new_32`, or
//! `new_128` at the module level.

use super::*;

/// Create service data for 16-bit UUID's
pub fn new_16<Data>(uuid: u16, data: Data) -> ServiceData<u16, Data> {
    ServiceData::new(uuid, data)
}

/// Create service data for 32-bit UUID's
pub fn new_32<Data>(uuid: u32, data: Data) -> ServiceData<u32, Data> {
    ServiceData::new(uuid, data)
}

/// Create service data for 64-bit UUID's
pub fn new_128<Data>(uuid: u128, data: Data) -> ServiceData<u128, Data> {
    ServiceData::new(uuid, data)
}

/// Service Data
///
/// Contains a UUID along with the coresponding data for that UUID
///
/// Use the module level functions
/// `[new_16]`(../fn.new_16.html),
/// `[new_32]`(../fn.new_32.html), or
/// `[new_128]` (../fn.new_128.html)
/// to construct a new, empty `ServiceData` (of 16, 32, or 128 bit UUIDs, respectively).
#[derive(Clone, Debug)]
pub struct ServiceData<UuidType, Data> {
    uuid: UuidType,
    data: Data,
}

impl<UuidType, Data> ServiceData<UuidType, Data> {
    fn new(uuid: UuidType, data: Data) -> Self {
        ServiceData { uuid, data }
    }

    pub fn get_uuid(&self) -> UuidType
    where
        UuidType: Copy,
    {
        self.uuid
    }

    /// Attempt to get the service data as `Data`
    pub fn get_data(&self) -> &Data {
        &self.data
    }
}

macro_rules! impl_raw {
    ( $ty:tt, $assigned_type:path ) => {
        impl<Data> IntoStruct for ServiceData<$ty, Data>
        where
            Data: bo_tie_att::TransferFormatInto,
        {
            fn data_len(&self) -> Result<usize, usize> {
                Ok(core::mem::size_of::<$ty>() + bo_tie_att::TransferFormatInto::len_of_into(&self.data))
            }

            fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, $crate::assigned::ConvertError> {
                if b.len() < core::mem::size_of::<$ty>() + $crate::assigned::HEADER_SIZE {
                    Err($crate::assigned::ConvertError {
                        required: core::mem::size_of::<$ty>() + $crate::assigned::HEADER_SIZE,
                        remaining: b.len(),
                    })
                } else {
                    let mut interm = StructIntermediate::new(b, $assigned_type.val()).unwrap();

                    self.uuid
                        .to_le_bytes()
                        .iter()
                        .for_each(|b| *interm.next().unwrap() = *b);

                    interm.try_extend_by(&self.data).unwrap();

                    Ok(interm.finish())
                }
            }
        }

        impl<Data> TryFromStruct<'_> for ServiceData<$ty, Data>
        where
            Data: bo_tie_att::TransferFormatTryFrom,
        {
            fn try_from_struct(st: EirOrAdStruct<'_>) -> Result<Self, Error>
            where
                Self: Sized,
            {
                if st.get_type() == $assigned_type.val() {
                    let data = st.get_data();

                    if data.len() >= core::mem::size_of::<$ty>() {
                        let (uuid_raw, service_data) = data.split_at(core::mem::size_of::<$ty>());

                        let mut bytes = [0u8; core::mem::size_of::<$ty>()];

                        bytes.copy_from_slice(uuid_raw);

                        Ok(ServiceData {
                            uuid: $ty::from_le_bytes(bytes),
                            data: bo_tie_att::TransferFormatTryFrom::try_from(service_data)?,
                        })
                    } else {
                        Err(Error::IncorrectLength)
                    }
                } else {
                    Err(Error::IncorrectAssignedType)
                }
            }
        }
    };
}

impl_raw! {u16, AssignedTypes::ServiceData16BitUUID }
impl_raw! {u32, AssignedTypes::ServiceData32BitUUID }
impl_raw! {u128, AssignedTypes::ServiceData128BitUUID }
