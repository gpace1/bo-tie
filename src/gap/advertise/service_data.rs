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
/// to crunstruct a new, empty `ServiceData` (of 16, 32, or 128 bit UUIDs, respectively).
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

    /// Get the data serialized
    pub fn get_serialized_data(&self) -> alloc::vec::Vec<u8>
    where
        Data: crate::att::TransferFormatInto,
    {
        crate::att::TransferFormatInto::into(&self.data)
    }
}

macro_rules! impl_raw {
    ( $type:tt, $ad_type:path ) => {
        impl<Data> IntoRaw for ServiceData<$type, Data>
        where
            Data: crate::att::TransferFormatInto,
        {
            fn into_raw(&self) -> alloc::vec::Vec<u8> {
                let mut raw = new_raw_type($ad_type.val());

                raw.extend_from_slice(&self.uuid.to_le_bytes());

                raw.extend(crate::att::TransferFormatInto::into(&self.data));

                set_len(&mut raw);

                raw
            }
        }

        impl<Data> TryFromRaw for ServiceData<$type, Data>
        where
            Data: crate::att::TransferFormatTryFrom,
        {
            fn try_from_raw(raw: &[u8]) -> Result<ServiceData<$type, Data>, Error> {
                let ad_type = $ad_type;
                from_raw! {raw, ad_type, {
                    use core::convert::TryInto;

                    if raw.len() >= 3 {
                        let (uuid_raw, data) = raw.split_at(core::mem::size_of::<$type>());
                        let err = crate::gap::advertise::Error::LeBytesConversionError;

                        ServiceData {
                            uuid: $type::from_le_bytes(uuid_raw.try_into().or(Err(err))?),
                            data: crate::att::TransferFormatTryFrom::try_from(data)?,
                        }
                    }
                    else {
                        return Err(crate::gap::advertise::Error::RawTooSmall)
                    }
                }}
            }
        }
    };
}

impl_raw! {u16, AssignedTypes::ServiceData16BitUUID }
impl_raw! {u32, AssignedTypes::ServiceData32BitUUID }
impl_raw! {u128, AssignedTypes::ServiceData128BitUUID }
