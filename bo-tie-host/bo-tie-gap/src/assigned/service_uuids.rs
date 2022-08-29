//! Advertising Data: Service Class UUID Data Type
//!
//! The struct Services is the data type for the list of service class UUIDs.

use super::*;
use alloc::collections::BTreeSet;
pub use bo_tie_host_util::Uuid;
use core::convert::{AsMut, AsRef};
use core::iter::{FromIterator, IntoIterator};

/// Internal trait for specifying the Data Type Value
///
/// For UUIDs there is a complete and an incomplete list version for each UUID type (16,
/// 32, 128 bit).
trait DataType {
    const INCOMPLETE: AssignedTypes;
    const COMPLETE: AssignedTypes;
}

impl DataType for Services<u16> {
    const INCOMPLETE: AssignedTypes = AssignedTypes::IncompleteListOf16bitServiceClassUUIDs;
    const COMPLETE: AssignedTypes = AssignedTypes::CompleteListOf16bitServiceClassUUIDs;
}

impl DataType for Services<u32> {
    const INCOMPLETE: AssignedTypes = AssignedTypes::IncompleteListOf32bitServiceClassUUIDs;
    const COMPLETE: AssignedTypes = AssignedTypes::CompleteListOf32bitServiceClassUUIDs;
}

impl DataType for Services<u128> {
    const INCOMPLETE: AssignedTypes = AssignedTypes::IncompleteListOf128bitServiceClassUUIDs;
    const COMPLETE: AssignedTypes = AssignedTypes::CompleteListOf128bitServiceClassUUIDs;
}

/// Create a Services data type for 16-bit UUIDs
///
/// This takes one input to indicate if the service list is to be a complete or incomplete
/// list of service id's.
pub fn new_16(complete: bool) -> Services<u16> {
    Services::new(complete)
}

/// Create a Services data type for 32-bit UUIDs
///
/// This takes one input to indicate if the service list is to be a complete or incomplete
/// list of service id's.
pub fn new_32(complete: bool) -> Services<u32> {
    Services::new(complete)
}

/// Create a Services data type for 128-bit UUIDs
///
/// This takes one input to indicate if the service list is to be a complete or incomplete
/// list of service id's.
pub fn new_128(complete: bool) -> Services<u128> {
    Services::new(complete)
}

/// Service UUIDs
///
/// Use the module level functions
/// `[new_16]`(../fn.new_16.html),
/// `[new_32]`(../fn.new_32.html), or
/// `[new_128]` (../fn.new_128.html)
/// to crunstruct a new, empty `Services` (of 16, 32, or 128 bit UUIDs, respectively).
///
/// This is a set of services uuids with sizes of u16, u32, or u128. `Services` can either
/// be set as a complete or incomplete list
///
/// `Services` is a set of uuids, so duplicate uuids cannot exist within an instance of
/// `Services`
///
/// Services implements `AsRef` for `BTreeSet` so use the methods of `BTreeSet` for editing
/// the UUIDs in the instance
#[derive(Clone, Debug)]
pub struct Services<T>
where
    T: Ord,
{
    set: BTreeSet<T>,
    complete: bool,
}

impl<T> Services<T>
where
    T: Ord,
{
    fn new(complete: bool) -> Self {
        Self {
            set: BTreeSet::new(),
            complete,
        }
    }

    /// True if the list is a complete list of service UUIDs
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Add uuids to the list of uuids
    ///
    /// This will only add UUIDs that can be converted to the respective size of the service
    /// UUIDs in the list. If the UUID cannot be converted into such size, then false is
    /// returned and the UUID is not added to the list.
    pub fn add<E>(&mut self, uuid: Uuid) -> bool
    where
        T: TryFrom<Uuid, Error = E>,
    {
        if let Ok(uuid_val) = core::convert::TryInto::<T>::try_into(uuid) {
            self.set.insert(uuid_val);
            true
        } else {
            false
        }
    }

    fn direct_add(&mut self, v: T) {
        self.set.insert(v);
    }
}

impl<T> AsRef<BTreeSet<T>> for Services<T>
where
    T: Ord,
{
    fn as_ref(&self) -> &BTreeSet<T> {
        &self.set
    }
}

impl<T> AsMut<BTreeSet<T>> for Services<T>
where
    T: Ord,
{
    fn as_mut(&mut self) -> &mut BTreeSet<T> {
        &mut self.set
    }
}

impl<T> core::ops::Deref for Services<T>
where
    T: Ord,
{
    type Target = BTreeSet<T>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> IntoIterator for Services<T>
where
    T: core::cmp::Ord,
{
    type Item = T;
    type IntoIter = <BTreeSet<T> as IntoIterator>::IntoIter;

    /// Useful for iterating over the contained UUIDs, but after this is done you obviously
    /// cannot tell if the list is complete or not.
    fn into_iter(self) -> Self::IntoIter {
        self.set.into_iter()
    }
}

macro_rules! impl_service_from_iterator {
    ( $size:ty ) => {
        impl<T> FromIterator<T> for Services<$size>
        where
            T: Into<$size>,
        {
            fn from_iter<Iter>(iter: Iter) -> Self
            where
                Iter: IntoIterator<Item = T>,
            {
                let mut services = Self::new(true);

                for i in iter {
                    services.direct_add(i.into());
                }

                services
            }
        }
    };
}

impl_service_from_iterator! {u16}
impl_service_from_iterator! {u32}
impl_service_from_iterator! {u128}

macro_rules! impl_from_services {
        ( $uuid_type_to:ty, $( $uuid_type_from:ty),+ ) => {
            $( impl<'a> From<Services<$uuid_type_from>> for Services<$uuid_type_to> {

                fn from( services: Services<$uuid_type_from> ) -> Self {
                    services.into_iter().map( |uuid| uuid.clone() as $uuid_type_to ).collect()
                }
            } )*
        };
    }

impl_from_services! {u128,u32,u16}
impl_from_services! {u32,u16}

macro_rules! impl_from_for_slice_with_complete {
    ( $type: ty ) => {
        impl<'a> From<(&'a [$type], bool)> for Services<$type> {
            fn from((uuids, complete): (&[$type], bool)) -> Self {
                let mut services = Self::new(complete);

                for uuid in uuids {
                    services.set.insert(*uuid);
                }

                services
            }
        }
    };
}

impl_from_for_slice_with_complete! {u16}
impl_from_for_slice_with_complete! {u32}
impl_from_for_slice_with_complete! {u128}

/// Implementation for primitive type numbers
///
/// Requires `$type` to implement a method by the name `to_le_bytes`
macro_rules! impl_raw {
    ( $ty:tt ) => {
        impl IntoStruct for Services<$ty> {
            fn data_len(&self) -> Result<usize, usize> {
                Ok(core::mem::size_of::<$ty>() * self.set.len())
            }

            fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, $crate::assigned::ConvertError> {
                if b.len() < core::mem::size_of::<$ty>() * self.set.len() + HEADER_SIZE {
                    Err($crate::assigned::ConvertError {
                        required: core::mem::size_of::<$ty>() * self.set.len() + HEADER_SIZE,
                        remaining: b.len(),
                    })
                } else {
                    let assigned_type = if self.set.is_empty() || self.complete {
                        Self::COMPLETE
                    } else {
                        Self::INCOMPLETE
                    };

                    let mut interm = StructIntermediate::new(b, assigned_type.val()).unwrap();

                    self.set
                        .iter()
                        .map(|v| $ty::to_le_bytes(*v))
                        .flatten()
                        .for_each(|b| *interm.next().unwrap() = b);

                    Ok(interm.finish())
                }
            }
        }

        impl TryFromStruct<'_> for Services<$ty> {
            fn try_from_struct(st: EirOrAdStruct<'_>) -> Result<Self, Error>
            where
                Self: Sized,
            {
                let task = |at: AssignedTypes| -> Result<Self, Error> {
                    let chunks = st.get_data().chunks_exact(core::mem::size_of::<$ty>());

                    if chunks.remainder().len() == 0 {
                        let set = chunks
                            .map(|raw_uuid| {
                                let mut buffer = [0; core::mem::size_of::<$ty>()];

                                buffer.copy_from_slice(raw_uuid);

                                <$ty>::from_le_bytes(buffer)
                            })
                            .collect::<BTreeSet<$ty>>();

                        let complete = at == Self::COMPLETE;

                        Ok(Services::<$ty> { set, complete })
                    } else {
                        Err(Error::IncorrectLength)
                    }
                };

                if st.get_type() == Self::INCOMPLETE.val() {
                    task(Self::INCOMPLETE)
                } else if st.get_type() == Self::COMPLETE.val() {
                    task(Self::COMPLETE)
                } else {
                    Err(Error::IncorrectAssignedType)
                }
            }
        }
    };
}

impl_raw! {u16}
impl_raw! {u32}
impl_raw! {u128}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn adv_service_uuid_test() {
        let test_16 = 12357u16;
        let test_32 = 123456789u32;
        let test_128 = 1372186947123894612389889949u128;

        let t16 = test_16.to_le_bytes();
        let t32 = test_32.to_le_bytes();
        let t128 = test_128.to_le_bytes();

        let raw_u16_comp_adv_data = &[
            3,
            AssignedTypes::CompleteListOf16bitServiceClassUUIDs.val(),
            t16[0],
            t16[1],
        ];

        let raw_u16_icom_adv_data = &[
            3,
            AssignedTypes::IncompleteListOf16bitServiceClassUUIDs.val(),
            t16[0],
            t16[1],
        ];

        let raw_u32_comp_adv_data = &[
            5,
            AssignedTypes::CompleteListOf32bitServiceClassUUIDs.val(),
            t32[0],
            t32[1],
            t32[2],
            t32[3],
        ];

        let raw_u32_icom_adv_data = &[
            5,
            AssignedTypes::IncompleteListOf32bitServiceClassUUIDs.val(),
            t32[0],
            t32[1],
            t32[2],
            t32[3],
        ];

        let raw_u128_comp_adv_data = &[
            17,
            AssignedTypes::CompleteListOf128bitServiceClassUUIDs.val(),
            t128[0],
            t128[1],
            t128[2],
            t128[3],
            t128[4],
            t128[5],
            t128[6],
            t128[7],
            t128[8],
            t128[9],
            t128[10],
            t128[11],
            t128[12],
            t128[13],
            t128[14],
            t128[15],
        ];

        let raw_u128_icom_adv_data = &[
            17,
            AssignedTypes::IncompleteListOf128bitServiceClassUUIDs.val(),
            t128[0],
            t128[1],
            t128[2],
            t128[3],
            t128[4],
            t128[5],
            t128[6],
            t128[7],
            t128[8],
            t128[9],
            t128[10],
            t128[11],
            t128[12],
            t128[13],
            t128[14],
            t128[15],
        ];

        let test_u16_comp_adv_data = EirOrAdStruct::try_new(raw_u16_comp_adv_data).unwrap().unwrap().0;

        let test_u16_icom_adv_data = EirOrAdStruct::try_new(raw_u16_icom_adv_data).unwrap().unwrap().0;

        let test_u32_comp_adv_data = EirOrAdStruct::try_new(raw_u32_comp_adv_data).unwrap().unwrap().0;

        let test_u32_icom_adv_data = EirOrAdStruct::try_new(raw_u32_icom_adv_data).unwrap().unwrap().0;

        let test_u128_comp_adv_data = EirOrAdStruct::try_new(raw_u128_comp_adv_data).unwrap().unwrap().0;

        let test_u128_icom_adv_data = EirOrAdStruct::try_new(raw_u128_icom_adv_data).unwrap().unwrap().0;

        let rslt_1 = Services::<u16>::try_from_struct(test_u16_comp_adv_data).unwrap();

        let rslt_2 = Services::<u16>::try_from_struct(test_u16_icom_adv_data).unwrap();

        let rslt_3 = Services::<u32>::try_from_struct(test_u32_comp_adv_data).unwrap();

        let rslt_4 = Services::<u32>::try_from_struct(test_u32_icom_adv_data).unwrap();

        let rslt_5 = Services::<u128>::try_from_struct(test_u128_comp_adv_data).unwrap();

        let rslt_6 = Services::<u128>::try_from_struct(test_u128_icom_adv_data).unwrap();

        assert_eq!(rslt_1.get(&test_16).map(|v| v.clone()), Some(test_16));

        assert_eq!(rslt_2.get(&test_16).map(|v| v.clone()), Some(test_16));

        assert_eq!(rslt_3.get(&test_32).map(|v| v.clone()), Some(test_32));

        assert_eq!(rslt_4.get(&test_32).map(|v| v.clone()), Some(test_32));

        assert_eq!(rslt_5.get(&test_128).map(|v| v.clone()), Some(test_128));

        assert_eq!(rslt_6.get(&test_128).map(|v| v.clone()), Some(test_128));
    }
}
