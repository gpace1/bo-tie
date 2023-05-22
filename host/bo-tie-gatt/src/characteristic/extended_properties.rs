//! Characteristic extended properties descriptor declaration implementation

use crate::characteristic::{AddCharacteristicComponent, VecArray};
use bo_tie_att::server::ServerAttributes;
use bo_tie_att::Attribute;
use bo_tie_core::buffer::stack::LinearBuffer;
use bo_tie_host_util::Uuid;
use core::borrow::Borrow;

/// UUID of an extended properties descriptor
pub(crate) const TYPE: Uuid = Uuid::from_u16(0x2900);

/// A constructor of a Characteristic extended properties descriptor declaration
///
/// This is a single staged builder, meaning only the method [`set_extended_properties`] needs to be
/// called to construct an extended properties Characteristic descriptor.
///
/// [`set_extended_properties`]: ExtendedPropertiesBuilder::<SetExtendedProperties>::set_extended_properties
pub struct ExtendedPropertiesBuilder<T> {
    current: T,
}

impl ExtendedPropertiesBuilder<SetExtendedProperties> {
    pub(crate) fn new() -> Self {
        ExtendedPropertiesBuilder {
            current: SetExtendedProperties,
        }
    }

    pub fn set_extended_properties<P>(self, properties: P) -> ExtendedPropertiesBuilder<Complete>
    where
        P: Borrow<[ExtendedProperties]>,
    {
        let mut extended_properties: LinearBuffer<{ ExtendedProperties::full_depth() }, ExtendedProperties> =
            LinearBuffer::new();

        unique_only!(extended_properties, properties.borrow());

        let current = Complete { extended_properties };

        ExtendedPropertiesBuilder { current }
    }
}

impl AddCharacteristicComponent for ExtendedPropertiesBuilder<SetExtendedProperties> {
    fn push_to(self, _: &mut ServerAttributes, _: &[crate::att::AttributeRestriction]) -> bool {
        false
    }
}

impl AddCharacteristicComponent for ExtendedPropertiesBuilder<Complete> {
    fn push_to(self, sa: &mut ServerAttributes, restrictions: &[crate::att::AttributeRestriction]) -> bool {
        let attribute_permissions = map_restrictions!(restrictions => Read);

        let attribute = Attribute::new(TYPE, attribute_permissions, VecArray(self.current.extended_properties));

        sa.push(attribute);

        true
    }
}

/// `ExtendedPropertiesBuilder` marker type
///
/// This marker type is used for enabling the method [`ExtendedPropertiesBuilder::set_extended_properties`].
///
/// [`ExtendedPropertiesBuilder::set_extended_properties`]: ExtendedPropertiesBuilder::<SetExtendedProperties>::set_extended_properties
pub struct SetExtendedProperties;

/// `ExtendedPropertiesBuilder` marker type
///
/// This marks that a `ExtendedPropertiesBuilder` is complete.
pub struct Complete {
    extended_properties: LinearBuffer<{ ExtendedProperties::full_depth() }, ExtendedProperties>,
}

#[derive(Copy, Clone, PartialEq, bo_tie_macros::DepthCount)]
pub enum ExtendedProperties {
    ReliableWrite,
    WritableAuxiliaries,
}

impl bo_tie_att::TransferFormatTryFrom for VecArray<{ ExtendedProperties::full_depth() }, ExtendedProperties> {
    fn try_from(raw: &[u8]) -> Result<Self, bo_tie_att::TransferFormatError> {
        if raw.len() == 2 {
            let flags = <u16>::from_le_bytes([raw[0], raw[1]]);

            let v = (0..ExtendedProperties::full_depth())
                .map(|shift| flags & (1 << shift))
                .filter(|flag| flag != &0)
                .try_fold(LinearBuffer::new(), |mut lb, flag| {
                    lb.try_push(match flag {
                        0x1 => ExtendedProperties::ReliableWrite,
                        0x2 => ExtendedProperties::WritableAuxiliaries,
                        _ => return Err(bo_tie_att::TransferFormatError::from("unknown extended property")),
                    })
                    .unwrap();
                    Ok(lb)
                })?;

            Ok(VecArray(v))
        } else {
            Err(bo_tie_att::TransferFormatError::bad_size(
                stringify!(ExtendedProperties),
                2,
                raw.len(),
            ))
        }
    }
}

impl bo_tie_att::TransferFormatInto for VecArray<{ ExtendedProperties::full_depth() }, ExtendedProperties> {
    fn len_of_into(&self) -> usize {
        ExtendedProperties::full_depth()
    }

    fn build_into_ret(&self, len_ret: &mut [u8]) {
        len_ret[0] = self.0.iter().fold(0u8, |field, ep| {
            field
                | match ep {
                    ExtendedProperties::ReliableWrite => 1 << 0,
                    ExtendedProperties::WritableAuxiliaries => 1 << 1,
                }
        });
    }
}
