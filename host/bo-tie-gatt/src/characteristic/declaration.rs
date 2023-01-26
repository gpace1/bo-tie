//! Characteristic Declaration Implementation

use crate::characteristic::{AddCharacteristicComponent, Properties};
use bo_tie_att::server::ServerAttributes;
use bo_tie_att::Attribute;
use bo_tie_host_util::Uuid;
use bo_tie_util::buffer::stack::LinearBuffer;
use core::borrow::Borrow;

/// UUID for a characteristic declaration
pub(crate) const TYPE: Uuid = Uuid::from_u16(0x2803);

/// A constructor of a Characteristic Declaration
///
/// This is a staged builder, meaning it must go through a series of method calls in order to
/// complete building the declaration. See method [`CharacteristicBuilder::set_declaration`].
///
/// The methods must be called in this order to complete the construction of a Characteristic
/// Declaration.
///
/// 1) [`set_properties`]
/// 2) [`set_uuid`]
/// 3) [`set_permissions`]
///
/// [`CharacteristicBuilder::set_declaration`]: crate::characteristic::CharacteristicBuilder::set_declaration
/// [`set_properties`]: DeclarationBuilder::<SetProperties>::set_properties
/// [`set_uuid`]: DeclarationBuilder::<SetUuid>::set_uuid
/// [`set_permissions`]: DeclarationBuilder::<SetPermissions>::set_permissions
pub struct DeclarationBuilder<T> {
    current: T,
}

impl DeclarationBuilder<SetProperties> {
    pub(crate) fn new() -> Self {
        DeclarationBuilder { current: SetProperties }
    }

    /// Set the Characteristic Properties
    pub fn set_properties<P>(self, properties: P) -> DeclarationBuilder<SetUuid>
    where
        P: Borrow<[Properties]>,
    {
        let mut characteristic_properties: LinearBuffer<{ Properties::full_depth() }, Properties> = LinearBuffer::new();

        unique_only!(characteristic_properties, properties.borrow());

        let current = SetUuid {
            properties: characteristic_properties,
        };

        DeclarationBuilder { current }
    }
}

impl DeclarationBuilder<SetUuid> {
    /// Set the UUID for the Characteristic
    pub fn set_uuid<U>(self, uuid: U) -> DeclarationBuilder<Complete>
    where
        U: Into<Uuid>,
    {
        let uuid = uuid.into();

        let current = Complete {
            properties: self.current.properties,
            uuid,
        };

        DeclarationBuilder { current }
    }
}

impl DeclarationBuilder<Complete> {
    pub(crate) fn set_value_handle(self, value_handle: u16) -> DeclarationBuilder<TrueComplete> {
        let current = TrueComplete {
            properties: self.current.properties,
            uuid: self.current.uuid,
            value_handle,
        };

        DeclarationBuilder { current }
    }
}

impl DeclarationBuilder<TrueComplete> {
    pub(crate) fn get_uuid(&self) -> Uuid {
        self.current.uuid
    }
}

impl AddCharacteristicComponent for DeclarationBuilder<TrueComplete> {
    fn push_to(self, sa: &mut ServerAttributes, restrictions: &[crate::att::AttributeRestriction]) -> bool {
        let declaration = Declaration {
            properties: self.current.properties,
            value_handle: self.current.value_handle,
            uuid: self.current.uuid,
        };

        let attribute_permissions = map_restrictions!(restrictions => Read);

        let attribute = Attribute::new(TYPE, attribute_permissions, declaration);

        sa.push(attribute);

        true
    }
}

/// `DeclarationBuilder` marker type
///
/// This marker type is used for enabling the method [`DeclarationBuilder::set_properties`].
///
/// [`DeclarationBuilder::set_properties`]: DeclarationBuilder::<SetProperties>::set_properties
pub struct SetProperties;

/// `DeclarationBuilder` marker type
///
/// This marker type is used for enabling the method [`DeclarationBuilder::set_uuid`].
///
/// [`DeclarationBuilder::set_uuid`]: DeclarationBuilder::<SetUuid>::set_uuid
pub struct SetUuid {
    properties: LinearBuffer<{ Properties::full_depth() }, Properties>,
}

/// `DeclarationBuilder` marker type
///
/// This marks that a `DeclarationBuilder` is complete.
pub struct Complete {
    properties: LinearBuffer<{ Properties::full_depth() }, Properties>,
    uuid: Uuid,
}

/// The *true* completion of a `DeclarationBuilder`
///
/// This is a marker type for the true completion of a the value declaration. This is not exposed
/// as part of the builder implementation as the value handle is set from the information
/// within a [`CharacteristicBuilder`].
///
/// [`CharacteristicBuilder`]: crate::characteristic::CharacteristicBuilder
pub struct TrueComplete {
    properties: LinearBuffer<{ Properties::full_depth() }, Properties>,
    uuid: Uuid,
    value_handle: u16,
}

#[derive(PartialEq)]
/// The Characteristic Declaration
pub struct Declaration {
    properties: LinearBuffer<{ Properties::full_depth() }, Properties>,
    value_handle: u16,
    uuid: Uuid,
}

impl bo_tie_att::TransferFormatTryFrom for Declaration {
    fn try_from(raw: &[u8]) -> Result<Self, bo_tie_att::TransferFormatError> {
        // The implementation of TransferFormatTryFrom for UUID will check if the length is good for
        // a 128 bit UUID
        if raw.len() >= 6 {
            Ok(Declaration {
                properties: Properties::from_bit_field(raw[1]),
                value_handle: bo_tie_att::TransferFormatTryFrom::try_from(&raw[1..3])?,
                uuid: bo_tie_att::TransferFormatTryFrom::try_from(&raw[3..])?,
            })
        } else {
            Err(bo_tie_att::TransferFormatError::bad_min_size(
                stringify!(Declaration),
                6,
                raw.len(),
            ))
        }
    }
}

impl bo_tie_att::TransferFormatInto for Declaration {
    fn len_of_into(&self) -> usize {
        3 + self.uuid.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = Properties::slice_to_bit_field(&self.properties);

        into_ret[1..3].copy_from_slice(&self.value_handle.to_le_bytes());

        self.uuid.build_into_ret(&mut into_ret[3..])
    }
}
