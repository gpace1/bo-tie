//! Characteristic value declaration implementation

use crate::characteristic::AddCharacteristicComponent;
use bo_tie_att::server::access_value::Trivial;
use bo_tie_att::server::{AccessValue, Comparable, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, TransferFormatInto, TransferFormatTryFrom};
use bo_tie_host_util::Uuid;
use bo_tie_util::buffer::stack::LinearBuffer;
use core::borrow::Borrow;

/// A constructor of a Characteristic value declaration
///
/// This is a staged builder, meaning it must go through a series of method calls in order to
/// complete building the value declaration. See method [`CharacteristicBuilder::set_value`].
///
/// Of the three (public) method of this builder, [`set_permissions`] must always be called, and one
/// of [`set_value`] or [`set_accessible_value`] must be called. These methods must be called in the
/// following order to complete the construction of a Characteristic value declaration
///
/// 1) `set_value` *or* `set_accessible_value`
/// 2) `set_permissions`
///
/// ## Accessors
/// Using method `set_accessible_value` means an accessor is used to interact with a characteristic
/// value. An accessor allows for an asynchronous operation to be done whenever a client performs
/// any read or write operation to the characteristic value. All accessors must implement the trait
/// [`AccessValue`]. See the documentation of module [`characteristic`] for examples of an accessor.
///
/// [`CharacteristicBuilder::set_value`]: crate::characteristic::CharacteristicBuilder::set_value
/// [`characteristic`]: crate::characteristic
pub struct ValueBuilder<T> {
    current: T,
}

impl ValueBuilder<SetValue> {
    pub(crate) fn new() -> Self {
        ValueBuilder { current: SetValue }
    }

    /// Set the initial value for the Characteristic value
    ///
    /// Whenever a client reads or writes to this value it is directly read from or written to.
    pub fn set_value<V>(self, value: V) -> ValueBuilder<SetPermissions<Trivial<V>>>
    where
        V: bo_tie_att::TransferFormatTryFrom + bo_tie_att::TransferFormatInto + PartialEq + Send + Sync + 'static,
    {
        let current = SetPermissions { value: Trivial(value) };

        ValueBuilder { current }
    }

    /// Set an initial, accessible value
    ///
    /// This value is accessed whenever a client reads or writes to it.
    pub fn set_accessible_value<A>(self, accessor: A) -> ValueBuilder<SetPermissions<A>>
    where
        A: AccessValue + 'static,
        A::ReadValue: TransferFormatInto + Comparable,
        A::WriteValue: TransferFormatTryFrom,
    {
        let current = SetPermissions { value: accessor };

        ValueBuilder { current }
    }
}

impl<V> ValueBuilder<SetPermissions<V>> {
    /// Set the Attribute permissions of the Characteristic value declaration
    pub fn set_permissions<P>(self, permissions: P) -> ValueBuilder<Complete<V>>
    where
        P: Borrow<[AttributePermissions]>,
    {
        let mut attribute_permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions> =
            LinearBuffer::new();

        unique_only!(attribute_permissions, permissions.borrow());

        let current = Complete {
            value: self.current.value,
            permissions: attribute_permissions,
        };

        ValueBuilder { current }
    }
}

impl<V> ValueBuilder<Complete<V>> {
    /// Set the characteristic uuid
    ///
    /// This method is called when constructing a Characteristic as the Characteristic UUID was
    /// already set by the user in the Characteristic declaration.
    pub(crate) fn set_characteristic_uuid(self, uuid: Uuid) -> ValueBuilder<TrueComplete<V>> {
        let current = TrueComplete {
            characteristic_uuid: uuid,
            value: self.current.value,
            permissions: self.current.permissions,
        };

        ValueBuilder { current }
    }
}

impl<A> AddCharacteristicComponent for ValueBuilder<TrueComplete<A>>
where
    A: AccessValue + 'static,
    A::ReadValue: TransferFormatInto + Comparable,
    A::WriteValue: TransferFormatTryFrom,
{
    fn push_to(self, sa: &mut ServerAttributes) -> bool {
        let attribute = Attribute::new(
            self.current.characteristic_uuid,
            self.current.permissions,
            self.current.value,
        );

        sa.push_accessor(attribute);

        true
    }
}

/// `ValueBuilder` marker type
///
/// This marker type is used for enabling the methods [`ValueBuilder::set_value`] and
/// [`ValueBuilder::set_accessible_value`].
///
/// [`ValueBuilder::set_value`]: ValueBuilder::<SetValue>::set_value
/// [`ValueBuilder::set_accessible_value`]: ValueBuilder::<SetValue>::set_accessible_value
pub struct SetValue;

/// `ValueBuilder` marker type
///
/// This marker type is used for enabling the method [`ValueBuilder::set_permissions`].
///
/// [`ValueBuilder::set_permissions`]: ValueBuilder::<SetPermissions>::set_permissions
pub struct SetPermissions<V> {
    value: V,
}

/// `ValueBuilder` marker type
///
/// This marks that a `ValueBuilder` is complete.
pub struct Complete<V> {
    value: V,
    permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
}

/// The *true* completion of a `ValueBuilder`
///
/// This is a marker type for the true completion of a the value declaration. This is not exposed
/// as part of the builder implementation as the characteristic UUID is set from the information
/// within a [`DeclarationBuilder`].
///
/// [`DeclarationBuilder`]: crate::characteristic::declaration::DeclarationBuilder
pub struct TrueComplete<V> {
    // This is un-hidden to help the explanation in the doc
    pub characteristic_uuid: Uuid,
    value: V,
    permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
}