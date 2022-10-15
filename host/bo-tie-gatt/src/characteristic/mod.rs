//! GATT characteristic information
//!
//! Most of this module is integrated into the process of creating the services. See
//! [`ServerBuilder`].
//!
//! [`ServerBuilder`]: crate::ServerBuilder

pub(crate) mod client_config;
pub(crate) mod declaration;
pub(crate) mod extended_properties;
pub(crate) mod server_config;
pub(crate) mod user_description;
pub(crate) mod value;

pub use crate::characteristic::client_config::{ClientConfiguration, ClientConfigurationBuilder};
pub use crate::characteristic::declaration::DeclarationBuilder;
pub use crate::characteristic::extended_properties::{ExtendedProperties, ExtendedPropertiesBuilder};
pub use crate::characteristic::server_config::{ServerConfiguration, ServerConfigurationBuilder};
pub use crate::characteristic::user_description::UserDescriptionBuilder;
pub use crate::characteristic::value::ValueBuilder;
use crate::Uuid;
use bo_tie_util::buffer::stack::LinearBuffer;

/// A vector growable up to `SIZE`
///
/// This is a wrapper around a [`LinearBuffer`]. Its used for implementing [`AccessValue`] and
/// [`AccessReadOnly`] for some of the attribute values of a Characteristic.
///
/// [`AccessValue`]: bo_tie_att::server::AccessValue
/// [`AccessReadOnly`]: bo_tie_att::server::AccessReadOnly
#[derive(Clone, PartialEq)]
pub struct VecArray<const SIZE: usize, T>(pub LinearBuffer<SIZE, T>);
/// Characteristic Properties
///
/// These are the properties that are part of the Characteristic Declaration
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, bo_tie_macros::DepthCount)]
pub enum Properties {
    Broadcast,
    Read,
    WriteWithoutResponse,
    Write,
    Notify,
    Indicate,
    AuthenticatedSignedWrite,
    ExtendedProperties,
}

impl Properties {
    fn to_val(&self) -> u8 {
        match *self {
            Properties::Broadcast => 1 << 0,
            Properties::Read => 1 << 1,
            Properties::WriteWithoutResponse => 1 << 2,
            Properties::Write => 1 << 3,
            Properties::Notify => 1 << 4,
            Properties::Indicate => 1 << 5,
            Properties::AuthenticatedSignedWrite => 1 << 6,
            Properties::ExtendedProperties => 1 << 7,
        }
    }

    fn slice_to_bit_field(properties: &[Self]) -> u8 {
        properties.iter().fold(0u8, |u, p| u | p.to_val())
    }

    fn from_bit_field(field: u8) -> LinearBuffer<{ Properties::full_depth() }, Self> {
        let from_raw = |raw| match raw {
            0x01 => Properties::Broadcast,
            0x02 => Properties::Read,
            0x04 => Properties::WriteWithoutResponse,
            0x08 => Properties::Write,
            0x10 => Properties::Notify,
            0x20 => Properties::Indicate,
            0x40 => Properties::AuthenticatedSignedWrite,
            0x80 => Properties::ExtendedProperties,
            _ => unreachable!(),
        };

        let mut buffer = LinearBuffer::new();

        for shift in 0..Properties::full_depth() {
            buffer.try_push(from_raw(field & (1 << shift))).unwrap()
        }

        buffer
    }
}

/// The builder type for a characteristic
pub struct CharacteristicBuilder<'a, D, V, E, U, C, S> {
    characteristic_adder: super::CharacteristicAdder<'a>,
    declaration_builder: DeclarationBuilder<D>,
    value_builder: ValueBuilder<V>,
    extended_properties_builder: ExtendedPropertiesBuilder<E>,
    user_description_builder: UserDescriptionBuilder<U>,
    client_configuration_builder: ClientConfigurationBuilder<C>,
    server_configuration_builder: ServerConfigurationBuilder<S>,
}

impl<'a>
    CharacteristicBuilder<
        'a,
        declaration::SetProperties,
        value::SetValue,
        extended_properties::SetExtendedProperties,
        user_description::SetDescription,
        client_config::ReadOnlyClientConfiguration,
        server_config::SetConfiguration,
    >
{
    pub(super) fn new(characteristic_adder: super::CharacteristicAdder<'a>) -> Self {
        CharacteristicBuilder {
            characteristic_adder,
            declaration_builder: DeclarationBuilder::new(),
            value_builder: ValueBuilder::new(),
            extended_properties_builder: ExtendedPropertiesBuilder::new(),
            user_description_builder: UserDescriptionBuilder::new(),
            client_configuration_builder: ClientConfigurationBuilder::new(),
            server_configuration_builder: ServerConfigurationBuilder::new(),
        }
    }
}

impl<'a, D, V, E, U, C, S> CharacteristicBuilder<'a, D, V, E, U, C, S> {
    /// Set the Characteristic declaration (must be called)
    ///
    /// This method must be called before a characteristic can be constructed.
    ///
    /// The input is a closure used to create a completed value builder. A `DeclarationBuilder` must
    /// be built through type-stages progressed through by methods calls. This diagram shows the
    /// possible paths in creating a complete `DeclarationBuilder` from the closure input into the
    /// closure output.
    #[cfg_attr(doc, aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart LR
    ///     A{{input}} --> B
    ///     subgraph a[constructor]
    ///     B(DeclarationBuilder::set_properties) --> C
    ///     end
    ///     C(DeclarationBuilder::set_uuid) --> D
    ///     D{{output}}
    /// ```
    ///
    /// ```rust
    /// use bo_tie_gatt::characteristic::Properties;
    /// # use bo_tie_gatt::ServerBuilder;
    /// # let mut sb = ServerBuilder::new_empty();
    /// # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
    /// # let characteristic_builder = characteristic_builder.set_value(|b| b.set_value(1234).set_permissions([]));
    ///
    /// characteristic_builder.set_declaration(|declaration_builder| {
    ///     declaration_builder.set_properties([Properties::Read, Properties::Write])
    ///     .set_uuid(0x1234u16)
    /// })
    /// # });
    /// ```
    pub fn set_declaration<F>(self, constructor: F) -> CharacteristicBuilder<'a, declaration::Complete, V, E, U, C, S>
    where
        F: FnOnce(DeclarationBuilder<declaration::SetProperties>) -> DeclarationBuilder<declaration::Complete>,
    {
        let declaration_builder = constructor(DeclarationBuilder::new());

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder,
            value_builder: self.value_builder,
            extended_properties_builder: self.extended_properties_builder,
            user_description_builder: self.user_description_builder,
            client_configuration_builder: self.client_configuration_builder,
            server_configuration_builder: self.server_configuration_builder,
        }
    }

    /// Set the Characteristic value declaration (must be called)
    ///
    /// This method must be called before a characteristic can be constructed.
    ///
    /// The input is a closure used to create a completed value builder. A `ValueBuilder` must be
    /// built through type-stages progressed through by methods calls. This diagram shows the
    /// possible paths in creating a complete `ValueBuilder` from the closure input into the closure
    /// output.
    ///
    #[cfg_attr(doc, aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart LR
    ///     A{{input}}-->B(ValueBuilder::set_value) & C(ValueBuilder::set_accessible_value)
    ///     subgraph a[constructor]
    ///     B(ValueBuilder::set_value) & C(ValueBuilder::set_accessible_value) -->D(set_permissions)
    ///     end
    ///     D(ValueBuilder::set_permissions)-->E{{output}}
    /// ```
    ///
    /// ```rust
    /// use bo_tie_att::{AttributePermissions, AttributeRestriction};
    /// use bo_tie_gatt::characteristic::Properties;
    /// # use bo_tie_gatt::ServerBuilder;
    /// # let mut sb = ServerBuilder::new_empty();
    /// # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
    ///
    /// characteristic_builder.set_declaration(|declaration_builder| {
    ///     declaration_builder.set_properties([Properties::Read])
    ///         .set_uuid(1u16)
    /// })
    /// .set_value(|builder| {
    ///     builder.set_value(1234)
    ///         .set_permissions([AttributePermissions::Read(AttributeRestriction::None)])
    /// })
    /// # });
    /// ```
    pub fn set_value<T, F>(self, constructor: F) -> CharacteristicBuilder<'a, D, value::Complete<T>, E, U, C, S>
    where
        F: FnOnce(ValueBuilder<value::SetValue>) -> ValueBuilder<value::Complete<T>>,
    {
        let value_builder = constructor(ValueBuilder::new());

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder: self.declaration_builder,
            value_builder,
            extended_properties_builder: self.extended_properties_builder,
            user_description_builder: self.user_description_builder,
            client_configuration_builder: self.client_configuration_builder,
            server_configuration_builder: self.server_configuration_builder,
        }
    }

    /// Add an extended properties descriptor
    ///
    /// This adds an extended properties descriptor to the Characteristic. This descriptor is
    /// optional and this method does not need to be called to construct the Characteristic.
    ///
    /// The input is a closure used to create a completed value builder. An
    /// `ExtendedPropertiesBuilder` must be built through type-stages progressed through by methods
    /// calls. This diagram shows the possible paths in creating a complete
    /// `ExtendedPropertiesBuilder` from the closure input into the closure output.
    ///
    #[cfg_attr(doc, aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart LR
    ///     A{{input}} --> B
    ///     subgraph a[constructor]
    ///     B(ExtendedPropertiesBuilder::set_extended_properties)
    ///     end
    ///     B --> D
    ///     D{{output}}
    /// ```
    ///
    /// ```rust
    /// use bo_tie_gatt::characteristic::{ExtendedProperties, Properties};
    /// # use bo_tie_gatt::ServerBuilder;
    /// # let mut sb = ServerBuilder::new_empty();
    /// # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
    /// # let characteristic_builder = characteristic_builder.set_value(|b| b.set_value(0).set_permissions([])).set_declaration(|d| d.set_properties([]).set_uuid(1u16));
    ///
    /// characteristic_builder.set_declaration(|declaration_builder| {
    ///     declaration_builder.set_properties([Properties::ExtendedProperties])
    ///     .set_uuid(0x1234u16)
    /// }).set_extended_properties(|ext_prop_builder| {
    ///     ext_prop_builder.set_extended_properties([ExtendedProperties::ReliableWrite])
    /// })
    /// # });
    /// ```
    pub fn set_extended_properties<F>(
        self,
        constructor: F,
    ) -> CharacteristicBuilder<'a, D, V, extended_properties::Complete, U, C, S>
    where
        F: FnOnce(
            ExtendedPropertiesBuilder<extended_properties::SetExtendedProperties>,
        ) -> ExtendedPropertiesBuilder<extended_properties::Complete>,
    {
        let extended_properties_builder = constructor(ExtendedPropertiesBuilder::new());

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder: self.declaration_builder,
            value_builder: self.value_builder,
            extended_properties_builder,
            user_description_builder: self.user_description_builder,
            client_configuration_builder: self.client_configuration_builder,
            server_configuration_builder: self.server_configuration_builder,
        }
    }

    /// Add an user description descriptor
    ///
    /// This adds a user description descriptor to the Characteristic. This descriptor is
    /// optional and this method does not need to be called to construct the Characteristic.
    ///
    /// The input is a closure used to create a completed value builder. A `UserDescriptionBuilder`
    /// must be built through type-stages progressed through by methods calls. This diagram shows
    /// the possible paths in creating a complete `UserDescriptionBuilder` from the closure input
    /// into the closure output.
    ///
    #[cfg_attr(doc, aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart LR
    ///     A{{input}} --> B & C & D
    ///     subgraph a[constructor]
    ///     B(UserDescriptionBuilder::read_only) --> F
    ///     C(UserDescriptionBuilder::set_description) --> E
    ///     D(UserDescriptionBuilder::set_accessible_description) --> E
    ///     F(UserDescriptionBuilder::set_read_only_description) --> G
    ///     end
    ///     E(UserDescriptionBuilder::set_permissions) --> H
    ///     G(UserDescriptionBuilder::set_read_only_restrictions) --> H
    ///     H{{output}}
    /// ```
    ///
    /// ```rust
    /// # use bo_tie_att::AttributeRestriction;
    /// # use bo_tie_gatt::ServerBuilder;
    /// # let mut sb = ServerBuilder::new_empty();
    /// # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
    /// # let characteristic_builder = characteristic_builder
    /// #    .set_declaration(|d| d.set_properties([]).set_uuid(1u16))
    /// #    .set_value(|v| v.set_value(0u16).set_permissions([]));
    ///
    /// characteristic_builder.set_user_description(|user_desc_builder| {
    ///     user_desc_builder.read_only()
    ///         .set_read_only_description("My Services Characteristic")
    ///         .set_read_only_restrictions([AttributeRestriction::None])
    /// })
    /// # });
    /// ```
    pub fn set_user_description<F, T>(
        self,
        constructor: F,
    ) -> CharacteristicBuilder<'a, D, V, E, user_description::Complete<T>, C, S>
    where
        F: FnOnce(
            UserDescriptionBuilder<user_description::SetDescription>,
        ) -> UserDescriptionBuilder<user_description::Complete<T>>,
    {
        let user_description_builder = constructor(UserDescriptionBuilder::new());

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder: self.declaration_builder,
            value_builder: self.value_builder,
            extended_properties_builder: self.extended_properties_builder,
            user_description_builder,
            client_configuration_builder: self.client_configuration_builder,
            server_configuration_builder: self.server_configuration_builder,
        }
    }

    /// Add a client configuration descriptor
    ///
    /// This adds a user description descriptor to the Characteristic. This descriptor is
    /// optional and this method does not need to be called to construct the Characteristic.
    ///
    /// The input closure is provided the builder for the client configuration descriptor. A
    /// `ClientConfigurationBuilder` cannot be created so the input to the closure must eventually
    /// be output by the closure (event when no changes are needed).
    ///
    /// ```
    /// use bo_tie_gatt::characteristic::{ClientConfiguration, Properties};
    /// # use bo_tie_att::AttributeRestriction;
    /// # use bo_tie_gatt::ServerBuilder;
    /// # let mut sb = ServerBuilder::new_empty();
    /// # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
    /// # let characteristic_builder = characteristic_builder
    /// #    .set_declaration(|d| d.set_properties([]).set_uuid(1u16))
    /// #    .set_value(|v| v.set_value(0u16).set_permissions([]));
    ///
    /// async fn on_client_config(_: &[ClientConfiguration]) {
    ///     // enable or disable notifications and indications
    /// }
    ///
    /// characteristic_builder.set_declaration(|declaration_builder| {
    ///     declaration_builder.set_properties([Properties::Notify, Properties::Indicate])
    ///         .set_uuid(0x1234u16)
    /// }).set_client_configuration(|client_config_builder| {
    ///     client_config_builder
    ///         .set_config([ClientConfiguration::Notification, ClientConfiguration::Indication])
    ///         .set_write_callback(|client_config| async move { on_client_config(&client_config).await })
    /// })
    /// # });
    /// ```
    pub fn set_client_configuration<F, T>(self, f: F) -> CharacteristicBuilder<'a, D, V, E, U, T, S>
    where
        F: FnOnce(
            ClientConfigurationBuilder<client_config::ReadOnlyClientConfiguration>,
        ) -> ClientConfigurationBuilder<T>,
    {
        let client_configuration_builder = f(ClientConfigurationBuilder::new());

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder: self.declaration_builder,
            value_builder: self.value_builder,
            extended_properties_builder: self.extended_properties_builder,
            user_description_builder: self.user_description_builder,
            client_configuration_builder,
            server_configuration_builder: self.server_configuration_builder,
        }
    }

    /// Add an user description descriptor
    ///
    /// This adds a user description descriptor to the Characteristic. This descriptor is
    /// optional and this method does not need to be called to construct the Characteristic.
    ///
    /// When there can be multiple clients sharing access to this Characteristic, a
    /// `ServerConfigurationBuilder` should be created once, have the configuration value set, and
    /// cloned within every `constructor`. The configuration should also be wrapped within some kind
    /// of shared reference, and be lockable if any client can write to it. This diagram shows a
    /// possible paths in creating a complete `ServerConfigurationBuilder` from  [`new`] to the type
    /// returned by `constructor`.
    #[cfg_attr(doc, aquamarine::aquamarine)]
    /// ```mermaid
    /// flowchart LR
    ///     subgraph once
    ///     A(ServerConfigurationBuilder::new) --> B
    ///     end
    ///     B(ServerConfigurationBuilder::set_config) --> C
    ///     subgraph c["in constructor or also once"]
    ///     C(ServerConfigurationBuilder::set_permissions)
    ///     end
    ///     C --> D
    ///     D{{output}}
    /// ```
    ///
    #[cfg_attr(
        feature = "tokio",
        doc = r##"
```
 // note: using feature "tokio"
 use std::sync::Arc;
 use tokio::sync::Mutex;
 use bo_tie_gatt::characteristic::{ServerConfiguration, ServerConfigurationBuilder, Properties};
 use bo_tie_att::{AttributePermissions, AttributeRestriction};
 # use bo_tie_gatt::ServerBuilder;
 # let mut sb = ServerBuilder::new_empty();
 # let characteristic_builder = sb.new_service(0u16, true).add_characteristics().new_characteristic(|characteristic_builder| {
 # let characteristic_builder = characteristic_builder
 #    .set_declaration(|d| d.set_properties([]).set_uuid(1u16))
 #    .set_value(|v| v.set_value(0u16).set_permissions([]));

 let server_config = ServerConfigurationBuilder::new()
    .set_config(Arc::new(Mutex::new(ServerConfiguration::new())))
    .set_permissions([
        AttributePermissions::Read(AttributeRestriction::None),
        AttributePermissions::Write(AttributeRestriction::Authorization)
    ]);

 characteristic_builder.set_declaration(|declaration_builder| {
     declaration_builder.set_properties([Properties::Notify, Properties::Indicate])
         .set_uuid(0x1234u16)
 }).set_server_configuration(|| {
     server_config.clone() 
 })
 # });
```
"##
    )]
    /// [`Server`]: crate::Server
    pub fn set_server_configuration<F, T>(
        self,
        constructor: F,
    ) -> CharacteristicBuilder<'a, D, V, E, U, C, server_config::Complete<T>>
    where
        F: FnOnce() -> ServerConfigurationBuilder<server_config::Complete<T>>,
    {
        let server_configuration_builder = constructor();

        CharacteristicBuilder {
            characteristic_adder: self.characteristic_adder,
            declaration_builder: self.declaration_builder,
            value_builder: self.value_builder,
            extended_properties_builder: self.extended_properties_builder,
            user_description_builder: self.user_description_builder,
            client_configuration_builder: self.client_configuration_builder,
            server_configuration_builder,
        }
    }
}

impl<'a, V, E, U, C, S> CharacteristicBuilder<'a, declaration::Complete, value::Complete<V>, E, U, C, S>
where
    ValueBuilder<value::TrueComplete<V>>: AddCharacteristicComponent,
    ExtendedPropertiesBuilder<E>: AddCharacteristicComponent,
    UserDescriptionBuilder<U>: AddCharacteristicComponent,
    ClientConfigurationBuilder<C>: AddCharacteristicComponent,
    ServerConfigurationBuilder<S>: AddCharacteristicComponent,
{
    /// Construct the Characteristic
    ///
    /// The characteristic will be constructed and the `CharacteristicAdder` will be returned.
    ///
    /// # Panic
    /// If any of the required builder methods were not called this will panic
    pub(crate) fn complete_characteristic(mut self) -> super::CharacteristicAdder<'a> {
        let server_attributes = &mut self.characteristic_adder.service_builder.server_builder.attributes;

        let declaration_builder = self
            .declaration_builder
            .set_value_handle(server_attributes.next_handle() + 1);

        let characteristic_uuid = declaration_builder.get_uuid();

        let value_builder = self.value_builder.set_characteristic_uuid(characteristic_uuid);

        let mut att_count = 2;

        assert!(declaration_builder.push_to(server_attributes));

        assert!(value_builder.push_to(server_attributes));

        if self.extended_properties_builder.push_to(server_attributes) {
            att_count += 1
        }

        if self.user_description_builder.push_to(server_attributes) {
            att_count += 1
        }

        if self.client_configuration_builder.push_to(server_attributes) {
            att_count += 1
        }

        if self.server_configuration_builder.push_to(server_attributes) {
            att_count += 1
        }

        self.characteristic_adder.end_group_handle += att_count;

        self.characteristic_adder
    }
}

/// A trait for adding characteristic component to a list of attributes
pub trait AddCharacteristicComponent {
    fn push_to(self, sa: &mut bo_tie_att::server::ServerAttributes) -> bool;
}

/// GATT Characteristic information
///
/// Information about a created Characteristic of a Service. This can be obtained with using the
/// method `iter_characteristics` of [`Service`](super::Service).
///
/// This is mainly useful for getting the handle to the characteristic value
pub struct Characteristic<'a> {
    server_attributes: &'a crate::att::server::ServerAttributes,
    handle: u16,
    end_handle: u16,
}

macro_rules! find_descriptor {
    ($characteristic:expr, $offset:expr, $attribute_type:path ) => {{
        let possible_handles = $characteristic.handle + $offset;

        let last_handle = core::cmp::min(possible_handles, $characteristic.end_handle);

        // Iterates over the attributes, skipping characteristic declaration and value attributes.
        $characteristic
            .server_attributes
            .iter_info_ranged(($characteristic.handle + 2)..last_handle)
            .find_map(|a| (a.get_uuid() == &$attribute_type).then(|| a.get_handle()))
    }};
}

impl Characteristic<'_> {
    /// Get the UUID of the characteristic's value
    pub fn get_uuid(&self) -> Uuid {
        *self
            .server_attributes
            .get_info(self.get_value_handle())
            .unwrap()
            .get_uuid()
    }

    /// Get the handle to the declaration
    ///
    /// # Note
    /// This is the starting handle for the characteristic
    pub fn get_declaration_handle(&self) -> u16 {
        self.handle
    }

    /// Get the handle to the last attribute within this characteristic
    pub fn get_end_handle(&self) -> u16 {
        self.end_handle
    }

    /// Get the handle to the characteristic value descriptor
    pub fn get_value_handle(&self) -> u16 {
        // The value declaration is always the next handle for this server implementation
        self.handle + 1
    }

    /// Get the handle to the extended properties descriptor
    ///
    /// This returns a handle if a extended properties exists for this characteristic.
    pub fn get_extended_properties_handle(&self) -> Option<u16> {
        find_descriptor!(self, 2, extended_properties::TYPE)
    }

    /// Get the handle to the user description descriptor
    ///
    /// This returns a handle if the user description exists for this characteristic.
    pub fn get_user_description_handle(&self) -> Option<u16> {
        find_descriptor!(self, 3, user_description::TYPE)
    }

    /// Get the handle to the client characteristic configuration descriptor
    ///
    /// This returns a handle if the client characteristic configuration exists for this
    /// characteristic.
    pub fn get_client_characteristic_configuration_handle(&self) -> Option<u16> {
        find_descriptor!(self, 4, client_config::TYPE)
    }

    /// Get the handle to the server characteristic configuration descriptor
    ///
    /// This returns a handle if the server characteristic configuration exists for this
    /// characteristic.
    pub fn get_server_characteristic_configuration_handle(&self) -> Option<u16> {
        find_descriptor!(self, 5, server_config::TYPE)
    }
}

pub(super) struct CharacteristicsIter<'a> {
    server_attributes: &'a crate::att::server::ServerAttributes,
    start_handle: u16,
    end_handle: u16,
}

impl<'a> CharacteristicsIter<'a> {
    pub fn new(
        server_attributes: &'a crate::att::server::ServerAttributes,
        service_start_handle: u16,
        service_end_handle: u16,
    ) -> Self {
        Self {
            server_attributes,
            start_handle: service_start_handle,
            end_handle: service_end_handle,
        }
    }
}

impl<'a> Iterator for CharacteristicsIter<'a> {
    type Item = Characteristic<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut start: Option<u16> = None;

        while self.start_handle <= self.end_handle {
            let attr_info = self.server_attributes.get_info(self.start_handle).unwrap();

            if attr_info.get_uuid() == &declaration::TYPE {
                match start {
                    None => start = Some(self.start_handle),
                    Some(handle) => {
                        self.start_handle += 1;

                        return Some(Characteristic {
                            server_attributes: self.server_attributes,
                            handle,
                            end_handle: self.start_handle,
                        });
                    }
                };
            } else {
                self.start_handle += 1
            }
        }

        None
    }
}
