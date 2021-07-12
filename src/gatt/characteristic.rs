use crate::{att, UUID};
use alloc::{format, string::String, vec::Vec};

/// Characteristic Properties
///
/// These are the properties that are part of the Characteristic Declaration
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
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

    fn from_bit_field(field: u8) -> Vec<Self> {
        let from_raw = |raw| match raw {
            0x01 => Properties::Broadcast,
            0x02 => Properties::Read,
            0x04 => Properties::WriteWithoutResponse,
            0x08 => Properties::Write,
            0x10 => Properties::Notify,
            0x20 => Properties::Indicate,
            0x40 => Properties::AuthenticatedSignedWrite,
            0x80 => Properties::ExtendedProperties,
            _ => panic!("Impossibile bit field"),
        };

        let mut vec = Vec::new();

        for shift in 0..8 {
            vec.push(from_raw(field & (1 << shift)))
        }

        vec
    }
}

impl att::TransferFormatTryFrom for Vec<Properties> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 1 {
            Ok(Properties::from_bit_field(raw[0]))
        } else {
            Err(att::TransferFormatError::bad_size(
                stringify!(Box<[Properties]>),
                1,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for Vec<Properties> {
    fn len_of_into(&self) -> usize {
        1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = Properties::slice_to_bit_field(self);
    }
}

#[derive(PartialEq)]
struct Declaration {
    properties: Vec<Properties>,
    value_handle: u16,
    uuid: UUID,
}

impl att::TransferFormatTryFrom for Declaration {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        // The implementation of TransferFormatTryFrom for UUID will check if the length is good for
        // a 128 bit UUID
        if raw.len() >= 6 {
            Ok(Declaration {
                properties: att::TransferFormatTryFrom::try_from(&raw[..1])?,
                value_handle: att::TransferFormatTryFrom::try_from(&raw[1..3])?,
                uuid: att::TransferFormatTryFrom::try_from(&raw[3..])?,
            })
        } else {
            Err(att::TransferFormatError::bad_min_size(
                stringify!(Declaration),
                6,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for Declaration {
    fn len_of_into(&self) -> usize {
        3 + self.uuid.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = Properties::slice_to_bit_field(&self.properties);

        into_ret[1..3].copy_from_slice(&self.value_handle.to_le_bytes());

        self.uuid.build_into_ret(&mut into_ret[3..])
    }
}

impl Declaration {
    const TYPE: UUID = UUID::from_u16(0x2803);

    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;
}

struct ValueDeclaration<'a, V> {
    /// The attribute type
    att_type: UUID,
    /// The attribute value
    value: V,
    /// The attribute permissions
    permissions: Option<&'a [att::AttributePermissions]>,
}

impl ValueDeclaration<'_, ()> {
    const DEFAULT_VALUE_PERMISSIONS: &'static [att::AttributePermissions] = &[];
}

#[derive(PartialEq)]
pub enum ExtendedProperties {
    ReliableWrite,
    WritableAuxiliaries,
}

impl ExtendedProperties {
    const BIT_FIELD_CNT: usize = 2;
}

impl att::TransferFormatTryFrom for Vec<ExtendedProperties> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            let flags = <u16>::from_le_bytes([raw[0], raw[1]]);

            (0..ExtendedProperties::BIT_FIELD_CNT)
                .map(|shift| flags & (1 << shift))
                .filter(|flag| flag != &0)
                .try_fold(Vec::new(), |mut v, flag| {
                    v.push(match flag {
                        0x1 => ExtendedProperties::ReliableWrite,
                        0x2 => ExtendedProperties::WritableAuxiliaries,
                        e => {
                            return Err(att::TransferFormatError::from(format!(
                                "Unknown Client Configuration '{}'",
                                e
                            )))
                        }
                    });
                    Ok(v)
                })
        } else {
            Err(att::TransferFormatError::bad_size(
                stringify!(ExtendedProperties),
                2,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for Vec<ExtendedProperties> {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, len_ret: &mut [u8]) {
        len_ret[0] = self.iter().fold(0u8, |field, ep| {
            field
                | match ep {
                    ExtendedProperties::ReliableWrite => 0x1,
                    ExtendedProperties::WritableAuxiliaries => 0x2,
                }
        });
    }
}

impl ExtendedProperties {
    const TYPE: UUID = UUID::from_u16(0x2900);

    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;
}

pub struct UserDescription<'a> {
    value: String,
    permissions: Option<&'a [att::AttributePermissions]>,
}

impl<'a> UserDescription<'a> {
    const TYPE: UUID = UUID::from_u16(0x2901);

    pub fn new<D, P>(description: D, permissions: P) -> Self
    where
        D: Into<String>,
        P: Into<Option<&'a [att::AttributePermissions]>>,
    {
        UserDescription {
            value: description.into(),
            permissions: permissions.into(),
        }
    }
}

#[derive(PartialEq)]
pub enum ClientConfiguration {
    Notification,
    Indication,
}

impl ClientConfiguration {
    /// Convert to native-endian bits
    fn to_bits(config: &[ClientConfiguration]) -> u16 {
        config.iter().fold(0u16, |bits, cfg| {
            bits | match cfg {
                ClientConfiguration::Notification => 1 << 0,
                ClientConfiguration::Indication => 1 << 1,
            }
        })
    }

    /// Convert from native-endian bits
    ///
    /// Bits that are specification defined as reserved are ignored
    fn from_bits(bits: u16) -> Vec<ClientConfiguration> {
        (0..2)
            .filter_map(|bit| match bits & 1 << bit {
                0x1 => Some(ClientConfiguration::Notification),
                0x2 => Some(ClientConfiguration::Indication),
                _ => None,
            })
            .collect()
    }
}

impl att::TransferFormatInto for Vec<ClientConfiguration> {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&ClientConfiguration::to_bits(self).to_le_bytes())
    }
}

impl att::TransferFormatTryFrom for Vec<ClientConfiguration> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            Ok(ClientConfiguration::from_bits(<u16>::from_le_bytes([raw[0], raw[1]])))
        } else {
            Err(att::TransferFormatError::bad_size(
                stringify!(ClientConfiguration),
                2,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for ClientConfiguration {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let val: u16 = match *self {
            ClientConfiguration::Notification => 0x1,
            ClientConfiguration::Indication => 0x2,
        };

        into_ret.copy_from_slice(&val.to_le_bytes())
    }
}

impl ClientConfiguration {
    const TYPE: UUID = UUID::from_u16(2902);

    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;
}

#[derive(PartialEq)]
pub enum ServerConfiguration {
    Broadcast,
}

impl ServerConfiguration {
    /// Convert to native-endian bits
    fn to_bits(config: &[ServerConfiguration]) -> u16 {
        config.iter().fold(0u16, |bits, cfg| {
            bits | match cfg {
                ServerConfiguration::Broadcast => 1 << 0,
            }
        })
    }

    /// Convert from native-endian bits
    ///
    /// Bits that are specification defined as reserved are ignored
    fn from_bits(bits: u16) -> Vec<ServerConfiguration> {
        (0..2)
            .filter_map(|bit| match bits & 1 << bit {
                0x1 => Some(ServerConfiguration::Broadcast),
                _ => None,
            })
            .collect()
    }
}

impl att::TransferFormatInto for Vec<ServerConfiguration> {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&ServerConfiguration::to_bits(self).to_le_bytes())
    }
}

impl att::TransferFormatTryFrom for Vec<ServerConfiguration> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            Ok(ServerConfiguration::from_bits(<u16>::from_le_bytes([raw[0], raw[1]])))
        } else {
            Err(att::TransferFormatError::bad_size(
                stringify!(ClientConfiguration),
                2,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for ServerConfiguration {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let val: u16 = match *self {
            ServerConfiguration::Broadcast => 0x1,
        };

        into_ret.copy_from_slice(&val.to_le_bytes())
    }
}

impl ServerConfiguration {
    const TYPE: UUID = UUID::from_u16(2903);

    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;
}

pub struct CharacteristicBuilder<'a, 'c, U, C, V> {
    characteristic_adder: super::CharacteristicAdder<'a>,
    properties: Vec<Properties>,
    uuid: Option<U>,
    value: Option<C>,
    value_permissions: &'c [att::AttributePermissions],
    ext_prop: Option<Vec<ExtendedProperties>>,
    ext_prop_permissions: Option<&'c [att::AttributePermissions]>,
    user_desc: Option<UserDescription<'c>>,
    client_cfg: Option<Vec<ClientConfiguration>>,
    client_cfg_permissions: Option<&'c [att::AttributePermissions]>,
    server_cfg: Option<Vec<ServerConfiguration>>,
    server_cfg_permissions: Option<&'c [att::AttributePermissions]>,
    pd: core::marker::PhantomData<V>,
}

impl<'a, 'c, U, C, V> CharacteristicBuilder<'a, 'c, U, C, V> {
    pub(super) fn new(characteristic_adder: super::CharacteristicAdder<'a>) -> Self {
        CharacteristicBuilder {
            characteristic_adder,
            properties: Vec::new(),
            uuid: None,
            value: None,
            value_permissions: &[],
            ext_prop: None,
            ext_prop_permissions: None,
            user_desc: None,
            client_cfg: None,
            client_cfg_permissions: None,
            server_cfg: None,
            server_cfg_permissions: None,
            pd: core::marker::PhantomData,
        }
    }
}

impl<'a, 'c, U, C, V> CharacteristicBuilder<'a, 'c, U, C, V>
where
    U: Into<UUID>,
    C: att::server::ServerAttributeValue<Value = V> + Sized + Send + 'static,
    V: att::TransferFormatTryFrom + att::TransferFormatInto + 'static,
{
    /// Set the value (Required)
    ///
    /// This is the value that is placed within the value descriptor.
    ///
    /// # Note
    /// This function must be called before `build_characteristic`
    pub fn set_value(mut self, value: C) -> Self {
        self.value = Some(value);

        self
    }

    /// Set the characteristic's UUID (Required)
    ///
    /// # Note
    /// This function must be called before `build_characteristic`
    pub fn set_uuid(mut self, uuid: U) -> Self {
        self.uuid = Some(uuid);

        self
    }

    /// Set the properties of the characteristic
    pub fn set_properties(mut self, properties: Vec<Properties>) -> Self {
        self.properties = properties;

        self
    }

    /// Set the permissions for accessing the *value*
    ///
    /// These are the attribute permissions for a client to access the value in the characteristic.
    ///
    /// # Note
    /// These permissions are assigned to the attribute containing the value characteristic
    /// descriptor, not any other attribute of the characteristic.
    pub fn set_permissions(mut self, permissions: &'c [att::AttributePermissions]) -> Self {
        self.value_permissions = permissions;

        self
    }

    /// Instruct the builder to create a `Extended Properties` characteristic descriptor
    /// upon building the characteristic unless the value of `extended_properties` is `None`.
    pub fn set_extended_properties<E, P>(mut self, extended_properties: E, permissions: P) -> Self
    where
        E: Into<Option<Vec<ExtendedProperties>>>,
        P: Into<Option<&'c [att::AttributePermissions]>>,
    {
        self.ext_prop = extended_properties.into();
        self.ext_prop_permissions = permissions.into();
        self
    }

    /// Instruct the builder to create a `User Description` characteristic descriptor
    /// upon building the characteristic unless the value of `user_description` is `None`.
    pub fn set_user_description<D>(mut self, user_description: D) -> Self
    where
        D: Into<Option<UserDescription<'c>>>,
    {
        self.user_desc = user_description.into();
        self
    }

    /// Instruct the builder to create a `Client Configuration` characteristic descriptor
    /// upon building the characteristic unless the value of `client_cfg` is `None`.
    pub fn set_client_configuration<Cfg, P>(mut self, client_cfg: Cfg, permissions: P) -> Self
    where
        Cfg: Into<Option<Vec<ClientConfiguration>>>,
        P: Into<Option<&'c [att::AttributePermissions]>>,
    {
        self.client_cfg = client_cfg.into();
        self.client_cfg_permissions = permissions.into();
        self
    }

    /// Instruct the builder to create a `Server Configuration` characteristic descriptor
    /// upon building the characteristic unless the value of `server_cfg` is `None`.
    pub fn set_server_configuration<Cfg, P>(mut self, server_cfg: Cfg, permissions: P) -> Self
    where
        Cfg: Into<Option<Vec<ServerConfiguration>>>,
        P: Into<Option<&'c [att::AttributePermissions]>>,
    {
        self.server_cfg = server_cfg.into();
        self.server_cfg_permissions = permissions.into();
        self
    }

    /// Build constructing the Characteristic
    ///
    /// This will return the CharacteristicAdder that was used to make this CharacteristicBuilder.
    pub fn complete_characteristic(mut self) -> super::CharacteristicAdder<'a> {
        use att::Attribute;

        let uuid = self.uuid.unwrap().into();

        let attributes = &mut self.characteristic_adder.service_builder.server_builder.attributes;

        let characteristic_declaration = Declaration {
            properties: self.properties,
            value_handle: attributes.next_handle() + 1,
            uuid,
        };

        let value_decl = ValueDeclaration {
            att_type: uuid,
            value: self.value.unwrap(),
            permissions: self.value_permissions.into(),
        };

        let declaration = Attribute::new(
            Declaration::TYPE,
            self.characteristic_adder
                .service_builder
                .default_permissions
                .unwrap_or(Declaration::DEFAULT_PERMISSIONS)
                .into(),
            characteristic_declaration,
        );

        attributes.push(declaration);

        let value = Attribute::new(
            value_decl.att_type,
            value_decl
                .permissions
                .or(self.characteristic_adder.service_builder.default_permissions)
                .unwrap_or(ValueDeclaration::DEFAULT_VALUE_PERMISSIONS)
                .into(),
            value_decl.value,
        );

        // last_attr is handle value of the added attribute
        attributes.push(value);

        if let Some(ext) = self.ext_prop.take() {
            attributes.push(Attribute::new(
                ExtendedProperties::TYPE,
                self.ext_prop_permissions
                    .or(self.characteristic_adder.service_builder.default_permissions)
                    .unwrap_or(ExtendedProperties::DEFAULT_PERMISSIONS)
                    .into(),
                ext,
            ));
        }

        if let Some(desc) = self.user_desc.take() {
            attributes.push(Attribute::new(
                UserDescription::TYPE,
                desc.permissions
                    .or(self.characteristic_adder.service_builder.default_permissions)
                    .unwrap_or(&[])
                    .into(),
                desc.value,
            ));
        }

        if let Some(client_cfg) = self.client_cfg.take() {
            attributes.push(Attribute::new(
                ClientConfiguration::TYPE,
                self.client_cfg_permissions
                    .or(self.characteristic_adder.service_builder.default_permissions)
                    .unwrap_or(ClientConfiguration::DEFAULT_PERMISSIONS)
                    .into(),
                client_cfg,
            ));
        }

        if let Some(server_cfg) = self.server_cfg.take() {
            attributes.push(Attribute::new(
                ServerConfiguration::TYPE,
                self.server_cfg_permissions
                    .or(self.characteristic_adder.service_builder.default_permissions)
                    .unwrap_or(ServerConfiguration::DEFAULT_PERMISSIONS)
                    .into(),
                server_cfg,
            ));
        }

        self.characteristic_adder.end_group_handle = attributes.next_handle() - 1;

        self.characteristic_adder
    }
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
        find_descriptor!(self, 2, ExtendedProperties::TYPE)
    }

    /// Get the handle to the user description descriptor
    ///
    /// This returns a handle if the user description exists for this characteristic.
    pub fn get_user_description_handle(&self) -> Option<u16> {
        find_descriptor!(self, 3, UserDescription::TYPE)
    }

    /// Get the handle to the client characteristic configuration descriptor
    ///
    /// This returns a handle if the client characteristic configuration exists for this
    /// characteristic.
    pub fn get_client_characteristic_configuration_handle(&self) -> Option<u16> {
        find_descriptor!(self, 4, ClientConfiguration::TYPE)
    }

    /// Get the handle to the server characteristic configuration descriptor
    ///
    /// This returns a handle if the server characteristic configuration exists for this
    /// characteristic.
    pub fn get_server_characteristic_configuration_handle(&self) -> Option<u16> {
        find_descriptor!(self, 5, ServerConfiguration::TYPE)
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

            if attr_info.get_uuid() == &Declaration::TYPE {
                match start {
                    None => start = Some(self.start_handle),
                    Some(handle) => {
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
