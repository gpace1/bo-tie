use alloc::{
    vec::Vec,
    string::String,
    format,
};
use crate::{att, UUID};

/// Characteristic Properties
///
/// These are the properties that are part of the Characteristic Declaration
#[derive(Clone,Copy,PartialEq,PartialOrd,Eq,Ord,Debug)]
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
    fn into_val(&self) -> u8 {
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

    fn into_bit_field(properties: &[Self]) -> u8 {
        properties.iter().fold( 0u8, |u, p| u | p.into_val() )
    }

    fn from_bit_field(field: u8) -> Vec<Self> {
        let from_raw = |raw| {
            match raw {
                0x01 => Properties::Broadcast,
                0x02 => Properties::Read,
                0x04 => Properties::WriteWithoutResponse,
                0x08 => Properties::Write,
                0x10 => Properties::Notify,
                0x20 => Properties::Indicate,
                0x40 => Properties::AuthenticatedSignedWrite,
                0x80 => Properties::ExtendedProperties,
                _ => panic!("Impossibile bit field")
            }
        };

        let mut vec = Vec::new();

        for shift in 0..8 {
            vec.push(from_raw( field & (1 << shift)))
        }

        vec
    }
}

impl att::TransferFormatTryFrom for Vec<Properties> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 1 {
            Ok(Properties::from_bit_field(raw[0]))
        } else {
            Err(att::TransferFormatError::bad_size(stringify!(Box<[Properties]>), 1, raw.len()))
        }
    }
}

impl att::TransferFormatInto for Vec<Properties> {
    fn len_of_into(&self) -> usize { 1 }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        into_ret[0] = Properties::into_bit_field(self);
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
            Err(att::TransferFormatError::bad_min_size(stringify!(Declaration), 6, raw.len()))
        }
    }
}

impl att::TransferFormatInto for Declaration {
    fn len_of_into(&self) -> usize {
        3 + self.uuid.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        into_ret[0] = Properties::into_bit_field( &self.properties );

        into_ret[1..3].copy_from_slice( &self.value_handle.to_le_bytes() );

        self.uuid.build_into_ret( &mut into_ret[3..] )
    }
}

impl Declaration {

    const TYPE: UUID = UUID::from_u16(0x2803);

    const PERMISSIONS: &'static [att::AttributePermissions] = &[att::AttributePermissions::Read];
}

struct ValueDeclaration<V> {
    /// The attribute type
    att_type: UUID,
    /// The attribute value
    value: V,
    /// The attribute permissions
    permissions: Vec<att::AttributePermissions>,
}

#[derive(PartialEq)]
pub enum ExtendedProperties {
    ReliableWrite,
    WritableAuxiliaries
}

impl ExtendedProperties {
    const BIT_FIELD_CNT: usize = 2;
}

impl att::TransferFormatTryFrom for Vec<ExtendedProperties> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            let flags = <u16>::from_le_bytes([raw[0], raw[1]]);

            (0..ExtendedProperties::BIT_FIELD_CNT)
                .map(|shift| flags & (1 << shift) )
                .filter(|flag| flag != &0)
                .try_fold(Vec::new(), |mut v, flag| {
                    v.push( match flag {
                        0x1 => ExtendedProperties::ReliableWrite,
                        0x2 => ExtendedProperties::WritableAuxiliaries,
                        e => return Err(att::TransferFormatError::from(format!("Unknown Client Configuration '{}'", e)))
                    } );
                    Ok(v)
                })
        } else {
            Err(att::TransferFormatError::bad_size(stringify!(ExtendedProperties), 2, raw.len()))
        }
    }
}

impl att::TransferFormatInto for Vec<ExtendedProperties> {

    fn len_of_into(&self) -> usize { 2 }

    fn build_into_ret(&self, len_ret: &mut [u8] ) {
        len_ret[0] = self.iter().fold(0u8, |field, ep| {
            field | match ep {
                ExtendedProperties::ReliableWrite => 0x1,
                ExtendedProperties::WritableAuxiliaries => 0x2,
            }
        } );
    }
}

impl ExtendedProperties {
    const TYPE: UUID = UUID::from_u16(0x2803);

    const PERMISSIONS: &'static [att::AttributePermissions] = &[att::AttributePermissions::Read];
}

pub struct UserDescription {
    value: String,
    permissions: Vec<att::AttributePermissions>
}

impl UserDescription {
    const TYPE: UUID = UUID::from_u16(0x2901);

    pub fn new<D>(description: D, permissions: Vec<att::AttributePermissions>) -> Self
    where D: Into<String>
    {
        UserDescription {
            value: description.into(),
            permissions
        }
    }
}

#[derive(PartialEq)]
pub enum ClientConfiguration {
    Notification,
    Indication
}

impl att::TransferFormatTryFrom for Vec<ClientConfiguration> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            let flags = <u16>::from_le_bytes([raw[0], raw[1]]);

            (0..2).map(|shift| flags & (1 << shift) )
                .filter(|flag| flag != &0)
                .try_fold(Vec::new(), |mut v, flag| {
                    v.push( match flag {
                        0x1 => ClientConfiguration::Notification,
                        0x2 => ClientConfiguration::Indication,
                        e => return Err(att::TransferFormatError::from(format!("Unknown Client Configuration '{}'", e)))
                    } );
                    Ok(v)
                })

        } else {
            Err(att::TransferFormatError::bad_size(stringify!(ClientConfiguration), 2, raw.len()))
        }
    }
}

impl att::TransferFormatInto for ClientConfiguration {
    fn len_of_into(&self) -> usize { 2 }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        let val: u16 = match *self {
            ClientConfiguration::Notification => 0x1,
            ClientConfiguration::Indication => 0x2,
        };

        into_ret.copy_from_slice( &val.to_le_bytes() )
    }
}

impl ClientConfiguration {
    const TYPE: UUID = UUID::from_u16(2903);

    const PERMISSIONS: &'static [att::AttributePermissions] = &[
        att::AttributePermissions::Read,
        att::AttributePermissions::Authentication(att::AttributeRestriction::Write),
        att::AttributePermissions::Authorization(att::AttributeRestriction::Write)
    ];
}

#[derive(PartialEq)]
pub enum ServerConfiguration {
    Broadcast
}

impl att::TransferFormatTryFrom for Vec<ServerConfiguration> {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        if raw.len() == 2 {
            match <u16>::from_le_bytes([raw[0], raw[1]]) {
                0x1 => Ok(alloc::vec![ ServerConfiguration::Broadcast ] ),
                e @ _ => Err(att::TransferFormatError::from(
                    format!("Unknown server configuration: '{}'", e)))
            }
        } else {
            Err(att::TransferFormatError::bad_size(stringify!(ServerConfiguration), 2, raw.len()))
        }
    }
}

impl att::TransferFormatInto for ServerConfiguration {
    fn len_of_into(&self) -> usize { 2 }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let val: u16 = match *self {
            ServerConfiguration::Broadcast => 0x1,
        };

        into_ret.copy_from_slice( &val.to_le_bytes() )
    }
}

impl ServerConfiguration {
    const TYPE: UUID = UUID::from_u16(2903);

    const PERMISSIONS: &'static [att::AttributePermissions] = &[
        att::AttributePermissions::Read,
        att::AttributePermissions::Authentication(att::AttributeRestriction::Write),
        att::AttributePermissions::Authorization(att::AttributeRestriction::Write)
    ];
}

pub struct CharacteristicBuilder<'a, C, V> {
    characteristic_adder: super::CharacteristicAdder<'a>,
    declaration: Declaration,
    value_decl: ValueDeclaration<C>,
    ext_prop: Option<Vec<ExtendedProperties>>,
    user_desc: Option<UserDescription>,
    client_cfg: Option<Vec<ClientConfiguration>>,
    server_cfg: Option<Vec<ServerConfiguration>>,
    pd: core::marker::PhantomData<V>,
}

impl<'a, C, V> CharacteristicBuilder<'a, C, V>
where C: att::server::ServerAttributeValue<V> + Sized + Send + Sync + 'static,
      V: att::TransferFormatTryFrom + att::TransferFormatInto + Send + Sync + PartialEq + 'static,
{
    pub(super) fn new(
        characteristic_adder: super::CharacteristicAdder<'a>,
        properties: Vec<Properties>,
        uuid: UUID,
        value: C,
        value_permissions: Vec<att::AttributePermissions>
    ) -> Self
    {
        CharacteristicBuilder {
            characteristic_adder,
            declaration: Declaration {
                properties,
                value_handle: 0,
                uuid
            },
            value_decl: ValueDeclaration {
                att_type: uuid,
                value,
                permissions: value_permissions,
            },
            ext_prop: None,
            user_desc: None,
            client_cfg: None,
            server_cfg: None,
            pd: core::marker::PhantomData
        }
    }

    /// Instruct the builder to create a `Extended Properties` characteristic descriptor
    /// upon building the characteristic unless the value of `extended_properties` is `None`.
    #[inline]
    pub fn set_extended_properties<E>( mut self, extended_properties: E) -> Self
    where E: Into<Option<Vec<ExtendedProperties>>>
    {
        self.ext_prop = extended_properties.into();
        self
    }

    /// Instruct the builder to create a `User Description` characteristic descriptor
    /// upon building the characteristic unless the value of `user_description` is `None`.
    #[inline]
    pub fn set_user_description<D>( mut self, user_description: D) -> Self
    where D: Into<Option<UserDescription>>
    {
        self.user_desc = user_description.into();
        self
    }

    /// Instruct the builder to create a `Client Configuration` characteristic descriptor
    /// upon building the characteristic unless the value of `client_cfg` is `None`.
    #[inline]
    pub fn set_client_configuration<Cfg>( mut self, client_cfg: Cfg) -> Self
    where Cfg: Into<Option<Vec<ClientConfiguration>>>
    {
        self.client_cfg = client_cfg.into();
        self
    }

    /// Instruct the builder to create a `Server Configuration` characteristic descriptor
    /// upon building the characteristic unless the value of `server_cfg` is `None`.
    #[inline]
    pub fn set_server_configuration<Cfg>( mut self, server_cfg: Cfg) -> Self
    where Cfg: Into<Option<Vec<ServerConfiguration>>>
    {
        self.server_cfg = server_cfg.into();
        self
    }

    /// Finish constructing the Characteristic
    ///
    /// This will return the CharacteristicAdder that was used to make this CharacteristicBuilder.
    ///
    pub fn finish_characteristic(mut self) -> super::CharacteristicAdder<'a>
    {
        use att::Attribute;

        let attributes = &mut self.characteristic_adder.service_builder.server_builder.attributes;

        // The value handle will be the handle after the declaration
        self.declaration.value_handle = attributes.next_handle() + 1;

        let declaration = Attribute::new(
            Declaration::TYPE,
            Declaration::PERMISSIONS.into(),
            self.declaration
        );

        attributes.push(declaration);

        let value = Attribute::new(
            self.value_decl.att_type,
            self.value_decl.permissions,
            self.value_decl.value
        );

        // last_attr is handle value of the added attribute
        let mut last_attr = attributes.push(value);

        if let Some(ext) = self.ext_prop.take() {
            last_attr = attributes.push(
                Attribute::new(
                    ExtendedProperties::TYPE,
                    ExtendedProperties::PERMISSIONS.into(),
                    ext,
                )
            );
        }

        if let Some(desc) = self.user_desc.take() {
            last_attr = attributes.push(
                Attribute::new(
                    UserDescription::TYPE,
                    desc.permissions,
                    desc.value
                )
            );
        }

        if let Some(client_cfg) = self.client_cfg.take() {
            last_attr = attributes.push(
                Attribute::new(
                    ClientConfiguration::TYPE,
                    ClientConfiguration::PERMISSIONS.into(),
                    client_cfg
                )
            );
        }

        if let Some(server_cfg) = self.server_cfg.take() {
            last_attr = attributes.push(
                Attribute::new(
                    ServerConfiguration::TYPE,
                    ServerConfiguration::PERMISSIONS.into(),
                    server_cfg
                )
            );
        }

        self.characteristic_adder.end_group_handle =last_attr;

        self.characteristic_adder
    }
}
