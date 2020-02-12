use alloc::{
    boxed::Box,
    vec::Vec,
};
use crate::{ att, l2cap, UUID};
use crate::att::TransferFormatInto;

pub mod characteristic;

struct ServiceDefinition;

impl ServiceDefinition {
    /// The permissions of the service definitions is just Read Only
    const PERMISSIONS: &'static [att::AttributePermissions] = &[att::AttributePermissions::Read];

    /// The primary service UUID
    const PRIMARY_SERVICE_TYPE: UUID = UUID::from_u16(0x2800);

    /// The secondary service UUID
    const SECONDARY_SERVICE_TYPE: UUID = UUID::from_u16(0x2801);
}

#[derive(PartialEq)]
struct ServiceInclude {
    service_handle: u16,
    end_group_handle: u16,
    short_service_type: Option<u16>,
}

impl att::TransferFormatTryFrom for ServiceInclude {
    fn try_from(raw: &[u8]) -> Result<Self, att::TransferFormatError> {
        // The implementation of TransferFormatTryFrom for UUID will check if the length is good for
        // a 128 bit UUID
        if raw.len() >= 6 {
            Ok(ServiceInclude {
                service_handle: att::TransferFormatTryFrom::try_from(&raw[..2])?,
                end_group_handle: att::TransferFormatTryFrom::try_from(&raw[2..4])?,
                short_service_type: if raw[4..].len() == 2 {
                    // Only 16 Bluetooth UUIDs are included with a Include Definition

                    Some(att::TransferFormatTryFrom::try_from(&raw[4..])?)
                } else if raw[4..].len() == 0 {
                    None
                } else {
                    return Err(att::TransferFormatError::from(
                        concat!("Invalid short service type in ", stringify!("ServiceInclude"))))
                },
            })
        } else {
            Err(att::TransferFormatError::bad_min_size(stringify!(ServiceInclude),
                                                       6, raw.len()))
        }
    }
}

impl att::TransferFormatInto for ServiceInclude {
    fn len_of_into(&self) -> usize {
        4 + if self.short_service_type.is_some() { 2 } else { 0 }
    }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        into_ret[..2].copy_from_slice( &self.service_handle.to_le_bytes() );

        into_ret[2..4].copy_from_slice( &self.end_group_handle.to_le_bytes() );

        if let Some(ty) = self.short_service_type {
            into_ret[4..].copy_from_slice( &ty.to_le_bytes() );
        }
    }
}

impl ServiceInclude {
    const TYPE: UUID = UUID::from_u16(0x2802);

    const PERMISSIONS: &'static [att::AttributePermissions] = &[att::AttributePermissions::Read];
}

pub struct ServiceBuilder<'a>
{
    service_type: UUID,
    /// The list of primary services. This is none if the service builder is constructing a
    /// secondary service.
    is_primary: bool,
    handle: u16,
    server_builder: &'a mut ServerBuilder,
}

impl<'a> ServiceBuilder<'a>
{
    fn new(
        server_builder: &'a mut ServerBuilder,
        service_type: UUID,
        is_primary: bool
    ) -> Self
    {
        let handle = server_builder.attributes.push(
            att::Attribute::new(
                if is_primary {
                    ServiceDefinition::PRIMARY_SERVICE_TYPE
                } else {
                    ServiceDefinition::SECONDARY_SERVICE_TYPE
                },
                ServiceDefinition::PERMISSIONS.into(),
                service_type
            )
        );

        ServiceBuilder { service_type, is_primary, handle, server_builder }
    }

    /// Start including other services
    ///
    /// This converts a `Service Builder` into a `IncludesAdder`. The returned `IncludesAdder`
    /// will allow for the addition of include definitions for other services. Afterwards an
    /// `IncludesAdder` can be further converted into a `CharacteristicAdder`
    pub fn into_includes_adder(self) -> IncludesAdder<'a> {
        IncludesAdder::new(self)
    }

    /// Start adding characteristics
    ///
    /// This converts a `Service Builder` into a `CharacteristicAdder`. Use this function when the
    /// service includes no other services. This will create a
    /// characteristic adder that can be used to add characteristics after the service difinition
    /// attribute. It is not possible to add includes to other services if this function is used.
    ///
    /// If you wish to create a service that includes other services, use the
    /// `[into_includes_adder](#add_service_includes)`
    /// function. That function will return a `IncludesAdder` which can be then converted into
    /// a `CharacteristicAdder` for adding characteristics to the service.
    pub fn into_characteristics_adder(self) -> CharacteristicAdder<'a> {
        let handle = self.handle;
        CharacteristicAdder::new(self, handle)
    }

    /// Create an empty service
    ///
    /// This will create a service with no include definitions or characteristics. This means that
    /// the service will contain no data other then what is in the service definition. As a result
    /// an empty service will only contain its UUID.
    pub fn make_empty(mut self) -> Service {
        // There is only one handle in an empty Service so both the service handle and end group
        // handle are the same
        self.make_service(self.handle)
    }

    fn make_service(&mut self, end_service_handle: u16 ) -> Service {

        let service = Service::new( self.handle, end_service_handle, self.service_type);

        if self.is_primary { self.server_builder.add_primary_service(service)}

        service
    }
}


/// Add Include Definition(s) to the service
///
/// The service that will contain the include definition(s) is the same service that was initially
/// constructing with ServiceBuilder.
///
/// This is created by the
/// `[into_includes_adder](../ServiceBuilder/index.html#into_includes_adder)`
/// function.
pub struct IncludesAdder<'a>
{
    service_builder: ServiceBuilder<'a>,
    end_group_handle: u16
}

impl<'a> IncludesAdder<'a>
{
    fn new( service_builder: ServiceBuilder<'a>)
    -> Self
    {
        let handle = service_builder.handle;

        IncludesAdder {
            service_builder,
            end_group_handle: handle,
        }
    }

    /// Add a service to include
    pub fn include_service( mut self, service: &Service ) -> Self {
        use core::convert::TryInto;

        let include = ServiceInclude {
            service_handle: service.service_handle,
            end_group_handle: service.end_group_handle,
            short_service_type: service.service_type.try_into().ok()
        };

        let attribute = att::Attribute::new(
            ServiceInclude::TYPE,
            ServiceInclude::PERMISSIONS.into(),
            include
        );

        self.end_group_handle = self.service_builder.server_builder.attributes.push(attribute);

        self
    }

    /// Convert to a CharacteristicAdder
    pub fn into_characteristics_adder(self) -> CharacteristicAdder<'a> {
        CharacteristicAdder::new(
            self.service_builder,
            self.end_group_handle
        )
    }

    /// Finish the service
    ///
    /// This will create a service that only has the service definition and service includes (if
    /// any). There will be no characteristics added to the service.
    pub fn finish_service(mut self) -> Service {

        self.service_builder.make_service(self.end_group_handle)
    }
}

/// Add characteristics to a service
///
/// The service that will contain the characteristic(s) is the same service that was initially
/// constructing with ServiceBuilder.
///
/// This is created by the
/// [`ServiceBuilder::into_characteristics_adder`](bo_tie::gatt::ServiceBuilder::into_characteristics_adder)
/// or
/// [`IncludesAdder::into_characteristics_adder`](bo_tie::gatt::IncludesAdder::into_characteristics_adder)
/// functions.
pub struct CharacteristicAdder<'a>
{
    service_builder: ServiceBuilder<'a>,
    end_group_handle: u16
}

impl<'a> CharacteristicAdder<'a>
{
    fn new(
        service_builder: ServiceBuilder<'a>,
        end_group_handle: u16,
    ) -> Self
    {
        CharacteristicAdder { service_builder, end_group_handle }
    }

    pub fn build_characteristic<C,V>(
        self,
        properties: Vec<characteristic::Properties>,
        uuid: UUID,
        value: C,
        value_permissions: Vec<att::AttributePermissions> )
    -> characteristic::CharacteristicBuilder<'a, C, V>
        where C: att::server::ServerAttributeValue<V> + Sized + Send + Sync + 'static,
              V: att::TransferFormatTryFrom + att::TransferFormatInto + Send + Sync + PartialEq + 'static,
    {
        characteristic::CharacteristicBuilder::new(
            self,
            properties,
            uuid,
            value,
            value_permissions
        )
    }

    /// Finish the service
    pub fn finish_service(mut self) -> Service {
        self.service_builder.make_service( self.end_group_handle )
    }
}

#[derive(Clone,Copy,PartialEq,PartialOrd,Eq,Ord,Debug)]
pub struct Service {
    /// The handle of the Service declaration attribute
    service_handle: u16,
    /// The handle of the last attribute in the service
    end_group_handle: u16,
    /// The UUID (also known as the attribute type) of the service. This is also the attribute
    /// value in the service definition.
    service_type: UUID,
}

impl Service {

    fn new( service_handle: u16, end_group_handle: u16, service_type: UUID ) -> Self
    {
        Service { service_handle, end_group_handle, service_type }
    }
}

pub struct GapServiceBuilder {
    server_builder: ServerBuilder
}

impl GapServiceBuilder {
    /// Service UUID
    const GAP_SERVICE_TYPE: UUID = UUID::from_u16(0x1800);

    /// Default Appearance
    pub const UNKNOWN_APPERANCE: u16 = 0;

    /// Make a new `GapServiceBuilder`
    ///
    /// The `device_name` is a readable string for the client. The appperance is an assigned number
    /// to indiciate to the client the external appearance of the device. Both these fields are
    /// optional with `device_name` defaulting to an empty string and 'unknown apperance'
    pub fn new<'a,D,A>(device_name: D, apperance: A) -> Self
    where D: Into<Option<&'a str>>,
          A: Into<Option<u16>>
    {
        use characteristic::Properties;
        use att::AttributePermissions;

        let device_name_props = [Properties::Read].to_vec();
        let apperance_props   = [Properties::Read].to_vec();

        let device_name_type = UUID::from_u16(0x2a00);
        let apperance_type   = UUID::from_u16(0x2a01);

        let device_name_val: Box<str> = if let Some(name) = device_name.into() {
            name.into()
        } else {
            "".into()
        };

        let apperance_val = if let Some(appr) = apperance.into() {
            Box::new(appr)
        } else {
            Box::new( Self::UNKNOWN_APPERANCE)
        };

        let device_name_att_perms = [AttributePermissions::Read].to_vec();
        let apperance_att_perms = [AttributePermissions::Read].to_vec();

        let mut server_builder = ServerBuilder::new_empty();

        server_builder.new_service_constructor(Self::GAP_SERVICE_TYPE, true)
        .into_characteristics_adder()
        .build_characteristic(device_name_props, device_name_type, device_name_val, device_name_att_perms)
        .finish_characteristic()
        .build_characteristic(apperance_props, apperance_type, apperance_val, apperance_att_perms)
        .finish_characteristic()
        .finish_service();

        GapServiceBuilder { server_builder }
    }
}

/// Constructor of a GATT server
///
/// This will construct a GATT server for use with BR/EDR/LE bluetooth operation.
pub struct ServerBuilder
{
    primary_services: Vec<Service>,
    attributes: att::server::ServerAttributes,
}

impl ServerBuilder
{

    /// Construct an empty `ServerBuilder`
    ///
    /// This creates a `ServerBuilder` without the specification required GAP service.
    pub fn new_empty() -> Self {
        Self {
            primary_services: Vec::new(),
            attributes: att::server::ServerAttributes::new(),
        }
    }

    /// Construct a new `ServicesBuiler`
    ///
    /// This will make a `ServiceBuilder` with the basic requirements for a GATT server. This
    /// server will only contain a *GAP* service with the characteristics *Device Name* and
    /// *Appearance*, but both of these characteristics contain no information.
    pub fn new() -> Self
    {
        GapServiceBuilder::new("", GapServiceBuilder::UNKNOWN_APPERANCE).server_builder
    }

    /// Construct a new `ServiceBuilder` with the provided GAP service builder
    ///
    /// The provided GAP service builder will be used to construct the required GAP service for the
    /// GATT server.
    pub fn new_with_gap(gap: GapServiceBuilder) -> Self {
        gap.server_builder
    }

    /// Create a service constructor
    pub fn new_service_constructor(&mut self, service_type: UUID, is_primary: bool)
    -> ServiceBuilder<'_>
    {
        ServiceBuilder::new(self, service_type, is_primary)
    }

    /// Make an server
    ///
    /// Construct an server from the server builder.
    pub fn make_server<C,Mtu>(self, connection_channel: &'_ C, server_mtu: Mtu)
    -> Server<C>
    where C: l2cap::ConnectionChannel,
          Mtu: Into<Option<u16>>
    {
        Server {
            primary_services: self.primary_services,
            server: att::server::Server::new(connection_channel, server_mtu.into(), Some(self.attributes))
        }
    }

    fn add_primary_service(&mut self, service: Service ) {
        self.primary_services.push(service)
    }
}

pub struct Server<'c, C>
{
    primary_services: Vec<Service>,
    server: att::server::Server<'c, C>
}

impl<'c, C> Server<'c, C> where C: l2cap::ConnectionChannel
{
    pub fn process_acl_data(&mut self, acl_data: &crate::l2cap::AclData) -> Result<(), crate::att::Error>
    {
        let (pdu_type, payload) = self.server.parse_acl_packet(&acl_data)?;

        match pdu_type {
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                log::info!("(GATT) processing '{}'", att::client::ClientPduName::ReadByGroupTypeRequest );

                self.process_read_by_group_type_request(payload)
            }
            _ => self.server.process_parsed_acl_data(pdu_type, payload)
        }
    }

    /// Read by group type permission check
    fn rbgt_permission_check(&self, service: &Service) -> Result<(), att::pdu::Error> {
        const REQUIRED_PERMS: &[att::AttributePermissions] = &[
            att::AttributePermissions::Read
        ];

        const RESTRICTED_PERMS: &[att::AttributePermissions] = &[
            att::AttributePermissions::Encryption(att::AttributeRestriction::Read, att::EncryptionKeySize::Bits128),
            att::AttributePermissions::Encryption(att::AttributeRestriction::Read, att::EncryptionKeySize::Bits192),
            att::AttributePermissions::Encryption(att::AttributeRestriction::Read, att::EncryptionKeySize::Bits256),
            att::AttributePermissions::Authentication(att::AttributeRestriction::Read),
            att::AttributePermissions::Authorization(att::AttributeRestriction::Read),
        ];

        self.server.check_permission(service.service_handle, REQUIRED_PERMS, RESTRICTED_PERMS)
    }

    fn process_read_by_group_type_request(&self, payload: &[u8]) -> Result<(), crate::att::Error> {

        /// Response Item
        #[derive(Clone,Copy)]
        struct ResponseItem<U> {
            service_handle: u16,
            end_group_handle: u16,
            uuid: U
        }

        struct ServiceGroupResponse<I>(I);

        impl<I,U> att::TransferFormatInto for ServiceGroupResponse<I>
        where I: Iterator<Item=ResponseItem<U>> + Clone,
              U: TransferFormatInto,
        {
            fn len_of_into(&self) -> usize {
                1 + self.0.clone().fold(0usize, |acc,ri| acc + 4 + ri.uuid.len_of_into() )
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {

                into_ret[0] = core::mem::size_of::<I::Item>() as u8;

                self.0.clone().fold(&mut into_ret[1..], | into_ret, response_item | {

                    let uuid_len = response_item.uuid.len_of_into();

                    into_ret[..2].copy_from_slice( &response_item.service_handle.to_le_bytes() );

                    into_ret[2..4].copy_from_slice( &response_item.service_handle.to_le_bytes() );

                    response_item.uuid.build_into_ret( &mut into_ret[4..(4 + uuid_len)] );

                    &mut into_ret[(4 + uuid_len)..]
                });
            }
        }

        match att::TransferFormatTryFrom::try_from(payload) {
            Ok(att::pdu::TypeRequest {
                   handle_range,
                   attr_type: ServiceDefinition::PRIMARY_SERVICE_TYPE,
               }) =>
            {
                let mut service_iter = self.primary_services.iter()
                    .filter(|s| s.service_handle >= handle_range.starting_handle &&
                        s.service_handle <= handle_range.ending_handle)
                    .map(|s| self.rbgt_permission_check(s).map(|_| s))
                    .peekable();

                // Check the permissions of the first service and determine if the client can
                // access the service UUID. If no error is returned by `permissions_error` then
                // the next UUIDs of the same type (16 bits or 128 bits) and permissible to the
                // client are added to the response packet until the max size of the packet is
                // reached. The first packet processed that is not of the same type or is not
                // permissible to the client stops the addition of UUIDs and the response packet
                // is then sent to the client.
                match service_iter.peek() {
                    Some(Ok(first_service)) => {
                        let payload_size = self.server.get_mtu() - 2; // pdu header size is 2 bytes

                        // Each data_size is 4 bytes for the attribute handle + the end group handle and
                        // either 2 bytes for short UUIDs or 16 bytes for full UUIDs
                        if first_service.service_type.is_16_bit() {
                            let service_iter = service_iter
                                .take_while(|rslt| rslt.is_ok())
                                .map(|rslt| rslt.unwrap())
                                .take_while(|s| s.service_type.is_16_bit())
                                .enumerate()
                                .take_while(|(cnt, _)| payload_size > cnt * (4 + 2))
                                .map(|(_, s)| ResponseItem {
                                    service_handle: s.service_handle,
                                    end_group_handle: s.end_group_handle,
                                    uuid: core::convert::TryInto::<u16>::try_into(s.service_type).unwrap(),
                                });

                            self.server.send_pdu( att::pdu::Pdu::new(
                                att::server::ServerPduName::ReadByGroupTypeResponse.into(),
                                ServiceGroupResponse(service_iter),
                                None
                            ));
                        } else {
                            let service_iter = service_iter
                                .take_while(|rslt| rslt.is_ok())
                                .map(|rslt| rslt.unwrap())
                                .enumerate()
                                .take_while(|(cnt, _)| payload_size > cnt * (4 + 16))
                                .map(|(_, s)| ResponseItem {
                                    service_handle: s.service_handle,
                                    end_group_handle: s.end_group_handle,
                                    uuid: <u128>::from(s.service_type),
                                });

                            self.server.send_pdu( att::pdu::Pdu::new(
                                att::server::ServerPduName::ReadByGroupTypeResponse.into(),
                                ServiceGroupResponse(service_iter),
                                None
                            ));
                        };
                    },

                    // Client didn't have adequate permissions to access the first service
                    Some(Err(e)) => self.server.send_error(
                        handle_range.starting_handle,
                        att::client::ClientPduName::ReadByGroupTypeRequest,
                        (*e).into()),

                    // No service attributes found within the requested range
                    None => self.server.send_error(
                        handle_range.starting_handle,
                        att::client::ClientPduName::ReadByGroupTypeRequest,
                        att::pdu::Error::InvalidHandle),
                }
            },
            Ok(att::pdu::TypeRequest { handle_range, .. } ) =>
                self.server.send_error(
                    handle_range.starting_handle,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnsupportedGroupType),
            _ =>
                self.server.send_error(
                    0,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnlikelyError),
        }

        Ok(())
    }
}

impl<'c, C> AsRef<att::server::Server<'c, C>> for Server<'c, C> where C: l2cap::ConnectionChannel {
    fn as_ref(&self) -> &att::server::Server<'c, C> {
        &self.server
    }
}

impl<'c, C> AsMut<att::server::Server<'c, C>> for Server<'c, C> where C: l2cap::ConnectionChannel {
    fn as_mut(&mut self) -> &mut att::server::Server<'c, C> {
        &mut self.server
    }
}

impl<'c, C> core::ops::Deref for Server<'c, C>
where C:l2cap::ConnectionChannel
{
    type Target = att::server::Server<'c, C>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'c, C> core::ops::DerefMut for Server<'c, C>
where C:l2cap::ConnectionChannel
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use alloc::boxed::Box;
    use crate::l2cap::ConnectionChannel;
    use crate::UUID;

    struct DummyConnection;

    impl ConnectionChannel for DummyConnection {
        fn send<Pdu>(&self, _: Pdu) where Pdu: Into<crate::l2cap::L2capPdu>{}
        fn receive(&self, _: &core::task::Waker) -> Option<Vec<crate::l2cap::AclDataFragment>> { None }
    }

    #[test]
    fn create_gatt_attributes() {

        let mut server_builder = ServerBuilder::new();

        let test_service_1 = server_builder.new_service_constructor( UUID::from_u16(0x1234), false )
            .into_characteristics_adder()
            .build_characteristic(
                vec!(characteristic::Properties::Read),
                UUID::from(0x1234u16),
                Box::new(0usize),
                vec!(att::AttributePermissions::Read)
            )
            .set_extended_properties( vec!(characteristic::ExtendedProperties::ReliableWrite) )
            .set_user_description( characteristic::UserDescription::new(
                "Test 1",
                vec!(att::AttributePermissions::Read) )
            )
            .set_client_configuration( vec!(characteristic::ClientConfiguration::Notification) )
            .set_server_configuration( vec!(characteristic::ServerConfiguration::Broadcast) )
            .finish_characteristic()
            .finish_service();

        let _test_service_2 = server_builder.new_service_constructor( UUID::from_u16(0x3456), true )
            .into_includes_adder()
            .include_service(&test_service_1)
            .finish_service();

        server_builder.make_server(&DummyConnection, 0xFFu16);
    }
}
