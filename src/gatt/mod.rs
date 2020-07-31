use alloc::vec::Vec;
use crate::{ att, l2cap, UUID};

pub mod characteristic;

struct ServiceDefinition;

impl ServiceDefinition {
    /// The permissions of the service definitions is just Read Only
    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;

    /// The primary service UUID
    pub const PRIMARY_SERVICE_TYPE: UUID = UUID::from_u16(0x2800);

    /// The secondary service UUID
    pub const SECONDARY_SERVICE_TYPE: UUID = UUID::from_u16(0x2801);
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
            Err(att::TransferFormatError::bad_min_size(stringify!(ServiceInclude), 6, raw.len()))
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

    const DEFAULT_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;
}

/// Construct a GATT Service.
///
/// Every service contains a service definition characteristic with a number of other optional
/// characteristics defined as part of the GATT protocol. A service can also have custom
/// characteristics defined in a higher layer protocol.
///
/// A `ServiceBuilder` is created with the function `new_service_constructor` of
/// [`ServerBuilder`](crate::gatt::ServerBuilder). `ServiceBuilder` is tied to the `ServerBuilder`
/// that created it, the service build by this will be part of the server.
///
/// By creating a `ServiceBuilder`, a service definition characteristic is added to the server.
/// Further characteristics of the service are optional, but they can be added by turning this
/// into a `IncludesAdder` or a `CharacteristicAdder`. The only way to add one or more includes
/// definition characteristics is to convert the server builder into a `IncludesAdder`. A
/// `IncludesAdder` can then be converted into `CharacteristicAdder` once all included services are
/// added. All other characteristics are added with the `CharacteristicAdder`. This is done to
/// enforce all include definition to come after the service definition but before any other
/// characteristics.
pub struct ServiceBuilder<'a>
{
    service_type: UUID,
    is_primary: bool,
    server_builder: &'a mut ServerBuilder,
    default_permissions: Option<&'a [att::AttributePermissions]>,
    definition_handle: Option<u16>,
}

impl<'a> ServiceBuilder<'a>
{
    fn new( server_builder: &'a mut ServerBuilder, service_type: UUID, is_primary: bool ) -> Self {
        ServiceBuilder {
            service_type,
            is_primary,
            server_builder,
            default_permissions: None,
            definition_handle: None,
        }
    }

    /// Set the service definition into the server attributes
    ///
    /// This will create and add the service definition to the Attribute Server and return the
    /// handle to it.
    fn set_service_definition(&mut self) {
        self.definition_handle = self.server_builder.attributes.push(
            att::Attribute::new(
                if self.is_primary {
                    ServiceDefinition::PRIMARY_SERVICE_TYPE
                } else {
                    ServiceDefinition::SECONDARY_SERVICE_TYPE
                },
                self.default_permissions.unwrap_or(ServiceDefinition::DEFAULT_PERMISSIONS).into(),
                self.service_type
            )
        )
        .into();
    }

    /// Start including other services
    ///
    /// This converts a `Service Builder` into a `IncludesAdder`. The returned `IncludesAdder`
    /// will allow for the addition of include definitions for other services. Afterwards an
    /// `IncludesAdder` can be further converted into a `CharacteristicAdder`
    pub fn into_includes_adder(mut self) -> IncludesAdder<'a> {
        self.set_service_definition();

        let end_handle = self.definition_handle.unwrap();

        IncludesAdder::new(self, end_handle)
    }

    /// Start adding characteristics
    ///
    /// This converts a `Service Builder` into a `CharacteristicAdder`. Use this function when the
    /// service includes no other services. This will create a characteristic adder that can be used
    /// to add characteristics after the service definition attribute. It is not possible to add
    /// includes to other services if this function is used.
    ///
    /// A `CharacteristicAdder` is used to add the value declaration, descriptor declaration,
    /// extended properties, user description, client configuration, and server configuration
    /// characteristics. All of these characteristics are optional when creating .
    ///
    /// If you wish to create a service that includes other services, use the
    /// `[into_includes_adder](#add_service_includes)`
    /// function. That function will return a `IncludesAdder` which can be then converted into
    /// a `CharacteristicAdder` for adding characteristics to the service.
    pub fn into_characteristics_adder(mut self) -> CharacteristicAdder<'a> {
        self.set_service_definition();

        let end_handle = self.definition_handle.unwrap();

        CharacteristicAdder::new(self, end_handle)
    }

    /// Create an empty service
    ///
    /// This will create a service with no include definitions or characteristics. The service will
    /// only contain the service definition characteristic.
    pub fn make_empty(mut self) -> Service {
        self.set_service_definition();

        // There is only one handle in an empty Service so both the service handle and end group
        // handle are the same
        self.make_service(self.definition_handle.unwrap())
    }

    /// Set the baseline attribute permissions for the service
    ///
    /// These permissions are used as the attribute permissions of the service definition and as the
    /// default permissions of every other characteristic of this service. While this is the only
    /// way to set the permissions of the service definition characteristic, the other
    /// characteristics can have their permissions set with their respective builders.
    pub fn set_att_permissions<P>(mut self, permissions: P ) -> Self
    where P: Into<Option<&'a [att::AttributePermissions]>>
    {
        self.default_permissions = permissions.into();
        self
    }

    fn make_service(&mut self, end_service_handle: u16 ) -> Service {

        let service = Service::new(
            self.definition_handle.unwrap(),
            end_service_handle,
            self.service_type
        );

        if self.is_primary { self.server_builder.add_primary_service(service) }

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
    fn new( service_builder: ServiceBuilder<'a>, service_definition_handle: u16 )
    -> Self
    {
        IncludesAdder {
            service_builder,
            end_group_handle: service_definition_handle,
        }
    }

    /// Add a service to include
    ///
    /// This takes a reference to the service to include with an optional permissions for the
    /// include definition. If no permissions are given, then it uses the default permissions of the
    /// service.
    pub fn include_service<P: Into<Option<&'a [att::AttributePermissions]>>> (
        mut self,
        service: &Service,
        permissions: P
    ) -> Self {
        use core::convert::TryInto;

        let include = ServiceInclude {
            service_handle: service.service_handle,
            end_group_handle: service.end_group_handle,
            short_service_type: service.service_type.try_into().ok()
        };

        let attribute = att::Attribute::new(
            ServiceInclude::TYPE,
            permissions.into().or(self.service_builder.default_permissions)
                .unwrap_or(ServiceInclude::DEFAULT_PERMISSIONS)
                .into(),
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
/// [`ServiceBuilder::into_characteristics_adder`](crate::gatt::ServiceBuilder::into_characteristics_adder)
/// or
/// [`IncludesAdder::into_characteristics_adder`](crate::gatt::IncludesAdder::into_characteristics_adder)
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

    pub fn build_characteristic<'c,C,V,P>(
        self,
        properties: Vec<characteristic::Properties>,
        uuid: UUID,
        value: C,
        value_permissions: P )
    -> characteristic::CharacteristicBuilder<'a,'c, C, V>
        where C: att::server::ServerAttributeValue<Value = V> + Send + Sized  + 'static,
              V: att::TransferFormatTryFrom + att::TransferFormatInto + 'static,
              P: Into<Option<&'c [att::AttributePermissions]>>
    {
        let permissions = value_permissions.into();

        characteristic::CharacteristicBuilder::new(
            self,
            properties,
            uuid,
            value,
            permissions
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

pub struct GapServiceBuilder<'a> {
    service_permissions: Option<&'a [att::AttributePermissions]>,
    device_name: &'a str,
    device_name_permissions: &'a [att::AttributePermissions],
    device_appearance: u16,
    device_appearance_permissions: &'a [att::AttributePermissions],
}

impl<'a> GapServiceBuilder<'a> {
    /// Service UUID
    const GAP_SERVICE_TYPE: UUID = UUID::from_u16(0x1800);

    /// Device Name Characteristic UUID
    const DEVICE_NAME_TYPE: UUID = UUID::from_u16(0x2a00);

    /// Device Appearance Characteristic UUID
    const DEVICE_APPEARANCE_TYPE: UUID = UUID::from_u16(0x2a01);

    /// Default attribute permissions
    const DEFAULT_ATTRIBUTE_PERMISSIONS: &'static [att::AttributePermissions] = att::FULL_READ_PERMISSIONS;

    /// Device Name characteristic properties
    const DEVICE_NAME_PROPERTIES: &'static [characteristic::Properties] = & [
        characteristic::Properties::Read,
    ];

    /// Device Appearance characteristic properties
    const DEVICE_APPEARANCE_PROPERTIES: &'static [characteristic::Properties] = &[
        characteristic::Properties::Read,
    ];

    /// Default Appearance
    pub const UNKNOWN_APPEARANCE: u16 = 0;

    /// Make a new `GapServiceBuilder`
    ///
    /// The `device_name` is a readable string for the client. The appearance is an assigned number
    /// to indicate to the client the external appearance of the device. Both these fields are
    /// optional with `device_name` defaulting to an empty string and appearance as 'unknown appearance'
    pub fn new<D,A>(device_name: D, appearance: A) -> Self
    where D: Into<Option<&'a str>>,
          A: Into<Option<u16>>
    {
        GapServiceBuilder {
            service_permissions: None,
            device_name: device_name.into().unwrap_or(""),
            device_name_permissions: Self::DEFAULT_ATTRIBUTE_PERMISSIONS,
            device_appearance: appearance.into().unwrap_or( Self::UNKNOWN_APPEARANCE ),
            device_appearance_permissions: Self::DEFAULT_ATTRIBUTE_PERMISSIONS,
        }
    }

    /// Set the service permissions
    ///
    /// This will be used as the permissions for all attributes of the GAP service.
    pub fn set_permissions(&mut self, permissions: &'a [att::AttributePermissions]) {
        self.service_permissions = permissions.into();
        self.device_name_permissions = permissions;
        self.device_appearance_permissions = permissions;
    }

    /// Set the attribute permissions for the device name characteristic
    pub fn set_name_permissions(&mut self, permissions: &'a [att::AttributePermissions]) {
        self.device_name_permissions = permissions
    }

    /// Set the attribute permissions for the device appearance characteristic
    pub fn set_appearance_permissions(&mut self, permissions: &'a [att::AttributePermissions] ) {
        self.device_appearance_permissions = permissions
    }

    fn into_gatt_service(self) -> ServerBuilder {
        use alloc::string::ToString;

        let mut server_builder = ServerBuilder::new_empty();

        server_builder.new_service_constructor(Self::GAP_SERVICE_TYPE, true)
            .set_att_permissions(self.service_permissions)
            .into_characteristics_adder()
            .build_characteristic(
                Self::DEVICE_NAME_PROPERTIES.to_vec(),
                Self::DEVICE_NAME_TYPE,
                self.device_name.to_string(),
                self.device_name_permissions)
            .finish_characteristic()
            .build_characteristic(
                Self::DEVICE_APPEARANCE_PROPERTIES.to_vec(),
                Self::DEVICE_APPEARANCE_TYPE,
                self.device_appearance,
                self.device_appearance_permissions)
            .finish_characteristic()
            .finish_service();

        server_builder
    }
}

impl Default for GapServiceBuilder<'_> {
    fn default() -> Self {
        GapServiceBuilder {
            service_permissions: None,
            device_name: "",
            device_appearance: GapServiceBuilder::UNKNOWN_APPEARANCE,
            device_name_permissions: GapServiceBuilder::DEFAULT_ATTRIBUTE_PERMISSIONS,
            device_appearance_permissions: GapServiceBuilder::DEFAULT_ATTRIBUTE_PERMISSIONS,
        }
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

    /// Construct a new `ServicesBuilder`
    ///
    /// This will make a `ServiceBuilder` with the basic requirements for a GATT server. This
    /// server will only contain a *GAP* service with the characteristics *Device Name* and
    /// *Appearance*, but both of these characteristics contain no information. The permissions for
    /// the GAP attributes will be the default read attributes.
    pub fn new() -> Self
    {
        GapServiceBuilder::default().into()
    }

    /// Construct a new `ServiceBuilder` with the provided GAP service builder
    ///
    /// The provided GAP service builder will be used to construct the required GAP service for the
    /// GATT server.
    pub fn new_with_gap(gap: GapServiceBuilder) -> Self {
        gap.into_gatt_service()
    }

    /// Create a service constructor
    pub fn new_service_constructor(&mut self, service_type: UUID, is_primary: bool)
    -> ServiceBuilder<'_>
    {
        ServiceBuilder::new(self, service_type, is_primary)
    }

    /// Get all the attributes of the server
    pub fn get_attributes(&self) -> &att::server::ServerAttributes {
        &self.attributes
    }

    /// Make an server
    ///
    /// Construct an server from the server builder.
    pub fn make_server<C>(self, connection_channel: &'_ C) -> Server<C>
    where C: l2cap::ConnectionChannel,
    {
        Server {
            primary_services: self.primary_services,
            server: att::server::Server::new(connection_channel, Some(self.attributes))
        }
    }

    fn add_primary_service(&mut self, service: Service ) {
        self.primary_services.push(service)
    }
}

impl From<GapServiceBuilder<'_>> for ServerBuilder {
    fn from(gap: GapServiceBuilder) -> Self {
        Self::new_with_gap(gap)
    }
}

pub struct Server<'c, C>
{
    primary_services: Vec<Service>,
    server: att::server::Server<'c, C>
}

impl<'c, C> Server<'c, C> where C: l2cap::ConnectionChannel
{
    pub async fn process_acl_data(&mut self, acl_data: &crate::l2cap::AclData)
    -> Result<(), crate::att::Error>
    {
        let (pdu_type, payload) = self.server.parse_acl_packet(&acl_data)?;

        match pdu_type {
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                log::info!("(GATT) processing '{}'", att::client::ClientPduName::ReadByGroupTypeRequest );

                self.process_read_by_group_type_request(payload).await
            }
            _ => self.server.process_parsed_acl_data(pdu_type, payload).await
        }
    }

    /// 'Read by group type' permission check
    fn rbgt_permission_check(&self, service: &Service) -> Result<(), att::pdu::Error> {
        self.server.check_permissions(service.service_handle, att::FULL_READ_PERMISSIONS)
    }

    async fn process_read_by_group_type_request(&self, payload: &[u8]) -> Result<(), crate::att::Error> {

        match att::TransferFormatTryFrom::try_from(payload) {
            Ok(att::pdu::TypeRequest {
                   handle_range,
                   attr_type: ServiceDefinition::PRIMARY_SERVICE_TYPE,
               }) =>
            {
                use att::pdu::{ReadGroupTypeData, ReadByGroupTypeResponse};

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
                        // pdu header size is 2 bytes
                        let payload_size = self.server.get_mtu() - 2;
                        let is_16_bit = first_service.service_type.is_16_bit();

                        let build_response_iter = service_iter
                            .take_while(|rslt| rslt.is_ok())
                            .map(|rslt| rslt.unwrap());

                        // Each data_size is 4 bytes for the attribute handle + the end group handle
                        // and either 2 bytes for short UUIDs or 16 bytes for full UUIDs
                        //
                        // Each collection is made to take while the *current* iteration does not
                        // overrun the maximum payload size.
                        let response = if is_16_bit {
                            build_response_iter.take_while(|s| s.service_type.is_16_bit())
                                .enumerate()
                                .take_while(|(cnt, _)| payload_size > (cnt + 1) * (4 + 2))
                                .by_ref()
                                .map(|(_, s)|
                                    ReadGroupTypeData::new(
                                        s.service_handle,
                                        s.end_group_handle,
                                        s.service_type
                                    )
                                )
                                .collect()
                        } else {
                            build_response_iter.enumerate()
                                .take_while(|(cnt, _)| payload_size > (cnt + 1) * (4 + 16))
                                .by_ref()
                                .map(|(_, s)|
                                    ReadGroupTypeData::new(
                                        s.service_handle,
                                        s.end_group_handle,
                                        s.service_type
                                    )
                                )
                                .collect()
                        };

                        let pdu = att::pdu::read_by_group_type_response(ReadByGroupTypeResponse::new(response));

                        self.server.send_pdu(pdu).await;
                    },

                    // Client didn't have adequate permissions to access the first service
                    Some(Err(e)) => {
                        self.server.send_error(
                            handle_range.starting_handle,
                            att::client::ClientPduName::ReadByGroupTypeRequest,
                            (*e).into()
                        ).await;

                        return Err((*e).into());
                    },

                    // No service attributes found within the requested range
                    None => {
                        self.server.send_error(
                            handle_range.starting_handle,
                            att::client::ClientPduName::ReadByGroupTypeRequest,
                            att::pdu::Error::AttributeNotFound
                        ).await;

                        return Ok(());
                    },
                }
            },
            Ok(att::pdu::TypeRequest { handle_range, .. } ) => {
                self.server.send_error(
                    handle_range.starting_handle,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnsupportedGroupType
                ).await;

                return Err(att::pdu::Error::UnsupportedGroupType.into())
            },
            _ => {
                self.server.send_error(
                    0,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnlikelyError
                ).await;

                return Err(att::pdu::Error::UnlikelyError.into())
            },
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
    use crate::l2cap::{ConnectionChannel, AclDataFragment, SendFut, MinimumMtu};
    use crate::UUID;
    use futures::task::Waker;
    use att::TransferFormatInto;

    struct DummyConnection;

    impl ConnectionChannel for DummyConnection {
        fn send(&self, _: crate::l2cap::AclData) -> SendFut {
            SendFut::new(true)
        }

        fn set_mtu(&self, _: u16) {}

        fn get_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn max_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn min_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn receive(&self, _: &core::task::Waker) -> Option<Vec<crate::l2cap::AclDataFragment>> { None }
    }

    #[test]
    fn create_gatt_attributes() {

        let test_att_permissions: &[att::AttributePermissions] = &[
            att::AttributePermissions::Read(att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128)),
            att::AttributePermissions::Write(att::AttributeRestriction::Authentication)
        ];

        let mut gap_service = GapServiceBuilder::new(None,None);

        gap_service.set_permissions(test_att_permissions);

        let mut server_builder = ServerBuilder::new_with_gap(gap_service);

        let test_service_1 = server_builder.new_service_constructor( UUID::from_u16(0x1234), false )
            .set_att_permissions(test_att_permissions)
            .into_characteristics_adder()
            .build_characteristic(
                vec!(characteristic::Properties::Read),
                UUID::from(0x1234u16),
                Box::new(0usize),
                None
            )
            .set_extended_properties( vec!(characteristic::ExtendedProperties::ReliableWrite), None )
            .set_user_description( characteristic::UserDescription::new("Test 1", None ) )
            .set_client_configuration( vec!(characteristic::ClientConfiguration::Notification), None )
            .set_server_configuration( vec!(characteristic::ServerConfiguration::Broadcast), None )
            .finish_characteristic()
            .finish_service();

        let _test_service_2 = server_builder.new_service_constructor( UUID::from_u16(0x3456), true )
            .set_att_permissions(test_att_permissions)
            .into_includes_adder()
            .include_service(&test_service_1, None)
            .finish_service();

        let server = server_builder.make_server(&DummyConnection);

        server.iter_attr_info()
            .for_each(|info| assert_eq!(info.get_permissions(), test_att_permissions,
                "failing UUID: {:#x}, handle: {}", info.get_uuid(), info.get_handle() ) )
    }

    struct TestChannel {
        last_sent_pdu: std::cell::Cell<Option<Vec<u8>>>
    }

    impl l2cap::ConnectionChannel for TestChannel {
        fn send(&self, data: crate::l2cap::AclData) -> l2cap::SendFut {
            self.last_sent_pdu.set(Some(data.into_raw_data()));

            l2cap::SendFut::new(true)
        }

        fn set_mtu(&self, _: u16) {}

        fn get_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn max_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn min_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

        fn receive(&self, _: &Waker) -> Option<Vec<AclDataFragment>> {
            unimplemented!()
        }
    }

    #[test]
    fn gatt_services_read_by_group_type() {

        use futures::executor::block_on;

        let mut server_builder = ServerBuilder::new();

        let first_test_uuid = UUID::from(0x1000u16);
        let second_test_uuid = UUID::from(0x1001u128);

        server_builder.new_service_constructor( first_test_uuid, true)
            .into_characteristics_adder()
            .build_characteristic(
                vec![characteristic::Properties::Read],
                UUID::from(0x2000u16),
                Box::new(0usize),
                None
            )
            .finish_characteristic()
            .finish_service();

        server_builder.new_service_constructor( second_test_uuid, true)
            .into_characteristics_adder()
            .build_characteristic(
                vec![characteristic::Properties::Read],
                UUID::from(0x2001u16),
                Box::new(0usize),
                None
            )
            .finish_characteristic()
            .finish_service();

        let test_channel = TestChannel { last_sent_pdu: None.into() };

        let mut server = server_builder.make_server(&test_channel);

        server.give_permissions_to_client([
            att::AttributePermissions::Read(att::AttributeRestriction::None)
        ]);

        let client_pdu = att::pdu::read_by_group_type_request(
            1..,
            ServiceDefinition::PRIMARY_SERVICE_TYPE
        );

        let acl_client_pdu = l2cap::AclData::new(
            TransferFormatInto::into(&client_pdu),
            att::L2CAP_CHANNEL_ID
        );

        assert_eq!( Ok(()), block_on(server.process_acl_data(&acl_client_pdu)), );

        let expected_response = att::pdu::ReadByGroupTypeResponse::new(
            vec![
                // Gap Service
                att::pdu::ReadGroupTypeData::new(1,5, GapServiceBuilder::GAP_SERVICE_TYPE),
                att::pdu::ReadGroupTypeData::new(6,8, first_test_uuid),
            ]
        );

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take()
                .map(|data| {
                    let acl_data = l2cap::AclData::from_raw_data(&data).unwrap();
                    att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
                } ),
        );

        let client_pdu = att::pdu::read_by_group_type_request(
            9..,
            ServiceDefinition::PRIMARY_SERVICE_TYPE
        );

        let acl_client_pdu = l2cap::AclData::new(
            TransferFormatInto::into(&client_pdu),
            att::L2CAP_CHANNEL_ID
        );

        assert_eq!( Ok(()), block_on(server.process_acl_data(&acl_client_pdu)), );

        let expected_response = att::pdu::ReadByGroupTypeResponse::new(
            vec![
                att::pdu::ReadGroupTypeData::new(9,11, second_test_uuid)
            ]
        );

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take()
                .map(|data| {
                    let acl_data = l2cap::AclData::from_raw_data(&data).unwrap();
                    att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
                } ),
        );

        let client_pdu = att::pdu::read_by_group_type_request(
            12..,
            ServiceDefinition::PRIMARY_SERVICE_TYPE
        );

        let acl_client_pdu = l2cap::AclData::new(
            TransferFormatInto::into(&client_pdu),
            att::L2CAP_CHANNEL_ID
        );

        // Request was made for for a attribute that was out of range
        assert_eq!( Ok(()), block_on(server.process_acl_data(&acl_client_pdu)) );
    }
}
