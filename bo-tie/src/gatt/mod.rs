//! Generic Attribute Protocol
//!
//! GATT is a thin wrapper protocol above the attribute (ATT) protocol.
//!
//! The GATT is mainly an data organization protocol used to help clients to identify what is on
//! the other device's attribute server. GATT organizes data into groups under a 'service'. Data
//! within a service is organized into 'characteristic' which contain 'characteristic descriptors'
//! that further provide meta explanation of the data. Each of these require attributes, so
//! individual data will use multiple attribute handles in order to contain all the GATT information
//! associated with it. However all this GATT information provides a standard way for the
//! Bluetooth SIG to assign services to provide common data formats.

use crate::{att, l2cap, UUID};
use alloc::vec::Vec;
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
                    return Err(att::TransferFormatError::from(concat!(
                        "Invalid short service type in ",
                        stringify!("ServiceInclude")
                    )));
                },
            })
        } else {
            Err(att::TransferFormatError::bad_min_size(
                stringify!(ServiceInclude),
                6,
                raw.len(),
            ))
        }
    }
}

impl att::TransferFormatInto for ServiceInclude {
    fn len_of_into(&self) -> usize {
        4 + if self.short_service_type.is_some() { 2 } else { 0 }
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.service_handle.to_le_bytes());

        into_ret[2..4].copy_from_slice(&self.end_group_handle.to_le_bytes());

        if let Some(ty) = self.short_service_type {
            into_ret[4..].copy_from_slice(&ty.to_le_bytes());
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
pub struct ServiceBuilder<'a> {
    service_uuid: UUID,
    is_primary: bool,
    server_builder: &'a mut ServerBuilder,
    default_permissions: Option<&'a [att::AttributePermissions]>,
    definition_handle: Option<u16>,
}

// Unfortunately this cannot be made into a method as the borrow checker would trip when this was
// used within another method that moved self.
macro_rules! make_service {
    ($this:expr, $end_service_handle:expr) => {{
        let service = Service::new(
            &$this.server_builder.attributes,
            $this.definition_handle.unwrap(),
            $end_service_handle,
            $this.service_uuid,
        );

        if $this.is_primary {
            $this.server_builder.primary_services.push(service.group_data)
        }

        service
    }};
}

impl<'a> ServiceBuilder<'a> {
    fn new(server_builder: &'a mut ServerBuilder, service_uuid: UUID, is_primary: bool) -> Self {
        ServiceBuilder {
            service_uuid,
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
        self.definition_handle = self
            .server_builder
            .attributes
            .push(att::Attribute::new(
                if self.is_primary {
                    ServiceDefinition::PRIMARY_SERVICE_TYPE
                } else {
                    ServiceDefinition::SECONDARY_SERVICE_TYPE
                },
                self.default_permissions
                    .unwrap_or(ServiceDefinition::DEFAULT_PERMISSIONS)
                    .into(),
                self.service_uuid,
            ))
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
    pub fn add_characteristics(mut self) -> CharacteristicAdder<'a> {
        self.set_service_definition();

        let end_handle = self.definition_handle.unwrap();

        CharacteristicAdder::new(self, end_handle)
    }

    /// Create an empty service
    ///
    /// This will create a service with no include definitions or characteristics. The service will
    /// only contain the service definition characteristic.
    pub fn make_empty(mut self) -> Service<'a> {
        self.set_service_definition();

        // There is only one handle in an empty Service so both the service handle and end group
        // handle are the same
        make_service!(self, self.definition_handle.unwrap())
    }

    /// Set the baseline attribute permissions for the service
    ///
    /// These permissions are used as the attribute permissions of the service definition and as the
    /// default permissions of every other characteristic of this service. While this is the only
    /// way to set the permissions of the service definition characteristic, the other
    /// characteristics can have their permissions set with their respective builders.
    pub fn set_att_permissions<P>(mut self, permissions: P) -> Self
    where
        P: Into<Option<&'a [att::AttributePermissions]>>,
    {
        self.default_permissions = permissions.into();
        self
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
pub struct IncludesAdder<'a> {
    service_builder: ServiceBuilder<'a>,
    end_group_handle: u16,
}

impl<'a> IncludesAdder<'a> {
    fn new(service_builder: ServiceBuilder<'a>, service_definition_handle: u16) -> Self {
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
    pub fn include_service<P: Into<Option<&'a [att::AttributePermissions]>>>(
        mut self,
        service: &Service<'_>,
        permissions: P,
    ) -> Self {
        use core::convert::TryInto;

        let include = ServiceInclude {
            service_handle: service.get_handle(),
            end_group_handle: service.get_end_group_handle(),
            short_service_type: service.get_uuid().try_into().ok(),
        };

        let attribute = att::Attribute::new(
            ServiceInclude::TYPE,
            permissions
                .into()
                .or(self.service_builder.default_permissions)
                .unwrap_or(ServiceInclude::DEFAULT_PERMISSIONS)
                .into(),
            include,
        );

        self.end_group_handle = self.service_builder.server_builder.attributes.push(attribute);

        self
    }

    /// Add characteristics to the server
    ///
    /// This finishes the included services section and begins the process of adding characteristics
    /// to the service.
    ///
    /// # Note
    /// Services cannot be included once this is called.
    pub fn add_characteristics(self) -> CharacteristicAdder<'a> {
        CharacteristicAdder::new(self.service_builder, self.end_group_handle)
    }

    /// Finish the service
    ///
    /// This will create a service that only has the service definition and service includes (if
    /// any). There will be no characteristics added to the service.
    pub fn finish_service(self) -> Service<'a> {
        make_service!(self.service_builder, self.end_group_handle)
    }
}

/// Add characteristics to a service
///
/// The service that will contain the characteristic(s) is the same service that was initially
/// constructing with ServiceBuilder.
///
/// This is created by the
/// [`ServiceBuilder::add_characteristics`](crate::gatt::ServiceBuilder::add_characteristics)
/// or
/// [`IncludesAdder::add_characteristics`](crate::gatt::IncludesAdder::add_characteristics)
/// functions.
pub struct CharacteristicAdder<'a> {
    service_builder: ServiceBuilder<'a>,
    end_group_handle: u16,
}

impl<'a> CharacteristicAdder<'a> {
    fn new(service_builder: ServiceBuilder<'a>, end_group_handle: u16) -> Self {
        CharacteristicAdder {
            service_builder,
            end_group_handle,
        }
    }

    /// Create a new characteristic builder
    ///
    /// The created builder will be used for setting up and creating a new characteristic.
    pub fn new_characteristic<'c, U, C, V>(self) -> characteristic::CharacteristicBuilder<'a, 'c, U, C, V> {
        characteristic::CharacteristicBuilder::new(self)
    }

    /// Finish the service
    pub fn finish_service(self) -> Service<'a> {
        make_service!(self.service_builder, self.end_group_handle)
    }
}

/// Information on a single GATT service.
///
/// This contains the information about the Service as it stands within the GATT server. It also
/// provides a way to iterate through the characteristics contained within the service.
#[derive(Clone, Copy)]
pub struct Service<'a> {
    /// The attributes list that this Service is in
    server_attributes: &'a crate::att::server::ServerAttributes,
    group_data: ServiceGroupData,
}

impl<'a> Service<'a> {
    fn new(
        server_attributes: &'a crate::att::server::ServerAttributes,
        service_handle: u16,
        end_group_handle: u16,
        service_uuid: UUID,
    ) -> Self {
        let group_data = ServiceGroupData {
            service_handle,
            end_group_handle,
            service_uuid,
        };

        Service {
            server_attributes,
            group_data,
        }
    }

    /// Get the handle of the service
    pub fn get_handle(&self) -> u16 {
        self.group_data.service_handle
    }

    /// Get the service type
    ///
    /// This returns the UUID of the Service.
    pub fn get_uuid(&self) -> crate::UUID {
        self.group_data.service_uuid
    }

    /// Get the end handle within the Service
    ///
    /// This is handle of the last Attribute within the Service
    pub fn get_end_group_handle(&self) -> u16 {
        self.group_data.end_group_handle
    }

    /// Iterate over the Characteristics within this Service
    pub fn iter_characteristics(&self) -> impl Iterator<Item = characteristic::Characteristic<'a>> + 'a {
        characteristic::CharacteristicsIter::new(
            self.server_attributes,
            self.group_data.service_handle,
            self.group_data.end_group_handle,
        )
    }
}

/// Group data about a service
///
/// This is the data used by the GATT server for quickly finding the Services within a GATT server
/// with a attribute group related request from the Server.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
struct ServiceGroupData {
    /// The handle of the Service declaration attribute.
    service_handle: u16,
    /// The handle of the last attribute in the service.
    end_group_handle: u16,
    /// The UUID of the service.
    service_uuid: UUID,
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
    const DEVICE_NAME_PROPERTIES: &'static [characteristic::Properties] = &[characteristic::Properties::Read];

    /// Device Appearance characteristic properties
    const DEVICE_APPEARANCE_PROPERTIES: &'static [characteristic::Properties] = &[characteristic::Properties::Read];

    /// Default Appearance
    pub const UNKNOWN_APPEARANCE: u16 = 0;

    /// Make a new `GapServiceBuilder`
    ///
    /// The `device_name` is a readable string for the client. The appearance is an assigned number
    /// to indicate to the client the external appearance of the device. Both these fields are
    /// optional with `device_name` defaulting to an empty string and appearance as 'unknown appearance'
    pub fn new<D, A>(device_name: D, appearance: A) -> Self
    where
        D: Into<Option<&'a str>>,
        A: Into<Option<u16>>,
    {
        GapServiceBuilder {
            service_permissions: None,
            device_name: device_name.into().unwrap_or(""),
            device_name_permissions: Self::DEFAULT_ATTRIBUTE_PERMISSIONS,
            device_appearance: appearance.into().unwrap_or(Self::UNKNOWN_APPEARANCE),
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
    pub fn set_appearance_permissions(&mut self, permissions: &'a [att::AttributePermissions]) {
        self.device_appearance_permissions = permissions
    }

    fn into_gatt_service(self) -> ServerBuilder {
        let mut server_builder = ServerBuilder::new_empty();

        server_builder
            .new_service(Self::GAP_SERVICE_TYPE, true)
            .set_att_permissions(self.service_permissions)
            .add_characteristics()
            .new_characteristic()
            .set_properties(Self::DEVICE_NAME_PROPERTIES.to_vec())
            .set_uuid(Self::DEVICE_NAME_TYPE)
            .set_value(alloc::string::String::from(self.device_name))
            .set_permissions(self.device_name_permissions)
            .complete_characteristic()
            .new_characteristic()
            .set_properties(Self::DEVICE_APPEARANCE_PROPERTIES.to_vec())
            .set_uuid(Self::DEVICE_APPEARANCE_TYPE)
            .set_value(self.device_appearance)
            .set_permissions(self.device_appearance_permissions)
            .complete_characteristic()
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

/// A GATT server builder
///
/// This is a builder of a GATT server. It provides a walk through process for creating the service
/// architecture of the server before the server is created.
///
/// ```
/// use bo_tie::gatt::{ServerBuilder, GapServiceBuilder, characteristic::Properties};
/// use bo_tie::att::{FULL_PERMISSIONS, server::NoQueuedWrites};
/// use bo_tie::l2cap::{BasicInfoFrame, ConnectionChannel, BasicFrameFragment};
/// use std::task::Waker;
/// use std::future::Future;
///
/// # const MY_SERVICE_UUID: bo_tie::UUID = bo_tie::UUID::from_u16(0);
/// # const MY_CHARACTERISTIC_UUID: bo_tie::UUID = bo_tie::UUID::from_u16(0);
/// # struct CC;
/// # impl bo_tie::l2cap::ConnectionChannel for CC {
/// #     type SendFut = futures::future::Ready<Result<(), Self::SendFutErr>>;
/// #     type SendFutErr = usize;
/// #     fn send(&self,data: BasicInfoFrame) -> Self::SendFut { unimplemented!() }
/// #     fn set_mtu(&self,mtu: u16) { unimplemented!() }
/// #     fn get_mtu(&self) -> usize { unimplemented!() }
/// #     fn max_mtu(&self) -> usize { unimplemented!() }
/// #     fn min_mtu(&self) -> usize { unimplemented!() }
/// #     fn receive(&self,waker: &Waker) -> Option<Vec<BasicFrameFragment>> { unimplemented!()}
/// # }
/// # let connection_channel = CC;
///
/// let gap_service = GapServiceBuilder::new("My Device", None);
///
/// let mut server_builder = ServerBuilder::from(gap_service);
///
/// server_builder.new_service(MY_SERVICE_UUID, true)
///     .add_characteristics()
///         .new_characteristic()
///             .set_uuid(MY_CHARACTERISTIC_UUID)
///             .set_value(0usize)
///             .set_permissions(FULL_PERMISSIONS)
///             .set_properties([Properties::Read, Properties::Write].to_vec())
///             .complete_characteristic()
///         .finish_service();
///
/// let server = server_builder.make_server(&connection_channel, NoQueuedWrites);
/// ```
pub struct ServerBuilder {
    primary_services: Vec<ServiceGroupData>,
    attributes: att::server::ServerAttributes,
}

impl ServerBuilder {
    /// Construct an empty `ServerBuilder`
    ///
    /// This creates a `ServerBuilder` without the specification required GAP service.
    pub fn new_empty() -> Self {
        Self {
            primary_services: Vec::new(),
            attributes: att::server::ServerAttributes::new(),
        }
    }

    /// Construct a new service
    pub fn new_service(&mut self, service_uuid: UUID, is_primary: bool) -> ServiceBuilder<'_> {
        ServiceBuilder::new(self, service_uuid, is_primary)
    }

    /// Get all the attributes of the server
    pub fn get_attributes(&self) -> &att::server::ServerAttributes {
        &self.attributes
    }

    /// Make an server
    ///
    /// Construct an server from the server builder.
    pub fn make_server<C, Q>(self, connection_channel: &'_ C, queue_writer: Q) -> Server<C, Q>
    where
        C: l2cap::ConnectionChannel,
        Q: crate::att::server::QueuedWriter,
    {
        let server = att::server::Server::new(connection_channel, Some(self.attributes), queue_writer);

        Server {
            primary_services: self.primary_services,
            server,
        }
    }
}

impl From<GapServiceBuilder<'_>> for ServerBuilder {
    fn from(gap: GapServiceBuilder) -> Self {
        gap.into_gatt_service()
    }
}

pub struct Server<'c, C, Q> {
    primary_services: Vec<ServiceGroupData>,
    server: att::server::Server<'c, C, Q>,
}

impl<'c, C, Q> Server<'c, C, Q>
where
    C: l2cap::ConnectionChannel,
    Q: att::server::QueuedWriter,
{
    /// Get information on the services within this GATT server
    pub fn get_service_info(&self) -> impl Iterator<Item = Service> {
        self.primary_services.iter().map(move |s| Service {
            server_attributes: self.server.get_attributes(),
            group_data: *s,
        })
    }

    /// Process some ACL data as a ATT client message
    pub async fn process_acl_data(&mut self, acl_data: &crate::l2cap::BasicInfoFrame) -> Result<(), crate::att::Error> {
        let (pdu_type, payload) = self.server.parse_acl_packet(&acl_data)?;

        match pdu_type {
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                log::info!(
                    "(GATT) processing '{}'",
                    att::client::ClientPduName::ReadByGroupTypeRequest
                );

                self.process_read_by_group_type_request(payload).await
            }
            _ => self.server.process_parsed_acl_data(pdu_type, payload).await,
        }
    }

    /// 'Read by group type' permission check
    fn rbgt_permission_check(&self, service: &ServiceGroupData) -> Result<(), att::pdu::Error> {
        self.server
            .check_permissions(service.service_handle, att::FULL_READ_PERMISSIONS)
    }

    async fn process_read_by_group_type_request(&self, payload: &[u8]) -> Result<(), crate::att::Error> {
        match att::TransferFormatTryFrom::try_from(payload) {
            Ok(att::pdu::TypeRequest {
                handle_range,
                attr_type: ServiceDefinition::PRIMARY_SERVICE_TYPE,
            }) => {
                use att::pdu::{ReadByGroupTypeResponse, ReadGroupTypeData};

                let mut service_iter = self
                    .primary_services
                    .iter()
                    .filter(|s| {
                        s.service_handle >= handle_range.starting_handle
                            && s.service_handle <= handle_range.ending_handle
                    })
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
                        let is_16_bit = first_service.service_uuid.is_16_bit();

                        let build_response_iter =
                            service_iter.take_while(|rslt| rslt.is_ok()).map(|rslt| rslt.unwrap());

                        // Each data_size is 4 bytes for the attribute handle + the end group handle
                        // and either 2 bytes for short UUIDs or 16 bytes for full UUIDs
                        //
                        // Each collection is made to take while the *current* iteration does not
                        // overrun the maximum payload size.
                        let response = if is_16_bit {
                            build_response_iter
                                .take_while(|s| s.service_uuid.is_16_bit())
                                .enumerate()
                                .take_while(|(cnt, _)| payload_size > (cnt + 1) * (4 + 2))
                                .by_ref()
                                .map(|(_, s)| {
                                    ReadGroupTypeData::new(s.service_handle, s.end_group_handle, s.service_uuid)
                                })
                                .collect()
                        } else {
                            build_response_iter
                                .enumerate()
                                .take_while(|(cnt, _)| payload_size > (cnt + 1) * (4 + 16))
                                .by_ref()
                                .map(|(_, s)| {
                                    ReadGroupTypeData::new(s.service_handle, s.end_group_handle, s.service_uuid)
                                })
                                .collect()
                        };

                        let pdu = att::pdu::read_by_group_type_response(ReadByGroupTypeResponse::new(response));

                        self.server.send_pdu(pdu).await
                    }

                    // Client didn't have adequate permissions to access the first service
                    Some(Err(e)) => {
                        self.server
                            .send_error(
                                handle_range.starting_handle,
                                att::client::ClientPduName::ReadByGroupTypeRequest,
                                (*e).into(),
                            )
                            .await?;

                        return Err((*e).into());
                    }

                    // No service attributes found within the requested range
                    None => {
                        self.server
                            .send_error(
                                handle_range.starting_handle,
                                att::client::ClientPduName::ReadByGroupTypeRequest,
                                att::pdu::Error::AttributeNotFound,
                            )
                            .await
                    }
                }
            }
            Ok(att::pdu::TypeRequest { handle_range, .. }) => {
                self.server
                    .send_error(
                        handle_range.starting_handle,
                        att::client::ClientPduName::ReadByGroupTypeRequest,
                        att::pdu::Error::UnsupportedGroupType,
                    )
                    .await?;

                Err(att::pdu::Error::UnsupportedGroupType.into())
            }
            _ => {
                self.server
                    .send_error(
                        0,
                        att::client::ClientPduName::ReadByGroupTypeRequest,
                        att::pdu::Error::UnlikelyError,
                    )
                    .await?;

                Err(att::pdu::Error::UnlikelyError.into())
            }
        }
    }
}

impl<'c, C, Q> AsRef<att::server::Server<'c, C, Q>> for Server<'c, C, Q> {
    fn as_ref(&self) -> &att::server::Server<'c, C, Q> {
        &self.server
    }
}

impl<'c, C, Q> AsMut<att::server::Server<'c, C, Q>> for Server<'c, C, Q> {
    fn as_mut(&mut self) -> &mut att::server::Server<'c, C, Q> {
        &mut self.server
    }
}

impl<'c, C, Q> core::ops::Deref for Server<'c, C, Q> {
    type Target = att::server::Server<'c, C, Q>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'c, C, Q> core::ops::DerefMut for Server<'c, C, Q> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::att::server::NoQueuedWrites;
    use crate::l2cap::{BasicFrameFragment, ConnectionChannel, MinimumMtu};
    use crate::UUID;
    use alloc::boxed::Box;
    use att::TransferFormatInto;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    struct DummySendFut;

    impl Future for DummySendFut {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }

    struct DummyConnection;

    impl ConnectionChannel for DummyConnection {
        type SendFut = DummySendFut;
        type SendFutErr = ();

        fn send(&self, _: crate::l2cap::BasicInfoFrame) -> Self::SendFut {
            DummySendFut
        }

        fn set_mtu(&self, _: u16) {}

        fn get_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn max_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn min_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn receive(&self, _: &core::task::Waker) -> Option<Vec<crate::l2cap::BasicFrameFragment>> {
            None
        }
    }

    #[test]
    fn create_gatt_attributes() {
        let test_att_permissions: &[att::AttributePermissions] = &[
            att::AttributePermissions::Read(att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128)),
            att::AttributePermissions::Write(att::AttributeRestriction::Authentication),
        ];

        let mut gap_service = GapServiceBuilder::new(None, None);

        gap_service.set_permissions(test_att_permissions);

        let mut server_builder = ServerBuilder::new_with_gap(gap_service);

        let test_service_1 = server_builder
            .new_service_constructor(UUID::from_u16(0x1234), false)
            .set_att_permissions(test_att_permissions)
            .add_characteristics()
            .build_characteristic(
                vec![characteristic::Properties::Read],
                UUID::from(0x1234u16),
                Box::new(0usize),
                None,
            )
            .set_extended_properties(vec![characteristic::ExtendedProperties::ReliableWrite], None)
            .set_user_description(characteristic::UserDescription::new("Test 1", None))
            .set_client_configuration(vec![characteristic::ClientConfiguration::Notification], None)
            .set_server_configuration(vec![characteristic::ServerConfiguration::Broadcast], None)
            .finish_characteristic()
            .finish_service();

        let _test_service_2 = server_builder
            .new_service_constructor(UUID::from_u16(0x3456), true)
            .set_att_permissions(test_att_permissions)
            .into_includes_adder()
            .include_service(&test_service_1, None)
            .finish_service();

        let server = server_builder.make_server(&DummyConnection, NoQueuedWrites);

        server.iter_attr_info().for_each(|info| {
            assert_eq!(
                info.get_permissions(),
                test_att_permissions,
                "failing UUID: {:#x}, handle: {}",
                info.get_uuid(),
                info.get_handle()
            )
        })
    }

    struct TestChannel {
        last_sent_pdu: std::cell::Cell<Option<Vec<u8>>>,
    }

    impl l2cap::ConnectionChannel for TestChannel {
        type SendFut = DummySendFut;
        type SendFutErr = ();

        fn send(&self, data: crate::l2cap::BasicInfoFrame) -> Self::SendFut {
            self.last_sent_pdu.set(Some(data.into_raw_data()));

            DummySendFut
        }

        fn set_mtu(&self, _: u16) {}

        fn get_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn max_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn min_mtu(&self) -> usize {
            crate::l2cap::LeU::MIN_MTU
        }

        fn receive(&self, _: &Waker) -> Option<Vec<BasicFrameFragment>> {
            unimplemented!()
        }
    }

    #[test]
    fn gatt_services_read_by_group_type() {
        use futures::executor::block_on;

        let mut server_builder = ServerBuilder::new();

        let first_test_uuid = UUID::from(0x1000u16);
        let second_test_uuid = UUID::from(0x1001u128);

        server_builder
            .new_service_constructor(first_test_uuid, true)
            .add_characteristics()
            .build_characteristic(
                vec![characteristic::Properties::Read],
                UUID::from(0x2000u16),
                Box::new(0usize),
                None,
            )
            .finish_characteristic()
            .finish_service();

        server_builder
            .new_service_constructor(second_test_uuid, true)
            .add_characteristics()
            .build_characteristic(
                vec![characteristic::Properties::Read],
                UUID::from(0x2001u16),
                Box::new(0usize),
                None,
            )
            .finish_characteristic()
            .finish_service();

        let test_channel = TestChannel {
            last_sent_pdu: None.into(),
        };

        let mut server = server_builder.make_server(&test_channel, NoQueuedWrites);

        server.give_permissions_to_client([att::AttributePermissions::Read(att::AttributeRestriction::None)]);

        let client_pdu = att::pdu::read_by_group_type_request(1.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(Ok(()), block_on(server.process_acl_data(&acl_client_pdu)),);

        let expected_response = att::pdu::ReadByGroupTypeResponse::new(vec![
            // Gap Service
            att::pdu::ReadGroupTypeData::new(1, 5, GapServiceBuilder::GAP_SERVICE_TYPE),
            att::pdu::ReadGroupTypeData::new(6, 8, first_test_uuid),
        ]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicInfoFrame::from_raw_data(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(9.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(Ok(()), block_on(server.process_acl_data(&acl_client_pdu)),);

        let expected_response =
            att::pdu::ReadByGroupTypeResponse::new(vec![att::pdu::ReadGroupTypeData::new(9, 11, second_test_uuid)]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicInfoFrame::from_raw_data(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(12.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        // Request was made for for a attribute that was out of range
        assert_eq!(Ok(()), block_on(server.process_acl_data(&acl_client_pdu)));
    }
}
