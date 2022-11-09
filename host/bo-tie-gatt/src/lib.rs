#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

/// macro to ensure that `$to` is filled only with unique items of `$from`.
macro_rules! unique_only {
    ($to:expr, $from:expr) => {
        for x in $from {
            if !$to.contains(x) {
                $to.try_push(*x).unwrap()
            }
        }
    };
}

/// same as `unique_only` but $from iterates over owned items
macro_rules! unique_only_owned {
    ($to:expr, $from:expr) => {
        for x in $from {
            if !$to.contains(&x) {
                $to.try_push(x).unwrap()
            }
        }
    };
}

pub mod characteristic;

use alloc::vec::Vec;

pub use bo_tie_att as att;
use bo_tie_att::AttributePermissions;
pub use bo_tie_host_util::Uuid;
pub use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::ConnectionChannel;
use bo_tie_util::buffer::stack::LinearBuffer;

struct ServiceDefinition;

impl ServiceDefinition {
    /// The permissions of the service definitions is just Read Only
    const DEFAULT_PERMISSIONS: [att::AttributePermissions; 6] = att::FULL_READ_PERMISSIONS;

    /// The primary service UUID
    pub const PRIMARY_SERVICE_TYPE: Uuid = Uuid::from_u16(0x2800);

    /// The secondary service UUID
    pub const SECONDARY_SERVICE_TYPE: Uuid = Uuid::from_u16(0x2801);
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
    const TYPE: Uuid = Uuid::from_u16(0x2802);

    const PERMISSIONS: [att::AttributePermissions; 6] = att::FULL_READ_PERMISSIONS;
}

/// Construct a GATT Service.
///
/// Every service contains a service definition characteristic with a number of other optional
/// characteristics defined as part of the GATT protocol. A service can also have custom
/// characteristics defined in a higher layer protocol.
///
/// A `ServiceBuilder` is created with the function `new_service_constructor` of
/// [`ServerBuilder`]. `ServiceBuilder` is tied to the `ServerBuilder`
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
    service_uuid: Uuid,
    is_primary: bool,
    server_builder: &'a mut ServerBuilder,
    default_permissions: Option<LinearBuffer<12, att::AttributePermissions>>,
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
    fn new(server_builder: &'a mut ServerBuilder, service_uuid: Uuid, is_primary: bool) -> Self {
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
                ServiceDefinition::DEFAULT_PERMISSIONS,
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

    /// Set the permissions for exposing the service
    ///
    /// In order to prevent services from being discoverable from unwanted Clients, a service may
    /// have attribute permissions applied to have the GATT server to act as a 'gatekeeper' to it
    /// (or a bouncer for a more modern day metaphor). If a client has not been granted any of the
    /// permissions within `permissions` they cannot discover this service or anything inside it.
    ///
    /// # Note
    /// No exposure protection is applied to this service if `permissions` is empty
    pub fn gatekeeper_permissions<P>(mut self, permissions: P) -> Self
    where
        P: core::borrow::Borrow<[AttributePermissions]>,
    {
        let mut default_permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions> =
            LinearBuffer::new();

        unique_only!(default_permissions, permissions.borrow().iter());

        self.default_permissions = default_permissions.into();

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

    /// Include another service
    ///
    /// This takes a reference to the service to include with an optional permissions for the
    /// include definition. If no permissions are given, then it uses the default permissions of the
    /// this service (not the service being included) for the include declaration.
    pub fn include_service(mut self, service_record: ServiceRecord) -> Self {
        let include = ServiceInclude {
            service_handle: service_record.record.service_handle,
            end_group_handle: service_record.record.end_group_handle,
            short_service_type: service_record.record.service_uuid.try_into().ok(),
        };

        let attribute = att::Attribute::new(ServiceInclude::TYPE, ServiceInclude::PERMISSIONS, include);

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
/// This is created by the [`ServiceBuilder::add_characteristics`] or
/// [`IncludesAdder::add_characteristics`] functions.
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
    pub fn new_characteristic<'c, F, V, E, U, C, S>(self, f: F) -> Self
    where
        F: FnOnce(
            characteristic::CharacteristicBuilder<
                'a,
                characteristic::declaration::SetProperties,
                characteristic::value::SetValue,
                characteristic::extended_properties::SetExtendedProperties,
                characteristic::user_description::SetDescription,
                characteristic::client_config::ReadOnlyClientConfiguration,
                characteristic::server_config::SetConfiguration,
            >,
        ) -> characteristic::CharacteristicBuilder<
            'a,
            characteristic::declaration::Complete,
            characteristic::value::Complete<V>,
            E,
            U,
            C,
            S,
        >,
        characteristic::value::ValueBuilder<characteristic::value::TrueComplete<V>>:
            characteristic::AddCharacteristicComponent,
        characteristic::extended_properties::ExtendedPropertiesBuilder<E>: characteristic::AddCharacteristicComponent,
        characteristic::user_description::UserDescriptionBuilder<U>: characteristic::AddCharacteristicComponent,
        characteristic::client_config::ClientConfigurationBuilder<C>: characteristic::AddCharacteristicComponent,
        characteristic::server_config::ServerConfigurationBuilder<S>: characteristic::AddCharacteristicComponent,
    {
        f(characteristic::CharacteristicBuilder::new(self)).complete_characteristic()
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
        service_uuid: Uuid,
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
    pub fn get_uuid(&self) -> crate::Uuid {
        self.group_data.service_uuid
    }

    /// Get the end handle within the Service
    ///
    /// This is handle of the last Attribute within the Service
    pub fn get_end_group_handle(&self) -> u16 {
        self.group_data.end_group_handle
    }

    /// Get a record to the data
    ///
    /// A record is the same thing as a [`Service`], but it does not have the lifetime back to
    /// the location of the service.
    pub fn as_record(&self) -> ServiceRecord {
        ServiceRecord {
            record: self.group_data,
        }
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

/// A service record
///
/// This contains the information of a [`Service`] without the reference to its location.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct ServiceRecord {
    record: ServiceGroupData,
}

impl From<Service<'_>> for ServiceRecord {
    fn from(s: Service<'_>) -> Self {
        ServiceRecord { record: s.group_data }
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
    service_uuid: Uuid,
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
    const GAP_SERVICE_TYPE: Uuid = Uuid::from_u16(0x1800);

    /// Device Name Characteristic UUID
    const DEVICE_NAME_TYPE: Uuid = Uuid::from_u16(0x2a00);

    /// Device Appearance Characteristic UUID
    const DEVICE_APPEARANCE_TYPE: Uuid = Uuid::from_u16(0x2a01);

    /// Default attribute permissions
    const DEFAULT_ATTRIBUTE_PERMISSIONS: &'static [att::AttributePermissions] = &att::FULL_READ_PERMISSIONS;

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
            .add_characteristics()
            .new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties(Self::DEVICE_NAME_PROPERTIES)
                            .set_uuid(Self::DEVICE_NAME_TYPE)
                    })
                    .set_value(|value| {
                        value
                            .set_value(alloc::string::String::from(self.device_name))
                            .set_permissions(self.device_name_permissions)
                    })
            })
            .new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties(Self::DEVICE_APPEARANCE_PROPERTIES)
                            .set_uuid(Self::DEVICE_APPEARANCE_TYPE)
                    })
                    .set_value(|value| {
                        value
                            .set_value(self.device_appearance)
                            .set_permissions(self.device_appearance_permissions)
                    })
            })
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
/// use bo_tie_gatt::{ServerBuilder, GapServiceBuilder, characteristic::Properties};
/// use bo_tie_att::{FULL_PERMISSIONS, server::NoQueuedWrites};
///
/// # use bo_tie_l2cap::{BasicFrameError,BasicInfoFrame, L2capFragment, send_future};
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use bo_tie_util::buffer::de_vec::DeVec;
/// # use bo_tie_util::buffer::TryExtend;
/// # const SERVICE_UUID: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(0);
/// # const CHARACTERISTIC_UUID: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(0);
/// # struct CC;
/// # impl bo_tie_l2cap::ConnectionChannel for CC {
/// #     type SendBuffer = DeVec<u8>;
/// #     type SendFut<'a> = Pin<Box<dyn Future<Output = Result<(), send_future::Error<()>>>>>;
/// #     type SendFutErr = ();
/// #     type RecvBuffer = DeVec<u8>;
/// #     type RecvFut<'a> = Pin<Box<dyn Future<Output = Option<Result<L2capFragment<Self::RecvBuffer>, BasicFrameError<<Self::RecvBuffer as TryExtend<u8>>::Error>>>>>>;
/// #     fn send(&self,data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
/// #     fn set_mtu(&mut self,_: u16) { unimplemented!() }
/// #     fn get_mtu(&self) -> usize { unimplemented!() }
/// #     fn max_mtu(&self) -> usize { unimplemented!() }
/// #     fn min_mtu(&self) -> usize { unimplemented!() }
/// #     fn receive(&mut self) -> Self::RecvFut<'_> { unimplemented!()}
/// # }
/// # let connection_channel = CC;
///
/// let gap_service = GapServiceBuilder::new("My Device", None);
///
/// let mut server_builder = ServerBuilder::from(gap_service);
///
/// server_builder.new_service(SERVICE_UUID, true)
///     .add_characteristics()
///     .new_characteristic(|characteristic_builder| {
///         characteristic_builder
///             .set_declaration(|declaration_builder| {
///                 declaration_builder
///                     .set_properties([Properties::Read])
///                     .set_uuid(CHARACTERISTIC_UUID)
///             })
///             .set_value(|value_builder| {
///                 value_builder
///                     .set_value(0usize)
///                     .set_permissions(bo_tie_att::FULL_READ_PERMISSIONS)
///             })
///     })
///     .finish_service();
///
/// let server = server_builder.make_server(NoQueuedWrites);
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
    pub fn new_service<U>(&mut self, service_uuid: U, is_primary: bool) -> ServiceBuilder<'_>
    where
        U: Into<Uuid>,
    {
        ServiceBuilder::new(self, service_uuid.into(), is_primary)
    }

    /// Get all the attributes of the server
    pub fn get_attributes(&self) -> &att::server::ServerAttributes {
        &self.attributes
    }

    /// Make an server
    ///
    /// Construct an server from the server builder.
    pub fn make_server<Q>(self, queue_writer: Q) -> Server<Q>
    where
        Q: att::server::QueuedWriter,
    {
        let server = att::server::Server::new(Some(self.attributes), queue_writer);

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

pub struct Server<Q> {
    primary_services: Vec<ServiceGroupData>,
    server: att::server::Server<Q>,
}

impl<Q> Server<Q>
where
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
    pub async fn process_acl_data<C>(
        &mut self,
        connection_channel: &mut C,
        acl_data: &l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<(), att::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let (pdu_type, payload) = self.server.parse_acl_packet(&acl_data)?;

        match pdu_type {
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                log::info!(
                    "(GATT) processing '{}'",
                    att::client::ClientPduName::ReadByGroupTypeRequest
                );

                self.process_read_by_group_type_request(connection_channel, payload)
                    .await
            }
            _ => {
                self.server
                    .process_parsed_acl_data(connection_channel, pdu_type, payload)
                    .await
            }
        }
    }

    /// 'Read by group type' permission check
    fn rbgt_permission_check(&self, service: &ServiceGroupData) -> Result<(), att::pdu::Error> {
        self.server
            .check_permissions(service.service_handle, &att::FULL_READ_PERMISSIONS)
    }

    async fn process_read_by_group_type_request<C>(
        &self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<(), att::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
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
                        let payload_size = connection_channel.get_mtu() - 2;
                        let can_be_16_bit = first_service.service_uuid.can_be_16_bit();

                        let build_response_iter =
                            service_iter.take_while(|rslt| rslt.is_ok()).map(|rslt| rslt.unwrap());

                        // Each data_size is 4 bytes for the attribute handle + the end group handle
                        // and either 2 bytes for short UUIDs or 16 bytes for full UUIDs
                        //
                        // Each collection is made to take while the *current* iteration does not
                        // overrun the maximum payload size.
                        let response = if can_be_16_bit {
                            build_response_iter
                                .take_while(|s| s.service_uuid.can_be_16_bit())
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

                        self.server.send_pdu(connection_channel, pdu).await
                    }

                    // Client didn't have adequate permissions to access the first service
                    Some(Err(e)) => {
                        self.server
                            .send_error(
                                connection_channel,
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
                                connection_channel,
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
                        connection_channel,
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
                        connection_channel,
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

impl<Q> AsRef<att::server::Server<Q>> for Server<Q> {
    fn as_ref(&self) -> &att::server::Server<Q> {
        &self.server
    }
}

impl<Q> AsMut<att::server::Server<Q>> for Server<Q> {
    fn as_mut(&mut self) -> &mut att::server::Server<Q> {
        &mut self.server
    }
}

impl<Q> core::ops::Deref for Server<Q> {
    type Target = att::server::Server<Q>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<Q> core::ops::DerefMut for Server<Q> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

/// A GATT client
///
/// This is an extension to an Attribute [`Client`] as it provides the added functionality of
/// processing the Services and Characteristics of a GATT server.
///
/// Since this is really just a wrapper, it can be created from an Attribute `Client`.
///
/// ```
/// # async fn fun<C: bo_tie_l2cap::ConnectionChannel>(mut connection_channel: C) {
/// use bo_tie_att::client::ConnectClient;
/// use bo_tie_gatt::Client;
///
/// let gatt_client: Client = ConnectClient::connect(&mut connection_channel, 64).await?.into();
/// # }
/// ```
///
/// [`Client`]: bo_tie_att::client::Client
pub struct Client {
    att_client: att::client::Client,
}

impl Client {
    fn new(att_client: att::client::Client) -> Self {
        Client { att_client }
    }

    /// Query the services
    ///
    /// This returns a `ServicesQuery` which is used to get the services on the remote device.
    pub fn query_services<'a, C: ConnectionChannel>(&'a self, connection_channel: &'a mut C) -> ServicesQuery<'a, C> {
        ServicesQuery::new(connection_channel, self)
    }
}

impl From<att::client::Client> for Client {
    fn from(c: att::client::Client) -> Self {
        Client::new(c)
    }
}

impl core::ops::Deref for Client {
    type Target = att::client::Client;

    fn deref(&self) -> &Self::Target {
        &self.att_client
    }
}

/// A querier for Services on a GATT server.
///
/// This struct is created from the method [`query_services`]. See its documentation for details.
pub struct ServicesQuery<'a, C> {
    channel: &'a mut C,
    client: &'a Client,
    iter: Option<alloc::vec::IntoIter<bo_tie_att::pdu::ReadGroupTypeData<Uuid>>>,
    handle: u16,
}

impl<'a, C: ConnectionChannel> ServicesQuery<'a, C> {
    fn new(channel: &'a mut C, client: &'a Client) -> Self {
        let iter = None;
        let handle = 0;

        ServicesQuery {
            channel,
            client,
            iter,
            handle,
        }
    }

    /// Send the *Read By Group Type Request*
    async fn send_request(
        &mut self,
    ) -> Result<
        Option<impl bo_tie_att::client::ResponseProcessor<Response = bo_tie_att::pdu::ReadByGroupTypeResponse<Uuid>>>,
        bo_tie_att::ConnectionError<C>,
    > {
        if self.handle == <u16>::MAX {
            return Ok(None);
        }

        self.client
            .att_client
            .read_by_group_type_request(
                self.channel,
                self.handle..<u16>::MAX,
                ServiceDefinition::PRIMARY_SERVICE_TYPE,
            )
            .await
            .map(|rp| Some(rp))
    }

    /// Await and process the *Read By Group Type Response*
    async fn await_response(
        &mut self,
        response_processor: impl bo_tie_att::client::ResponseProcessor<
            Response = bo_tie_att::pdu::ReadByGroupTypeResponse<Uuid>,
        >,
    ) -> Result<Option<bo_tie_att::pdu::ReadByGroupTypeResponse<Uuid>>, bo_tie_att::ConnectionError<C>> {
        use bo_tie_att::pdu::Error;
        use bo_tie_l2cap::ConnectionChannelExt;

        let frames = self.channel.receive_b_frame().await.map_err(|e| e.from_infallible())?;

        if frames.len() != 1 {
            return Err(bo_tie_att::Error::Other("received more than one L2CAP PDU").into());
        };

        match response_processor.process_response(frames.first().unwrap()) {
            Ok(response) => Ok(Some(response)),
            Err(bo_tie_att::Error::Pdu(pdu)) if pdu.get_parameters().error == Error::AttributeNotFound => Ok(None), // no more services
            Err(e) => Err(e.into()),
        }
    }

    /// Query the next Service
    ///
    /// This will return the next service on the Server. If there is no more services then `None`
    /// is returned.
    pub async fn query_next(&mut self) -> Result<Option<ServiceRecord>, bo_tie_att::ConnectionError<C>> {
        loop {
            if self.iter.is_none() {
                let response = match self.send_request().await? {
                    None => break Ok(None),
                    Some(processor) => match self.await_response(processor).await {
                        Ok(None) => {
                            // set the handle to have `send_request` always return `Ok(None)`
                            self.handle = <u16>::MAX;

                            break Ok(None);
                        } // no more services
                        Err(e) => break Err(e),
                        Ok(Some(response)) => response,
                    },
                };

                self.iter = response.into_inner().into_iter().into()
            }

            match self.iter.as_mut().and_then(|iter| iter.next()) {
                None => self.iter = None,
                Some(group_data) => {
                    let record = ServiceGroupData {
                        service_handle: group_data.get_handle(),
                        end_group_handle: group_data.get_end_group_handle(),
                        service_uuid: *group_data.get_data(),
                    };

                    self.handle = group_data.get_end_group_handle().checked_add(1).unwrap_or(<u16>::MAX);

                    break Ok(Some(ServiceRecord { record }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::att::server::NoQueuedWrites;
    use crate::l2cap::{ConnectionChannel, L2capFragment, MinimumMtu};
    use crate::Uuid;
    use att::TransferFormatInto;
    use bo_tie_att::server::access_value::Trivial;
    use bo_tie_att::{AttributePermissions, AttributeRestriction};
    use bo_tie_l2cap::{send_future, BasicFrameError};
    use bo_tie_util::buffer::de_vec::DeVec;
    use bo_tie_util::buffer::TryExtend;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    struct DummySendFut;

    impl Future for DummySendFut {
        type Output = Result<(), send_future::Error<()>>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }

    struct DummyRecvFut;

    impl Future for DummyRecvFut {
        type Output = Option<Result<L2capFragment<DeVec<u8>>, BasicFrameError<<DeVec<u8> as TryExtend<u8>>::Error>>>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            unimplemented!()
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

        let mut server_builder = ServerBuilder::from(gap_service);

        let test_service_1 = server_builder
            .new_service(Uuid::from_u16(0x1234), false)
            .add_characteristics()
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([
                                characteristic::Properties::Read,
                                characteristic::Properties::ExtendedProperties,
                            ])
                            .set_uuid(0x1234u16)
                    })
                    .set_value(|value_builder| value_builder.set_value(0usize).set_permissions(test_att_permissions))
                    .set_user_description(|user_desc_builder| {
                        user_desc_builder
                            .read_only()
                            .set_read_only_description("Test 1")
                            .set_read_only_restrictions([AttributeRestriction::None])
                    })
                    .set_extended_properties(|ext_prop_builder| {
                        ext_prop_builder.set_extended_properties([characteristic::ExtendedProperties::ReliableWrite])
                    })
                    .set_client_configuration(|client_cfg_builder| {
                        client_cfg_builder.set_config([characteristic::ClientConfiguration::Notification])
                    })
                    .set_server_configuration(|| {
                        characteristic::ServerConfigurationBuilder::new()
                            .set_config(Trivial(characteristic::ServerConfiguration::new()))
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::None)])
                    })
            })
            .finish_service();

        let service_1_record = test_service_1.as_record();

        let _test_service_2 = server_builder
            .new_service(Uuid::from_u16(0x3456), true)
            .into_includes_adder()
            .include_service(service_1_record)
            .finish_service();

        let server = server_builder.make_server(NoQueuedWrites);

        for characteristic in server
            .get_service_info()
            .map(|service| service.iter_characteristics())
            .flatten()
        {
            let value_handle = characteristic.get_value_handle();

            let info = server.get_attributes().get_info(value_handle).unwrap();

            assert_eq!(
                info.get_permissions(),
                test_att_permissions,
                "failing UUID: {:#x}, handle: {}",
                info.get_uuid(),
                info.get_handle()
            )
        }
    }

    struct TestChannel {
        last_sent_pdu: std::cell::Cell<Option<Vec<u8>>>,
    }

    impl ConnectionChannel for TestChannel {
        type SendBuffer = DeVec<u8>;
        type SendFut<'a> = DummySendFut;
        type SendFutErr = ();
        type RecvBuffer = DeVec<u8>;
        type RecvFut<'a> = DummyRecvFut where Self: 'a,;

        fn send(&self, data: crate::l2cap::BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
            self.last_sent_pdu.set(Some(data.try_into_packet().unwrap()));

            DummySendFut
        }

        fn set_mtu(&mut self, _: u16) {}

        fn get_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn max_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn min_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn receive(&mut self) -> Self::RecvFut<'_> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn gatt_services_read_by_group_type() {
        let gap_service = GapServiceBuilder::new(None, None);

        let mut server_builder = ServerBuilder::from(gap_service);

        let first_test_uuid = Uuid::from(0x1000u16);
        let second_test_uuid = Uuid::from(0x1001u128);

        server_builder
            .new_service(first_test_uuid, true)
            .add_characteristics()
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([characteristic::Properties::Read])
                            .set_uuid(0x2000u16)
                    })
                    .set_value(|value_builder| {
                        value_builder
                            .set_value(0usize)
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::None)])
                    })
            })
            .finish_service();

        server_builder
            .new_service(second_test_uuid, true)
            .add_characteristics()
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([characteristic::Properties::Read])
                            .set_uuid(0x2001u16)
                    })
                    .set_value(|value_builder| {
                        value_builder
                            .set_value(0usize)
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::None)])
                    })
            })
            .finish_service();

        let mut test_channel = TestChannel {
            last_sent_pdu: None.into(),
        };

        let mut server = server_builder.make_server(NoQueuedWrites);

        server.give_permissions_to_client([att::AttributePermissions::Read(att::AttributeRestriction::None)]);

        let client_pdu = att::pdu::read_by_group_type_request(1.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(
            Ok(()),
            server.process_acl_data(&mut test_channel, &acl_client_pdu).await
        );

        let expected_response = att::pdu::ReadByGroupTypeResponse::new(vec![
            // Gap Service
            att::pdu::ReadGroupTypeData::new(1, 5, GapServiceBuilder::GAP_SERVICE_TYPE),
            att::pdu::ReadGroupTypeData::new(6, 8, first_test_uuid),
        ]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicInfoFrame::<Vec<_>>::try_from_slice(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(9.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(
            Ok(()),
            server.process_acl_data(&mut test_channel, &acl_client_pdu).await
        );

        let expected_response =
            att::pdu::ReadByGroupTypeResponse::new(vec![att::pdu::ReadGroupTypeData::new(9, 11, second_test_uuid)]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicInfoFrame::<Vec<_>>::try_from_slice(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(12.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicInfoFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        // Request was made for for a attribute that was out of range
        assert_eq!(
            Ok(()),
            server.process_acl_data(&mut test_channel, &acl_client_pdu).await
        );
    }
}
