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

macro_rules! map_restrictions {
    ( $restrictions:expr => Read ) => {{
        let mut permissions = bo_tie_core::buffer::stack::LinearBuffer::<
            { bo_tie_att::AttributeRestriction::full_depth() },
            bo_tie_att::AttributePermissions,
        >::new();

        map_restrictions!($restrictions => Read => permissions);

        permissions
    }};
    ( $restrictions:expr => Write ) => {{
        let mut permissions = bo_tie_core::buffer::stack::LinearBuffer::<
            { bo_tie_att::AttributeRestriction::full_depth() },
            bo_tie_att::AttributePermissions,
        >::new();

        map_restrictions!($restrictions => Write => permissions)
    }};
    ( $restrictions:expr => Read & Write ) => {{
        let mut permissions = bo_tie_core::buffer::stack::LinearBuffer::<
            { bo_tie_att::AttributePermissions::full_depth() },
            bo_tie_att::AttributePermissions,
        >::new();

        map_restrictions!($restrictions => Read & Write => permissions);

        permissions
    }};
    ( $restrictions:expr => Read => $permissions:expr) => {{
        for restriction in $restrictions.iter() {
            $permissions
                .try_push(bo_tie_att::AttributePermissions::Read(*restriction))
                .unwrap();
        }
    }};
    ( $restrictions:expr => Write => $permissions:expr) => {{
        for restriction in $restrictions.iter() {
            $permissions
                .try_push(bo_tie_att::AttributePermissions::Write(*restriction))
                .unwrap();
        }
    }};
    ( $restrictions:expr => Read & Write => $permissions:expr) => {{
        for restriction in $restrictions.iter() {
            $permissions
                .try_push(bo_tie_att::AttributePermissions::Read(*restriction))
                .unwrap();
        }

        for restriction in $restrictions.iter() {
            $permissions
                .try_push(bo_tie_att::AttributePermissions::Write(*restriction))
                .unwrap();
        }
    }};
}

pub mod characteristic;
pub mod uuid;

use crate::characteristic::client_config::SetClientConfig;
use crate::characteristic::ClientConfiguration;
use bo_tie_att as att;
use bo_tie_att::pdu::HandleRange;
use bo_tie_core::buffer::stack::LinearBuffer;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LogicalLink, PhysicalLink};
use std::future::Future;

/// The minimum size of the ATT profile's MTU (running the GATT profile)
///
/// This is also the default ATT_MTU when running the GATT profile over a LE physical link.
///
/// # Note
/// This value is only for 'regular' LE ATT protocol operation. This is not the same value for
/// enhanced LE ATT or BR/EDR.
const LE_MINIMUM_ATT_MTU: u16 = LeULink::SUPPORTED_MTU;

struct ServiceDefinition;

impl ServiceDefinition {
    /// The permissions of the service definitions is just Read Only
    const DEFAULT_PERMISSIONS: [att::AttributePermissions; 6] = att::FULL_READ_PERMISSIONS;

    /// The primary service UUID
    pub const PRIMARY_SERVICE_TYPE: Uuid = uuid::PRIMARY_SERVICE;

    /// The secondary service UUID
    pub const SECONDARY_SERVICE_TYPE: Uuid = uuid::SECONDARY_SERVICE;
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
    const TYPE: Uuid = uuid::INCLUDE_DEFINITION;
}

struct ServiceBuilderSource<'a> {
    primary_services: &'a mut alloc::vec::Vec<ServiceGroupData>,
    attributes: &'a mut att::server::ServerAttributes,
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
    source: ServiceBuilderSource<'a>,
    definition_handle: Option<u16>,
    access_restrictions: LinearBuffer<{ att::AttributeRestriction::full_depth() }, att::AttributeRestriction>,
}

// Unfortunately this cannot be made into a method as the borrow checker would trip when this was
// used within another method that moved self.
macro_rules! make_service {
    ($this:expr, $end_service_handle:expr) => {{
        let service = Service::new(
            $this.source.attributes,
            $this.is_primary,
            $this.definition_handle.unwrap(),
            $end_service_handle,
            $this.service_uuid,
        );

        if $this.is_primary {
            $this.source.primary_services.push(service.group_data)
        }

        service
    }};
}

impl<'a> ServiceBuilder<'a> {
    const DEFAULT_RESTRICTIONS: [att::AttributeRestriction; att::AttributeRestriction::full_depth()] = [
        att::AttributeRestriction::None,
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits192),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits256),
        att::AttributeRestriction::Authorization,
        att::AttributeRestriction::Authentication,
    ];

    fn new(source: ServiceBuilderSource<'a>, service_uuid: Uuid) -> Self {
        let access_restrictions = Self::DEFAULT_RESTRICTIONS.into();

        let is_primary = true;

        ServiceBuilder {
            service_uuid,
            is_primary,
            source,
            definition_handle: None,
            access_restrictions,
        }
    }

    /// Set the Access Restriction to this Service
    ///
    /// Permissions can be set for the characteristic values, but the rest of the characteristics
    /// descriptors of the service are readable or writeable by default to the connected device. In
    /// order to restrict access to these descriptors this method must be called change the default
    /// read permissions. The default restriction is replaced with the input
    /// restrictions and the operation of reading or writing to the descriptor requires the client
    /// to be [*given*] the permission containing the restriction.
    ///
    /// This affects all the service definition and characteristics, but not retroactively. If this
    /// is called after say [`set_service_definition`], then the service definition
    ///
    /// The main reason to use `gatekeep` is to ensure that the client is either encrypted,
    /// authenticated and/or authorized to access the GAP service.
    ///
    /// [*given*]: bo_tie_att::server::Server::give_permissions_to_client
    #[cfg(feature = "unstable")]
    fn set_access_restriction(mut self, restrictions: &[att::AttributeRestriction]) -> Self {
        self.access_restrictions.clear();

        for restriction in restrictions {
            if !self.access_restrictions.contains(restriction) {
                self.access_restrictions.try_push(*restriction).unwrap();
            }
        }

        self
    }

    /// Set the service definition into the server attributes
    ///
    /// This will create and add the service definition to the Attribute Server and return the
    /// handle to it.
    fn set_service_definition(&mut self) {
        self.definition_handle = self
            .source
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

    /// Make this Service a 'secondary' service
    pub fn make_secondary(mut self) -> Self {
        self.is_primary = false;
        self
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
}

/// Adder of Services to a Server
///
/// See method [`add_services`] of `Server`
///
/// [`add_services`]: Server::add_services
pub struct ServicesAdder<'a> {
    primary_services: &'a mut alloc::vec::Vec<ServiceGroupData>,
    attributes: &'a mut att::server::ServerAttributes,
}

impl<'a> ServicesAdder<'a> {
    fn new(
        primary_services: &'a mut alloc::vec::Vec<ServiceGroupData>,
        attributes: &'a mut att::server::ServerAttributes,
    ) -> Self {
        ServicesAdder {
            primary_services,
            attributes,
        }
    }

    /// Add a Single Service
    ///
    /// This returns a [`ServerBuilder`] to construct the new service to be added to the Server.
    pub fn add(&mut self, service_uuid: Uuid) -> ServiceBuilder<'_> {
        let source = ServiceBuilderSource {
            primary_services: self.primary_services,
            attributes: self.attributes,
        };

        ServiceBuilder::new(source, service_uuid)
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
    /// This takes a record to the service to include with an optional permissions for the
    /// include definition. The service must be within the same server as this include definition.
    /// The information within the record is checked to see if the information within it is still
    /// valid.
    ///
    /// After the information within the service record is validated an includes definition is added
    /// to the service for the information within the service record.
    ///
    /// # Error
    /// The `service_record` was not within the same server as this includes definition, or the
    /// information within the service record is no longer valid.
    ///
    /// If an error occurs then an includes definition is not added to the server for the provided
    /// `service_record`.
    pub fn include_service(mut self, service_record: ServiceRecord) -> Result<Self, IncludeServiceError> {
        let service = Service::try_from_record(self.service_builder.source.attributes, service_record)?;

        let include = ServiceInclude {
            service_handle: service.get_handle(),
            end_group_handle: service.get_end_group_handle(),
            short_service_type: service.get_uuid().try_into().ok(),
        };

        let permissions = map_restrictions!(self.service_builder.access_restrictions => Read);

        let attribute = att::Attribute::new(ServiceInclude::TYPE, permissions, include);

        self.end_group_handle = self.service_builder.source.attributes.push(attribute);

        Ok(self)
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

#[derive(Debug)]
pub enum IncludeServiceError {
    ServiceDoesNotExist,
    ServiceInformationPrimaryStatusDoesNotMatch,
    ServiceUuidDoesNotMatch,
}

impl core::fmt::Display for IncludeServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            IncludeServiceError::ServiceDoesNotExist => f.write_str("no service exists for this service record"),
            IncludeServiceError::ServiceInformationPrimaryStatusDoesNotMatch => unreachable!(),
            IncludeServiceError::ServiceUuidDoesNotMatch => {
                f.write_str("the UUID of the service does not match the UUID within the service record")
            }
        }
    }
}

impl From<ServiceRecordError> for IncludeServiceError {
    fn from(value: ServiceRecordError) -> Self {
        match value {
            ServiceRecordError::InvalidType => IncludeServiceError::ServiceDoesNotExist,
            ServiceRecordError::InvalidHandle => IncludeServiceError::ServiceDoesNotExist,
            ServiceRecordError::InvalidValue => unreachable!(),
            ServiceRecordError::InvalidPrimaryStatus => {
                IncludeServiceError::ServiceInformationPrimaryStatusDoesNotMatch
            }
            ServiceRecordError::InvalidServiceUuid => IncludeServiceError::ServiceUuidDoesNotMatch,
        }
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
    last_characteristic: Option<characteristic::CharacteristicRecord>,
}

impl<'a> CharacteristicAdder<'a> {
    fn new(service_builder: ServiceBuilder<'a>, end_group_handle: u16) -> Self {
        CharacteristicAdder {
            service_builder,
            end_group_handle,
            last_characteristic: None,
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
                characteristic::client_config::SetClientConfiguration,
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

    /// Get the record of the lastly created characteristic
    ///
    /// This returns the record of the last characteristic created by this `CharacteristicAdder`
    pub fn get_last_record(&self) -> Option<&characteristic::CharacteristicRecord> {
        self.last_characteristic.as_ref()
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
        server_attributes: &'a att::server::ServerAttributes,
        is_primary: bool,
        service_handle: u16,
        end_group_handle: u16,
        service_uuid: Uuid,
    ) -> Self {
        let group_data = ServiceGroupData {
            is_primary,
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
            group_data: self.group_data,
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

    /// Try to get a `Service` for the provided record
    ///
    /// If there is a service at `handle` it is returned.
    ///
    /// # Error
    /// Information within `record` did not match the information within the server.
    fn try_from_record(
        attributes: &att::server::ServerAttributes,
        record: ServiceRecord,
    ) -> Result<Service<'_>, ServiceRecordError> {
        let attribute_info = attributes
            .get_info(record.group_data.service_handle)
            .ok_or(ServiceRecordError::InvalidHandle)?;

        let is_primary = if *attribute_info.get_uuid() == ServiceDefinition::PRIMARY_SERVICE_TYPE {
            true
        } else if *attribute_info.get_uuid() == ServiceDefinition::SECONDARY_SERVICE_TYPE {
            false
        } else {
            return Err(ServiceRecordError::InvalidType);
        };

        if record.is_primary() != is_primary {
            return Err(ServiceRecordError::InvalidPrimaryStatus);
        }

        let service_uuid: Uuid = *attributes
            .get_value(record.group_data.service_handle)
            .ok_or(ServiceRecordError::InvalidValue)?;

        if service_uuid != record.get_uuid() {
            return Err(ServiceRecordError::InvalidServiceUuid);
        }

        Ok(Service::new(
            attributes,
            is_primary,
            record.group_data.service_handle,
            record.group_data.end_group_handle,
            record.group_data.service_uuid,
        ))
    }
}

/// A service record
///
/// This contains the information of a [`Service`] without the reference to its location.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct ServiceRecord {
    group_data: ServiceGroupData,
}

impl ServiceRecord {
    /// Check if the service is a primary service
    pub fn is_primary(&self) -> bool {
        self.group_data.is_primary
    }

    /// Get the service UUID
    pub fn get_uuid(&self) -> Uuid {
        self.group_data.service_uuid
    }

    /// Get the handle of the service
    pub fn get_handle(&self) -> u16 {
        self.group_data.service_handle
    }

    /// Get the end handle of the service
    ///
    /// This returns the handle of the last attribute within this service.
    pub fn get_end_group_handle(&self) -> u16 {
        self.group_data.end_group_handle
    }

    /// Get the handle group range
    ///
    /// This returns the range of Attribute handles used by this service
    pub fn get_range(&self) -> core::ops::RangeInclusive<u16> {
        self.group_data.service_handle..=self.group_data.end_group_handle
    }
}

impl From<Service<'_>> for ServiceRecord {
    fn from(s: Service<'_>) -> Self {
        ServiceRecord {
            group_data: s.group_data,
        }
    }
}

enum ServiceRecordError {
    InvalidType,
    InvalidValue,
    InvalidHandle,
    InvalidPrimaryStatus,
    InvalidServiceUuid,
}

/// Group data about a service
///
/// This is the data used by the GATT server for quickly finding the Services within a GATT server
/// with a attribute group related request from the Server.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
struct ServiceGroupData {
    is_primary: bool,
    /// The handle of the Service declaration attribute.
    service_handle: u16,
    /// The handle of the last attribute in the service.
    end_group_handle: u16,
    /// The UUID of the service.
    service_uuid: Uuid,
}

/// A Constructor of the GAP Service
///
/// This is used to construct the GAP Service. This service is unique as the characteristics are
/// also unique to it. Per the Specification, every GAT server is required to have the GAP service,
/// so this is often the starting point in constructing a GATT [`Server`].
///
/// A [`ServerBuilder`] can be constructed from a `GapServiceBuilder` with the method
pub struct GapServiceBuilder<'a> {
    device_name: &'a str,
    device_name_read_restrictions: &'a [att::AttributeRestriction],
    device_name_write_restrictions: &'a [att::AttributeRestriction],
    device_appearance: u16,
    device_appearance_write_restrictions: &'a [att::AttributeRestriction],
    preferred_connection_parameters: Option<characteristic::gap::PreferredConnectionParameters>,
    preferred_connection_read_restrictions: &'a [att::AttributeRestriction],
    central_address_resolution: Option<bool>,
    add_rpa_only_characteristic: bool,
}

impl<'a> GapServiceBuilder<'a> {
    /// Service UUID
    const GAP_SERVICE_TYPE: Uuid = uuid::gap::GAP_SERVICE;

    /// Device Name Characteristic UUID
    const DEVICE_NAME_TYPE: Uuid = uuid::gap::DEVICE_NAME;

    /// Device Appearance Characteristic UUID
    const DEVICE_APPEARANCE_TYPE: Uuid = uuid::gap::APPEARANCE;

    /// Peripheral Preferred Connection Parameters UUID
    const PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS_TYPE: Uuid = uuid::gap::PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS;

    /// Central Address Resolution Uuid
    const CENTRAL_ADDRESS_RESOLUTION_TYPE: Uuid = uuid::gap::CENTRAL_ADDRESS_RESOLUTION;

    /// Resolvable Private Address Only Uuid
    const RESOLVABLE_PRIVATE_ADDRESS_ONLY_TYPE: Uuid = uuid::gap::RESOLVABLE_PRIVATE_ADDRESS_ONLY;

    /// Default attribute permissions
    // This is a reference to an array (instead of a slice) so that it errors if the types
    // AttributeRestriction or EncryptionKeySize has enums added to them.
    const DEFAULT_NAME_PERMISSIONS: &'static [att::AttributeRestriction; att::AttributeRestriction::full_depth()] = &[
        att::AttributeRestriction::None,
        att::AttributeRestriction::Authorization,
        att::AttributeRestriction::Authentication,
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits192),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits256),
    ];

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
            device_name: device_name.into().unwrap_or(""),
            device_name_read_restrictions: Self::DEFAULT_NAME_PERMISSIONS,
            device_name_write_restrictions: &[],
            device_appearance: appearance.into().unwrap_or(Self::UNKNOWN_APPEARANCE),
            device_appearance_write_restrictions: &[],
            preferred_connection_parameters: None,
            preferred_connection_read_restrictions: &[],
            central_address_resolution: None,
            add_rpa_only_characteristic: false,
        }
    }

    /// Indicate that the Device is Discoverable
    ///
    /// This is a shortcut for changing the Attribute Permissions of the device name Characteristic
    /// to be readable for any connected device.
    pub fn device_is_discoverable(&mut self) {
        self.device_name_read_restrictions = &[
            att::AttributeRestriction::None,
            att::AttributeRestriction::Authorization,
            att::AttributeRestriction::Authentication,
            att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128),
            att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits192),
            att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits256),
        ];
    }

    /// Enable the Device Name to be Written to
    ///
    /// This enables writing to the device name vale. This method takes a list of restrictions for
    /// the client to be able to write the device name.
    pub fn enable_device_name_write(&mut self, restrictions: &'a [att::AttributeRestriction]) {
        self.device_name_write_restrictions = restrictions;
    }

    /// Enable the Device Appearance to be Written to
    ///
    /// This enables writing to the device appearance value. This method takes a list of
    /// restrictions for the client to be able to write the device name.
    pub fn enable_appearance_write(&mut self, restrictions: &'a [att::AttributeRestriction]) {
        self.device_appearance_write_restrictions = restrictions;
    }

    /// Add the Preferred Connection Parameters
    ///
    /// This adds the optional characteristic for the preferred connection parameters. This
    /// characteristic is only optional for the device in the *peripheral* role, the *central*
    /// device shall not have this characteristic.
    ///
    /// | Parameters | Description | Value |
    /// |------------|-------------|-------|
    /// |interval_min| The minimum connection interval | between 7.5ms to 4s and a multiple of 1.25ms |
    /// |interval_max| The maximum connection interval | between 7.5ms to 4s and a multiple of 1.25ms<br/>Must be greater than interval_min |
    /// |latency| The peripheral latency | *subrate_factor * (latency + 1) < 500*<br/>and<br/>*subrate_factor * (latency + 1) < timeout / 2* |
    /// |timeout| The supervision timeout | greater than *(latency + 1) * subrate_factor * interval_max * 2* |
    ///
    /// `restrictions` is the client restrictions for reading the preferred connection parameters.
    /// An input of `None` is equivalent to having full read permissions.
    pub fn add_preferred_connection_parameters<R>(
        &mut self,
        interval_min: core::time::Duration,
        interval_max: core::time::Duration,
        latency: u16,
        timeout: core::time::Duration,
        restrictions: R,
    ) where
        R: Into<Option<&'a [att::AttributeRestriction]>>,
    {
        let interval_min = interval_min.as_millis() * 1000 / 1250;
        let interval_max = interval_max.as_millis() * 1000 / 1250;
        let timeout = timeout.as_millis() / 10;

        self.preferred_connection_parameters = characteristic::gap::PreferredConnectionParameters {
            interval_min: interval_min as u16,
            interval_max: interval_max as u16,
            latency,
            timeout: timeout as u16,
        }
        .into();

        let restrictions = restrictions.into().unwrap_or(&att::FULL_RESTRICTIONS);

        self.preferred_connection_read_restrictions = restrictions;
    }

    /// Add the Characteristic for the *Central* to indicate it supports Private Address Resolution
    ///
    /// This adds the characteristic to indicate that the central device supports private address
    /// resolution. This characteristic is mandatory for the device in the central role if it
    /// supports 'privacy'. It is optional for the central to have this characteristic if 'privacy'
    /// is not supported, but if it is used then the input `supported` must be false.
    ///
    /// If `supported` is `false` then the central does not support address resolution, if the input
    /// is `true` the the central supports address resolution. The `restrictions` are the client
    /// restrictions for reading the characteristic value.
    pub fn add_central_rpa_support(&mut self, supported: bool) {
        self.central_address_resolution = Some(supported);
    }

    /// Add the Characteristic to indicate that this device will only use Resolvable Private
    /// Addresses.
    ///
    /// This adds the optional characteristic to mark that this device will only use resolvable
    /// private addresses after bonding with the connected device.
    ///
    /// # Note
    /// This can only be added if the device support 'Privacy'.
    pub fn add_rpa_only(&mut self) {
        self.add_rpa_only_characteristic = true;
    }

    fn get_device_name_properties(&self) -> &'static [characteristic::Properties] {
        match (
            self.device_name_read_restrictions.len(),
            self.device_name_write_restrictions.len(),
        ) {
            (0, 0) => &[],
            (_, 0) => &[characteristic::Properties::Read],
            (0, _) => &[characteristic::Properties::Write],
            (_, _) => &[characteristic::Properties::Read, characteristic::Properties::Write],
        }
    }

    fn create_device_name_permissions(&self) -> impl core::borrow::Borrow<[att::AttributePermissions]> {
        let mut device_name_permissions =
            LinearBuffer::<{ att::AttributePermissions::full_depth() }, att::AttributePermissions>::new();

        unique_only_owned!(
            device_name_permissions,
            self.device_name_read_restrictions
                .iter()
                .map(|restriction| att::AttributePermissions::Read(*restriction))
        );

        unique_only_owned!(
            device_name_permissions,
            self.device_name_write_restrictions
                .iter()
                .map(|restriction| att::AttributePermissions::Write(*restriction))
        );

        device_name_permissions
    }

    fn get_device_appearance_properties(&self) -> &'static [characteristic::Properties] {
        if self.device_appearance_write_restrictions.len() != 0 {
            &[characteristic::Properties::Read, characteristic::Properties::Write]
        } else {
            &[characteristic::Properties::Read]
        }
    }

    fn create_device_appearance_permissions(&self) -> impl core::borrow::Borrow<[att::AttributePermissions]> {
        let mut appearance_permissions =
            LinearBuffer::<{ att::AttributePermissions::full_depth() }, att::AttributePermissions>::new();

        for permission in att::FULL_READ_PERMISSIONS {
            appearance_permissions.try_push(permission).unwrap();
        }

        unique_only_owned!(
            appearance_permissions,
            self.device_appearance_write_restrictions
                .iter()
                .map(|restriction| att::AttributePermissions::Write(*restriction))
        );

        appearance_permissions
    }

    fn get_preferred_connection_parameters_properties(&self) -> &'static [characteristic::Properties] {
        if self.preferred_connection_read_restrictions.len() != 0 {
            &[characteristic::Properties::Read]
        } else {
            &[]
        }
    }

    fn create_preferred_connection_parameter_permissions(
        &self,
    ) -> impl core::borrow::Borrow<[att::AttributePermissions]> {
        let mut permissions =
            LinearBuffer::<{ att::AttributeRestriction::full_depth() }, att::AttributePermissions>::new();

        unique_only_owned!(
            permissions,
            self.preferred_connection_read_restrictions
                .iter()
                .map(|restriction| att::AttributePermissions::Read(*restriction))
        );

        permissions
    }

    fn into_gatt_service(mut self) -> ServerBuilder {
        let mut server_builder = ServerBuilder::new_empty();

        let mut characteristic_adder = server_builder
            .new_service(Self::GAP_SERVICE_TYPE)
            .add_characteristics()
            .new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties(self.get_device_name_properties())
                            .set_uuid(Self::DEVICE_NAME_TYPE)
                    })
                    .set_value(|value| {
                        value
                            .set_value(alloc::string::String::from(self.device_name))
                            .set_permissions(self.create_device_name_permissions())
                    })
            })
            .new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties(self.get_device_appearance_properties())
                            .set_uuid(Self::DEVICE_APPEARANCE_TYPE)
                    })
                    .set_value(|value| {
                        value
                            .set_value(self.device_appearance)
                            .set_permissions(self.create_device_appearance_permissions())
                    })
            });

        if let Some(connection_parameters) = self.preferred_connection_parameters.take() {
            characteristic_adder = characteristic_adder.new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties(self.get_preferred_connection_parameters_properties())
                            .set_uuid(Self::PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS_TYPE)
                    })
                    .set_value(|value| {
                        value
                            .set_value(connection_parameters)
                            .set_permissions(self.create_preferred_connection_parameter_permissions())
                    })
            });
        }

        if let Some(central_address_resolution) = self.central_address_resolution.take() {
            characteristic_adder = characteristic_adder.new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([characteristic::Properties::Read])
                            .set_uuid(Self::CENTRAL_ADDRESS_RESOLUTION_TYPE)
                    })
                    .set_value(|value_builder| {
                        let value: u8 = if central_address_resolution { 1 } else { 0 };

                        value_builder
                            .set_value(value)
                            .set_permissions(att::FULL_READ_PERMISSIONS)
                    })
            });
        }

        if self.add_rpa_only_characteristic {
            characteristic_adder = characteristic_adder.new_characteristic(|characteristic| {
                characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([characteristic::Properties::Read])
                            .set_uuid(Self::RESOLVABLE_PRIVATE_ADDRESS_ONLY_TYPE)
                    })
                    .set_value(|value| value.set_value(0u8).set_permissions(att::FULL_READ_PERMISSIONS))
            });
        }

        characteristic_adder.finish_service();

        server_builder
    }
}

/// A GATT server builder
///
/// This is a builder of a GATT server. It provides a walk through process for creating the service
/// architecture of the server before the server is created.
///
/// ```
/// # use bo_tie_gatt::{ServerBuilder, GapServiceBuilder, characteristic::Properties};
/// # use bo_tie_att::{FULL_PERMISSIONS, server::NoQueuedWrites};
/// # use bo_tie_l2cap::{BasicFrameError,BasicFrame, L2capFragment, send_future};
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use bo_tie_core::buffer::de_vec::DeVec;
/// # use bo_tie_core::buffer::TryExtend;
/// # const SERVICE_UUID: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(0);
/// # const CHARACTERISTIC_UUID: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(0);
/// # struct CC;
/// # impl bo_tie_l2cap::ConnectionChannel for CC {
/// #     type SendBuffer = DeVec<u8>;
/// #     type SendFut<'a> = Pin<Box<dyn Future<Output = Result<(), send_future::Error<usize>>>>>;
/// #     type SendErr = usize;
/// #     type RecvBuffer = DeVec<u8>;
/// #     type RecvFut<'a> = Pin<Box<dyn Future<Output = Option<Result<L2capFragment<Self::RecvBuffer>, BasicFrameError<<Self::RecvBuffer as TryExtend<u8>>::Error>>>>>>;
/// #     fn send(&self,data: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
/// #     fn set_mtu(&mut self,_: u16) { unimplemented!() }
/// #     fn get_mtu(&self) -> usize { unimplemented!() }
/// #     fn max_mtu(&self) -> usize { unimplemented!() }
/// #     fn min_mtu(&self) -> usize { unimplemented!() }
/// #     fn receive_fragment(&mut self) -> Self::RecvFut<'_> { unimplemented!()}
/// # }
/// # let channel = CC;
///
/// let gap_service = GapServiceBuilder::new("My Device", None);
///
/// let mut server_builder = ServerBuilder::from(gap_service);
///
/// server_builder.new_service(SERVICE_UUID)
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
    max_mtu: u16,
    primary_services: alloc::vec::Vec<ServiceGroupData>,
    attributes: att::server::ServerAttributes,
    gatt_service_info: Option<GattServiceInfo>,
}

impl ServerBuilder {
    /// Construct an empty `ServerBuilder`
    ///
    /// This creates a `ServerBuilder` without the specification required GAP service.
    pub fn new_empty() -> Self {
        Self {
            max_mtu: LE_MINIMUM_ATT_MTU,
            primary_services: alloc::vec::Vec::new(),
            attributes: att::server::ServerAttributes::new(),
            gatt_service_info: None,
        }
    }

    /// Set the maximum MTU this server can provide to its client
    ///
    /// Through an ATT Exchange MTU request, the client will be able to change the MTU up to this
    /// value.
    ///
    /// # Note
    /// This method does nothing if input `mtu` is not greater than [`LE_MINIMUM_ATT_MTU`].
    pub fn set_max_mtu(&mut self, mtu: u16) {
        if mtu > LE_MINIMUM_ATT_MTU {
            self.max_mtu = mtu;
        }
    }

    /// Construct a new service
    ///
    /// This is used to add a service to the Server. A services consists of a declaration, included
    /// services, and a number of characteristics. The return is a `ServiceBuilder` designed to walk
    /// through the process of setting up the new service.
    ///
    /// ```
    /// # use bo_tie_gatt::characteristic::Properties;
    /// # use bo_tie_gatt::ServerBuilder;
    /// # use bo_tie_host_util::Uuid;
    /// # use bo_tie_gatt::att::FULL_READ_PERMISSIONS;
    /// # let mut server_builder = ServerBuilder::new_empty();
    /// # let service_uuid_1 = Uuid::from_u128(12345678);
    /// # let service_uuid_2 = Uuid::from_u128(87654321);
    /// # let characteristic_uuid = Uuid::from_u128(0xfffff);
    /// # let value = 1234;
    ///
    /// // this adds a service with a single characteristic
    /// let service_reference = server_builder.new_service(service_uuid_1)
    ///     .add_characteristics()
    ///     .new_characteristic(|characteristic_builder| {
    ///         characteristic_builder.set_declaration(|declaration_builder| {
    ///             declaration_builder
    ///                 .set_properties([Properties::Read])
    ///                 .set_uuid(characteristic_uuid)
    ///         })
    ///         .set_value(|value_builder| {
    ///             value_builder
    ///                 .set_value(value)
    ///                 .set_permissions(FULL_READ_PERMISSIONS)
    ///         })
    ///     })
    ///     .finish_service()
    ///     .as_record();
    ///
    /// // this adds a service that includes the prior service
    /// server_builder.new_service(service_uuid_2)
    ///     .make_secondary()
    ///     .into_includes_adder()
    ///     .include_service(service_reference)
    ///     .unwrap()
    ///     .finish_service();
    /// ```
    pub fn new_service<U>(&mut self, service_uuid: U) -> ServiceBuilder<'_>
    where
        U: Into<Uuid>,
    {
        let source = ServiceBuilderSource {
            primary_services: &mut self.primary_services,
            attributes: &mut self.attributes,
        };

        ServiceBuilder::new(source, service_uuid.into())
    }

    /// Construct the Generic Attribute Profile Service
    ///
    /// This is a specific service defined within the Bluetooth Specification. This service's
    /// characteristics relate to the state of the
    ///
    /// # Panic
    /// This method can only be called once to construct the GATT Service
    pub fn new_gatt_service<F>(&mut self, f: F)
    where
        F: FnOnce(GattServiceBuilder<'_>) -> GattServiceBuilder<'_>,
    {
        let builder = GattServiceBuilder::new(self);

        let gatt_info = f(builder).build();

        self.gatt_service_info = gatt_info.into();
    }

    /// Get all the attributes of the server
    pub fn get_attributes(&self) -> &att::server::ServerAttributes {
        &self.attributes
    }

    /// Make an server
    ///
    /// Construct an server from the server builder.
    pub fn make_server<Q>(mut self, queue_writer: Q) -> Server<Q>
    where
        Q: att::server::QueuedWriter,
    {
        let gatt_service_info = if let Some(info) = self.gatt_service_info {
            info
        } else {
            GattServiceBuilder::new(&mut self).build()
        };

        #[cfg(feature = "cryptography")]
        gatt_service_info.initiate_database_hash(&mut self.attributes);

        let server =
            att::server::Server::new_fixed(LE_MINIMUM_ATT_MTU, self.max_mtu, Some(self.attributes), queue_writer);

        Server {
            primary_services: self.primary_services,
            server,
            gatt_service_info,
        }
    }
}

impl From<GapServiceBuilder<'_>> for ServerBuilder {
    fn from(gap: GapServiceBuilder) -> Self {
        gap.into_gatt_service()
    }
}

pub struct Server<Q> {
    primary_services: alloc::vec::Vec<ServiceGroupData>,
    server: att::server::Server<Q>,
    gatt_service_info: GattServiceInfo,
}

/// Send an attribute PDU to the client
///
/// # Inputs
/// $this: `self` for `Server`
/// $channel: BasicFrameChannel,
/// $pdu: `pdu::Pdu<_>`,
macro_rules! send_pdu {
    ( $channel:expr, $pdu:expr $(,)?) => {{
        log::info!("(GATT) sending {:?}", $pdu);

        send_pdu!(SKIP_LOG, $channel, $pdu)
    }};

    (SKIP_LOG, $channel:expr, $pdu:expr $(,)?) => {{
        let acl_data = bo_tie_att::TransferFormatInto::into(&$pdu);

        $channel
            .send(acl_data)
            .await
            .map_err(|e| bo_tie_att::ConnectionError::SendError(e))
    }};
}

/// Send an error the the client
///
/// # Inpus
/// channel: BasicFrameChannel,,
/// handle: `u16`,
/// received_opcode: `ClientPduName`,
/// pdu_error: `pdu::Error`,
macro_rules! send_error {
    (
    $channel:expr,
    $handle:expr,
    $received_opcode:expr,
    $pdu_error:expr $(,)?
) => {{
        log::info!(
            "(GATT) sending error response. Received Op Code: '{:#x}', Handle: '{:?}', error: '{}'",
            Into::<u8>::into($received_opcode),
            $handle,
            $pdu_error
        );

        send_pdu!(
            SKIP_LOG,
            $channel,
            bo_tie_att::pdu::error_response($received_opcode.into(), $handle, $pdu_error),
        )
    }};
}

impl<Q> Server<Q>
where
    Q: att::server::QueuedWriter,
{
    /// Iterate over the services within this GATT server
    pub fn iter_services(&self) -> impl Iterator<Item = Service> {
        self.primary_services.iter().map(move |s| Service {
            server_attributes: self.server.get_attributes(),
            group_data: *s,
        })
    }

    /// Process an ATT PDU
    ///
    /// This processes an ATT client PDU with the requirements imposed by a GATT profile. It is
    /// important to call this method to ensure that the GATT profile requirements are met within
    /// the underlying ATT server.
    pub async fn process_att_pdu<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        b_frame: &l2cap::pdu::BasicFrame<alloc::vec::Vec<u8>>,
    ) -> Result<bo_tie_att::server::Status, att::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let (pdu_type, payload) = self.server.parse_att_pdu(&b_frame)?;
        match pdu_type {
            att::client::ClientPduName::FindByTypeValueRequest => {
                self.process_find_by_type_value_request(channel, payload).await
            }
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                self.process_read_by_group_type_request(channel, payload).await?;

                Ok(bo_tie_att::server::Status::None)
            }
            att::client::ClientPduName::ExchangeMtuRequest => self.ensure_mtu_request(channel, payload).await,
            _ => self.server.process_parsed_att_pdu(channel, pdu_type, payload).await,
        }
    }

    fn create_read_by_group_type_response_primary(
        &self,
        handle_range: HandleRange,
        response: &mut impl bo_tie_core::buffer::TryExtend<u8>,
    ) -> Result<(), att::pdu::Error> {
        use core::ops::RangeBounds;

        log::info!(
            "(GATT) processing PDU ATT_READ_BY_GROUP_TYPE_REQ for Primary Services {{ starting \
            handle: {}, ending handle: {} }}",
            handle_range.starting_handle,
            handle_range.ending_handle,
        );

        let mut iter = self
            .primary_services
            .iter()
            .filter(|service| handle_range.to_range_bounds().contains(&service.service_handle))
            .map(|service| {
                self.server
                    .check_permissions(service.service_handle, &att::FULL_READ_PERMISSIONS)
                    .map(|_| service)
            })
            .peekable();

        let mut size = 2;

        match iter.peek() {
            None => Err(att::pdu::Error::AttributeNotFound),
            Some(Err(err)) => Err(*err),
            Some(Ok(service_group_data)) if service_group_data.service_uuid.can_be_16_bit() => {
                response.try_extend_one(6).unwrap();

                iter.filter_map(|permission_check| permission_check.ok())
                    .take_while(|service_group_data| service_group_data.service_uuid.can_be_16_bit())
                    .take_while(|_| ((size + 6) < self.get_mtu()).then(|| size += 6).is_some())
                    .fold(response, |response, service_group_data| {
                        let start = service_group_data.service_handle.to_le_bytes();

                        let end = service_group_data.end_group_handle.to_le_bytes();

                        let value = <u16>::try_from(service_group_data.service_uuid).unwrap().to_le_bytes();

                        response
                            .try_extend(start.into_iter().chain(end.into_iter()).chain(value.into_iter()))
                            .unwrap();

                        response
                    });

                Ok(())
            }
            Some(Ok(_)) => {
                response.try_extend_one(20).unwrap();

                iter.filter_map(|permission_check| permission_check.ok())
                    .take_while(|_| ((size + 20) < self.get_mtu()).then(|| size += 6).is_some())
                    .fold(response, |response, service_group_data| {
                        let start = service_group_data.service_handle.to_le_bytes();

                        let end = service_group_data.end_group_handle.to_le_bytes();

                        let value = <u128>::from(service_group_data.service_uuid).to_le_bytes();

                        response
                            .try_extend(start.into_iter().chain(end.into_iter()).chain(value.into_iter()))
                            .unwrap();

                        response
                    });

                Ok(())
            }
        }
    }

    fn create_read_by_group_type_response_secondary(
        &self,
        handle_range: HandleRange,
        _: &mut impl bo_tie_core::buffer::TryExtend<u8>,
    ) -> Result<(), att::pdu::Error> {
        log::info!(
            "(GATT) processing PDU ATT_READ_BY_GROUP_TYPE_REQ for Secondary Services {{ starting \
            handle: {}, ending handle: {} }}",
            handle_range.starting_handle,
            handle_range.ending_handle,
        );

        // secondary services are not supported yet
        Err(att::pdu::Error::AttributeNotFound)
    }

    /// Process a Read by Group Type Request
    ///
    /// A GATT profile Client will send this to a server to query for the Primary Services.
    async fn process_read_by_group_type_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<(), att::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let request: att::pdu::TypeRequest = match att::TransferFormatTryFrom::try_from(payload) {
            Ok(request) => request,
            Err(_) => {
                return send_error!(
                    channel,
                    0,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::InvalidPDU,
                );
            }
        };

        let mut response = alloc::vec::Vec::new();

        match match request.attr_type {
            uuid::PRIMARY_SERVICE => {
                self.create_read_by_group_type_response_primary(request.handle_range, &mut response)
            }
            uuid::SECONDARY_SERVICE => {
                self.create_read_by_group_type_response_secondary(request.handle_range, &mut response)
            }
            _ => Err(att::pdu::Error::UnsupportedGroupType),
        } {
            Err(error) => {
                send_error!(
                    channel,
                    request.handle_range.starting_handle,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    error,
                )
            }
            Ok(()) => {
                let pdu = att::pdu::Pdu::new(att::server::ServerPduName::ReadByGroupTypeResponse.into(), response);

                send_pdu!(channel, pdu)
            }
        }
    }

    fn create_find_by_type_value_response(
        &self,
        payload: &[u8],
    ) -> Result<Option<alloc::vec::Vec<att::pdu::TypeValueResponse>>, att::pdu::Error> {
        let handle_range: HandleRange = match att::TransferFormatTryFrom::try_from(&payload[..4]) {
            Ok(handle_range) => handle_range,
            Err(_) => {
                log::trace!(
                    "(GATT) ATT_FIND_BY_TYPE_VALUE_REQ: cannot get handle range from payload, \
                    sending error {} to client",
                    att::pdu::Error::InvalidPDU
                );

                return Err(att::pdu::Error::InvalidPDU);
            }
        };

        let attribute_type: Uuid = match att::TransferFormatTryFrom::try_from(&payload[4..6]) {
            Ok(uuid) => uuid,
            Err(_) => {
                log::trace!(
                    "(GATT) ATT_FIND_BY_TYPE_VALUE_REQ: cannot get handle range from payload, \
                    sending error {} to client",
                    att::pdu::Error::InvalidPDU
                );

                return Err(att::pdu::Error::InvalidPDU);
            }
        };

        match attribute_type {
            uuid::PRIMARY_SERVICE => self.create_find_by_type_value_response_for_primary(handle_range, &payload[6..]),
            uuid::SECONDARY_SERVICE => Err(att::pdu::Error::AttributeNotFound),
            uuid::CHARACTERISTIC => {
                self.create_find_by_type_value_response_for_characteristic(handle_range, &payload[6..])
            }
            _ => Ok(None),
        }
    }

    fn create_find_by_type_value_response_for_primary(
        &self,
        handle_range: HandleRange,
        raw_uuid: &[u8],
    ) -> Result<Option<alloc::vec::Vec<att::pdu::TypeValueResponse>>, att::pdu::Error> {
        use core::ops::RangeBounds;

        let searched_for_uuid: Uuid = match att::TransferFormatTryFrom::try_from(raw_uuid) {
            Ok(uuid) => uuid,
            Err(_) => {
                log::trace!(
                    "(GATT) ATT_FIND_BY_TYPE_VALUE_REQ: value in request is not supported by GATT, \
                    punting to ATT implementation of ATT_FIND_BY_TYPE_VALUE"
                );

                return Ok(None);
            }
        };

        log::info!(
            "(GATT) processing PDU ATT_FIND_BY_TYPE_VALUE_REQ for primary service {{ start \
            handle: {}, end handle: {}, primary service UUID: {:x}}}",
            handle_range.starting_handle,
            handle_range.ending_handle,
            searched_for_uuid
        );

        // the response starts with a 1 byte opcode
        let mut size = 1;

        let handle_information_list = self
            .primary_services
            .iter()
            .filter(|service_data| {
                service_data.service_uuid == searched_for_uuid
                    && handle_range.to_range_bounds().contains(&service_data.service_handle)
                    && self
                        .server
                        .check_permissions(service_data.service_handle, &att::FULL_READ_PERMISSIONS)
                        .is_ok()
            })
            .take_while(|_| ((size + 4) < self.server.get_mtu()).then(|| size += 4).is_some())
            .map(|service_data| {
                att::pdu::TypeValueResponse::new(service_data.service_handle, service_data.end_group_handle)
            })
            .collect::<alloc::vec::Vec<_>>();

        if handle_information_list.is_empty() {
            return Err(att::pdu::Error::AttributeNotFound);
        }

        Ok(Some(handle_information_list))
    }

    fn create_find_by_type_value_response_for_characteristic(
        &self,
        handle_range: HandleRange,
        raw_uuid: &[u8],
    ) -> Result<Option<alloc::vec::Vec<att::pdu::TypeValueResponse>>, att::pdu::Error> {
        use core::ops::RangeBounds;

        let searched_for_uuid: Uuid = match att::TransferFormatTryFrom::try_from(raw_uuid) {
            Ok(uuid) => uuid,
            Err(_) => {
                log::trace!(
                    "(GATT) ATT_FIND_BY_TYPE_VALUE_REQ: value in request is not supported by GATT, \
                    punting to ATT implementation of ATT_FIND_BY_TYPE_VALUE"
                );

                return Ok(None);
            }
        };

        log::info!(
            "(GATT) processing PDU ATT_FIND_BY_TYPE_VALUE_REQ for characteristic {{ start \
            handle: {}, end handle: {}, characteristic UUID: {:x}}}",
            handle_range.starting_handle,
            handle_range.ending_handle,
            searched_for_uuid
        );

        // the response starts with a 1 byte opcode
        let mut size = 1;

        let handle_information_list = self
            .iter_services()
            .flat_map(|service_data| service_data.iter_characteristics())
            .filter(|characteristic| characteristic.get_uuid() == searched_for_uuid)
            .filter(|characteristic| {
                handle_range
                    .to_range_bounds()
                    .contains(&characteristic.get_declaration_handle())
                    && handle_range
                        .to_range_bounds()
                        .contains(&characteristic.get_end_handle())
            })
            .take_while(|_| ((size + 4) < self.server.get_mtu()).then(|| size += 4).is_some())
            .map(|characteristic| {
                att::pdu::TypeValueResponse::new(
                    characteristic.get_declaration_handle(),
                    characteristic.get_end_handle(),
                )
            })
            .collect::<alloc::vec::Vec<_>>();

        if handle_information_list.is_empty() {
            return Err(att::pdu::Error::AttributeNotFound);
        }

        Ok(Some(handle_information_list))
    }

    async fn process_find_by_type_value_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<bo_tie_att::server::Status, att::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        match self.create_find_by_type_value_response(payload) {
            Err(e) => {
                send_error!(channel, 0, att::client::ClientPduName::FindByTypeValueRequest, e)?;

                Ok(bo_tie_att::server::Status::None)
            }
            Ok(Some(type_value_responses)) => {
                let pdu = att::pdu::Pdu::new(
                    att::server::ServerPduName::FindByTypeValueResponse.into(),
                    type_value_responses,
                );

                send_pdu!(channel, pdu)?;

                Ok(bo_tie_att::server::Status::None)
            }
            Ok(None) => {
                self.server
                    .process_parsed_att_pdu(channel, att::client::ClientPduName::FindByTypeValueRequest, payload)
                    .await
            }
        }
    }

    /// Ensure the MTU request does not contain a MTU less than [`LE_MINIMUM_ATT_MTU`]
    async fn ensure_mtu_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<bo_tie_att::server::Status, att::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        match <att::pdu::MtuRequest as att::TransferFormatTryFrom>::try_from(payload) {
            Ok(request) if LE_MINIMUM_ATT_MTU <= request.0 => {
                self.server
                    .process_parsed_att_pdu(channel, att::client::ClientPduName::ExchangeMtuRequest, payload)
                    .await
            }
            Ok(_) => {
                send_error!(
                    channel,
                    0,
                    att::client::ClientPduName::ExchangeMtuRequest,
                    att::pdu::Error::RequestNotSupported,
                )?;

                Ok(bo_tie_att::server::Status::None)
            }
            Err(_) => {
                send_error!(
                    channel,
                    0,
                    att::client::ClientPduName::ExchangeMtuRequest,
                    att::pdu::Error::InvalidPDU,
                )?;

                Ok(bo_tie_att::server::Status::None)
            }
        }
    }

    /// Add Services to the Server
    ///
    /// Services can be added to the Server if it has the service changed characteristic. Services
    /// cannot be added
    ///
    /// This takes a connection channel and closure. The connection channel is used to send the
    /// indication to the Client that the services have changed. The closure is used to add the
    /// Services to the Server.
    ///
    /// The closure takes a `ServiceAdder` which should be used to add a number of services to the
    ///
    /// # Note
    /// An indication is not sent to the ATT client if no services are added.
    pub async fn add_services<T, F>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        f: F,
    ) -> Result<(), AddServicesError<T>>
    where
        T: LogicalLink,
        F: for<'a> FnOnce(ServicesAdder<'a>),
    {
        let service_changed_handle = if let Some(handle) = self.gatt_service_info.service_change_handle {
            handle
        } else {
            return Err(AddServicesError::NoServicesChangedCharacteristic);
        };

        let starting_handle = self.server.get_attributes().next_handle();

        f(ServicesAdder::new(
            &mut self.primary_services,
            self.server.get_mut_attributes(),
        ));

        // this will not panic. Besides the reserved attribute, the GATT
        // service and service changed characteristic are within the server.
        let ending_handle = self.server.get_attributes().next_handle() - 1;

        if starting_handle > ending_handle {
            // no services were added
            return Ok(());
        }

        let service_changed = characteristic::gatt::ServiceChangedValue {
            starting_handle,
            ending_handle,
        };

        let indication = att::pdu::create_indication(service_changed_handle, service_changed);

        send_pdu!(channel, indication).map_err(|e| AddServicesError::ConnectionError(e))
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

pub enum AddServicesError<T: LogicalLink> {
    NoServicesChangedCharacteristic,
    ConnectionError(att::ConnectionError<T>),
}

impl<T> core::fmt::Debug for AddServicesError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Debug,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AddServicesError::NoServicesChangedCharacteristic => f.write_str("NoServicesChangedCharacteristic"),
            AddServicesError::ConnectionError(e) => core::fmt::Debug::fmt(e, f),
        }
    }
}

impl<T> core::fmt::Display for AddServicesError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AddServicesError::NoServicesChangedCharacteristic => f.write_str(
                "services cannot be added as the server was built without the \
                    Service Changed Characteristic of the GATT Service",
            ),
            AddServicesError::ConnectionError(c) => core::fmt::Display::fmt(c, f),
        }
    }
}

#[cfg(feature = "std")]
impl<T> std::error::Error for AddServicesError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::SendErr: std::error::Error,
    <T::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
{
}

/// A GATT client
///
/// This is an extension to an Attribute [`Client`] as it provides the added functionality of
/// processing the Services and Characteristics of a GATT server.
///
/// Since this is really just a wrapper, it can be created from an Attribute `Client`.
///
/// ```
/// # async fn fun<C: bo_tie_l2cap::ConnectionChannel>(mut channel: C) -> Result<(), bo_tie_att::ConnectionError<C>> {
/// use bo_tie_att::client::ConnectFixedClient;
/// use bo_tie_gatt::Client;
///
/// let gatt_client: Client = ConnectFixedClient::connect(&mut channel, 64).await?.into();
/// # Ok(()) }
/// ```
///
/// [`Client`]: bo_tie_att::client::Client
pub struct Client {
    att_client: att::client::Client,
    known_services: alloc::vec::Vec<ServiceRecord>,
}

impl Client {
    fn new(att_client: att::client::Client) -> Self {
        let known_services = alloc::vec::Vec::new();

        Client {
            att_client,
            known_services,
        }
    }

    /// Partially discover the services of the peer device
    ///
    /// This sends a single read by group type request for the GATT services of the peer device.
    /// This method may need to be repeatedly called in order to get all services from the peer.
    /// The return is a [`ResponseProcessor`] for the read by group type response (or error) from
    /// the peer device. When the response processor outputs `true`, then all services have been
    /// discovered.
    ///
    /// ```
    /// # use bo_tie_l2cap::LogicalLink;
    /// # use bo_tie_l2cap::BasicFrameChannel;
    /// # use bo_tie_gatt::Client;
    /// # async fn test<T: LogicalLink>(mut channel: BasicFrameChannel<T>, mut client: Client) {
    /// use bo_tie_att::client::ResponseProcessor;
    ///
    /// loop {
    ///     let query_next = client.partial_service_discovery(&mut channel)
    ///         .await
    ///         .expect("failed to send request");
    ///
    ///     let response = channel.receive()
    ///         .await
    ///         .expect("failed to receive response");
    ///
    ///     // When true is returned by `process_response`
    ///     // then all services were discovered on the
    ///     // peer device.
    ///     if query_next.process_response(&response)
    ///         .expect("unexpected response")
    ///     {
    ///         break;
    ///     }
    /// }
    ///
    /// let services = client.get_known_services();
    /// # }
    /// ```
    pub async fn partial_service_discovery<'a, T: LogicalLink>(
        &'a mut self,
        channel: &mut BasicFrameChannel<T>,
    ) -> Result<QueryResponseProcessor<'a>, bo_tie_att::ConnectionError<T>> {
        let start_handle = self
            .known_services
            .last()
            .map(|last| last.get_range().end().checked_add(1).unwrap_or(<u16>::MAX))
            .unwrap_or(1);

        let request_future = self
            .att_client
            .read_by_group_type_request(channel, start_handle.., uuid::PRIMARY_SERVICE);

        let response_processor = request_future.await?;

        Ok(QueryResponseProcessor {
            client: self,
            response_processor,
        })
    }

    /// Get the discovered services
    ///
    /// This returns the services that were discovered on the remote's Attribute server.
    ///
    /// # Note
    /// Any services that have yet to be discovered must be discovered via the method
    /// `partial_discover`
    pub fn get_known_services(&self) -> &[ServiceRecord] {
        &self.known_services
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

pub struct QueryResponseProcessor<'a> {
    client: &'a mut Client,
    response_processor: bo_tie_att::client::response_processor::ReadByGroupTypeResponseProcessor<Uuid>,
}

impl bo_tie_att::client::ResponseProcessor for QueryResponseProcessor<'_> {
    type Response = bool;

    fn process_response(
        self,
        b_frame: &bo_tie_l2cap::pdu::BasicFrame<alloc::vec::Vec<u8>>,
    ) -> Result<Self::Response, bo_tie_att::Error> {
        let response = match self.response_processor.process_response(b_frame) {
            Ok(response) => response.into_inner(),
            Err(bo_tie_att::Error::Pdu(pdu)) => match pdu.get_parameters().error {
                bo_tie_att::pdu::Error::AttributeNotFound => alloc::vec::Vec::new(),
                e => return Err(e.into()),
            },
            Err(e) => return Err(e.into()),
        };

        if response.is_empty() {
            return Ok(true);
        }

        for group_data in response {
            let service_group_data = ServiceGroupData {
                is_primary: true,
                service_handle: group_data.get_handle(),
                end_group_handle: group_data.get_end_group_handle(),
                service_uuid: *group_data.get_data(),
            };

            let record = ServiceRecord {
                group_data: service_group_data,
            };

            self.client.known_services.push(record);

            if service_group_data.end_group_handle == <u16>::MAX {
                // reached the last handle
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// The GATT Service Builder
///
/// The GATT service provides information on the client of the state of the GATT Server.
pub struct GattServiceBuilder<'a> {
    characteristic_adder: CharacteristicAdder<'a>,
    service_changed: Option<u16>,
    database_hash: Option<u16>,
}

impl<'a> GattServiceBuilder<'a> {
    const GATT_SERVICE_UUID: Uuid = Uuid::from_u16(0x1801);

    /// Create a new `GattServiceBuilder`
    fn new(server_builder: &'a mut ServerBuilder) -> Self {
        let characteristic_adder = server_builder
            .new_service(Self::GATT_SERVICE_UUID)
            .add_characteristics();

        GattServiceBuilder {
            characteristic_adder,
            service_changed: None,
            database_hash: None,
        }
    }

    /// Add the service changed characteristic
    ///
    /// This characteristic is an indication only characteristic that is used to update the client
    /// that the services on the server has changed.
    ///
    /// # Warning
    ///
    /// For now, this GATT implementation only supports adding the service changed characteristic
    /// and not the actual indications for it. This means that changing the GATT services of a
    /// server is also unsupported at this time. The purpose of this is to add the characteristic so
    /// that it will exist to send indications whenever the support for changing services is
    /// implemented.
    ///
    /// ## Indications
    ///
    /// The characteristic value cannot be read nor written as this is an *indication* only
    /// characteristic. However, this characteristic has a client configuration descriptor that the
    /// client can use to enable or disable the indications.
    ///
    /// Indications for this characteristic must be sent if enabled and the server changes its
    /// architecture of GATT services.
    ///
    /// # Inputs
    ///
    /// The value of client configuration is initially false, but upon reconnecting it needs to be
    /// set to the last set value by the client. Input `enabled` will be the initially set value for
    /// the client configuration characteristic.
    ///
    /// When the client writes to the client configuration descriptor, the input closure `on_change`
    /// is called with the boolean indicating if Indications were enabled or disabled by the client.
    ///
    /// The final input is the restrictions on the client for writing to the descriptor. Per the
    /// Bluetooth specification the client has no restriction on reading it.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use std::sync::atomic::{AtomicBool, Ordering};
    /// # use bo_tie_att::AttributeRestriction;
    /// # use bo_tie_gatt::{GattServiceBuilder, ServerBuilder};
    /// # use bo_tie_gatt::characteristic::ClientConfiguration;
    ///
    /// async fn doc_test(mut server_builder: ServerBuilder) {
    /// let service_changed = Arc::new(AtomicBool::default());
    /// let service_changed_clone = service_changed.clone();
    ///
    /// server_builder.new_gatt_service(|builder| {
    ///     builder.add_service_changed(
    ///         service_changed.load(Ordering::SeqCst),
    ///         |enabled| async { service_changed_clone.store(enabled, Ordering::SeqCst) },
    ///         [AttributeRestriction::None]
    ///     )
    /// });
    /// # }
    /// ```
    ///
    pub fn add_service_changed<Fun, Fut, R>(mut self, enabled: bool, mut on_change: Fun, write_restrictions: R) -> Self
    where
        Fun: FnMut(bool) -> Fut + Send + 'static,
        Fut: Future + Send,
        R: core::borrow::Borrow<[bo_tie_att::AttributeRestriction]>,
    {
        const UUID: Uuid = crate::uuid::gatt::SERVICE_CHANGED;

        const PERMISSIONS: [att::AttributePermissions; 0] = [];

        const PROPERTIES: [characteristic::Properties; 1] = [characteristic::Properties::Indicate];

        self.characteristic_adder = self.characteristic_adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(PROPERTIES).set_uuid(UUID))
                .set_value(|value| value.set_value(()).set_permissions(PERMISSIONS))
                .set_client_configuration(|client_config| {
                    client_config
                        .set_config([ClientConfiguration::Indication])
                        .init_config(if enabled {
                            [ClientConfiguration::Indication].as_slice()
                        } else {
                            &[]
                        })
                        .set_write_callback(move |config| on_change(config.contains(&ClientConfiguration::Indication)))
                        .set_write_restrictions(write_restrictions)
                })
        });

        self.service_changed = self
            .characteristic_adder
            .get_last_record()
            .map(|record| record.get_value_handle());

        self
    }

    /// Add the client supported features Characteristic
    ///
    /// This Characteristic must be added if this device supports both the Client and Server
    /// Attribute Protocol roles.
    pub fn add_client_supported_features<T, B>(mut self, features: T) -> Self
    where
        T: IntoIterator<Item = B>,
        B: core::borrow::Borrow<characteristic::gatt::ClientFeatures>,
    {
        const UUID: Uuid = uuid::gatt::CLIENT_SUPPORTED_FEATURES;

        const PERMISSIONS: [att::AttributePermissions; att::AttributePermissions::full_depth()] = att::FULL_PERMISSIONS;

        const PROPERTIES: [characteristic::Properties; 2] =
            [characteristic::Properties::Read, characteristic::Properties::Write];

        let mut list = characteristic::gatt::ClientFeaturesValue::default();

        for feature in features {
            list.add_feature(*feature.borrow())
        }

        self.characteristic_adder = self.characteristic_adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(PROPERTIES).set_uuid(UUID))
                .set_value(|value| value.set_value(list).set_permissions(PERMISSIONS))
        });

        self
    }

    /// Add the database hash Characteristic
    ///
    /// This has is automatically generated upon creating of of the GATT server.
    #[cfg(feature = "cryptography")]
    pub fn add_database_hash(mut self) -> Self {
        const UUID: Uuid = uuid::gatt::DATABASE_HASH;

        const PERMISSIONS: [att::AttributePermissions; att::AttributePermissions::full_depth() / 2] =
            att::FULL_READ_PERMISSIONS;

        const PROPERTIES: [characteristic::Properties; 1] = [characteristic::Properties::Read];

        let temp_val = characteristic::gatt::HashValue::all_zero();

        self.characteristic_adder = self.characteristic_adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(PROPERTIES).set_uuid(UUID))
                .set_value(|value| value.set_value(temp_val).set_permissions(PERMISSIONS))
        });

        self.database_hash = self
            .characteristic_adder
            .get_last_record()
            .map(|record| record.get_value_handle());

        self
    }

    /// Add the GATT server supported features Characteristic
    pub fn add_server_supported_features<T>(mut self, features: T) -> Self
    where
        T: core::borrow::Borrow<[characteristic::gatt::ServerFeatures]>,
    {
        const UUID: Uuid = uuid::gatt::SERVER_SUPPORTED_FEATURES;

        const PERMISSIONS: [att::AttributePermissions; att::AttributePermissions::full_depth() / 2] =
            att::FULL_READ_PERMISSIONS;

        const PROPERTIES: [characteristic::Properties; 1] = [characteristic::Properties::Read];

        let mut list = characteristic::gatt::ServerFeaturesList::new();

        unique_only!(list.features, features.borrow());

        self.characteristic_adder = self.characteristic_adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(PROPERTIES).set_uuid(UUID))
                .set_value(|value| value.set_value(list).set_permissions(PERMISSIONS))
        });

        self
    }

    fn build(self) -> GattServiceInfo {
        self.characteristic_adder.finish_service();

        GattServiceInfo {
            service_change_handle: self.service_changed,
            database_hash_handle: self.database_hash,
        }
    }
}

/// Information for setting up the GATT service
///
/// This is used for generating the GATT service information that needs to be part of the server.
#[derive(Default)]
struct GattServiceInfo {
    service_change_handle: Option<u16>,
    database_hash_handle: Option<u16>,
}

impl GattServiceInfo {
    /// Initiate the GATT database hash characteristic
    ///
    /// This will initiate the database hash if the user has added the database hash characteristic.
    /// This should be called once the server is created, and every time the anything in the server
    /// changes except for a characteristic value.
    ///
    /// If there is no GATT database hash, then this is effectively a no-op.
    #[cfg(feature = "cryptography")]
    fn initiate_database_hash(&self, server_attributes: &mut att::server::ServerAttributes) {
        use characteristic::gatt::HashValue;

        if let Some(handle) = self.database_hash_handle {
            let hash = HashValue::generate(server_attributes);

            *server_attributes.get_mut_value::<HashValue>(handle).unwrap() = hash;
        }
    }
}
