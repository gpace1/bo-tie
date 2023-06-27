#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;
extern crate core;

/// The minimum size of the ATT profile's MTU (running the GATT profile)
///
/// This is also the default ATT_MTU when running the GATT profile over a LE physical link.
///
/// # Note
/// This value is only for 'regular' LE ATT protocol operation. This is not the same value for
/// enhanced LE ATT or BR/EDR.
const LE_MINIMUM_ATT_MTU: u16 = 23;

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

pub use bo_tie_att as att;
use bo_tie_att::TransferFormatInto;
use bo_tie_core::buffer::stack::LinearBuffer;
pub use bo_tie_host_util::Uuid;
pub use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::{ConnectionChannel, ConnectionChannelExt};

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
        let service = Service::get_service(self.service_builder.source.attributes, service_record)?;

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
    fn get_service(
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
    const GAP_SERVICE_TYPE: Uuid = Uuid::from_u16(0x1800);

    /// Device Name Characteristic UUID
    const DEVICE_NAME_TYPE: Uuid = Uuid::from_u16(0x2a00);

    /// Device Appearance Characteristic UUID
    const DEVICE_APPEARANCE_TYPE: Uuid = Uuid::from_u16(0x2a01);

    /// Peripheral Preferred Connection Parameters UUID
    const PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS_TYPE: Uuid = Uuid::from_u16(0x2a04);

    /// Central Address Resolution Uuid
    const CENTRAL_ADDRESS_RESOLUTION_TYPE: Uuid = Uuid::from_u16(0x2aa6);

    /// Resolvable Private Address Only Uuid
    const RESOLVABLE_PRIVATE_ADDRESS_ONLY_TYPE: Uuid = Uuid::from_u16(0x2aa6);

    /// Default attribute permissions
    // This is a reference to an array (instead of a slice) so that it errors if the types
    // AttributeRestriction or EncryptionKeySize has enums added to them.
    const DEFAULT_NAME_PERMISSIONS: &'static [att::AttributeRestriction; att::AttributeRestriction::full_depth() - 1] =
        &[
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
/// use bo_tie_gatt::{ServerBuilder, GapServiceBuilder, characteristic::Properties};
/// use bo_tie_att::{FULL_PERMISSIONS, server::NoQueuedWrites};
///
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
/// # let connection_channel = CC;
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
            primary_services: alloc::vec::Vec::new(),
            attributes: att::server::ServerAttributes::new(),
            gatt_service_info: None,
        }
    }

    /// Construct a new service
    ///
    /// This is used to add a service to the Server. A services consists of a declaration, included
    /// services, and a number of characteristics. The return is a `ServiceBuilder` designed to walk
    /// through the process of setting up the new service within the attributes of the (to be)
    /// constructed GATT server.
    ///
    /// # Service Including
    /// Services may be included after they are put within
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

        let server = att::server::Server::new(LE_MINIMUM_ATT_MTU, Some(self.attributes), queue_writer);

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
/// $connection_channel: `impl ConnectionChannel`,
/// $pdu: `pdu::Pdu<_>`,
macro_rules! send_pdu {
    ( $connection_channel:expr, $pdu:expr $(,)?) => {{
        log::info!("(GATT) sending {}", $pdu.get_opcode());

        send_pdu!(SKIP_LOG, $connection_channel, $pdu)
    }};

    (SKIP_LOG, $connection_channel:expr, $pdu:expr $(,)?) => {{
        let interface_data = bo_tie_att::TransferFormatInto::into(&$pdu);

        let acl_data = bo_tie_l2cap::pdu::BasicFrame::new(interface_data, bo_tie_att::L2CAP_CHANNEL_ID);

        $connection_channel
            .send(acl_data)
            .await
            .map_err(|e| bo_tie_att::ConnectionError::<C>::SendError(e))
    }};
}

/// Send an error the the client
///
/// # Inpus
/// connection_channel: `impl ConnectionChannel`,
/// handle: `u16`,
/// received_opcode: `ClientPduName`,
/// pdu_error: `pdu::Error`,
macro_rules! send_error {
    (
    $connection_channel:expr,
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
            $connection_channel,
            bo_tie_att::pdu::error_response($received_opcode.into(), $handle, $pdu_error),
        )
    }};
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

    /// Process an ATT PDU
    ///
    /// This processes an ATT client PDU with the requirements imposed by a GATT profile. It is
    /// important to call this method to ensure that the GATT profile requirements are met within
    /// the underlying ATT server.
    pub async fn process_att_pdu<C>(
        &mut self,
        connection_channel: &mut C,
        b_frame: &l2cap::pdu::BasicFrame<alloc::vec::Vec<u8>>,
    ) -> Result<bo_tie_att::server::Status, att::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let (pdu_type, payload) = self.server.parse_att_pdu(&b_frame)?;

        match pdu_type {
            att::client::ClientPduName::ReadByGroupTypeRequest => {
                log::info!(
                    "(GATT) processing '{}'",
                    att::client::ClientPduName::ReadByGroupTypeRequest
                );

                self.process_read_by_group_type_request(connection_channel, payload)
                    .await?;

                Ok(bo_tie_att::server::Status::None)
            }
            att::client::ClientPduName::ExchangeMtuRequest => {
                if self.check_mtu_request(connection_channel, payload).await? {
                    self.server
                        .process_parsed_att_pdu(connection_channel, pdu_type, payload)
                        .await
                } else {
                    Ok(bo_tie_att::server::Status::None)
                }
            }
            _ => {
                self.server
                    .process_parsed_att_pdu(connection_channel, pdu_type, payload)
                    .await
            }
        }
    }

    /// Process a Read by Group Type Request
    ///
    /// A GATT profile Client will send this to a server to query for the Primary Services.
    async fn process_read_by_group_type_request<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<(), att::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        use core::ops::RangeBounds;

        struct Response {
            data: alloc::vec::Vec<u8>,
        }

        impl Response {
            fn new<Q, R: RangeBounds<u16>>(server: &Server<Q>, handle_range: R, mtu: usize) -> Self {
                let uuid_size = core::cell::Cell::new(None);

                let data = server
                    .primary_services
                    .iter()
                    .filter(|service_data| handle_range.contains(&service_data.service_handle))
                    .enumerate()
                    .take_while(|(cnt, service_data)| {
                        match (uuid_size.get(), service_data.service_uuid.can_be_16_bit()) {
                            (None, true) => {
                                uuid_size.set(Some(2));
                                true
                            }
                            (None, false) => {
                                uuid_size.set(Some(16));
                                true
                            }
                            (Some(2), true) => (cnt + 1) * (2 + 4) < (mtu - 2),
                            (Some(16), false) => (cnt + 1) * (16 + 4) < (mtu - 2),
                            _ => false,
                        }
                    })
                    .fold(alloc::vec![0], |mut vec, (_, service_data)| {
                        vec[0] += (uuid_size.get().unwrap() + 4) as u8;

                        let mut buffer = [0u8; 16 + 4];

                        service_data.service_handle.build_into_ret(&mut buffer[..2]);

                        service_data.end_group_handle.build_into_ret(&mut buffer[2..4]);

                        service_data
                            .service_uuid
                            .build_into_ret(&mut buffer[4..(4 + uuid_size.get().unwrap())]);

                        vec
                    });

                Self { data }
            }
        }

        impl TransferFormatInto for Response {
            fn len_of_into(&self) -> usize {
                self.data.len()
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                into_ret.copy_from_slice(&self.data);
            }
        }

        let request: att::pdu::TypeRequest = match att::TransferFormatTryFrom::try_from(payload) {
            Ok(request) => request,
            Err(_) => {
                return send_error!(
                    connection_channel,
                    0,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnlikelyError,
                );
            }
        };

        if ServiceDefinition::PRIMARY_SERVICE_TYPE != request.attr_type {
            return send_error!(
                connection_channel,
                request.handle_range.starting_handle,
                att::client::ClientPduName::ReadByGroupTypeRequest,
                att::pdu::Error::UnsupportedGroupType,
            );
        }

        if !request.handle_range.is_valid() {
            return send_error!(
                connection_channel,
                0,
                att::client::ClientPduName::ReadByGroupTypeRequest,
                att::pdu::Error::UnlikelyError,
            );
        }

        // Check if the first primary service declaration can be read by the client

        let check_readable = self
            .primary_services
            .iter()
            .filter(|service_data| {
                request
                    .handle_range
                    .to_range_bounds()
                    .contains(&service_data.service_handle)
            })
            .nth(0)
            .ok_or(att::pdu::Error::AttributeNotFound)
            .map(|first| {
                self.server
                    .check_permissions(first.service_handle, &att::FULL_READ_PERMISSIONS)
            });

        if let Err(e) = check_readable {
            return send_error!(
                connection_channel,
                0,
                att::client::ClientPduName::ReadByGroupTypeRequest,
                e
            );
        }

        let response = Response::new(self, request.handle_range.to_range_bounds(), self.server.get_mtu());

        let pdu = att::pdu::Pdu::new(att::server::ServerPduName::ReadByGroupTypeResponse.into(), response);

        send_pdu!(connection_channel, pdu)
    }

    /// Check a MTU request to ensure it does not contain a MTU less than [`LE_MINIMUM_ATT_MTU`]
    async fn check_mtu_request<C>(
        &self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<bool, att::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        match <att::pdu::MtuRequest as att::TransferFormatTryFrom>::try_from(payload) {
            Ok(request) => Ok(LE_MINIMUM_ATT_MTU >= request.0),
            Err(_) => {
                send_error!(
                    connection_channel,
                    0,
                    att::client::ClientPduName::ReadByGroupTypeRequest,
                    att::pdu::Error::UnlikelyError,
                )?;

                Ok(false)
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
    pub async fn add_services<C, F>(&mut self, connection_channel: &C, f: F) -> Result<(), AddServicesError<C>>
    where
        C: ConnectionChannel,
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

        send_pdu!(connection_channel, indication).map_err(|e| AddServicesError::ConnectionError(e))
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

pub enum AddServicesError<C: ConnectionChannel> {
    NoServicesChangedCharacteristic,
    ConnectionError(att::ConnectionError<C>),
}

impl<C> core::fmt::Debug for AddServicesError<C>
where
    C: ConnectionChannel,
    C::SendErr: core::fmt::Debug,
    C::RecvErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AddServicesError::NoServicesChangedCharacteristic => f.write_str("NoServicesChangedCharacteristic"),
            AddServicesError::ConnectionError(e) => core::fmt::Debug::fmt(e, f),
        }
    }
}

impl<C: ConnectionChannel> core::fmt::Display for AddServicesError<C>
where
    C: ConnectionChannel,
    C::SendErr: core::fmt::Display,
    C::RecvErr: core::fmt::Display,
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
impl<C> std::error::Error for AddServicesError<C>
where
    C: ConnectionChannel,
    C::SendErr: std::error::Error,
    C::RecvErr: std::error::Error,
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
/// # async fn fun<C: bo_tie_l2cap::ConnectionChannel>(mut connection_channel: C) -> Result<(), bo_tie_att::ConnectionError<C>> {
/// use bo_tie_att::client::ConnectClient;
/// use bo_tie_gatt::Client;
///
/// let gatt_client: Client = ConnectClient::connect(&mut connection_channel, 64).await?.into();
/// # Ok(()) }
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
        let handle = 1;

        ServicesQuery {
            channel,
            client,
            iter,
            handle,
        }
    }

    /// Send the *Read By Group Type Request* for primary services
    async fn send_request_for_primary_services(
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

        let frame = self
            .channel
            .receive_b_frame()
            .await
            .map_err(|e| bo_tie_att::ConnectionError::RecvError(e))?;

        match response_processor.process_response(&frame) {
            Ok(response) => Ok(Some(response)),
            Err(bo_tie_att::Error::Pdu(pdu)) if pdu.get_parameters().error == Error::AttributeNotFound => Ok(None), // no more services
            Err(e) => Err(e.into()),
        }
    }

    /// Query the next Service
    ///
    /// This will return the next primary service on the Server. If there is no more services then
    /// `None` is returned.
    pub async fn query_next(&mut self) -> Result<Option<ServiceRecord>, bo_tie_att::ConnectionError<C>> {
        loop {
            if self.iter.is_none() {
                let response = match self.send_request_for_primary_services().await? {
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
                        is_primary: true,
                        service_handle: group_data.get_handle(),
                        end_group_handle: group_data.get_end_group_handle(),
                        service_uuid: *group_data.get_data(),
                    };

                    self.handle = group_data.get_end_group_handle().checked_add(1).unwrap_or(<u16>::MAX);

                    break Ok(Some(ServiceRecord { group_data: record }));
                }
            }
        }
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
    /// that the services on the server has changed. This
    pub fn add_service_changed(mut self) -> Self {
        const UUID: Uuid = Uuid::from_u16(0x2A05);

        const PERMISSIONS: [att::AttributePermissions; 0] = [];

        const PROPERTIES: [characteristic::Properties; 1] = [characteristic::Properties::Indicate];

        self.characteristic_adder = self.characteristic_adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(PROPERTIES).set_uuid(UUID))
                .set_value(|value| value.set_value(()).set_permissions(PERMISSIONS))
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
        const UUID: Uuid = Uuid::from_u16(0x2B29);

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
        const UUID: Uuid = Uuid::from_u16(0x2B2A);

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
        const UUID: Uuid = Uuid::from_u16(0x2803);

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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::att::server::NoQueuedWrites;
    use crate::characteristic::CharacteristicBuilder;
    use crate::l2cap::{ConnectionChannel, L2capFragment, MinimumMtu};
    use crate::Uuid;
    use att::TransferFormatInto;
    use bo_tie_att::server::access_value::Trivial;
    use bo_tie_att::{AttributePermissions, AttributeRestriction};
    use bo_tie_core::buffer::de_vec::DeVec;
    use bo_tie_core::buffer::TryExtend;
    use bo_tie_l2cap::{send_future, BasicFrameError};
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    struct DummySendFut;

    impl Future for DummySendFut {
        type Output = Result<(), send_future::Error<usize>>;

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

        let mut server_builder = ServerBuilder::from(gap_service);

        let test_service_1 = server_builder
            .new_service(Uuid::from_u16(0x1234))
            .make_secondary()
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
                            .set_write_restrictions([AttributeRestriction::None])
                    })
            })
            .finish_service()
            .as_record();

        let _test_service_2 = server_builder
            .new_service(Uuid::from_u16(0x3456))
            .into_includes_adder()
            .include_service(test_service_1)
            .unwrap()
            .finish_service();

        let server = server_builder.make_server(NoQueuedWrites);
    }

    struct TestChannel {
        last_sent_pdu: std::cell::Cell<Option<Vec<u8>>>,
    }

    impl ConnectionChannel for TestChannel {
        type SendBuffer = DeVec<u8>;
        type SendFut<'a> = DummySendFut;
        type SendErr = usize;
        type RecvBuffer = DeVec<u8>;
        type RecvFut<'a> = DummyRecvFut where Self: 'a,;

        fn send(&self, data: crate::l2cap::BasicFrame<Vec<u8>>) -> Self::SendFut<'_> {
            self.last_sent_pdu.set(Some(data.try_into_packet().unwrap()));

            DummySendFut
        }

        fn set_mtu(&mut self, _: u16) {}

        fn get_mtu(&self) -> usize {
            bo_tie_l2cap::LeULinkType::MIN_SUPPORTED_MTU
        }

        fn max_mtu(&self) -> usize {
            bo_tie_l2cap::LeULinkType::MIN_SUPPORTED_MTU
        }

        fn min_mtu(&self) -> usize {
            bo_tie_l2cap::LeULinkType::MIN_SUPPORTED_MTU
        }

        fn receive_fragment(&mut self) -> Self::RecvFut<'_> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn gatt_services_read_by_group_type() {
        let gap_service = GapServiceBuilder::new(None, None);

        let mut server_builder = ServerBuilder::from(gap_service);

        let first_test_uuid = Uuid::from(0x1000u16);
        let second_test_uuid = Uuid::from(0x1001u128);

        server_builder.new_gatt_service(|gatt_service_builder| gatt_service_builder.add_database_hash());

        server_builder
            .new_service(first_test_uuid)
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
            .new_service(second_test_uuid)
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

        let acl_client_pdu = l2cap::BasicFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(Ok(()), server.process_att_pdu(&mut test_channel, &acl_client_pdu).await);

        let expected_response = att::pdu::ReadByGroupTypeResponse::new(vec![
            // GAP Service
            att::pdu::ReadGroupTypeData::new(1, 5, GapServiceBuilder::GAP_SERVICE_TYPE),
            // GATT Service
            att::pdu::ReadGroupTypeData::new(6, 8, GattServiceBuilder::GATT_SERVICE_UUID),
            att::pdu::ReadGroupTypeData::new(9, 11, first_test_uuid),
        ]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicFrame::<Vec<_>>::try_from_slice(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(11.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        assert_eq!(Ok(()), server.process_att_pdu(&mut test_channel, &acl_client_pdu).await);

        let expected_response =
            att::pdu::ReadByGroupTypeResponse::new(vec![att::pdu::ReadGroupTypeData::new(12, 14, second_test_uuid)]);

        assert_eq!(
            Some(att::pdu::read_by_group_type_response(expected_response)),
            test_channel.last_sent_pdu.take().map(|data| {
                let acl_data = l2cap::BasicFrame::<Vec<_>>::try_from_slice(&data).unwrap();
                att::TransferFormatTryFrom::try_from(acl_data.get_payload()).unwrap()
            }),
        );

        let client_pdu = att::pdu::read_by_group_type_request(15.., ServiceDefinition::PRIMARY_SERVICE_TYPE);

        let acl_client_pdu = l2cap::BasicFrame::new(TransferFormatInto::into(&client_pdu), att::L2CAP_CHANNEL_ID);

        // Request was made for for a attribute that was out of range
        assert_eq!(Ok(()), server.process_att_pdu(&mut test_channel, &acl_client_pdu).await);
    }

    fn is_send<T: Future + Send>(t: T) {}

    #[allow(dead_code)]
    fn send_test<C>(mut c: C)
    where
        C: ConnectionChannel + Send,
        <C::RecvBuffer as TryExtend<u8>>::Error: Send,
        C::SendErr: Send,
        for<'a> C::SendFut<'a>: Send,
    {
        let gap = GapServiceBuilder::new("dev", None);

        let server = ServerBuilder::from(gap).make_server(NoQueuedWrites);

        is_send(server.process_read_by_group_type_request(&c, &[]))
    }
}
