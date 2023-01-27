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
        let mut permissions = bo_tie_util::buffer::stack::LinearBuffer::<
            { bo_tie_att::AttributeRestriction::full_depth() },
            bo_tie_att::AttributePermissions,
        >::new();

        map_restrictions!($restrictions => Read => permissions);

        permissions
    }};
    ( $restrictions:expr => Write ) => {{
        let mut permissions = bo_tie_util::buffer::stack::LinearBuffer::<
            { bo_tie_att::AttributeRestriction::full_depth() },
            bo_tie_att::AttributePermissions,
        >::new();

        map_restrictions!($restrictions => Write => permissions)
    }};
    ( $restrictions:expr => Read & Write ) => {{
        let mut permissions = bo_tie_util::buffer::stack::LinearBuffer::<
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

use alloc::vec::Vec;

pub use bo_tie_att as att;
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
    definition_handle: Option<u16>,
    access_restrictions: LinearBuffer<{ att::AttributeRestriction::full_depth() }, att::AttributeRestriction>,
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
    const DEFAULT_RESTRICTIONS: [att::AttributeRestriction; att::AttributeRestriction::full_depth()] = [
        att::AttributeRestriction::None,
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits128),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits192),
        att::AttributeRestriction::Encryption(att::EncryptionKeySize::Bits256),
        att::AttributeRestriction::Authorization,
        att::AttributeRestriction::Authentication,
    ];

    fn new(server_builder: &'a mut ServerBuilder, service_uuid: Uuid, is_primary: bool) -> Self {
        let access_restrictions = Self::DEFAULT_RESTRICTIONS.into();

        ServiceBuilder {
            service_uuid,
            is_primary,
            server_builder,
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

        let permissions = map_restrictions!(self.service_builder.access_restrictions => Read);

        let attribute = att::Attribute::new(ServiceInclude::TYPE, permissions, include);

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

impl ServiceRecord {
    /// Get the service UUID
    pub fn get_uuid(&self) -> Uuid {
        self.record.service_uuid
    }

    /// Get the handle group range
    ///
    /// This returns the range of Attribute handles used by this service
    pub fn get_range(&self) -> core::ops::RangeInclusive<u16> {
        self.record.service_handle..=self.record.end_group_handle
    }
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

/// A Constructor of the GAP Service
///
/// This is used to construct the GAP Service. This service is unique as the characteristics are
/// also unique to it. Per the Specification, every GAT server is required to have the GAP service,
/// so this is often the starting point in constructing a GATT [`Server`].
///
/// A [`ServerBuilder`] can be constructed from a `GapServiceBuilder` with the method
pub struct GapServiceBuilder<'a> {
    access_restrictions: &'a [att::AttributeRestriction],
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
        let access_restrictions = &ServiceBuilder::DEFAULT_RESTRICTIONS;

        GapServiceBuilder {
            access_restrictions,
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
    /// |interval_min| The minimum connection interval | 7.5ms to 4s and a multiple of 1.25ms |
    /// |interval_max| The maximum connection interval | 7.5ms to 4s and a multiple of 1.25ms<br/>Must be greater than interval_min |
    /// |latency| The peripheral latency | *subrate_factor * (latency + 1) < 500*<br/>and<br/>*subrate_factor * (latency + 1) < timeout / 2* |
    /// |timeout| The supervision timeout | *(latency + 1) * subrate_factor * interval_max * 2*<br/>a multiple of 10ms |
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
            .new_service(Self::GAP_SERVICE_TYPE, true)
            .set_access_restriction(self.access_restrictions)
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
/// #     type SendFut<'a> = Pin<Box<dyn Future<Output = Result<(), send_future::Error<usize>>>>>;
/// #     type SendFutErr = usize;
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
        struct Response<'a, Q> {
            server: &'a Server<Q>,
            is_128_uuids: bool,
            start_handle: usize,
            ending_handle: usize,
            max_payload_size: usize,
            shortcut: usize,
        }

        impl<'a, Q: att::server::QueuedWriter> Response<'a, Q> {
            fn new<C: ConnectionChannel>(
                connection_channel: &C,
                server: &'a Server<Q>,
                is_128_uuids: bool,
                start_handle: usize,
                ending_handle: usize,
            ) -> Self {
                // The first 2 bytes of the response are the attribute opcode and length
                let max_payload_size = core::cmp::min(connection_channel.get_mtu() - 2, <u8>::MAX.into());

                let shortcut = 0;

                Self {
                    server,
                    is_128_uuids,
                    start_handle,
                    ending_handle,
                    max_payload_size,
                    shortcut,
                }
            }

            fn check(&self, service: &ServiceGroupData) -> bool {
                if self.is_128_uuids {
                    (!service.service_uuid.can_be_16_bit())
                        && <usize>::from(service.service_handle) >= self.start_handle
                        && <usize>::from(service.service_handle) <= self.ending_handle
                        && self.server.rbgt_permission_check(service).is_ok()
                } else {
                    service.service_uuid.can_be_16_bit()
                        && <usize>::from(service.service_handle) >= self.start_handle
                        && <usize>::from(service.service_handle) <= self.ending_handle
                        && self.server.rbgt_permission_check(service).is_ok()
                }
            }

            /// Check if any
            ///
            /// # Returns
            /// * `Ok(true)` -> when a service is found that the client can read
            /// * `Ok(false)` -> no service is found
            /// * `Err(error)` -> a service was found but the client does
            ///                   not have permissions to read it.
            fn has_any(&mut self) -> Result<bool, att::pdu::Error> {
                self.server.primary_services[self.shortcut..]
                    .iter()
                    .enumerate()
                    .find_map(|(cnt, service_data)| {
                        if self.is_128_uuids
                            && (!service_data.service_uuid.can_be_16_bit())
                            && <usize>::from(service_data.service_handle) >= self.start_handle
                            && <usize>::from(service_data.service_handle) <= self.ending_handle
                        {
                            self.shortcut = self.shortcut + cnt;

                            Some(self.server.rbgt_permission_check(service_data))
                        } else if !self.is_128_uuids
                            && service_data.service_uuid.can_be_16_bit()
                            && <usize>::from(service_data.service_handle) >= self.start_handle
                            && <usize>::from(service_data.service_handle) <= self.ending_handle
                            && self.server.rbgt_permission_check(service_data).is_ok()
                        {
                            self.shortcut = self.shortcut + cnt;

                            Some(self.server.rbgt_permission_check(service_data))
                        } else {
                            None
                        }
                    })
                    .transpose()
                    .map(|o| o.is_some())
            }

            /// The size of each response structure
            ///
            /// A response structure contains the attribute handle of the service, the end group
            /// handle of the service, and the UUID of the service value.
            fn data_size(&self) -> usize {
                if self.is_128_uuids {
                    4 + 16
                } else {
                    4 + 2
                }
            }
        }

        impl<Q: att::server::QueuedWriter> bo_tie_att::TransferFormatInto for Response<'_, Q> {
            fn len_of_into(&self) -> usize {
                1 + self.server.primary_services[self.shortcut..]
                    .iter()
                    .filter(|service_data| self.check(service_data))
                    .enumerate()
                    .take_while(|(cnt, _)| self.max_payload_size >= (cnt + 1) * self.data_size())
                    .map(|_| self.data_size())
                    .sum::<usize>()
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                into_ret[0] = self.data_size() as u8;

                self.server.primary_services[self.shortcut..]
                    .iter()
                    .filter(|service_data| self.check(service_data))
                    .enumerate()
                    .take_while(|(cnt, _)| self.max_payload_size >= (cnt + 1) * self.data_size())
                    .map(|(_, service_data)| service_data)
                    .fold(&mut into_ret[1..], |into_ret, service_data| {
                        service_data.service_handle.build_into_ret(&mut into_ret[..2]);

                        service_data.end_group_handle.build_into_ret(&mut into_ret[2..4]);

                        service_data
                            .service_uuid
                            .build_into_ret(&mut into_ret[4..self.data_size()]);

                        &mut into_ret[self.data_size()..]
                    });
            }
        }

        match att::TransferFormatTryFrom::try_from(payload) {
            Ok(att::pdu::TypeRequest {
                handle_range,
                attr_type: ServiceDefinition::PRIMARY_SERVICE_TYPE,
            }) => {
                if handle_range.is_valid() {
                    let mut list_16 = Response::new(
                        connection_channel,
                        self,
                        false,
                        handle_range.starting_handle.into(),
                        handle_range.ending_handle.into(),
                    );

                    let mut list_128 = Response::new(
                        connection_channel,
                        self,
                        true,
                        handle_range.starting_handle.into(),
                        handle_range.ending_handle.into(),
                    );

                    // Start with 16 bit UUIDs
                    match list_16.has_any() {
                        Ok(true) => {
                            let pdu =
                                att::pdu::Pdu::new(att::server::ServerPduName::ReadByGroupTypeResponse.into(), list_16);

                            self.server.send_pdu(connection_channel, pdu).await
                        }
                        Err(e) => {
                            self.server
                                .send_error(
                                    connection_channel,
                                    handle_range.starting_handle,
                                    att::client::ClientPduName::ReadByGroupTypeRequest,
                                    e,
                                )
                                .await?;

                            Err(e.into())
                        }
                        // try 128 bit UUIDs
                        Ok(false) => match list_128.has_any() {
                            Ok(true) => {
                                let pdu = att::pdu::Pdu::new(
                                    att::server::ServerPduName::ReadByGroupTypeResponse.into(),
                                    list_128,
                                );

                                self.server.send_pdu(connection_channel, pdu).await
                            }
                            Ok(false) => {
                                self.server
                                    .send_error(
                                        connection_channel,
                                        handle_range.starting_handle,
                                        att::client::ClientPduName::ReadByGroupTypeRequest,
                                        att::pdu::Error::AttributeNotFound,
                                    )
                                    .await?;

                                // This does not return an error as it may
                                // be part of the normal operation of service
                                // discovery.
                                Ok(())
                            }
                            Err(e) => {
                                self.server
                                    .send_error(
                                        connection_channel,
                                        handle_range.starting_handle,
                                        att::client::ClientPduName::ReadByGroupTypeRequest,
                                        e,
                                    )
                                    .await?;

                                Err(e.into())
                            }
                        },
                    }
                } else {
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
        type SendFutErr = usize;
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

    fn is_send<T: Future + Send>(t: T) {}

    #[allow(dead_code)]
    fn send_test<C>(mut c: C)
    where
        C: ConnectionChannel + Send + Sync,
        <C::RecvBuffer as TryExtend<u8>>::Error: Send,
        C::SendFutErr: Send,
        for<'a> C::SendFut<'a>: Send,
    {
        let gap = GapServiceBuilder::new("dev", None);

        let server = ServerBuilder::from(gap).make_server(NoQueuedWrites);

        is_send(server.process_read_by_group_type_request(&c, &[]))
    }
}
