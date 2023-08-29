//! UUIDs of the GAP Service

use bo_tie_host_util::Uuid;

/// The UUID for the *Generic Access* service
///
/// This UUID appears as the value of a service definition attribute
pub const GAP_SERVICE: Uuid = Uuid::from_u16(0x1800);

/// The UUID for the *Device Name* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const DEVICE_NAME: Uuid = Uuid::from_u16(0x2A00);

/// The UUID for the *Appearance* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const APPEARANCE: Uuid = Uuid::from_u16(0x2A01);

/// The UUID for the *Peripheral Preferred Connection Parameters* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS: Uuid = Uuid::from_u16(0x2A04);

/// The UUID for the *Central Address Resolution* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const CENTRAL_ADDRESS_RESOLUTION: Uuid = Uuid::from_u16(0x2AA6);

/// The UUID for the *Resolvable Private Address Only* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const RESOLVABLE_PRIVATE_ADDRESS_ONLY: Uuid = Uuid::from_u16(0x2AC9);

/// The UUID for the *Encrypted Data Key Material* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const ENCRYPTED_DATA_KEY_MATERIAL: Uuid = Uuid::from_u16(0x2B88);

/// The UUID for the *LE GATT Security Levels* characteristic
///
/// This UUID is used within the attribute value of the characteristic declaration and as the UUID
/// for the characteristic value declaration attribute.
pub const LE_GATT_SECURITY_LEVELS_CHARACTERISTIC: Uuid = Uuid::from_u16(0x2BF5);
