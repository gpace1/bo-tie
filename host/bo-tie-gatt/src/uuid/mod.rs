//! Specification defined UUIDs
//!
//! This module contains UUID constants defined within the Bluetooth Specification for use with
//! GATT.

pub mod gap;
pub mod gatt;

use bo_tie_host_util::Uuid;

/// The UUID for a *Primary Service*
///
/// This is used as the UUID of a service declaration attribute. This marks the service as a
/// primary service and not a secondary service.
pub const PRIMARY_SERVICE: Uuid = Uuid::from_u16(0x2800);

/// The UUID for a *Secondary Service*
///
/// This is used as the UUID of a service declaration attribute. This marks the service as a
/// secondary service and not a primary service.
pub const SECONDARY_SERVICE: Uuid = Uuid::from_u16(0x2801);

/// The UUID for an *Include*
///
/// This is used as the UUID of an include definition attribute
pub const INCLUDE_DEFINITION: Uuid = Uuid::from_u16(0x2802);

/// The UUID for a *Characteristic*
///
/// This is used as the UUID of a characteristic declaration attribute.
pub const CHARACTERISTIC: Uuid = Uuid::from_u16(0x2803);

/// The UUID for a *Characteristic Extended Properties*
///
/// This is used as the UUID of a characteristic extended properties descriptor attribute.
pub const CHARACTERISTIC_EXTENDED_PROPERTIES: Uuid = Uuid::from_u16(0x2900);

/// The UUID for a *Characteristic User Description*
///
/// This is used as the UUID of a characteristic user description descriptor attribute.
pub const CHARACTERISTIC_USER_DESCRIPTION: Uuid = Uuid::from_u16(0x2901);

/// The UUID for a *Client Characteristic Configuration*
///
/// This is used as the UUID of a client characteristic configuration descriptor attribute.
pub const CLIENT_CHARACTERISTIC_CONFIGURATION: Uuid = Uuid::from_u16(0x2902);

/// The UUID for a *Server Characteristic Configuration*
///
/// This is used as the UUID of a server characteristic configuration descriptor attribute.
pub const SERVER_CHARACTERISTIC_CONFIGURATION: Uuid = Uuid::from_u16(0x2903);

/// The UUID for a *Characteristic Presentation Format*
///
/// This is used as the UUID of a characteristic presentation format descriptor attribute.
pub const CHARACTERISTIC_PRESENTATION_FORMAT: Uuid = Uuid::from_u16(0x2904);

/// The UUID for a *Characteristic Aggregate Format*
///
/// This is used as the UUID of a characteristic aggregate format descriptor attribute.
pub const CHARACTERISTIC_AGGREGATE_FORMAT: Uuid = Uuid::from_u16(0x2905);
