//! UUIDs of the GATT Service

use bo_tie_host_util::Uuid;

/// The UUID for the GATT service
///
/// This UUID appears as the value of a service definition attribute
pub const GATT_SERVICE: Uuid = Uuid::from_u16(0x1801);

/// The UUID for the *Service Changed* characteristic
pub const SERVICE_CHANGED: Uuid = Uuid::from_u16(0x2A05);

/// The UUID for the *Client Supported Features* characteristic
pub const CLIENT_SUPPORTED_FEATURES: Uuid = Uuid::from_u16(0x2B29);

/// The UUID for the *Database Hash* characteristic
pub const DATABASE_HASH: Uuid = Uuid::from_u16(0x2B2A);

/// The UUID for the *Server Supported Features* characteristic
pub const SERVER_SUPPORTED_FEATURES: Uuid = Uuid::from_u16(0x2B3A);
