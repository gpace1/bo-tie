//! Security Aspects
//!
//! GAP defines security modes for both BR/EDR and LE. This module has enumerations to represent
//! those modes for use in higher or lower layer protocols.
//!
//! ## LE Security Modes
//! LE Security Modes happen are quite different from BR/EDR modes. Instead of providing a stronger
//! level of security, LE modes are used for different domains of Bluetooth LE. Security Mode one is
//! for data transferred within a connection between two devices. Security Mode two is for data
//! signing in both connection and connectionless data transfer. Security Mode three is for a
//! Broadcast Isochronous Group (BIG).
//!
//! The levels of a mode are used to define the security strength of the operational domain.

/// LE Security Mode One
///
/// Security Mode one is for the security aspects of a LE connection or broadcast between two
/// devices. Levels two and three may use either LE legacy pairing or LE Secure Connections. All
/// levels must satisfy the security requirements of the levels below.
///
/// ### Level 1
/// No authentication and no encryption
///
/// ### Level 2
/// Unauthenticated pairing with encryption
///
/// ### Level 3
/// Authenticated pairing with encryption
///
/// ### Level 4
/// Authenticated LE Secure Connections with 128-bit strength encryption key
pub enum LeSecurityModeOne {
    Level1,
    Level2,
    Level3,
    Level4,
}

/// LE Security Mode Two
///
/// Security Mode two is for connection based data signing when two devices are operating in
/// Security Mode one level one. A mode two level can be established under Security Mode
/// one level two, three, or four granted that the Security Mode one level meats the authentication
/// requirements of the mode two level.
///
/// ### Level 1
/// Unauthenticated pairing with data signing.
///
/// ### Level 2
/// Authenticated pairing with data signing.
pub enum LeSecurityModeTwo {
    Level1,
    Level2,
}

/// LE Security Mode Three
///
/// ### Level 1
/// No authorization and no encryption
///
/// ### Level 2
/// Use of unauthenticated Broadcast_Code
///
/// ### Level 3
/// Use of authenticated Bradcast_Code
pub enum LeSecurityModeThree {
    Level1,
    Level2,
    Level3,
}
