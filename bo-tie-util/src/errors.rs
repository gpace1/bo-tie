//! `bo-tie` Errors
//!
//! These are errors that are used by the libraries within `bo-tie`.

use core::fmt::{self, Display, Formatter};

/// A Controller Error
///
/// `Error` is an enum for representing the controller error codes listed in volume one part F of
/// the Bluetooth core specification. `bo-tie` uses `Error` instead of the error codes because
/// `Error` implements `Debug`, `Display`, and `Error` to print out the error *names* instead of
/// just an error code.
///
/// ## Non Controller Errors
/// Most of the errors within `Errors` map to controller error codes, but there are a few
/// enumerations within `Error` that do not match to a an error code. `Errors` is used for all
/// error cases and not all of these are representable by the errors listed within the core
/// specification.
///
/// ### `NoError`
/// The enum `NoError` is created from the error code zero. There is no official error for zero, but
/// it is used by host controller interface events and other things to signify there was no error.
///
/// ### `Unknown`
/// Sometimes a controller (or host) can send an error that is not part of the Bluetooth
/// Specification. This can be because the error is a manufacture's specific error or just a bug.
/// These error codes get turned into the error `Unknown`.
///
/// ### `MissingErrorCode`
/// This only occurs whenever the error code is not present. When this occurs it generally
/// means that was an event containing an incomplete event parameter.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Error {
    NoError,
    Unknown(u8),
    MissingErrorCode,
    // Start of Bluetooth Specified HCI error codes
    UnknownHciCommand,
    UnknownConnectionIdentifier,
    HardwareFailure,
    PageTimeout,
    AuthenticationFailure,
    PinOrKeyMissing,
    MemoryCapacityExceeded,
    ConnectionTimeout,
    ConnectionLimitExceeded,
    SynchronousConnectionLimitToADeviceExceeded,
    ConnectionAlreadyExists,
    CommandDisallowed,
    ConnectionRejectedDueToLimitedResources,
    ConnectionRejectedDueToSecurityReasons,
    ConnectionRejectedDueToUnacceptableBluetoothAddress,
    ConnectionAcceptTimeoutExceeded,
    UnsupportedFeatureOrParameterValue,
    InvalidHciCommandParameters,
    RemoteUserTerminatedConnection,
    RemoteDeviceTerminatedConnectionDueToLowResources,
    RemoteDeviceTerminatedConnectionDueToPowerOff,
    ConnectionTerminatedByLocalHost,
    RepeatedAttempts,
    PairingNotAllowed,
    UnknownLmpPdu,
    UnsupportedRemoteFeature,
    ScoOffsetRejected,
    ScoIntervalRejected,
    ScoAirModeRejected,
    InvalidLmpParametersOrInvalidLlParameters,
    UnspecifiedError,
    UnsupportedLmpParameterValueOrUnsupportedLlParameterValue,
    RoleChangeNotAllowed,
    LmpResponseTimeoutOrLlResponseTimeout,
    LmpErrorTransactionCollisionOrLlProcedureCollision,
    LmpPduNotAllowed,
    EncryptionModeNotAcceptable,
    LinkKeyCannotBeChanged,
    RequestedQosNosSupported,
    InstantPassed,
    PairingWithUnitKeyNotSupported,
    DifferentTransactionCollision,
    QosUnacceptableParameter,
    QosRejected,
    ChannelAssessmentNotSupported,
    InsufficientSecurity,
    ParameterOutOfMandatoryRange,
    RoleSwitchPending,
    ReservedSlotViolation,
    RoleSwitchFailed,
    ExtendedInquiryResponseTooLarge,
    SimplePairingNotSupportedByHost,
    HostBusyBecausePairing,
    ConnectionRejectedDueToNoSuitableChannelFound,
    ControllerBusy,
    UnacceptableConnectionParameters,
    AdvertisingTimeout,
    ConnectionTerminatedDueToMicFailure,
    ConnectionFailedToBeEstablishedOrSynchronizationTimeout,
    CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging,
    Type0SubmapNotDefined,
    UnknownAdvertisingIdentifier,
    LimitReached,
    OperationCancelledByHost,
    PacketTooLong,
}

impl Error {
    pub fn ok_or_else<F, E>(self, err: F) -> Result<(), E>
    where
        F: FnOnce(Self) -> E,
    {
        if let Error::NoError = self {
            Ok(())
        } else {
            Err(err(self))
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Error::NoError => write!(f, "NoError"),
            Error::Unknown(val) => write!(f, "Unknown Error Code (0x{:X})", val),
            Error::MissingErrorCode => f.write_str("MissingErrorCode"),
            Error::UnknownHciCommand => write!(f, "UnknownHciCommand (0x{:X})", 0x01),
            Error::UnknownConnectionIdentifier => write!(f, "UnknownConnectionIdentifier (0x{:X})", 0x02),
            Error::HardwareFailure => write!(f, "HardwareFailure (0x{:X})", 0x03),
            Error::PageTimeout => write!(f, "PageTimeout (0x{:X})", 0x04),
            Error::AuthenticationFailure => write!(f, "AuthenticationFailure (0x{:X})", 0x05),
            Error::PinOrKeyMissing => write!(f, "PinOrKeyMissing (0x{:X})", 0x06),
            Error::MemoryCapacityExceeded => write!(f, "MemoryCapacityExceeded (0x{:X})", 0x07),
            Error::ConnectionTimeout => write!(f, "ConnectionTimeout (0x{:X})", 0x08),
            Error::ConnectionLimitExceeded => write!(f, "ConnectionLimitExceeded (0x{:X})", 0x09),
            Error::SynchronousConnectionLimitToADeviceExceeded => {
                write!(f, "SynchronousConnectionLimitToADeviceExceeded (0x{:X})", 0x0a)
            }
            Error::ConnectionAlreadyExists => write!(f, "ConnectionAlreadyExists (0x{:X})", 0x0b),
            Error::CommandDisallowed => write!(f, "CommandDisallowed (0x{:X})", 0x0c),
            Error::ConnectionRejectedDueToLimitedResources => {
                write!(f, "ConnectionRejectedDueToLimitedResources (0x{:X})", 0x0d)
            }
            Error::ConnectionRejectedDueToSecurityReasons => {
                write!(f, "ConnectionRejectedDueToSecurityReasons (0x{:X})", 0x0e)
            }
            Error::ConnectionRejectedDueToUnacceptableBluetoothAddress => {
                write!(f, "ConnectionRejectedDueToUnacceptableBluetoothAddress (0x{:X})", 0x0f)
            }
            Error::ConnectionAcceptTimeoutExceeded => {
                write!(f, "ConnectionAcceptTimeoutExceeded (0x{:X})", 0x10)
            }
            Error::UnsupportedFeatureOrParameterValue => {
                write!(f, "UnsupportedFeatureOrParameterValue (0x{:X})", 0x11)
            }
            Error::InvalidHciCommandParameters => write!(f, "InvalidHciCommandParameters (0x{:X})", 0x12),
            Error::RemoteUserTerminatedConnection => {
                write!(f, "RemoteUserTerminatedConnection (0x{:X})", 0x13)
            }
            Error::RemoteDeviceTerminatedConnectionDueToLowResources => {
                write!(f, "RemoteDeviceTerminatedConnectionDueToLowResources (0x{:X})", 0x14)
            }
            Error::RemoteDeviceTerminatedConnectionDueToPowerOff => {
                write!(f, "RemoteDeviceTerminatedConnectionDueToPowerOff (0x{:X})", 0x15)
            }
            Error::ConnectionTerminatedByLocalHost => {
                write!(f, "ConnectionTerminatedByLocalHost (0x{:X})", 0x16)
            }
            Error::RepeatedAttempts => write!(f, "RepeatedAttempts (0x{:X})", 0x17),
            Error::PairingNotAllowed => write!(f, "PairingNotAllowed (0x{:X})", 0x18),
            Error::UnknownLmpPdu => write!(f, "UnknownLmpPdu (0x{:X})", 0x19),
            Error::UnsupportedRemoteFeature => {
                write!(f, "UnsupportedRemoteFeature (0x{:X})", 0x1a)
            }
            Error::ScoOffsetRejected => write!(f, "SCOOffsetRejected (0x{:X})", 0x1b),
            Error::ScoIntervalRejected => write!(f, "SCOIntervalRejected (0x{:X})", 0x1c),
            Error::ScoAirModeRejected => write!(f, "SCOAirModeRejected (0x{:X})", 0x1d),
            Error::InvalidLmpParametersOrInvalidLlParameters => {
                write!(f, "InvalidLMPParametersOrInvalidLLParameters (0x{:X})", 0x1e)
            }
            Error::UnspecifiedError => write!(f, "UnspecifiedError (0x{:X})", 0x1f),
            Error::UnsupportedLmpParameterValueOrUnsupportedLlParameterValue => write!(
                f,
                "UnsupportedLMPParameterValueOrUnsupportedLLParameterValue (0x{:X})",
                0x20
            ),
            Error::RoleChangeNotAllowed => write!(f, "RoleChangeNotAllowed (0x{:X})", 0x21),
            Error::LmpResponseTimeoutOrLlResponseTimeout => {
                write!(f, "LMPResponseTimeoutOrLLResponseTimeout (0x{:X})", 0x22)
            }
            Error::LmpErrorTransactionCollisionOrLlProcedureCollision => {
                write!(f, "LPMErrorTranslationCollisionOrLLProcedureColision (0x{:X})", 0x23)
            }
            Error::LmpPduNotAllowed => write!(f, "LmpPduNotAllowed (0x{:X})", 0x24),
            Error::EncryptionModeNotAcceptable => write!(f, "EncryptionModeNotAcceptable (0x{:X})", 0x25),
            Error::LinkKeyCannotBeChanged => write!(f, "LinkKeyCannotBeChanged (0x{:X})", 0x26),
            Error::RequestedQosNosSupported => write!(f, "RequestedQosNosSupported (0x{:X})", 0x27),
            Error::InstantPassed => write!(f, "InstantPassed (0x{:X})", 0x28),
            Error::PairingWithUnitKeyNotSupported => {
                write!(f, "PairingWithUnitKeyNotSupported (0x{:X})", 0x29)
            }
            Error::DifferentTransactionCollision => {
                write!(f, "DifferentTransactionCollision (0x{:X})", 0x2a)
            }
            Error::QosUnacceptableParameter => write!(f, "QosUnacceptableParameter (0x{:X})", 0x2c),
            Error::QosRejected => write!(f, "QosRejected (0x{:X})", 0x2d),
            Error::ChannelAssessmentNotSupported => {
                write!(f, "ChannelAssessmentNotSupported (0x{:X})", 0x2e)
            }
            Error::InsufficientSecurity => write!(f, "InsufficientSecurity (0x{:X})", 0x2f),
            Error::ParameterOutOfMandatoryRange => write!(f, "ParameterOutOfMandatoryRange (0x{:X})", 0x30),
            Error::RoleSwitchPending => write!(f, "RoleSwitchPending (0x{:X})", 0x32),
            Error::ReservedSlotViolation => write!(f, "ReservedSlotViolation (0x{:X})", 0x34),
            Error::RoleSwitchFailed => write!(f, "RoleSwitchFailed (0x{:X})", 0x35),
            Error::ExtendedInquiryResponseTooLarge => {
                write!(f, "ExtendedInquiryResponseTooLarge (0x{:X})", 0x36)
            }
            Error::SimplePairingNotSupportedByHost => {
                write!(f, "SimplePairingNotSupportedByHost (0x{:X})", 0x37)
            }
            Error::HostBusyBecausePairing => write!(f, "HostBusyBecausePairing (0x{:X})", 0x38),
            Error::ConnectionRejectedDueToNoSuitableChannelFound => {
                write!(f, "ConnectionRejectedDueToNoSuitableChannelFound (0x{:X})", 0x39)
            }
            Error::ControllerBusy => write!(f, "ControllerBusy (0x{:X})", 0x3a),
            Error::UnacceptableConnectionParameters => {
                write!(f, "UnacceptableConnectionParameters (0x{:X})", 0x3b)
            }
            Error::AdvertisingTimeout => write!(f, "AdvertisingTimeout (0x{:X})", 0x3c),
            Error::ConnectionTerminatedDueToMicFailure => {
                write!(f, "ConnectionTerminatedDueToMicFailure (0x{:X})", 0x3d)
            }
            Error::ConnectionFailedToBeEstablishedOrSynchronizationTimeout => {
                write!(
                    f,
                    "ConnectionFailedToBeEstablishedOrSynchronizationTimeout (0x{:X})",
                    0x3e
                )
            }
            Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => write!(
                f,
                "CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging (0x{:X})",
                0x40
            ),
            Error::Type0SubmapNotDefined => write!(f, "Type0SubmapNotDefined (0x{:X})", 0x41),
            Error::UnknownAdvertisingIdentifier => {
                write!(f, "UnknownAdvertisingIdentifier (0x{:X})", 0x42)
            }
            Error::LimitReached => write!(f, "LimitReached (0x{:X})", 0x43),
            Error::OperationCancelledByHost => write!(f, "OperationCancelledByHost (0x{:X})", 0x44),
            Error::PacketTooLong => write!(f, "PacketTooLong (0x{:X})", 0x45),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        macro_rules! ctrl_err {
            ($f:expr, $($arg:tt)*) => {{
                f.write_str("controller error: ")?;

                core::write!(f, $($arg)*)?;

                f.write_str(
                    " (see the Bluetooth Core Specification vol 1, part F: Controller Error Codes)")
            }}
        }

        match self {
            Error::NoError => f.write_str("no error"),
            Error::Unknown(val) => write!(f, "unknown error code (0x{:X})", val),
            Error::MissingErrorCode => f.write_str("missing error parameter"),
            Error::UnknownHciCommand => f.write_str("unknown HCI command"),
            Error::UnknownConnectionIdentifier => ctrl_err!(f, "unknown connection identifier"),
            Error::HardwareFailure => ctrl_err!(f, "hardware failure"),
            Error::PageTimeout => ctrl_err!(f, "page timeout"),
            Error::AuthenticationFailure => ctrl_err!(f, "authentication failure"),
            Error::PinOrKeyMissing => ctrl_err!(f, "PIN or key missing"),
            Error::MemoryCapacityExceeded => ctrl_err!(f, "memory capacity exceeded"),
            Error::ConnectionTimeout => ctrl_err!(f, "connection timeout"),
            Error::ConnectionLimitExceeded => ctrl_err!(f, "connection limit exceeded"),
            Error::SynchronousConnectionLimitToADeviceExceeded => {
                ctrl_err!(f, "synchronous connection limit to a device exceeded")
            }
            Error::ConnectionAlreadyExists => ctrl_err!(f, "connection already exists"),
            Error::CommandDisallowed => ctrl_err!(f, "command disallowed"),
            Error::ConnectionRejectedDueToLimitedResources => {
                ctrl_err!(f, "connection rejected due to limited resources")
            }
            Error::ConnectionRejectedDueToSecurityReasons => {
                ctrl_err!(f, "connection rejected due to security reasons")
            }
            Error::ConnectionRejectedDueToUnacceptableBluetoothAddress => {
                ctrl_err!(f, "connection rejected due to unacceptable bluetooth address")
            }
            Error::ConnectionAcceptTimeoutExceeded => ctrl_err!(f, "connection accept timeout exceeded"),
            Error::UnsupportedFeatureOrParameterValue => ctrl_err!(f, "unsupported feature or parameter value"),
            Error::InvalidHciCommandParameters => ctrl_err!(f, "invalid hCI command parameters"),
            Error::RemoteUserTerminatedConnection => ctrl_err!(f, "remote user terminated connection"),
            Error::RemoteDeviceTerminatedConnectionDueToLowResources => {
                ctrl_err!(f, "remote device terminated connection due to low resources")
            }
            Error::RemoteDeviceTerminatedConnectionDueToPowerOff => {
                ctrl_err!(f, "remote device terminated connection due to power off")
            }
            Error::ConnectionTerminatedByLocalHost => ctrl_err!(f, "connection terminated by local host"),
            Error::RepeatedAttempts => ctrl_err!(f, "repeated attempts"),
            Error::PairingNotAllowed => ctrl_err!(f, "pairing not allowed"),
            Error::UnknownLmpPdu => ctrl_err!(f, "unknown LMP PDU"),
            Error::UnsupportedRemoteFeature => f.write_str("unsupported remote feature"),
            Error::ScoOffsetRejected => ctrl_err!(f, "SCO offset rejected"),
            Error::ScoIntervalRejected => ctrl_err!(f, "SCO interval rejected"),
            Error::ScoAirModeRejected => ctrl_err!(f, "SCO air mode rejected"),
            Error::InvalidLmpParametersOrInvalidLlParameters => {
                f.write_str("invalid LMP parameters / invalid LL parameters")
            }
            Error::UnspecifiedError => ctrl_err!(f, "unspecified error"),
            Error::UnsupportedLmpParameterValueOrUnsupportedLlParameterValue => {
                f.write_str("unsupported LMP parameter value / unsupported LL parameter value")
            }
            Error::RoleChangeNotAllowed => ctrl_err!(f, "role change not allowed"),
            Error::LmpResponseTimeoutOrLlResponseTimeout => f.write_str("LMP response timeout / LL response timeout"),
            Error::LmpErrorTransactionCollisionOrLlProcedureCollision => {
                f.write_str("LPM error transaction collision / LL procedure collision")
            }
            Error::LmpPduNotAllowed => ctrl_err!(f, "LMP PDU not allowed"),
            Error::EncryptionModeNotAcceptable => ctrl_err!(f, "encryption mode not acceptable"),
            Error::LinkKeyCannotBeChanged => ctrl_err!(f, "link key cannot be changed"),
            Error::RequestedQosNosSupported => ctrl_err!(f, "requested qos nos supported"),
            Error::InstantPassed => ctrl_err!(f, "instant passed"),
            Error::PairingWithUnitKeyNotSupported => ctrl_err!(f, "pairing with unit key not supported"),
            Error::DifferentTransactionCollision => ctrl_err!(f, "different transaction collision"),
            Error::QosUnacceptableParameter => ctrl_err!(f, "qos unacceptable parameter"),
            Error::QosRejected => ctrl_err!(f, "qos rejected"),
            Error::ChannelAssessmentNotSupported => ctrl_err!(f, "channel assessment not supported"),
            Error::InsufficientSecurity => ctrl_err!(f, "insufficient security"),
            Error::ParameterOutOfMandatoryRange => ctrl_err!(f, "parameter out of mandatory range"),
            Error::RoleSwitchPending => ctrl_err!(f, "role switch pending"),
            Error::ReservedSlotViolation => ctrl_err!(f, "reserved slot violation"),
            Error::RoleSwitchFailed => ctrl_err!(f, "role switch failed"),
            Error::ExtendedInquiryResponseTooLarge => ctrl_err!(f, "extended inquiry response too large"),
            Error::SimplePairingNotSupportedByHost => ctrl_err!(f, "simple pairing not supported by host"),
            Error::HostBusyBecausePairing => ctrl_err!(f, "host busy because pairing"),
            Error::ConnectionRejectedDueToNoSuitableChannelFound => {
                ctrl_err!(f, "connection rejected due to no suitable channel found")
            }
            Error::ControllerBusy => ctrl_err!(f, "controller busy"),
            Error::UnacceptableConnectionParameters => ctrl_err!(f, "unacceptable connection parameters"),
            Error::AdvertisingTimeout => ctrl_err!(f, "advertising timeout"),
            Error::ConnectionTerminatedDueToMicFailure => ctrl_err!(f, "connection terminated due to MIC failure"),
            Error::ConnectionFailedToBeEstablishedOrSynchronizationTimeout => {
                ctrl_err!(f, "connection failed to be established / synchronization timeout")
            }
            Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => {
                ctrl_err!(
                    f,
                    "coarse clock adjustment rejected but will try to adjust using clock dragging"
                )
            }
            Error::Type0SubmapNotDefined => f.write_str("type0 sub-map not defined"),
            Error::UnknownAdvertisingIdentifier => ctrl_err!(f, "unknown advertising identifier"),
            Error::LimitReached => ctrl_err!(f, "limit reached"),
            Error::OperationCancelledByHost => ctrl_err!(f, "operation cancelled by host"),
            Error::PacketTooLong => ctrl_err!(f, "packet too long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<u8> for Error {
    fn from(raw: u8) -> Self {
        match raw {
            0x00 => Error::NoError,
            0x01 => Error::UnknownHciCommand,
            0x02 => Error::UnknownConnectionIdentifier,
            0x03 => Error::HardwareFailure,
            0x04 => Error::PageTimeout,
            0x05 => Error::AuthenticationFailure,
            0x06 => Error::PinOrKeyMissing,
            0x07 => Error::MemoryCapacityExceeded,
            0x08 => Error::ConnectionTimeout,
            0x09 => Error::ConnectionLimitExceeded,
            0x0a => Error::SynchronousConnectionLimitToADeviceExceeded,
            0x0b => Error::ConnectionAlreadyExists,
            0x0c => Error::CommandDisallowed,
            0x0d => Error::ConnectionRejectedDueToLimitedResources,
            0x0e => Error::ConnectionRejectedDueToSecurityReasons,
            0x0f => Error::ConnectionRejectedDueToUnacceptableBluetoothAddress,
            0x10 => Error::ConnectionAcceptTimeoutExceeded,
            0x11 => Error::UnsupportedFeatureOrParameterValue,
            0x12 => Error::InvalidHciCommandParameters,
            0x13 => Error::RemoteUserTerminatedConnection,
            0x14 => Error::RemoteDeviceTerminatedConnectionDueToLowResources,
            0x15 => Error::RemoteDeviceTerminatedConnectionDueToPowerOff,
            0x16 => Error::ConnectionTerminatedByLocalHost,
            0x17 => Error::RepeatedAttempts,
            0x18 => Error::PairingNotAllowed,
            0x19 => Error::UnknownLmpPdu,
            0x1a => Error::UnsupportedRemoteFeature,
            0x1b => Error::ScoOffsetRejected,
            0x1c => Error::ScoIntervalRejected,
            0x1d => Error::ScoAirModeRejected,
            0x1e => Error::InvalidLmpParametersOrInvalidLlParameters,
            0x1f => Error::UnspecifiedError,
            0x20 => Error::UnsupportedLmpParameterValueOrUnsupportedLlParameterValue,
            0x21 => Error::RoleChangeNotAllowed,
            0x22 => Error::LmpResponseTimeoutOrLlResponseTimeout,
            0x23 => Error::LmpErrorTransactionCollisionOrLlProcedureCollision,
            0x24 => Error::LmpPduNotAllowed,
            0x25 => Error::EncryptionModeNotAcceptable,
            0x26 => Error::LinkKeyCannotBeChanged,
            0x27 => Error::RequestedQosNosSupported,
            0x28 => Error::InstantPassed,
            0x29 => Error::PairingWithUnitKeyNotSupported,
            0x2a => Error::DifferentTransactionCollision,
            0x2c => Error::QosUnacceptableParameter,
            0x2d => Error::QosRejected,
            0x2e => Error::ChannelAssessmentNotSupported,
            0x2f => Error::InsufficientSecurity,
            0x30 => Error::ParameterOutOfMandatoryRange,
            0x32 => Error::RoleSwitchPending,
            0x34 => Error::ReservedSlotViolation,
            0x35 => Error::RoleSwitchFailed,
            0x36 => Error::ExtendedInquiryResponseTooLarge,
            0x37 => Error::SimplePairingNotSupportedByHost,
            0x38 => Error::HostBusyBecausePairing,
            0x39 => Error::ConnectionRejectedDueToNoSuitableChannelFound,
            0x3a => Error::ControllerBusy,
            0x3b => Error::UnacceptableConnectionParameters,
            0x3c => Error::AdvertisingTimeout,
            0x3d => Error::ConnectionTerminatedDueToMicFailure,
            0x3e => Error::ConnectionFailedToBeEstablishedOrSynchronizationTimeout,
            0x40 => Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging,
            0x41 => Error::Type0SubmapNotDefined,
            0x42 => Error::UnknownAdvertisingIdentifier,
            0x43 => Error::LimitReached,
            0x44 => Error::OperationCancelledByHost,
            0x45 => Error::PacketTooLong,
            _ => Error::Unknown(raw),
        }
    }
}

impl From<Error> for Option<u8> {
    fn from(error: Error) -> Self {
        match error {
            Error::NoError => Some(0u8),
            Error::Unknown(v) => Some(v),
            Error::MissingErrorCode => None,
            Error::UnknownHciCommand => Some(0x01),
            Error::UnknownConnectionIdentifier => Some(0x02),
            Error::HardwareFailure => Some(0x03),
            Error::PageTimeout => Some(0x04),
            Error::AuthenticationFailure => Some(0x05),
            Error::PinOrKeyMissing => Some(0x06),
            Error::MemoryCapacityExceeded => Some(0x07),
            Error::ConnectionTimeout => Some(0x08),
            Error::ConnectionLimitExceeded => Some(0x09),
            Error::SynchronousConnectionLimitToADeviceExceeded => Some(0x0a),
            Error::ConnectionAlreadyExists => Some(0x0b),
            Error::CommandDisallowed => Some(0x0c),
            Error::ConnectionRejectedDueToLimitedResources => Some(0x0d),
            Error::ConnectionRejectedDueToSecurityReasons => Some(0x0e),
            Error::ConnectionRejectedDueToUnacceptableBluetoothAddress => Some(0x0f),
            Error::ConnectionAcceptTimeoutExceeded => Some(0x10),
            Error::UnsupportedFeatureOrParameterValue => Some(0x11),
            Error::InvalidHciCommandParameters => Some(0x12),
            Error::RemoteUserTerminatedConnection => Some(0x13),
            Error::RemoteDeviceTerminatedConnectionDueToLowResources => Some(0x14),
            Error::RemoteDeviceTerminatedConnectionDueToPowerOff => Some(0x15),
            Error::ConnectionTerminatedByLocalHost => Some(0x16),
            Error::RepeatedAttempts => Some(0x17),
            Error::PairingNotAllowed => Some(0x18),
            Error::UnknownLmpPdu => Some(0x19),
            Error::UnsupportedRemoteFeature => Some(0x1a),
            Error::ScoOffsetRejected => Some(0x1b),
            Error::ScoIntervalRejected => Some(0x1c),
            Error::ScoAirModeRejected => Some(0x1d),
            Error::InvalidLmpParametersOrInvalidLlParameters => Some(0x1e),
            Error::UnspecifiedError => Some(0x1f),
            Error::UnsupportedLmpParameterValueOrUnsupportedLlParameterValue => Some(0x20),
            Error::RoleChangeNotAllowed => Some(0x21),
            Error::LmpResponseTimeoutOrLlResponseTimeout => Some(0x22),
            Error::LmpErrorTransactionCollisionOrLlProcedureCollision => Some(0x23),
            Error::LmpPduNotAllowed => Some(0x24),
            Error::EncryptionModeNotAcceptable => Some(0x25),
            Error::LinkKeyCannotBeChanged => Some(0x26),
            Error::RequestedQosNosSupported => Some(0x27),
            Error::InstantPassed => Some(0x28),
            Error::PairingWithUnitKeyNotSupported => Some(0x29),
            Error::DifferentTransactionCollision => Some(0x2a),
            Error::QosUnacceptableParameter => Some(0x2c),
            Error::QosRejected => Some(0x2d),
            Error::ChannelAssessmentNotSupported => Some(0x2e),
            Error::InsufficientSecurity => Some(0x2f),
            Error::ParameterOutOfMandatoryRange => Some(0x30),
            Error::RoleSwitchPending => Some(0x32),
            Error::ReservedSlotViolation => Some(0x34),
            Error::RoleSwitchFailed => Some(0x35),
            Error::ExtendedInquiryResponseTooLarge => Some(0x36),
            Error::SimplePairingNotSupportedByHost => Some(0x37),
            Error::HostBusyBecausePairing => Some(0x38),
            Error::ConnectionRejectedDueToNoSuitableChannelFound => Some(0x39),
            Error::ControllerBusy => Some(0x3a),
            Error::UnacceptableConnectionParameters => Some(0x3b),
            Error::AdvertisingTimeout => Some(0x3c),
            Error::ConnectionTerminatedDueToMicFailure => Some(0x3d),
            Error::ConnectionFailedToBeEstablishedOrSynchronizationTimeout => Some(0x3e),
            Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => Some(0x40),
            Error::Type0SubmapNotDefined => Some(0x41),
            Error::UnknownAdvertisingIdentifier => Some(0x42),
            Error::LimitReached => Some(0x43),
            Error::OperationCancelledByHost => Some(0x44),
            Error::PacketTooLong => Some(0x45),
        }
    }
}

/// The error for an invalid Bluetooth addresses
///
/// This is returned whenever trying to create a [`BlueoothDeviceAddress`] fails.
///
/// [`BluetoothDeviceAddress`]: super::BluetoothDeviceAddress
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressError {
    AddressIsZero,
    AddressIsAllOnes,
}

impl Display for AddressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::AddressIsZero => f.write_str("the random part of the address is zero"),
            AddressError::AddressIsAllOnes => f.write_str("the random part of the address is all ones"),
        }
    }
}

/// Error type for
/// [BluetoothDeviceAddress::try_from_static](crate::BluetoothDeviceAddress::try_from_static)
pub type StaticDeviceError = AddressError;

/// Error type for
/// [BluetoothDeviceAddress::try_from_non_resolvable](crate::BluetoothDeviceAddress::try_from_non_resolvable)
pub type NonResolvableError = AddressError;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ResolvableError {
    PRandIsZero,
    PRandIsAllOnes,
}

impl Display for ResolvableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolvableError::PRandIsZero => f.write_str("the random part of the prand is all zeros"),
            ResolvableError::PRandIsAllOnes => f.write_str("the random part of the prand is all ones"),
        }
    }
}
