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
    UnknownHCICommand,
    UnknownConnectionIdentifier,
    HardwareFailure,
    PageTimeout,
    AuthenticationFailure,
    PINorKeyMissing,
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
    InvalidHCICommandParameters,
    RemoteUserTerminatedConnection,
    RemoteDeviceTerminatedConnectionDueToLowResources,
    RemoteDeviceTerminatedConnectionDueToPowerOff,
    ConnectionTerminatedByLocalHost,
    RepeatedAttempts,
    PairingNotAllowed,
    UnknownLMPPDU,
    UnsupportedRemoteFeatureOrUnsupportedLMPFeature,
    SCOOffsetRejected,
    SCOIntervalRejected,
    SCOAirModeRejected,
    InvalidLMPParametersOrInvalidLLParameters,
    UnspecifiedError,
    UnsupportedLMPParameterValueOrUnsupportedLLParameterValue,
    RoleChangeNotAllowed,
    LMPResponseTimeoutOrLLResponseTimeout,
    LPMErrorTransactionCollisionOrLLProcedureCollision,
    LMPPDUNotAllowed,
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
    ConnectionTerminatedDueToMICFailure,
    ConnectionFailedToBeEstablished,
    MACConnectionFailed,
    CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging,
    Type0SubmapNotDefined,
    UnknownAdvertisingIdentifier,
    LimitReached,
    OperationCancelledByHost,
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            NoError => write!(f, "NoError"),
            Unknown(val) => write!(f, "Unknown Error Code (0x{:X})", val),
            MissingErrorCode => f.write_str("MissingErrorCode"),
            UnknownHCICommand => write!(f, "UnknownHCICommand (0x{:X})", 0x01),
            UnknownConnectionIdentifier => write!(f, "UnknownConnectionIdentifier (0x{:X})", 0x02),
            HardwareFailure => write!(f, "HardwareFailure (0x{:X})", 0x03),
            PageTimeout => write!(f, "PageTimeout (0x{:X})", 0x04),
            AuthenticationFailure => write!(f, "AuthenticationFailure (0x{:X})", 0x05),
            PINorKeyMissing => write!(f, "PINorKeyMissing (0x{:X})", 0x06),
            MemoryCapacityExceeded => write!(f, "MemoryCapacityExceeded (0x{:X})", 0x07),
            ConnectionTimeout => write!(f, "ConnectionTimeout (0x{:X})", 0x08),
            ConnectionLimitExceeded => write!(f, "ConnectionLimitExceeded (0x{:X})", 0x09),
            SynchronousConnectionLimitToADeviceExceeded => {
                write!(f, "SynchronousConnectionLimitToADeviceExceeded (0x{:X})", 0x0a)
            }
            ConnectionAlreadyExists => write!(f, "ConnectionAlreadyExists (0x{:X})", 0x0b),
            CommandDisallowed => write!(f, "CommandDisallowed (0x{:X})", 0x0c),
            ConnectionRejectedDueToLimitedResources => {
                write!(f, "ConnectionRejectedDueToLimitedResources (0x{:X})", 0x0d)
            }
            ConnectionRejectedDueToSecurityReasons => {
                write!(f, "ConnectionRejectedDueToSecurityReasons (0x{:X})", 0x0e)
            }
            ConnectionRejectedDueToUnacceptableBluetoothAddress => {
                write!(f, "ConnectionRejectedDueToUnacceptableBluetoothAddress (0x{:X})", 0x0f)
            }
            ConnectionAcceptTimeoutExceeded => {
                write!(f, "ConnectionAcceptTimeoutExceeded (0x{:X})", 0x10)
            }
            UnsupportedFeatureOrParameterValue => {
                write!(f, "UnsupportedFeatureOrParameterValue (0x{:X})", 0x11)
            }
            InvalidHCICommandParameters => write!(f, "InvalidHCICommandParameters (0x{:X})", 0x12),
            RemoteUserTerminatedConnection => {
                write!(f, "RemoteUserTerminatedConnection (0x{:X})", 0x13)
            }
            RemoteDeviceTerminatedConnectionDueToLowResources => {
                write!(f, "RemoteDeviceTerminatedConnectionDueToLowResources (0x{:X})", 0x14)
            }
            RemoteDeviceTerminatedConnectionDueToPowerOff => {
                write!(f, "RemoteDeviceTerminatedConnectionDueToPowerOff (0x{:X})", 0x15)
            }
            ConnectionTerminatedByLocalHost => {
                write!(f, "ConnectionTerminatedByLocalHost (0x{:X})", 0x16)
            }
            RepeatedAttempts => write!(f, "RepeatedAttempts (0x{:X})", 0x17),
            PairingNotAllowed => write!(f, "PairingNotAllowed (0x{:X})", 0x18),
            UnknownLMPPDU => write!(f, "UnknownLMPPDU (0x{:X})", 0x19),
            UnsupportedRemoteFeatureOrUnsupportedLMPFeature => {
                write!(f, "UnsupportedRemoteFeatureOrUnsupportedLMPFeature (0x{:X})", 0x1a)
            }
            SCOOffsetRejected => write!(f, "SCOOffsetRejected (0x{:X})", 0x1b),
            SCOIntervalRejected => write!(f, "SCOIntervalRejected (0x{:X})", 0x1c),
            SCOAirModeRejected => write!(f, "SCOAirModeRejected (0x{:X})", 0x1d),
            InvalidLMPParametersOrInvalidLLParameters => {
                write!(f, "InvalidLMPParametersOrInvalidLLParameters (0x{:X})", 0x1e)
            }
            UnspecifiedError => write!(f, "UnspecifiedError (0x{:X})", 0x1f),
            UnsupportedLMPParameterValueOrUnsupportedLLParameterValue => write!(
                f,
                "UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue (0x{:X})",
                0x20
            ),
            RoleChangeNotAllowed => write!(f, "RoleChangeNotAllowed (0x{:X})", 0x21),
            LMPResponseTimeoutOrLLResponseTimeout => {
                write!(f, "LMPResponseTimeoutOrLLResponseTimeout (0x{:X})", 0x22)
            }
            LPMErrorTransactionCollisionOrLLProcedureCollision => {
                write!(f, "LPMErrorTransationCollisionOrLLProcedureColision (0x{:X})", 0x23)
            }
            LMPPDUNotAllowed => write!(f, "LMPPDUNotAllowed (0x{:X})", 0x24),
            EncryptionModeNotAcceptable => write!(f, "EncryptionModeNotAcceptable (0x{:X})", 0x25),
            LinkKeyCannotBeChanged => write!(f, "LinkKeyCannotBeChanged (0x{:X})", 0x26),
            RequestedQosNosSupported => write!(f, "RequestedQosNosSupported (0x{:X})", 0x27),
            InstantPassed => write!(f, "InstantPassed (0x{:X})", 0x28),
            PairingWithUnitKeyNotSupported => {
                write!(f, "PairingWithUnitKeyNotSupported (0x{:X})", 0x29)
            }
            DifferentTransactionCollision => {
                write!(f, "DifferentTransactionCollision (0x{:X})", 0x2a)
            }
            QosUnacceptableParameter => write!(f, "QosUnacceptableParameter (0x{:X})", 0x2c),
            QosRejected => write!(f, "QosRejected (0x{:X})", 0x2d),
            ChannelAssessmentNotSupported => {
                write!(f, "ChannelAssessmetNotSupported (0x{:X})", 0x2e)
            }
            InsufficientSecurity => write!(f, "InsufficientSecurity (0x{:X})", 0x2f),
            ParameterOutOfMandatoryRange => write!(f, "ParameterOutOfMandatorRange (0x{:X})", 0x30),
            RoleSwitchPending => write!(f, "RoleSwitchPending (0x{:X})", 0x32),
            ReservedSlotViolation => write!(f, "ReservedSlotViolation (0x{:X})", 0x34),
            RoleSwitchFailed => write!(f, "RoleSwithFailed (0x{:X})", 0x35),
            ExtendedInquiryResponseTooLarge => {
                write!(f, "ExtendedInquiryResponseTooLarge (0x{:X})", 0x36)
            }
            SimplePairingNotSupportedByHost => {
                write!(f, "SimplePairingNotSupportedByHost (0x{:X})", 0x37)
            }
            HostBusyBecausePairing => write!(f, "HostBusyBecausePairing (0x{:X})", 0x38),
            ConnectionRejectedDueToNoSuitableChannelFound => {
                write!(f, "ConnectionRejectedDueToNoSuitableChannelFound (0x{:X})", 0x39)
            }
            ControllerBusy => write!(f, "ControllerBusy (0x{:X})", 0x3a),
            UnacceptableConnectionParameters => {
                write!(f, "UnacceptableConnectionParameters (0x{:X})", 0x3b)
            }
            AdvertisingTimeout => write!(f, "AdvertisingTimeout (0x{:X})", 0x3c),
            ConnectionTerminatedDueToMICFailure => {
                write!(f, "ConnectionTerminatedDueToMICFailure (0x{:X})", 0x3d)
            }
            ConnectionFailedToBeEstablished => {
                write!(f, "ConnectionFailedToBeEstablished (0x{:X})", 0x3e)
            }
            MACConnectionFailed => write!(f, "MACConnectionFailed (0x{:X})", 0x3f),
            CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => write!(
                f,
                "CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging (0x{:X})",
                0x40
            ),
            Type0SubmapNotDefined => write!(f, "Type0SubmapNotDefined (0x{:X})", 0x41),
            UnknownAdvertisingIdentifier => {
                write!(f, "UnknownAdvertisingIdentifier (0x{:X})", 0x42)
            }
            LimitReached => write!(f, "LimitReached (0x{:X})", 0x43),
            OperationCancelledByHost => write!(f, "OperationCancelledByHost (0x{:X})", 0x44),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        macro_rules! ctrl_err {
            ($f:expr, $($arg:tt)*) => {
                f.write_str("controller error: ")?;

                core::write!(f, $($arg)*)?;

                f.write_str(
                    " (see the Bluetooth Core Specification vol 1, part F: Controller Error Codes)")
            }
        }

        match self {
            Error::NoError => f.write_str("no error"),
            Error::Unknown(val) => write!(f, "unknown error code (0x{:X})", val),
            Error::MissingErrorCode => f.write_str("missing error parameter"),
            Error::UnknownHCICommand => f.write_str("unknown HCI command"),
            Error::UnknownConnectionIdentifier => ctrl_err!("unknown connection identifier"),
            Error::HardwareFailure => ctrl_err!("hardware failure"),
            Error::PageTimeout => ctrl_err!("page timeout"),
            Error::AuthenticationFailure => ctrl_err!("authentication failure"),
            Error::PINorKeyMissing => ctrl_err!("PIN or key missing"),
            Error::MemoryCapacityExceeded => ctrl_err!("memory capacity exceeded"),
            Error::ConnectionTimeout => ctrl_err!("connection timeout"),
            Error::ConnectionLimitExceeded => ctrl_err!("connection limit exceeded"),
            Error::SynchronousConnectionLimitToADeviceExceeded => {
                ctrl_err!("synchronous connection limit to a device exceeded")
            }
            Error::ConnectionAlreadyExists => ctrl_err!("connection already exists"),
            Error::CommandDisallowed => ctrl_err!("command disallowed"),
            Error::ConnectionRejectedDueToLimitedResources => {
                ctrl_err!("connection rejected due to limited resources")
            }
            Error::ConnectionRejectedDueToSecurityReasons => ctrl_err!("connection rejected due to security reasons"),
            Error::ConnectionRejectedDueToUnacceptableBluetoothAddress => {
                ctrl_err!("connection rejected due to unacceptable bluetooth address")
            }
            Error::ConnectionAcceptTimeoutExceeded => ctrl_err!("connection accept timeout exceeded"),
            Error::UnsupportedFeatureOrParameterValue => ctrl_err!("unsupported feature or parameter value"),
            Error::InvalidHCICommandParameters => ctrl_err!("invalid hCI command parameters"),
            Error::RemoteUserTerminatedConnection => ctrl_err!("remote user terminated connection"),
            Error::RemoteDeviceTerminatedConnectionDueToLowResources => {
                ctrl_err!("remote device terminated connection due to low resources")
            }
            Error::RemoteDeviceTerminatedConnectionDueToPowerOff => {
                ctrl_err!("remote device terminated connection due to power off")
            }
            Error::ConnectionTerminatedByLocalHost => ctrl_err!("connection terminated by local host"),
            Error::RepeatedAttempts => ctrl_err!("repeated attempts"),
            Error::PairingNotAllowed => ctrl_err!("pairing not allowed"),
            Error::UnknownLMPPDU => ctrl_err!("unknown LMP PDU"),
            Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature => {
                f.write_str("unsupported remote feature / unsupported LMP feature")
            }
            Error::SCOOffsetRejected => ctrl_err!("SCO offset rejected"),
            Error::SCOIntervalRejected => ctrl_err!("SCO interval rejected"),
            Error::SCOAirModeRejected => ctrl_err!("SCO air mode rejected"),
            Error::InvalidLMPParametersOrInvalidLLParameters => {
                f.write_str("invalid LMP parameters / invalid LL parameters")
            }
            Error::UnspecifiedError => ctrl_err!("unspecified error"),
            Error::UnsupportedLMPParameterValueOrUnsupportedLLParameterValue => {
                f.write_str("unsupported LMP parameter value / unsupported LL parameter value")
            }
            Error::RoleChangeNotAllowed => ctrl_err!("role change not allowed"),
            Error::LMPResponseTimeoutOrLLResponseTimeout => f.write_str("LMP response timeout / LL response timeout"),
            Error::LPMErrorTransactionCollisionOrLLProcedureCollision => {
                f.write_str("LPM error transaction collision / LL procedure collision")
            }
            Error::LMPPDUNotAllowed => ctrl_err!("LMP PDU not allowed"),
            Error::EncryptionModeNotAcceptable => ctrl_err!("encryption mode not acceptable"),
            Error::LinkKeyCannotBeChanged => ctrl_err!("link key cannot be changed"),
            Error::RequestedQosNosSupported => ctrl_err!("requested qos nos supported"),
            Error::InstantPassed => ctrl_err!("instant passed"),
            Error::PairingWithUnitKeyNotSupported => ctrl_err!("pairing with unit key not supported"),
            Error::DifferentTransactionCollision => ctrl_err!("different transaction collision"),
            Error::QosUnacceptableParameter => ctrl_err!("qos unacceptable parameter"),
            Error::QosRejected => ctrl_err!("qos rejected"),
            Error::ChannelAssessmentNotSupported => ctrl_err!("channel assessment not supported"),
            Error::InsufficientSecurity => ctrl_err!("insufficient security"),
            Error::ParameterOutOfMandatoryRange => ctrl_err!("parameter out of mandatory range"),
            Error::RoleSwitchPending => ctrl_err!("role switch pending"),
            Error::ReservedSlotViolation => ctrl_err!("reserved slot violation"),
            Error::RoleSwitchFailed => ctrl_err!("role switch failed"),
            Error::ExtendedInquiryResponseTooLarge => ctrl_err!("extended inquiry response too large"),
            Error::SimplePairingNotSupportedByHost => ctrl_err!("simple pairing not supported by host"),
            Error::HostBusyBecausePairing => ctrl_err!("host busy because pairing"),
            Error::ConnectionRejectedDueToNoSuitableChannelFound => {
                ctrl_err!("connection rejected due to no suitable channel found")
            }
            Error::ControllerBusy => ctrl_err!("controller busy"),
            Error::UnacceptableConnectionParameters => ctrl_err!("unacceptable connection parameters"),
            Error::AdvertisingTimeout => ctrl_err!("advertising timeout"),
            Error::ConnectionTerminatedDueToMICFailure => ctrl_err!("connection terminated due to MIC failure"),
            Error::ConnectionFailedToBeEstablished => ctrl_err!("connection failed to be established"),
            Error::MACConnectionFailed => ctrl_err!("MAC connection failed"),
            Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => {
                ctrl_err!("coarse clock adjustment rejected but will try to adjust using clock dragging")
            }
            Error::Type0SubmapNotDefined => f.write_str("type0 sub-map not defined"),
            Error::UnknownAdvertisingIdentifier => ctrl_err!("unknown advertising identifier"),
            Error::LimitReached => ctrl_err!("limit reached"),
            Error::OperationCancelledByHost => ctrl_err!("operation cancelled by host"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<u8> for Error {
    fn from(raw: u8) -> Self {
        use crate::hci::error::Error::*;

        match raw {
            0x00 => Error::NoError,
            0x01 => Error::UnknownHCICommand,
            0x02 => Error::UnknownConnectionIdentifier,
            0x03 => Error::HardwareFailure,
            0x04 => Error::PageTimeout,
            0x05 => Error::AuthenticationFailure,
            0x06 => Error::PINorKeyMissing,
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
            0x12 => Error::InvalidHCICommandParameters,
            0x13 => Error::RemoteUserTerminatedConnection,
            0x14 => Error::RemoteDeviceTerminatedConnectionDueToLowResources,
            0x15 => Error::RemoteDeviceTerminatedConnectionDueToPowerOff,
            0x16 => Error::ConnectionTerminatedByLocalHost,
            0x17 => Error::RepeatedAttempts,
            0x18 => Error::PairingNotAllowed,
            0x19 => Error::UnknownLMPPDU,
            0x1a => Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature,
            0x1b => Error::SCOOffsetRejected,
            0x1c => Error::SCOIntervalRejected,
            0x1d => Error::SCOAirModeRejected,
            0x1e => Error::InvalidLMPParametersOrInvalidLLParameters,
            0x1f => Error::UnspecifiedError,
            0x20 => Error::UnsupportedLMPParameterValueOrUnsupportedLLParameterValue,
            0x21 => Error::RoleChangeNotAllowed,
            0x22 => Error::LMPResponseTimeoutOrLLResponseTimeout,
            0x23 => Error::LPMErrorTransactionCollisionOrLLProcedureCollision,
            0x24 => Error::LMPPDUNotAllowed,
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
            0x3d => Error::ConnectionTerminatedDueToMICFailure,
            0x3e => Error::ConnectionFailedToBeEstablished,
            0x3f => Error::MACConnectionFailed,
            0x40 => Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging,
            0x41 => Error::Type0SubmapNotDefined,
            0x42 => Error::UnknownAdvertisingIdentifier,
            0x43 => Error::LimitReached,
            0x44 => Error::OperationCancelledByHost,
            _ => Error::Unknown(raw),
        }
    }
}

impl From<Error> for u8 {
    fn from(error: Error) -> Self {
        match error {
            Error::NoError | Error::Message(_) => 0x00,
            Error::UnknownHCICommand => 0x01,
            Error::UnknownConnectionIdentifier => 0x02,
            Error::HardwareFailure => 0x03,
            Error::PageTimeout => 0x04,
            Error::AuthenticationFailure => 0x05,
            Error::PINorKeyMissing => 0x06,
            Error::MemoryCapacityExceeded => 0x07,
            Error::ConnectionTimeout => 0x08,
            Error::ConnectionLimitExceeded => 0x09,
            Error::SynchronousConnectionLimitToADeviceExceeded => 0x0a,
            Error::ConnectionAlreadyExists => 0x0b,
            Error::CommandDisallowed => 0x0c,
            Error::ConnectionRejectedDueToLimitedResources => 0x0d,
            Error::ConnectionRejectedDueToSecurityReasons => 0x0e,
            Error::ConnectionRejectedDueToUnacceptableBluetoothAddress => 0x0f,
            Error::ConnectionAcceptTimeoutExceeded => 0x10,
            Error::UnsupportedFeatureOrParameterValue => 0x11,
            Error::InvalidHCICommandParameters => 0x12,
            Error::RemoteUserTerminatedConnection => 0x13,
            Error::RemoteDeviceTerminatedConnectionDueToLowResources => 0x14,
            Error::RemoteDeviceTerminatedConnectionDueToPowerOff => 0x15,
            Error::ConnectionTerminatedByLocalHost => 0x16,
            Error::RepeatedAttempts => 0x17,
            Error::PairingNotAllowed => 0x18,
            Error::UnknownLMPPDU => 0x19,
            Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature => 0x1a,
            Error::SCOOffsetRejected => 0x1b,
            Error::SCOIntervalRejected => 0x1c,
            Error::SCOAirModeRejected => 0x1d,
            Error::InvalidLMPParametersOrInvalidLLParameters => 0x1e,
            Error::UnspecifiedError => 0x1f,
            Error::UnsupportedLMPParameterValueOrUnsupportedLLParameterValue => 0x20,
            Error::RoleChangeNotAllowed => 0x21,
            Error::LMPResponseTimeoutOrLLResponseTimeout => 0x22,
            Error::LPMErrorTransactionCollisionOrLLProcedureCollision => 0x23,
            Error::LMPPDUNotAllowed => 0x24,
            Error::EncryptionModeNotAcceptable => 0x25,
            Error::LinkKeyCannotBeChanged => 0x26,
            Error::RequestedQosNosSupported => 0x27,
            Error::InstantPassed => 0x28,
            Error::PairingWithUnitKeyNotSupported => 0x29,
            Error::DifferentTransactionCollision => 0x2a,
            Error::QosUnacceptableParameter => 0x2c,
            Error::QosRejected => 0x2d,
            Error::ChannelAssessmentNotSupported => 0x2e,
            Error::InsufficientSecurity => 0x2f,
            Error::ParameterOutOfMandatoryRange => 0x30,
            Error::RoleSwitchPending => 0x32,
            Error::ReservedSlotViolation => 0x34,
            Error::RoleSwitchFailed => 0x35,
            Error::ExtendedInquiryResponseTooLarge => 0x36,
            Error::SimplePairingNotSupportedByHost => 0x37,
            Error::HostBusyBecausePairing => 0x38,
            Error::ConnectionRejectedDueToNoSuitableChannelFound => 0x39,
            Error::ControllerBusy => 0x3a,
            Error::UnacceptableConnectionParameters => 0x3b,
            Error::AdvertisingTimeout => 0x3c,
            Error::ConnectionTerminatedDueToMICFailure => 0x3d,
            Error::ConnectionFailedToBeEstablished => 0x3e,
            Error::MACConnectionFailed => 0x3f,
            Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging => 0x40,
            Error::Type0SubmapNotDefined => 0x41,
            Error::UnknownAdvertisingIdentifier => 0x42,
            Error::LimitReached => 0x43,
            Error::OperationCancelledByHost => 0x44,
            Error::Unknown(v) => v,
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
