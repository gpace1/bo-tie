//! Host Controller Interface errors
//!
//! These are the HCI errors that can be generated by the controller as listed in Vol 2 Part D of
//! the Bluetooth v5.0 Specification

use core::fmt::{Debug, Display, Formatter, Result};

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Error {

    /// NoError is not part of the official error list in the Bluetooth Spec (v5 | Vol 2, Part D
    /// Sect 2). Its just a placeholder for when there is no error generated
    NoError,
    /// When an unknown error code is received.
    Unknown(u8),
    /// A bo-tie specific or HCI related error message that is not an error code from the Controller
    Message(&'static str),

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
    UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue,
    RoleChangeNotAllowed,
    LMPResponseTimeoutOrLLResponseTimeout,
    LPMErrorTransationCollisionOrLLProcedureColision,
    LMPPDUNotAllowed,
    EncryptionModeNotAcceptable,
    LinkKeyCannotBeChanged,
    RequestedQosNosSupported,
    InstantPassed,
    PairingWithUnitKeyNotSupported,
    DifferentTransactionCollision,
    QosUnacceptableParameter,
    QosRejected,
    ChannelAssessmetNotSupported,
    InsufficientSecurity,
    ParameterOutOfMandatorRange,
    RoleSwitchPending,
    ReservedSlotViolation,
    RoleSwithFailed,
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

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Error {
        Error::Message(msg)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::Error::*;

        match *self {
            NoError => write!(f, "NoError"),
            Unknown(val) => write!(f, "Unknown Error Code (0x{:X})", val),
            Message(msg) => write!(f, "{}", msg),
            UnknownHCICommand => write!(f, "UnknownHCICommand (0x{:X})", 0x01),
            UnknownConnectionIdentifier => write!(f, "UnknownConnectionIdentifier (0x{:X})", 0x02),
            HardwareFailure => write!(f, "HardwareFailure (0x{:X})", 0x03),
            PageTimeout => write!(f, "PageTimeout (0x{:X})", 0x04),
            AuthenticationFailure => write!(f, "AuthenticationFailure (0x{:X})", 0x05),
            PINorKeyMissing => write!(f, "PINorKeyMissing (0x{:X})", 0x06),
            MemoryCapacityExceeded => write!(f, "MemoryCapacityExceeded (0x{:X})", 0x07),
            ConnectionTimeout => write!(f, "ConnectionTimeout (0x{:X})", 0x08),
            ConnectionLimitExceeded => write!(f, "ConnectionLimitExceeded (0x{:X})", 0x09),
            SynchronousConnectionLimitToADeviceExceeded => write!(
                f,
                "SynchronousConnectionLimitToADeviceExceeded (0x{:X})",
                0x0a
            ),
            ConnectionAlreadyExists => write!(f, "ConnectionAlreadyExists (0x{:X})", 0x0b),
            CommandDisallowed => write!(f, "CommandDisallowed (0x{:X})", 0x0c),
            ConnectionRejectedDueToLimitedResources => {
                write!(f, "ConnectionRejectedDueToLimitedResources (0x{:X})", 0x0d)
            }
            ConnectionRejectedDueToSecurityReasons => {
                write!(f, "ConnectionRejectedDueToSecurityReasons (0x{:X})", 0x0e)
            }
            ConnectionRejectedDueToUnacceptableBluetoothAddress => write!(
                f,
                "ConnectionRejectedDueToUnacceptableBluetoothAddress (0x{:X})",
                0x0f
            ),
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
            RemoteDeviceTerminatedConnectionDueToLowResources => write!(
                f,
                "RemoteDeviceTerminatedConnectionDueToLowResources (0x{:X})",
                0x14
            ),
            RemoteDeviceTerminatedConnectionDueToPowerOff => write!(
                f,
                "RemoteDeviceTerminatedConnectionDueToPowerOff (0x{:X})",
                0x15
            ),
            ConnectionTerminatedByLocalHost => {
                write!(f, "ConnectionTerminatedByLocalHost (0x{:X})", 0x16)
            }
            RepeatedAttempts => write!(f, "RepeatedAttempts (0x{:X})", 0x17),
            PairingNotAllowed => write!(f, "PairingNotAllowed (0x{:X})", 0x18),
            UnknownLMPPDU => write!(f, "UnknownLMPPDU (0x{:X})", 0x19),
            UnsupportedRemoteFeatureOrUnsupportedLMPFeature => write!(
                f,
                "UnsupportedRemoteFeatureOrUnsupportedLMPFeature (0x{:X})",
                0x1a
            ),
            SCOOffsetRejected => write!(f, "SCOOffsetRejected (0x{:X})", 0x1b),
            SCOIntervalRejected => write!(f, "SCOIntervalRejected (0x{:X})", 0x1c),
            SCOAirModeRejected => write!(f, "SCOAirModeRejected (0x{:X})", 0x1d),
            InvalidLMPParametersOrInvalidLLParameters => write!(
                f,
                "InvalidLMPParametersOrInvalidLLParameters (0x{:X})",
                0x1e
            ),
            UnspecifiedError => write!(f, "UnspecifiedError (0x{:X})", 0x1f),
            UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue => write!(
                f,
                "UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue (0x{:X})",
                0x20
            ),
            RoleChangeNotAllowed => write!(f, "RoleChangeNotAllowed (0x{:X})", 0x21),
            LMPResponseTimeoutOrLLResponseTimeout => {
                write!(f, "LMPResponseTimeoutOrLLResponseTimeout (0x{:X})", 0x22)
            }
            LPMErrorTransationCollisionOrLLProcedureColision => write!(
                f,
                "LPMErrorTransationCollisionOrLLProcedureColision (0x{:X})",
                0x23
            ),
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
            ChannelAssessmetNotSupported => {
                write!(f, "ChannelAssessmetNotSupported (0x{:X})", 0x2e)
            }
            InsufficientSecurity => write!(f, "InsufficientSecurity (0x{:X})", 0x2f),
            ParameterOutOfMandatorRange => write!(f, "ParameterOutOfMandatorRange (0x{:X})", 0x30),
            RoleSwitchPending => write!(f, "RoleSwitchPending (0x{:X})", 0x32),
            ReservedSlotViolation => write!(f, "ReservedSlotViolation (0x{:X})", 0x34),
            RoleSwithFailed => write!(f, "RoleSwithFailed (0x{:X})", 0x35),
            ExtendedInquiryResponseTooLarge => {
                write!(f, "ExtendedInquiryResponseTooLarge (0x{:X})", 0x36)
            }
            SimplePairingNotSupportedByHost => {
                write!(f, "SimplePairingNotSupportedByHost (0x{:X})", 0x37)
            }
            HostBusyBecausePairing => write!(f, "HostBusyBecausePairing (0x{:X})", 0x38),
            ConnectionRejectedDueToNoSuitableChannelFound => write!(
                f,
                "ConnectionRejectedDueToNoSuitableChannelFound (0x{:X})",
                0x39
            ),
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

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "HCI Error: {}. See the error code section of the Bluetooth Specification \
            (Version 5, Vol 2, Part D) for more information",
            match self {
                Error::NoError => {
                    // This isn't part of the bluetooth spec and is used to indicate no error
                    return write!(f, "No Error");
                }
                Error::Unknown(val) => {
                    return write!(f, "Unknown Error Code (0x{:X})", val)
                }
                Error::Message(msg) => {
                    return write!(f, "{}", msg)
                }
                Error::UnknownHCICommand =>
                    "Unknown HCI Command",
                Error::UnknownConnectionIdentifier =>
                    "Unknown Connection Identifier",
                Error::HardwareFailure =>
                    "Hardware Failure",
                Error::PageTimeout =>
                    "Page Timeout",
                Error::AuthenticationFailure =>
                    "Authentication Failure",
                Error::PINorKeyMissing =>
                    "PIN or Key Missing",
                Error::MemoryCapacityExceeded =>
                    "Memory Capacity Exceeded",
                Error::ConnectionTimeout =>
                    "Connection Timeout",
                Error::ConnectionLimitExceeded =>
                    "Connection Limit Exceeded",
                Error::SynchronousConnectionLimitToADeviceExceeded =>
                    "Synchronous Connection Limit To A Device Exceeded",
                Error::ConnectionAlreadyExists =>
                    "Connection Already Exists",
                Error::CommandDisallowed =>
                    "Command Disallowed",
                Error::ConnectionRejectedDueToLimitedResources =>
                    "Connection Rejected Due To Limited Resources",
                Error::ConnectionRejectedDueToSecurityReasons =>
                    "Connection Rejected Due To Security Reasons",
                Error::ConnectionRejectedDueToUnacceptableBluetoothAddress =>
                    "Connection Rejected Due To Unacceptable Bluetooth Address",
                Error::ConnectionAcceptTimeoutExceeded =>
                    "Connection Accept Timeout Exceeded",
                Error::UnsupportedFeatureOrParameterValue =>
                    "Unsupported Feature Or Parameter Value",
                Error::InvalidHCICommandParameters =>
                    "Invalid HCI Command Parameters",
                Error::RemoteUserTerminatedConnection =>
                    "Remote User Terminated Connection",
                Error::RemoteDeviceTerminatedConnectionDueToLowResources =>
                    "Remote Device Terminated Connection Due To Low Resources",
                Error::RemoteDeviceTerminatedConnectionDueToPowerOff =>
                    "Remote Device Terminated Connection Due To Power Off",
                Error::ConnectionTerminatedByLocalHost =>
                    "Connection Terminated By Local Host",
                Error::RepeatedAttempts =>
                    "Repeated Attempts",
                Error::PairingNotAllowed =>
                    "Pairing Not Allowed",
                Error::UnknownLMPPDU =>
                    "Unknown LMP PDU",
                Error::UnsupportedRemoteFeatureOrUnsupportedLMPFeature =>
                    "Unsupported Remote Feature / Unsupported LMP Feature",
                Error::SCOOffsetRejected =>
                    "SCO Offset Rejected",
                Error::SCOIntervalRejected =>
                    "SCO Interval Rejected",
                Error::SCOAirModeRejected =>
                    "SCO Air Mode Rejected",
                Error::InvalidLMPParametersOrInvalidLLParameters =>
                    "Invalid LMP Parameters / Invalid LL Parameters",
                Error::UnspecifiedError =>
                    "Unspecified Error",
                Error::UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue =>
                    "Unspported LMP Parameter Value / Unsupported LL Parameter V Alue",
                Error::RoleChangeNotAllowed =>
                    "Role Change Not Allowed",
                Error::LMPResponseTimeoutOrLLResponseTimeout =>
                    "LMP Response Timeout / LL Response Timeout",
                Error::LPMErrorTransationCollisionOrLLProcedureColision =>
                    "LPM Error Transation Collision / LL Procedure Colision",
                Error::LMPPDUNotAllowed =>
                    "LMP PDU Not Allowed",
                Error::EncryptionModeNotAcceptable =>
                    "Encryption Mode Not Acceptable",
                Error::LinkKeyCannotBeChanged =>
                    "Link Key Cannot Be Changed",
                Error::RequestedQosNosSupported =>
                    "Requested Qos Nos Supported",
                Error::InstantPassed =>
                    "Instant Passed",
                Error::PairingWithUnitKeyNotSupported =>
                    "Pairing With Unit Key Not Supported",
                Error::DifferentTransactionCollision =>
                    "Different Transaction Collision",
                Error::QosUnacceptableParameter =>
                    "Qos Unacceptable Parameter",
                Error::QosRejected =>
                    "Qos Rejected",
                Error::ChannelAssessmetNotSupported =>
                    "Channel Assessmet Not Supported",
                Error::InsufficientSecurity =>
                    "Insufficient Security",
                Error::ParameterOutOfMandatorRange =>
                    "Parameter Out Of Mandator Range",
                Error::RoleSwitchPending =>
                    "Role Switch Pending",
                Error::ReservedSlotViolation =>
                    "Reserved Slot Violation",
                Error::RoleSwithFailed =>
                    "Role Swith Failed",
                Error::ExtendedInquiryResponseTooLarge =>
                    "Extended Inquiry Response Too Large",
                Error::SimplePairingNotSupportedByHost =>
                    "Simple Pairing Not Supported By Host",
                Error::HostBusyBecausePairing =>
                    "Host Busy Because Pairing",
                Error::ConnectionRejectedDueToNoSuitableChannelFound =>
                    "Connection Rejected Due To No Suitable Channel Found",
                Error::ControllerBusy =>
                    "Controller Busy",
                Error::UnacceptableConnectionParameters =>
                    "Unacceptable Connection Parameters",
                Error::AdvertisingTimeout =>
                    "Advertising Timeout",
                Error::ConnectionTerminatedDueToMICFailure =>
                    "Connection Terminated Due To MIC Failure",
                Error::ConnectionFailedToBeEstablished =>
                    "Connection Failed To Be Established",
                Error::MACConnectionFailed =>
                    "MAC Connection Failed",
                Error::CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging =>
                    "Coarse Clock Adjustment Rejected But Will Try To Adjust Using Clock Dragging",
                Error::Type0SubmapNotDefined =>
                    "Type0 Submap Not Defined",
                Error::UnknownAdvertisingIdentifier =>
                    "Unknown Advertising Identifier",
                Error::LimitReached =>
                    "Limit Reached",
                Error::OperationCancelledByHost =>
                    "Operation Cancelled By Host",
            }
        )
    }
}

impl core::convert::From<u8> for Error {

    fn from(raw: u8) -> Self {
        use crate::hci::error::Error::*;

        match raw {
            0x00 => NoError,
            0x01 => UnknownHCICommand,
            0x02 => UnknownConnectionIdentifier,
            0x03 => HardwareFailure,
            0x04 => PageTimeout,
            0x05 => AuthenticationFailure,
            0x06 => PINorKeyMissing,
            0x07 => MemoryCapacityExceeded,
            0x08 => ConnectionTimeout,
            0x09 => ConnectionLimitExceeded,
            0x0a => SynchronousConnectionLimitToADeviceExceeded,
            0x0b => ConnectionAlreadyExists,
            0x0c => CommandDisallowed,
            0x0d => ConnectionRejectedDueToLimitedResources,
            0x0e => ConnectionRejectedDueToSecurityReasons,
            0x0f => ConnectionRejectedDueToUnacceptableBluetoothAddress,
            0x10 => ConnectionAcceptTimeoutExceeded,
            0x11 => UnsupportedFeatureOrParameterValue,
            0x12 => InvalidHCICommandParameters,
            0x13 => RemoteUserTerminatedConnection,
            0x14 => RemoteDeviceTerminatedConnectionDueToLowResources,
            0x15 => RemoteDeviceTerminatedConnectionDueToPowerOff,
            0x16 => ConnectionTerminatedByLocalHost,
            0x17 => RepeatedAttempts,
            0x18 => PairingNotAllowed,
            0x19 => UnknownLMPPDU,
            0x1a => UnsupportedRemoteFeatureOrUnsupportedLMPFeature,
            0x1b => SCOOffsetRejected,
            0x1c => SCOIntervalRejected,
            0x1d => SCOAirModeRejected,
            0x1e => InvalidLMPParametersOrInvalidLLParameters,
            0x1f => UnspecifiedError,
            0x20 => UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue,
            0x21 => RoleChangeNotAllowed,
            0x22 => LMPResponseTimeoutOrLLResponseTimeout,
            0x23 => LPMErrorTransationCollisionOrLLProcedureColision,
            0x24 => LMPPDUNotAllowed,
            0x25 => EncryptionModeNotAcceptable,
            0x26 => LinkKeyCannotBeChanged,
            0x27 => RequestedQosNosSupported,
            0x28 => InstantPassed,
            0x29 => PairingWithUnitKeyNotSupported,
            0x2a => DifferentTransactionCollision,
            0x2c => QosUnacceptableParameter,
            0x2d => QosRejected,
            0x2e => ChannelAssessmetNotSupported,
            0x2f => InsufficientSecurity,
            0x30 => ParameterOutOfMandatorRange,
            0x32 => RoleSwitchPending,
            0x34 => ReservedSlotViolation,
            0x35 => RoleSwithFailed,
            0x36 => ExtendedInquiryResponseTooLarge,
            0x37 => SimplePairingNotSupportedByHost,
            0x38 => HostBusyBecausePairing,
            0x39 => ConnectionRejectedDueToNoSuitableChannelFound,
            0x3a => ControllerBusy,
            0x3b => UnacceptableConnectionParameters,
            0x3c => AdvertisingTimeout,
            0x3d => ConnectionTerminatedDueToMICFailure,
            0x3e => ConnectionFailedToBeEstablished,
            0x3f => MACConnectionFailed,
            0x40 => CoarseClockAdjustmentRejectedButWillTryToAdjustUsingClockDragging,
            0x41 => Type0SubmapNotDefined,
            0x42 => UnknownAdvertisingIdentifier,
            0x43 => LimitReached,
            0x44 => OperationCancelledByHost,
               _ => Unknown(raw),
        }
    }
}

impl core::convert::From<Error> for u8 {
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
            Error::UnspportedLMPParameterValueOrUnsupportedLLParameterVAlue => 0x20,
            Error::RoleChangeNotAllowed => 0x21,
            Error::LMPResponseTimeoutOrLLResponseTimeout => 0x22,
            Error::LPMErrorTransationCollisionOrLLProcedureColision => 0x23,
            Error::LMPPDUNotAllowed => 0x24,
            Error::EncryptionModeNotAcceptable => 0x25,
            Error::LinkKeyCannotBeChanged => 0x26,
            Error::RequestedQosNosSupported => 0x27,
            Error::InstantPassed => 0x28,
            Error::PairingWithUnitKeyNotSupported => 0x29,
            Error::DifferentTransactionCollision => 0x2a,
            Error::QosUnacceptableParameter => 0x2c,
            Error::QosRejected => 0x2d,
            Error::ChannelAssessmetNotSupported => 0x2e,
            Error::InsufficientSecurity => 0x2f,
            Error::ParameterOutOfMandatorRange => 0x30,
            Error::RoleSwitchPending => 0x32,
            Error::ReservedSlotViolation => 0x34,
            Error::RoleSwithFailed => 0x35,
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
