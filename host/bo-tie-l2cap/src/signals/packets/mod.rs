//! Definitions of L2CAP signaling packets

mod iter;

use crate::channel::id::{AclCid, ChannelIdentifier, LeCid};
use crate::pdu::control_frame::ControlFrame;
use crate::signals::{SignalError, TryIntoSignal};
use core::fmt::{self, Display, Formatter};
use core::num::NonZeroU8;

macro_rules! max_u16 {
    ($( #[ $doc:meta ], )* $name:ident, $min:literal) => {
        max_u16! {
            $( # [ $doc ], )* ;
            #[doc = "create a new `"],
            #[doc = stringify!($name)],
            #[doc = "`\n"],
            #[doc = "\n"],
            #[doc = "# Panic\n"],
            #[doc = "This will panic if `val` is less than "],
            #[doc = stringify!($min)],
            #[doc = "."],
            $name,
            65535, // a.k.a. <u16>::MAX
            $min
        }
    };

    ($( #[ $doc:meta ], )* $name:ident, $max:literal, $min:literal) => {
        max_u16! {
            $( # [ $doc ], )* ;
            #[doc = "create a new `"],
            #[doc = stringify!($name)],
            #[doc = "`\n"],
            #[doc = "\n"],
            #[doc = "# Panic\n"],
            #[doc = "This will panic if `val` is greater than "],
            #[doc = stringify!($max)],
            #[doc = " or less than "],
            #[doc = stringify!($min)],
            #[doc = "."],
            $name,
            $max,
            $min
        }
    };

    ($( #[ $def_doc:meta ], )* ; $( #[ $new_doc:meta ], )* $name:ident, $max:literal, $min:literal) => {
        $( # [ $def_doc ] )*
        #[derive(Clone, Copy, Debug)]
        pub struct $name {
            val: u16,
        }

        impl $name {
            $( # [ $new_doc ] )*
            #[allow(unused_comparisons)]
            pub fn new(val: u16) -> Self {
                match Self::try_new(val) {
                    Ok(this) => this,
                    Err(e) => panic!("{e}")
                }
            }

            #[doc = "Try to create a new `"]
            #[doc = stringify!($name)]
            #[doc = "`\n"]
            #[doc = "\n"]
            #[doc = "# Error"]
            #[doc = "An error is returned if the panic condition as stated for method [`new`] "]
            #[doc = "were to occur\n"]
            #[doc = "\n"]
            #[doc = "[`new`]: "]
            #[doc = stringify!($new)]
            #[doc = "::new"]
            pub fn try_new(val: u16) -> Result<Self, BoundsError> {
                #[allow(unused_comparisons)]
                if val > $max {
                    Err(BoundsError::TooLarge(stringify!($name), stringify!($max)))
                } else if val < $min {
                    Err(BoundsError::TooSmall(stringify!($name), stringify!($min)))
                } else {
                    Ok($name { val })
                }
            }

            /// Convert into the inner value
            pub fn into_inner(self) -> u16 {
                self.val
            }

            /// Get the value
            pub fn get(&self) -> u16 {
                self.val
            }
        }

        impl core::ops::Deref for $name {
            type Target = u16;

            fn deref(&self) -> &Self::Target {
                &self.val
            }
        }

        impl<T: Into<u16>> From<T> for $name {
            fn from(val: T) -> Self {
                $name::new(val.into())
            }
        }


    }
}

/// Codes for each Signal Type
///
/// This is the enum of the different signaling codes within L2CAP.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum SignalCode {
    CommandRejectResponse,
    ConnectionRequest,
    ConnectionResponse,
    ConfigurationRequest,
    ConfigurationResponse,
    DisconnectionRequest,
    DisconnectionResponse,
    EchoRequest,
    EchoResponse,
    InformationRequest,
    InformationResponse,
    ConnectionParameterUpdateRequest,
    ConnectionParameterUpdateResponse,
    LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse,
    FlowControlCreditIndication,
    CreditBasedConnectionRequest,
    CreditBasedConnectionResponse,
    CreditBasedReconfigureRequest,
    CreditBasedReconfigureResponse,
}

impl SignalCode {
    /// Get the raw code value of the Signal
    pub fn into_code(self) -> u8 {
        match self {
            SignalCode::CommandRejectResponse => 0x1,
            SignalCode::ConnectionRequest => 0x2,
            SignalCode::ConnectionResponse => 0x3,
            SignalCode::ConfigurationRequest => 0x4,
            SignalCode::ConfigurationResponse => 0x5,
            SignalCode::DisconnectionRequest => 0x6,
            SignalCode::DisconnectionResponse => 0x7,
            SignalCode::EchoRequest => 0x8,
            SignalCode::EchoResponse => 0x9,
            SignalCode::InformationRequest => 0xa,
            SignalCode::InformationResponse => 0xb,
            SignalCode::ConnectionParameterUpdateRequest => 0x12,
            SignalCode::ConnectionParameterUpdateResponse => 0x13,
            SignalCode::LeCreditBasedConnectionRequest => 0x14,
            SignalCode::LeCreditBasedConnectionResponse => 0x15,
            SignalCode::FlowControlCreditIndication => 0x16,
            SignalCode::CreditBasedConnectionRequest => 0x17,
            SignalCode::CreditBasedConnectionResponse => 0x18,
            SignalCode::CreditBasedReconfigureRequest => 0x19,
            SignalCode::CreditBasedReconfigureResponse => 0x1a,
        }
    }

    /// Create a `SignalCode` from the raw code value
    pub fn try_from_code(val: u8) -> Result<Self, InvalidSignalCode> {
        match val {
            0x1 => Ok(SignalCode::CommandRejectResponse),
            0x2 => Ok(SignalCode::ConnectionRequest),
            0x3 => Ok(SignalCode::ConnectionResponse),
            0x4 => Ok(SignalCode::ConfigurationRequest),
            0x5 => Ok(SignalCode::ConfigurationResponse),
            0x6 => Ok(SignalCode::DisconnectionRequest),
            0x7 => Ok(SignalCode::DisconnectionResponse),
            0x8 => Ok(SignalCode::EchoRequest),
            0x9 => Ok(SignalCode::EchoResponse),
            0xa => Ok(SignalCode::InformationRequest),
            0xb => Ok(SignalCode::InformationResponse),
            0x12 => Ok(SignalCode::ConnectionParameterUpdateRequest),
            0x13 => Ok(SignalCode::ConnectionParameterUpdateResponse),
            0x14 => Ok(SignalCode::LeCreditBasedConnectionRequest),
            0x15 => Ok(SignalCode::LeCreditBasedConnectionResponse),
            0x16 => Ok(SignalCode::FlowControlCreditIndication),
            0x17 => Ok(SignalCode::CreditBasedConnectionRequest),
            0x18 => Ok(SignalCode::CreditBasedConnectionResponse),
            0x19 => Ok(SignalCode::CreditBasedReconfigureRequest),
            0x1a => Ok(SignalCode::CreditBasedReconfigureResponse),
            _ => Err(InvalidSignalCode(val)),
        }
    }

    /// Check if the code is used by the ACL-U signaling channel
    pub fn used_by_acl_u(&self) -> bool {
        match self {
            Self::CommandRejectResponse
            | Self::ConnectionRequest
            | Self::ConnectionResponse
            | Self::ConfigurationRequest
            | Self::ConfigurationResponse
            | Self::DisconnectionRequest
            | Self::DisconnectionResponse
            | Self::EchoRequest
            | Self::EchoResponse
            | Self::InformationRequest
            | Self::InformationResponse
            | Self::FlowControlCreditIndication
            | Self::CreditBasedConnectionRequest
            | Self::CreditBasedConnectionResponse
            | Self::CreditBasedReconfigureRequest
            | Self::CreditBasedReconfigureResponse => true,
            Self::ConnectionParameterUpdateRequest
            | Self::ConnectionParameterUpdateResponse
            | Self::LeCreditBasedConnectionRequest
            | Self::LeCreditBasedConnectionResponse => false,
        }
    }

    /// Check if the code is used by the LE-U signaling channel
    pub fn used_by_le_u(&self) -> bool {
        match self {
            Self::ConnectionRequest
            | Self::ConnectionResponse
            | Self::ConfigurationRequest
            | Self::ConfigurationResponse
            | Self::EchoRequest
            | Self::EchoResponse
            | Self::InformationRequest
            | Self::InformationResponse => false,
            Self::CommandRejectResponse
            | Self::DisconnectionRequest
            | Self::DisconnectionResponse
            | Self::ConnectionParameterUpdateRequest
            | Self::ConnectionParameterUpdateResponse
            | Self::LeCreditBasedConnectionRequest
            | Self::LeCreditBasedConnectionResponse
            | Self::FlowControlCreditIndication
            | Self::CreditBasedConnectionRequest
            | Self::CreditBasedConnectionResponse
            | Self::CreditBasedReconfigureRequest
            | Self::CreditBasedReconfigureResponse => true,
        }
    }
}

impl Display for SignalCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("L2CAP ")?;

        match self {
            SignalCode::CommandRejectResponse => f.write_str("command reject response"),
            SignalCode::ConnectionRequest => f.write_str("connection request"),
            SignalCode::ConnectionResponse => f.write_str("connection response"),
            SignalCode::ConfigurationRequest => f.write_str("configuration request"),
            SignalCode::ConfigurationResponse => f.write_str("configuration response"),
            SignalCode::DisconnectionRequest => f.write_str("disconnection request"),
            SignalCode::DisconnectionResponse => f.write_str("disconnection response"),
            SignalCode::EchoRequest => f.write_str("echo request"),
            SignalCode::EchoResponse => f.write_str("echo response"),
            SignalCode::InformationRequest => f.write_str("information request"),
            SignalCode::InformationResponse => f.write_str("information response"),
            SignalCode::ConnectionParameterUpdateRequest => f.write_str("connection parameter update request"),
            SignalCode::ConnectionParameterUpdateResponse => f.write_str("connection parameter update response"),
            SignalCode::LeCreditBasedConnectionRequest => f.write_str("LE credit based connection request"),
            SignalCode::LeCreditBasedConnectionResponse => f.write_str("LE credit based connection response"),
            SignalCode::FlowControlCreditIndication => f.write_str("flow control credit indication"),
            SignalCode::CreditBasedConnectionRequest => f.write_str("credit based connection request"),
            SignalCode::CreditBasedConnectionResponse => f.write_str("credit based connection response"),
            SignalCode::CreditBasedReconfigureRequest => f.write_str("credit based reconfigure request"),
            SignalCode::CreditBasedReconfigureResponse => f.write_str("credit based reconfigure response"),
        }
    }
}

impl From<SignalCode> for u8 {
    fn from(code: SignalCode) -> Self {
        code.into_code()
    }
}

impl TryFrom<u8> for SignalCode {
    type Error = InvalidSignalCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        SignalCode::try_from_code(value)
    }
}

/// Error for an invalid signal code
#[derive(Debug, Copy, Clone)]
pub struct InvalidSignalCode(u8);

impl Display for InvalidSignalCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "code {} is not a valid L2CAP signal packet type", self.0)
    }
}

/// Trait for a Signal
///
/// Every signal implements this trait.
pub trait Signal {
    /// Get the code for the signal
    fn get_code(&self) -> SignalCode;

    /// Get the identifier within the signal packet.
    fn get_identifier(&self) -> NonZeroU8;

    /// Get the *Data Length* field of the signal packet
    fn get_data_length(&self) -> u16;
}

/// Trait for signals that dynamically allocate channels
///
/// Signals that handle tye dynamic allocation of channels implement this trait.
pub trait SignalWithDynChannel {
    /// Get the local channel
    ///
    /// This will return the local channel identifier if it exists for this signal.
    fn get_local_cid(&self) -> Option<ChannelIdentifier>;

    /// Get the remote channel
    ///
    /// This will return the remote channel identifier if it exists for this signal.
    fn get_remote_cid(&self) -> Option<ChannelIdentifier>;
}

/// Command Rejection Reason
///
/// This is an enum of the *Reason* field within the command reject response signaling packet
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum CommandRejectReason {
    CommandNotUnderstood,
    SignalingMtuExceeded,
    InvalidCidInRequest,
}

impl CommandRejectReason {
    /// Convert to the value
    fn into_val(self) -> u16 {
        match self {
            CommandRejectReason::CommandNotUnderstood => 0x0u16,
            CommandRejectReason::SignalingMtuExceeded => 0x1u16,
            CommandRejectReason::InvalidCidInRequest => 0x2u16,
        }
    }

    /// Convert from the value
    fn try_from_value(value: u16) -> Result<Self, InvalidCommandRejectReason> {
        match value {
            0 => Ok(CommandRejectReason::CommandNotUnderstood),
            1 => Ok(CommandRejectReason::SignalingMtuExceeded),
            2 => Ok(CommandRejectReason::InvalidCidInRequest),
            _ => Err(InvalidCommandRejectReason(value)),
        }
    }
}

impl From<CommandRejectReason> for u16 {
    fn from(reason: CommandRejectReason) -> Self {
        reason.into_val()
    }
}

impl TryFrom<u16> for CommandRejectReason {
    type Error = InvalidCommandRejectReason;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from_value(value)
    }
}

/// Error for an invalid `CommandRejectReason` value
#[derive(Debug, Copy, Clone)]
pub struct InvalidCommandRejectReason(u16);

impl Display for InvalidCommandRejectReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "value {} is not a valid command reject reason", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCommandRejectReason {}

/// The *reason data* for a command rejection
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CommandRejectReasonData {
    None,
    Mtu(u16),
    RequestedCid(u16, u16),
}

impl CommandRejectReasonData {
    fn len(&self) -> usize {
        match self {
            CommandRejectReasonData::None => 0,
            CommandRejectReasonData::Mtu(_) => 2,
            CommandRejectReasonData::RequestedCid(_, _) => 4,
        }
    }

    fn iter_pos(&self, pos: usize) -> Option<u8> {
        match self {
            CommandRejectReasonData::None => None,
            CommandRejectReasonData::Mtu(mtu) => match pos {
                0 => mtu.to_le_bytes().get(0).copied(),
                1 => mtu.to_le_bytes().get(1).copied(),
                _ => None,
            },
            CommandRejectReasonData::RequestedCid(local, remote) => match pos {
                0 => local.to_le_bytes().get(0).copied(),
                1 => local.to_le_bytes().get(1).copied(),
                2 => remote.to_le_bytes().get(0).copied(),
                3 => remote.to_le_bytes().get(1).copied(),
                _ => None,
            },
        }
    }

    fn try_from_slice(s: &[u8]) -> Result<Self, CommandRejectReasonDataError> {
        match s.len() {
            0 => Ok(CommandRejectReasonData::None),
            2 => Ok(CommandRejectReasonData::Mtu(<u16>::from_le_bytes([s[0], s[1]]))),
            4 => Ok(CommandRejectReasonData::RequestedCid(
                <u16>::from_le_bytes([s[0], s[1]]),
                <u16>::from_le_bytes([s[2], s[3]]),
            )),
            _ => Err(CommandRejectReasonDataError::InvalidSize),
        }
    }
}

/// Error for an invalid `CommandRejectReasonData`
#[derive(Debug, Copy, Clone)]
pub enum CommandRejectReasonDataError {
    InvalidSize,
}

impl Display for CommandRejectReasonDataError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidSize => f.write_str("reason data has an invalid size"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CommandRejectReasonDataError {}

/// Command Rejection Response
///
/// This L2CAP signal packet is sent when a device rejects a received request signal.
#[derive(Debug, Copy, Clone)]
pub struct CommandRejectResponse {
    identifier: NonZeroU8,
    reason: CommandRejectReason,
    data: CommandRejectReasonData,
}

impl CommandRejectResponse {
    const CODE: u8 = 0x1;

    /// Create a `CommandRejectResponse` for a signalling command that could not be understood
    ///
    /// This is used whenever a signal containing a value in the code field that is not supported by
    /// this device.
    ///
    /// Set input `rejected_signal` to an `Err( /*code*/ )` for an unknown signal code.
    pub fn new_command_not_understood(identifier: NonZeroU8) -> Self {
        CommandRejectResponse {
            identifier,
            reason: CommandRejectReason::CommandNotUnderstood,
            data: CommandRejectReasonData::None,
        }
    }

    /// Create a `CommandRejectResponse` for a signalling command that exceeded the MTU
    pub fn new_signaling_mtu_exceeded(identifier: NonZeroU8, actual_mtu: u16) -> Self {
        CommandRejectResponse {
            identifier,
            reason: CommandRejectReason::SignalingMtuExceeded,
            data: CommandRejectReasonData::Mtu(actual_mtu),
        }
    }

    /// Create a `CommandRejectResponse` for a signalling command that contained an invalid channel
    /// ID.
    pub fn new_invalid_cid_in_request(identifier: NonZeroU8, local_cid: u16, remote_cid: u16) -> Self {
        CommandRejectResponse {
            identifier,
            reason: CommandRejectReason::InvalidCidInRequest,
            data: CommandRejectReasonData::RequestedCid(local_cid, remote_cid),
        }
    }

    /// Get the length of the signal command reject response packet
    ///
    /// # Note
    /// This is the length of the information payload within a control frame (c-frame).
    pub fn size(&self) -> usize {
        6 + self.data.len()
    }

    /// Create a c-frame from this signal
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub(crate) fn into_control_frame(self, channel_id: ChannelIdentifier) -> ControlFrame<iter::CmdRejectRspIter> {
        ControlFrame::new(iter::CmdRejectRspIter::new(self), channel_id)
    }

    /// Try to create a `CommandRejectResponse` from raw L2CAP data.
    pub fn try_from_raw_control_frame<L>(data: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(data)
    }
}

impl Signal for CommandRejectResponse {
    fn get_code(&self) -> SignalCode {
        SignalCode::CommandRejectResponse
    }

    fn get_identifier(&self) -> NonZeroU8 {
        self.identifier
    }

    fn get_data_length(&self) -> u16 {
        match self.data {
            CommandRejectReasonData::None => 2,
            CommandRejectReasonData::Mtu(_) => 4,
            CommandRejectReasonData::RequestedCid(_, _) => 6,
        }
    }
}

impl TryIntoSignal for CommandRejectResponse {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if CommandRejectResponse::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let reason_raw = <u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len as usize != raw[6..].len() {
            return Err(SignalError::InvalidLengthField);
        }

        let reason =
            CommandRejectReason::try_from_value(reason_raw).map_err(|e| SignalError::InvalidCommandRejectReason(e))?;

        let data = CommandRejectReasonData::try_from_slice(&raw[6..])
            .map_err(|e| SignalError::InvalidCommandRejectReasonData(e))?;

        Ok(CommandRejectResponse {
            identifier,
            reason,
            data,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Acl(AclCid::SignalingChannel).to_val()
            || raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}

/// Disconnection Request Signal
///
/// This signal is used for terminating a dynamically allocated L2CAP channel
#[derive(Clone, Copy, Debug)]
pub struct DisconnectRequest {
    pub identifier: NonZeroU8,
    pub destination_cid: ChannelIdentifier,
    pub source_cid: ChannelIdentifier,
}

impl DisconnectRequest {
    const CODE: u8 = 0x6;

    /// Get the destination CID
    pub fn get_destination_cid(&self) -> ChannelIdentifier {
        self.destination_cid
    }

    /// Get the source CID
    pub fn get_source_cid(&self) -> ChannelIdentifier {
        self.source_cid
    }

    /// Create a Disconnect Request
    pub fn new(identifier: NonZeroU8, destination_cid: ChannelIdentifier, source_cid: ChannelIdentifier) -> Self {
        Self {
            identifier,
            destination_cid,
            source_cid,
        }
    }

    /// Create a c-frame from this signal
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub(crate) fn into_control_frame(self, channel_id: ChannelIdentifier) -> ControlFrame<iter::DisconnectRequestIter> {
        ControlFrame::new(iter::DisconnectRequestIter::new(self), channel_id)
    }

    /// Try to create a `CommandRejectResponse` from raw L2CAP data.
    pub fn try_from_raw_control_frame<L>(data: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(data)
    }
}

impl Signal for DisconnectRequest {
    fn get_code(&self) -> SignalCode {
        SignalCode::DisconnectionRequest
    }

    fn get_identifier(&self) -> NonZeroU8 {
        self.identifier
    }

    fn get_data_length(&self) -> u16 {
        4
    }
}

impl TryIntoSignal for DisconnectRequest {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if DisconnectRequest::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len != 4 {
            return Err(SignalError::InvalidLengthField);
        }

        let raw_destination_cid = <u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let destination_cid = L::try_channel_from_raw(raw_destination_cid).ok_or(SignalError::InvalidChannel)?;

        let raw_source_cid = <u16>::from_le_bytes([
            raw.get(6).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(7).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let source_cid = L::try_channel_from_raw(raw_source_cid).ok_or(SignalError::InvalidChannel)?;

        Ok(DisconnectRequest {
            identifier,
            destination_cid,
            source_cid,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Acl(AclCid::SignalingChannel).to_val()
            || raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}

/// Disconnection Response Signal
///
/// This signal is used for terminating a dynamically allocated L2CAP channel
#[derive(Clone, Copy, Debug)]
pub struct DisconnectResponse {
    pub identifier: NonZeroU8,
    pub destination_cid: ChannelIdentifier,
    pub source_cid: ChannelIdentifier,
}

impl DisconnectResponse {
    const CODE: u8 = 0x7;

    /// Create a c-frame from this signal
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub(crate) fn into_control_frame(
        self,
        channel_id: ChannelIdentifier,
    ) -> ControlFrame<iter::DisconnectResponseIter> {
        ControlFrame::new(iter::DisconnectResponseIter::new(self), channel_id)
    }

    /// Try to create a `CommandRejectResponse` from raw L2CAP data.
    pub fn try_from_raw_control_frame<L>(data: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(data)
    }
}

impl Signal for DisconnectResponse {
    fn get_code(&self) -> SignalCode {
        SignalCode::DisconnectionResponse
    }

    fn get_identifier(&self) -> NonZeroU8 {
        self.identifier
    }

    fn get_data_length(&self) -> u16 {
        4
    }
}

impl TryIntoSignal for DisconnectResponse {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if DisconnectResponse::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len != 4 {
            return Err(SignalError::InvalidLengthField);
        }

        let raw_destination_cid = <u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let destination_cid = L::try_channel_from_raw(raw_destination_cid).ok_or(SignalError::InvalidChannel)?;

        let raw_source_cid = <u16>::from_le_bytes([
            raw.get(6).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(7).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let source_cid = L::try_channel_from_raw(raw_source_cid).ok_or(SignalError::InvalidChannel)?;

        Ok(DisconnectResponse {
            identifier,
            destination_cid,
            source_cid,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Acl(AclCid::SignalingChannel).to_val()
            || raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}

/// Simplified Protocol/Service Multiplexer
///
/// This is used to label the kind of L2CAP credit based connection being made. Some codes are fixed
/// and assigned by the Bluetooth SIG group, others are dynamically allocated by a higher layer
/// protocol (such as GATT).
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct SimplifiedProtocolServiceMultiplexer(u16);

impl SimplifiedProtocolServiceMultiplexer {
    /// Create a new `SimplifiedProtocolServiceMultiplexer` from a SIG assigned value
    ///
    /// # Panic
    /// `val` must be in the range (inclusive) of 0x1 to 0x7F
    pub fn new_fixed(val: u16) -> Self {
        assert!(val > 0 && val < 0x80);

        Self(val)
    }

    /// Create a new `SimplifiedProtocolServiceMultiplexer` from a dynamic value
    ///
    /// # Panic
    /// `val` must be in the range (inclusive) of 0x80 to 0xFF
    pub fn new_dyn(val: u16) -> Self {
        assert!(val > 0x7F && val < 0x100);

        Self(val)
    }

    fn try_from_raw(val: u16) -> Result<Self, ()> {
        match val {
            0x1..=0x7F | 0x80..=0xFF => Ok(Self(val)),
            _ => Err(()),
        }
    }
}

/// Error for bounded values
///
/// This is returned whenever an object is attempted to be created with a value outside of an
/// acceptable range.
#[derive(Debug)]
pub enum BoundsError {
    TooSmall(&'static str, &'static str),
    TooLarge(&'static str, &'static str),
}

impl Display for BoundsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            BoundsError::TooSmall(what, bound) => write!(f, "value for {what} is smaller than {bound}"),
            BoundsError::TooLarge(what, bound) => write!(f, "value for {what} is larger than {bound}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BoundsError {}

max_u16!(#[doc = "Credit based connection maximum PDU payload size"], LeCreditMps, 65533, 23);
max_u16!(#[doc = "Credit based connection maximum transmission size"], LeCreditMtu, 23);

/// LE credit based connection request
#[derive(Clone, Copy, Debug)]
pub struct LeCreditBasedConnectionRequest {
    pub identifier: NonZeroU8,
    pub spsm: SimplifiedProtocolServiceMultiplexer,
    pub source_dyn_cid: crate::channel::id::DynChannelId<crate::LeULink>,
    pub mtu: LeCreditMtu,
    pub mps: LeCreditMps,
    pub initial_credits: u16,
}

impl LeCreditBasedConnectionRequest {
    pub const CODE: u8 = 0x14;

    /// Get the source CID
    ///
    /// This will map the dynamic CID to the full channel identifier.
    pub fn get_source_cid(&self) -> ChannelIdentifier {
        ChannelIdentifier::Le(crate::channel::id::LeCid::DynamicallyAllocated(self.source_dyn_cid))
    }

    /// Convert this `LeCreditBasedConnectionRequest` into a C-frame for an LE-U logic link
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub fn into_control_frame(self, channel_id: ChannelIdentifier) -> ControlFrame<iter::LeCreditRequestIter> {
        ControlFrame::new(iter::LeCreditRequestIter::new(self), channel_id)
    }

    /// Try to create a `LeCreditBasedConnectionRequest` from a C-frame
    pub fn try_from_raw_control_frame<L>(c_frame: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(c_frame)
    }
}

impl Signal for LeCreditBasedConnectionRequest {
    fn get_code(&self) -> SignalCode {
        SignalCode::LeCreditBasedConnectionRequest
    }

    fn get_identifier(&self) -> NonZeroU8 {
        self.identifier
    }

    fn get_data_length(&self) -> u16 {
        10
    }
}

impl SignalWithDynChannel for LeCreditBasedConnectionRequest {
    fn get_local_cid(&self) -> Option<ChannelIdentifier> {
        self.get_source_cid().into()
    }

    fn get_remote_cid(&self) -> Option<ChannelIdentifier> {
        None
    }
}

impl TryIntoSignal for LeCreditBasedConnectionRequest {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if LeCreditBasedConnectionRequest::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len != 10 {
            return Err(SignalError::InvalidLengthField);
        }

        let spsm = SimplifiedProtocolServiceMultiplexer::try_from_raw(<u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidSpsm)?;

        let source_cid = ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([
            raw.get(6).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(7).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidChannel)?;

        let dyn_cid =
            if let ChannelIdentifier::Le(crate::channel::id::LeCid::DynamicallyAllocated(dyn_cid)) = source_cid {
                dyn_cid
            } else {
                return Err(SignalError::InvalidChannel);
            };

        let mtu = LeCreditMtu::try_new(<u16>::from_le_bytes([
            raw.get(8).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(9).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidValue)?;

        let mps = LeCreditMps::try_new(<u16>::from_le_bytes([
            raw.get(10).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(11).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidValue)?;

        let initial_credits = <u16>::from_le_bytes([
            raw.get(12).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(13).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        Ok(LeCreditBasedConnectionRequest {
            identifier,
            spsm,
            mtu,
            mps,
            initial_credits,
            source_dyn_cid: dyn_cid,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}

/// Errors for the *result* field of a [`LeCreditBasedConnectionResponse`]
///
/// These are the errors that are sent in response to
#[derive(Debug, Copy, Clone)]
pub enum LeCreditBasedConnectionResponseError {
    SpsmNotSupported,
    NoResourcesAvailable,
    InsufficientAuthentication,
    InsufficientAuthorization,
    EncryptionKeySizeTooShort,
    InsufficientEncryption,
    InvalidSourceCid,
    SourceCidAlreadyAllocated,
    UnacceptableParameters,
    /// Used when an error value is received and is not defined by the current Bluetooth Spec. This
    /// should not be used to set the error when responding to a *LE Credit Based Connection
    /// Request*.
    Unknown(u16),
}

impl LeCreditBasedConnectionResponseError {
    /// Convert a `LeCreditBasedConnectionResponseError` to its value
    pub fn to_val(&self) -> u16 {
        match self {
            LeCreditBasedConnectionResponseError::SpsmNotSupported => 0x2,
            LeCreditBasedConnectionResponseError::NoResourcesAvailable => 0x4,
            LeCreditBasedConnectionResponseError::InsufficientAuthentication => 0x5,
            LeCreditBasedConnectionResponseError::InsufficientAuthorization => 0x6,
            LeCreditBasedConnectionResponseError::EncryptionKeySizeTooShort => 0x7,
            LeCreditBasedConnectionResponseError::InsufficientEncryption => 0x8,
            LeCreditBasedConnectionResponseError::InvalidSourceCid => 0x9,
            LeCreditBasedConnectionResponseError::SourceCidAlreadyAllocated => 0xa,
            LeCreditBasedConnectionResponseError::UnacceptableParameters => 0xb,
            LeCreditBasedConnectionResponseError::Unknown(_) => panic!(""),
        }
    }

    /// Try to create a `LeCreditBasedConnectionResponseError` from a value
    ///
    /// This will convert the value into an error unless the value is zero. If the return is an
    /// `Err(_)` then the result of the connection request was *connection successful*
    pub fn try_from_raw(value: u16) -> Result<LeCreditBasedConnectionResponseError, ()> {
        match value {
            0 => Err(()),
            0x2 => Ok(LeCreditBasedConnectionResponseError::SpsmNotSupported),
            0x4 => Ok(LeCreditBasedConnectionResponseError::NoResourcesAvailable),
            0x5 => Ok(LeCreditBasedConnectionResponseError::InsufficientAuthentication),
            0x6 => Ok(LeCreditBasedConnectionResponseError::InsufficientAuthorization),
            0x7 => Ok(LeCreditBasedConnectionResponseError::EncryptionKeySizeTooShort),
            0x8 => Ok(LeCreditBasedConnectionResponseError::InsufficientEncryption),
            0x9 => Ok(LeCreditBasedConnectionResponseError::InvalidSourceCid),
            0xa => Ok(LeCreditBasedConnectionResponseError::SourceCidAlreadyAllocated),
            0xb => Ok(LeCreditBasedConnectionResponseError::UnacceptableParameters),
            v => Ok(LeCreditBasedConnectionResponseError::Unknown(v)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LeCreditBasedConnectionResponse {
    pub identifier: NonZeroU8,
    pub destination_dyn_cid: crate::channel::id::DynChannelId<crate::LeULink>,
    pub mtu: LeCreditMtu,
    pub mps: LeCreditMps,
    pub initial_credits: u16,
    pub result: Result<(), LeCreditBasedConnectionResponseError>,
}

impl LeCreditBasedConnectionResponse {
    const CODE: u8 = 0x15;

    /// Create a new `LeCreditBasedConnectionResponse` for rejecting the request.
    ///
    /// # Note
    /// The `identifier` must the the same identifier used within the request.
    pub fn new_rejected(identifier: NonZeroU8, reason: LeCreditBasedConnectionResponseError) -> Self {
        Self {
            identifier,
            destination_dyn_cid: crate::channel::id::DynChannelId::new_unchecked(0),
            mtu: LeCreditMtu { val: 0 },
            mps: LeCreditMps { val: 0 },
            initial_credits: 0,
            result: Err(reason),
        }
    }

    /// Get the destination CID
    ///
    /// This will map `destination_dyn_cid` to the full channel identifier.
    pub fn get_destination_cid(&self) -> ChannelIdentifier {
        ChannelIdentifier::Le(crate::channel::id::LeCid::DynamicallyAllocated(
            self.destination_dyn_cid,
        ))
    }

    /// Create a c-frame from this signal
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub(crate) fn into_control_frame(self, channel_id: ChannelIdentifier) -> ControlFrame<iter::LeCreditResponseIter> {
        ControlFrame::new(iter::LeCreditResponseIter::new(self), channel_id)
    }

    /// Try to create a `LeCreditBasedConnectionRequest` from a C-frame
    pub fn try_from_raw_control_frame<L>(c_frame: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(c_frame)
    }
}

impl Signal for LeCreditBasedConnectionResponse {
    fn get_code(&self) -> SignalCode {
        SignalCode::LeCreditBasedConnectionResponse
    }

    fn get_identifier(&self) -> NonZeroU8 {
        self.identifier
    }

    fn get_data_length(&self) -> u16 {
        10
    }
}

impl SignalWithDynChannel for LeCreditBasedConnectionResponse {
    fn get_local_cid(&self) -> Option<ChannelIdentifier> {
        self.get_destination_cid().into()
    }

    fn get_remote_cid(&self) -> Option<ChannelIdentifier> {
        None
    }
}

impl TryIntoSignal for LeCreditBasedConnectionResponse {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if LeCreditBasedConnectionResponse::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len != 10 {
            return Err(SignalError::InvalidLengthField);
        }

        let destination_cid = ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidSpsm)?;

        let destination_dyn_cid =
            if let ChannelIdentifier::Le(crate::channel::id::LeCid::DynamicallyAllocated(dyn_cid)) = destination_cid {
                dyn_cid
            } else {
                return Err(SignalError::InvalidChannel);
            };

        let mtu = LeCreditMtu::try_new(<u16>::from_le_bytes([
            raw.get(6).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(7).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidValue)?;

        let mps = LeCreditMps::try_new(<u16>::from_le_bytes([
            raw.get(8).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(9).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidValue)?;

        let initial_credits = <u16>::from_le_bytes([
            raw.get(10).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(11).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let result_raw = <u16>::from_le_bytes([
            raw.get(12).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(13).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        let result = match LeCreditBasedConnectionResponseError::try_from_raw(result_raw) {
            Ok(error) => Err(error),
            Err(_) => Ok(()),
        };

        Ok(LeCreditBasedConnectionResponse {
            identifier,
            destination_dyn_cid,
            mtu,
            mps,
            initial_credits,
            result,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}

/// Flow control credit indication PDU
///
/// A flow control credit indication contains a number of credits for sending to the channel
/// identified within the same indication. These credits are additional, they increase the amount
/// of frames that can be sent to the specified channel.
#[derive(Clone, Copy, Debug)]
pub struct FlowControlCreditInd {
    identifier: NonZeroU8,
    cid: ChannelIdentifier,
    credits: u16,
}

impl FlowControlCreditInd {
    const CODE: u8 = 0x16;

    /// Create a new `FlowControlCreditInd`
    ///
    /// Input `cid` is the identifier for the channel providing the credits.
    ///
    /// # Panic
    /// Input `cid` must be channel identifier that is valid for a credit based connection.
    pub fn new(identifier: NonZeroU8, cid: ChannelIdentifier, credits: u16) -> Self {
        match cid {
            ChannelIdentifier::Le(LeCid::DynamicallyAllocated(_))
            | ChannelIdentifier::Acl(AclCid::DynamicallyAllocated(_)) => (),
            _ => panic!("{cid} is not a valid channel identifier for use with "),
        }

        Self {
            identifier,
            cid,
            credits,
        }
    }

    /// Create a new `FlowControlCreditInd` for an ACL-U credit based connection
    ///
    /// Input `cid` is the identifier for the channel providing the credits.
    pub fn new_acl(
        identifier: NonZeroU8,
        dyn_cid: crate::channel::id::DynChannelId<crate::AclULink>,
        credits: u16,
    ) -> Self {
        let cid = ChannelIdentifier::Acl(AclCid::DynamicallyAllocated(dyn_cid));

        Self {
            identifier,
            cid,
            credits,
        }
    }

    /// Create a new `FlowControlCreditInd` for a LE-U credit based connection
    ///
    /// Input `cid` is the identifier for the channel providing the credits.
    pub fn new_le(
        identifier: NonZeroU8,
        dyn_cid: crate::channel::id::DynChannelId<crate::LeULink>,
        credits: u16,
    ) -> Self {
        let cid = ChannelIdentifier::Le(LeCid::DynamicallyAllocated(dyn_cid));

        Self {
            identifier,
            cid,
            credits,
        }
    }

    /// Get the credit amount
    pub fn get_credits(&self) -> u16 {
        self.credits
    }

    /// Get the channel identifier given credit
    ///
    /// This returns the channel that indicated as having a credit increase by the sending device.
    pub fn get_cid(&self) -> ChannelIdentifier {
        self.cid
    }

    /// Create a c-frame from this signal
    ///
    /// # Panic
    /// `channel_id` can only be a signalling channel
    pub(crate) fn into_control_frame(
        self,
        channel_id: ChannelIdentifier,
    ) -> ControlFrame<iter::FlowControlCreditIndIter> {
        ControlFrame::new(iter::FlowControlCreditIndIter::new(self), channel_id)
    }

    /// Try to create a `LeCreditBasedConnectionRequest` from a C-frame
    pub fn try_from_raw_control_frame<L>(c_frame: &[u8]) -> Result<Self, crate::pdu::ControlFrameError>
    where
        L: crate::link_flavor::LinkFlavor,
    {
        ControlFrame::try_from_slice::<L>(c_frame)
    }
}

impl TryIntoSignal for FlowControlCreditInd {
    fn try_from<L>(raw: &[u8]) -> Result<Self, SignalError>
    where
        L: crate::link_flavor::LinkFlavor,
        Self: Sized,
    {
        if FlowControlCreditInd::CODE != *raw.get(0).ok_or(SignalError::InvalidSize)? {
            return Err(SignalError::IncorrectCode);
        }

        let raw_identifier = raw.get(1).copied().ok_or(SignalError::InvalidSize)?;

        let identifier = NonZeroU8::try_from(raw_identifier).map_err(|_| SignalError::InvalidIdentifier)?;

        let data_len = <u16>::from_le_bytes([
            raw.get(2).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(3).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        if data_len != 4 {
            return Err(SignalError::InvalidLengthField);
        }

        let cid = ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([
            raw.get(4).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(5).copied().ok_or(SignalError::InvalidSize)?,
        ]))
        .map_err(|_| SignalError::InvalidSpsm)?;

        let credits = <u16>::from_le_bytes([
            raw.get(6).copied().ok_or(SignalError::InvalidSize)?,
            raw.get(7).copied().ok_or(SignalError::InvalidSize)?,
        ]);

        Ok(FlowControlCreditInd {
            identifier,
            cid,
            credits,
        })
    }

    fn correct_channel(raw_channel_id: u16) -> bool {
        raw_channel_id == ChannelIdentifier::Acl(AclCid::SignalingChannel).to_val()
            || raw_channel_id == ChannelIdentifier::Le(LeCid::LeSignalingChannel).to_val()
    }
}
