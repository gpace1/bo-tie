//! Signaling L2CAP Commands
//!
//! L2CAP supports signal packets to provide a L2CAP level configuration.
//!
//! # Note
//! This module is very unfinished and is gated behind the feature `unstable`

pub mod packets;
pub mod processor;

pub use processor::SignalsProcessor;

/// The Channel Identifier for ACL-U signals
pub const ACL_U_SIGNAL_CHANNEL_ID: crate::channels::ChannelIdentifier =
    crate::ChannelIdentifier::Acl(crate::channels::AclCid::SignalingChannel);

/// The channel identifier for LE-U signals
pub const LE_U_SIGNAL_CHANNEL_ID: crate::channels::ChannelIdentifier =
    crate::ChannelIdentifier::Le(crate::channels::LeCid::LeSignalingChannel);

pub(crate) trait TryIntoSignal {
    fn try_from(raw: &[u8]) -> Result<Self, SignalError>
    where
        Self: Sized;

    fn correct_channel(raw_channel_id: u16) -> bool;
}

/// Error for converting into a Signal from a [`ControlFrame`]
///
/// [`ControlFrame`]: crate::ControlFrame
#[derive(Debug, Copy, Clone)]
pub enum SignalError {
    IncorrectCode,
    InvalidSize,
    InvalidIdentifier,
    InvalidLengthField,
    InvalidCommandRejectReason(packets::InvalidCommandRejectReason),
    InvalidCommandRejectReasonData(packets::CommandRejectReasonDataError),
    InvalidSpsm,
    InvalidChannel,
}

impl core::fmt::Display for SignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::IncorrectCode => f.write_str("the code field is different from the expected signal"),
            Self::InvalidSize => f.write_str("invalid control frame size"),
            Self::InvalidIdentifier => f.write_str("the identifier field cannot be zero"),
            Self::InvalidLengthField => f.write_str("length field does not match data length"),
            Self::InvalidCommandRejectReason(r) => core::fmt::Display::fmt(&r, f),
            Self::InvalidCommandRejectReasonData(r) => core::fmt::Display::fmt(&r, f),
            Self::InvalidSpsm => f.write_str("invalid simplified protocol/service multiplexer"),
            Self::InvalidChannel => f.write_str("invalid channel identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignalError {}
