//! Processing for Unused Channels
//!
//! Channels are only used when an object is created for them. The client may send a L2CAP PDU if it
//! expects that the channel's implementation exists for this device. If the PDU is for a fixed
//! channel a [`UnusedChannelResponse`] implementation will provide a response equivalent to either
//! *channel is not used* or *channel has no support*. However, a dynamically allocated channels are
//! ignored and produce the [`InvalidChannel`] error.

pub mod le;

use crate::channel::id::ChannelIdentifier;
use crate::channel::shared::BasicHeadedFragment;
use crate::pdu::FragmentL2capPdu;

/// Response for a PDU for an unused channel
///
/// A channel is unused when an object for the channel has not been created (or was dropped) by the
/// user of a logical link. This is used to generate responses for L2CAP PDUs with the response
/// akin to "*higher layer protocol* for this channel is not available".
///
/// e.g. for a LE logical link, this will return *pairing not supported* for the Security Manager
/// channel.
pub trait UnusedChannelResponse {
    /// The processor of a received L2CAP PDU
    type ReceiveProcessor: ReceiveDataProcessor;

    /// The response sent back to the peer device
    type Response: FragmentL2capPdu;

    /// Generate the response from `Self::ReceiveData`
    ///
    /// A response is only generated for fixed channels. `None` is returned for dynamically
    /// allocated channels.
    fn try_generate_response(request_data: Self::ReceiveProcessor) -> Option<Self::Response>;

    /// Create a new `ReceiveData`
    fn new_response_data(pdu_len: usize, channel_id: ChannelIdentifier) -> Self::ReceiveProcessor;

    /// Create a new junking `ReceiveData`
    ///
    /// This is called whenever a channel is dropped in the middle of receiving a L2CAP PDU.
    ///
    /// Input `pdu_bytes` is the amount of bytes received so far.
    fn new_junked_data(pdu_len: usize, pdu_bytes: usize, channel_id: ChannelIdentifier) -> Self::ReceiveProcessor;
}

/// Data from a received PDU
///
/// There may be some processing of the request required in order to form a proper response for an
/// unused channel. This is used to determine both the end of the fragments from the
pub trait ReceiveDataProcessor: Copy + Clone + core::fmt::Debug + PartialEq {
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Process a fragment
    ///
    /// `true` is returned when the full PDU is processed.
    ///
    /// # Note
    /// `fragment` will only contain bytes after the basic header of the PDU.
    fn process<T>(&mut self, fragment: BasicHeadedFragment<T>) -> Result<bool, Self::Error>
    where
        T: Iterator<Item = u8> + ExactSizeIterator;
}
