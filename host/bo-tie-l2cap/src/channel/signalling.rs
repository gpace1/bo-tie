//! Signalling Channel implementation

use crate::channel::id::{AclCid, ChannelIdentifier, LeCid};
use crate::channel::{ChannelDirection, DynChannelState, DynChannelStateInner, LeUChannelType};
use crate::link_flavor::LeULink;
use crate::logical_link_private::NewDynChannelError;
use crate::pdu::{FragmentL2capPdu, RecombineL2capPdu, RecombinePayloadIncrementally};
use crate::signals::packets::{
    CommandRejectResponse, DisconnectRequest, DisconnectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse, LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu, Signal,
    SignalCode, SimplifiedProtocolServiceMultiplexer,
};
use crate::{CreditBasedChannel, LogicalLink, PhysicalLink, PhysicalLinkExt};
use bo_tie_core::buffer::stack::LinearBuffer;
use core::num::NonZeroU8;

/// A Signalling Channel
///
/// L2CAP has two Signalling Channels, one for an ACL-U logical link and one for a LE-U logical
/// link. This type is used for either of the two.
///
/// For a LE-U logical link, a Signalling Channel can be created via the [`get_signalling_channel`]
/// method of `LeULogicalLink`
///
/// [`get_signalling_channel`]: crate::LeULogicalLink::get_signalling_channel
#[derive(Debug)]
pub struct SignallingChannel<L> {
    channel_id: ChannelIdentifier,
    logical_link: L,
}

impl<L> SignallingChannel<L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: L) -> Self {
        Self {
            channel_id,
            logical_link,
        }
    }

    /// Get the channel identifier for this Signalling Channel
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }
}

impl<L: LogicalLink> SignallingChannel<L> {
    /// Send a Signal
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    async fn send<T: FragmentL2capPdu>(&mut self, c_frame: T) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: FragmentL2capPdu,
    {
        self.logical_link.get_mut_physical_link().send_pdu(c_frame).await
    }

    /// Request a disconnection of a L2CAP connection
    ///
    /// This sends the *disconnection request* to the linked device for the specific channel. Only
    /// L2CAP connection may be disconnected via this command.
    ///
    /// # Note
    /// The disconnection of the L2CAP connection does not occur until after a disconnection
    /// response is received by this device (with the correct fields).
    pub async fn request_disconnection(
        &mut self,
        dyn_channel_id: ChannelIdentifier,
    ) -> Result<(), RequestDisconnectError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        match dyn_channel_id {
            ChannelIdentifier::Le(LeCid::DynamicallyAllocated(_))
            | ChannelIdentifier::Acl(AclCid::DynamicallyAllocated(_)) => (),
            _ => return Err(RequestDisconnectError::NotAConnectionChannel(dyn_channel_id)),
        }

        let channel_buffer = self
            .logical_link
            .initiated_disconnect_of_dyn_channel(dyn_channel_id)
            .ok_or_else(|| RequestDisconnectError::NoChannelFoundForId(dyn_channel_id))?;

        match channel_buffer {
            LeUChannelType::CreditBasedChannel { data } => {
                let (source_id, destination_id) = match &data.peer_channel_id {
                    ChannelDirection::Source(s) => (*s, dyn_channel_id),
                    ChannelDirection::Destination(d) => (dyn_channel_id, *d),
                };

                let disconnect_request = DisconnectRequest::new(NonZeroU8::new(1).unwrap(), destination_id, source_id);

                let c_frame = disconnect_request.into_control_frame(self.channel_id);

                self.send(c_frame)
                    .await
                    .map_err(|e| RequestDisconnectError::SendError(e))
            }
            _ => unreachable!("unexpected invalid dynamic channel buffer data"),
        }
    }

    /// Give credits to the peer device
    ///
    /// This sends a *flow control credit indication* to the peer device to increase the credit
    /// amount for this channel by `credits`. The number of credits will be increased for the
    /// provided `credit_channel` and the peer device will be able to send up to `credits` amount
    /// of PDUs plus any amount credits that the peer already had.
    pub(crate) async fn give_credits_to_peer(
        &mut self,
        channel_credits: crate::channel::ChannelCredits,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> where {
        let credit_ind = FlowControlCreditInd::new(
            NonZeroU8::new(1).unwrap(),
            channel_credits.get_channel_id(),
            channel_credits.get_credits(),
        );

        let c_frame = credit_ind.into_control_frame(self.channel_id);

        self.send(c_frame).await
    }

    /// Request an LE Credit Based Connection
    ///
    /// This will send the request to create a LE credit based connection with the linked device. A
    /// connection is not completed until a response is received via the method [`receive`].
    ///
    /// # Output
    /// The output is a copy of the request sent to the linked device.
    ///
    /// # Error
    /// An error is returned if this is not called on a LE-U logical link or all dynamic channels
    /// for the logical link are already used.
    ///
    /// [`receive`]: SignallingChannel::receive
    pub async fn request_le_credit_connection(
        &mut self,
        spsm: SimplifiedProtocolServiceMultiplexer,
        mtu: LeCreditMtu,
        mps: LeCreditMps,
        initial_credits: u16,
    ) -> Result<
        LeCreditBasedConnectionRequest,
        RequestLeCreditConnectionError<<L::PhysicalLink as PhysicalLink>::SendErr>,
    > {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = self
            .logical_link
            .reserve_dyn_channel()
            .map_err(|e| RequestLeCreditConnectionError::CreateDynChannelError(e))?
        else {
            return Err(RequestLeCreditConnectionError::InvalidChannelIdentifier);
        };

        let request = LeCreditBasedConnectionRequest {
            identifier: NonZeroU8::new(1).unwrap(),
            spsm,
            source_dyn_cid: channel_id,
            mtu,
            mps,
            initial_credits,
        };

        let control_frame = request.into_control_frame(self.channel_id);

        self.send(control_frame)
            .await
            .map_err(|e| RequestLeCreditConnectionError::SendError(e))?;

        Ok(request)
    }
}

/// Error returned by method [`request_disconnection`]
///
/// [`request_disconnection`]: SignallingChannel::request_disconnection
#[derive(Debug)]
pub enum RequestDisconnectError<S> {
    SendError(S),
    NotAConnectionChannel(ChannelIdentifier),
    NoChannelFoundForId(ChannelIdentifier),
}

impl<S> core::fmt::Display for RequestDisconnectError<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::SendError(s) => core::fmt::Display::fmt(s, f),
            Self::NotAConnectionChannel(id) => {
                write!(f, "{id} is not a connection channel")
            }
            Self::NoChannelFoundForId(id) => {
                write!(f, "there exists L2CAP connection with the channel ID {id} (on this ")
            }
        }
    }
}

/// Error returned by method [`request_le_credit_connection`]
///
/// [`request_le_credit_connection`]: SignallingChannel::request_le_credit_connection
#[derive(Debug)]
pub enum RequestLeCreditConnectionError<S> {
    SendError(S),
    NotLeULogicalLink,
    CreateDynChannelError(NewDynChannelError),
    InvalidChannelIdentifier,
}

impl<S> core::fmt::Display for RequestLeCreditConnectionError<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::SendError(s) => core::fmt::Display::fmt(s, f),
            Self::NotLeULogicalLink => {
                f.write_str("an LE credit based connection can only be created on a LE-U logical link")
            }
            Self::CreateDynChannelError(d) => {
                write!(f, "{d}")
            }
            Self::InvalidChannelIdentifier => f.write_str("invalid channel identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl<S> std::error::Error for RequestLeCreditConnectionError<S> where S: std::error::Error {}

/// Signal received from a LE-U logically linked device
///
/// This is an enumeration of the signals that can be passed over the signalling channel for a LE-U
/// logical link.
#[non_exhaustive]
#[derive(Debug)]
pub enum ReceivedLeUSignal {
    UnknownSignal {
        /// The unknown signal code
        code: u8,
        /// A prefabricated rejection response to this command.  
        reject_response: ReceivedRequest<CommandRejectResponse>,
    },
    CommandRejectRsp(ReceivedResponse<CommandRejectResponse>),
    DisconnectRequest(ReceivedRequest<DisconnectRequest>),
    DisconnectResponse(ReceivedResponse<DisconnectResponse>),
    LeCreditBasedConnectionRequest(ReceivedRequest<LeCreditBasedConnectionRequest>),
    LeCreditBasedConnectionResponse(ReceivedResponse<LeCreditBasedConnectionResponse>),
    FlowControlCreditIndication(FlowControlCreditInd),
}

impl ReceivedLeUSignal {
    /// Reject or ignore the received Signal
    ///
    /// If this `ReceivedSignal` is a request, then a *Command Reject Response* is sent to the other
    /// device with the command not understood reason. If this is not a request then the received
    /// signal is ignored and no reject signal is sent.
    pub async fn quick_reject<L: LogicalLink>(
        self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        match self {
            ReceivedLeUSignal::UnknownSignal { .. }
            | ReceivedLeUSignal::CommandRejectRsp(_)
            | ReceivedLeUSignal::DisconnectResponse(_)
            | ReceivedLeUSignal::LeCreditBasedConnectionResponse(_)
            | ReceivedLeUSignal::FlowControlCreditIndication(_) => Ok(()),
            ReceivedLeUSignal::DisconnectRequest(request) => request.reject_as_not_understood(signalling_channel).await,
            ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                request.reject_as_not_understood(signalling_channel).await
            }
        }
    }

    fn try_from(builder: &ReceiveLeUSignalRecombineBuilder) -> Result<Self, ConvertSignalError> {
        match &builder.state {
            ReceiveLeUSignalRecombineBuilderState::Init => Err(ConvertSignalError::IncompleteSignal),
            ReceiveLeUSignalRecombineBuilderState::Unknown(unknown) => {
                let signal_code = *unknown.header.get(0).unwrap();

                let command_reject = CommandRejectResponse::new_command_not_understood(
                    unknown.get_identifier().ok_or(ConvertSignalError::IncompleteSignal)?,
                );

                let request = ReceivedRequest::new(command_reject);

                Ok(ReceivedLeUSignal::UnknownSignal {
                    code: signal_code,
                    reject_response: request,
                })
            }
            ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(raw) => {
                CommandRejectResponse::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedLeUSignal::CommandRejectRsp(ReceivedResponse::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::CommandRejectResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(raw) => {
                DisconnectRequest::try_from_raw_control_frame::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::DisconnectRequest(ReceivedRequest::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionRequest, e))
            }
            ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(raw) => {
                DisconnectResponse::try_from_raw_control_frame::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::DisconnectResponse(ReceivedResponse::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(raw) => {
                LeCreditBasedConnectionRequest::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedLeUSignal::LeCreditBasedConnectionRequest(ReceivedRequest::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionRequest, e))
            }
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(raw) => {
                LeCreditBasedConnectionResponse::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedLeUSignal::LeCreditBasedConnectionResponse(ReceivedResponse::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(raw) => {
                FlowControlCreditInd::try_from_raw_control_frame(raw)
                    .map(|s| ReceivedLeUSignal::FlowControlCreditIndication(s))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::FlowControlCreditIndication, e))
            }
        }
    }
}

impl RecombineL2capPdu for ReceivedLeUSignal {
    type RecombineMeta<'a> = ();
    type RecombineError = ConvertSignalError;
    type RecombineBuffer<'a> = ();
    type PayloadRecombiner<'a> = ReceiveLeUSignalRecombineBuilder;

    fn recombine<'a>(
        payload_length: u16,
        _: ChannelIdentifier,
        _: Self::RecombineBuffer<'a>,
        _: Self::RecombineMeta<'a>,
    ) -> Self::PayloadRecombiner<'a> {
        ReceiveLeUSignalRecombineBuilder::new(payload_length.into())
    }
}

/// A recombine builder for a `ReceivedSignal`
///
/// This is used whenever a control signal is [received] to convert the transmission data into a
/// signal type.
///
/// # Enumerations
/// [received]: SignallingChannel::receive
#[derive(Default, Debug)]
pub enum ReceiveLeUSignalRecombineBuilderState {
    // state used before the signalling code is received
    #[default]
    Init,
    // Used for an error condition where the L2CAP signalling packet is 'unknown'
    Unknown(UnknownSignal),
    CommandRejectRsp(LinearBuffer<8, u8>),
    DisconnectRequest(LinearBuffer<8, u8>),
    DisconnectResponse(LinearBuffer<8, u8>),
    LeCreditBasedConnectionRequest(LinearBuffer<14, u8>),
    LeCreditBasedConnectionResponse(LinearBuffer<14, u8>),
    FlowControlCreditIndication(LinearBuffer<8, u8>),
}

#[derive(Debug)]
pub struct ReceiveLeUSignalRecombineBuilder {
    payload_length: usize,
    state: ReceiveLeUSignalRecombineBuilderState,
}

impl ReceiveLeUSignalRecombineBuilder {
    fn new(payload_length: usize) -> Self {
        let state = ReceiveLeUSignalRecombineBuilderState::default();

        ReceiveLeUSignalRecombineBuilder { payload_length, state }
    }

    pub(crate) fn get_payload_length(&self) -> usize {
        self.payload_length
    }

    pub(crate) fn get_byte_count(&self) -> usize {
        match &self.state {
            ReceiveLeUSignalRecombineBuilderState::Init => 0,
            ReceiveLeUSignalRecombineBuilderState::Unknown(u) => u.received_bytes_ignored,
            ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(l) => l.len(),
            ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(l) => l.len(),
            ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(l) => l.len(),
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(l) => l.len(),
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(l) => l.len(),
            ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(l) => l.len(),
        }
    }

    fn first_byte(&mut self, first: u8) -> Result<(), ConvertSignalError> {
        match SignalCode::try_from_code(first) {
            Ok(SignalCode::CommandRejectResponse) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp([first].into()))
            }
            Ok(SignalCode::DisconnectionRequest) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::DisconnectRequest([first].into()))
            }
            Ok(SignalCode::DisconnectionResponse) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::DisconnectResponse([first].into()))
            }
            Ok(SignalCode::LeCreditBasedConnectionRequest) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest([first].into()))
            }
            Ok(SignalCode::LeCreditBasedConnectionResponse) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse([first].into()))
            }
            Ok(SignalCode::FlowControlCreditIndication) => {
                Ok(self.state = ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication([first].into()))
            }
            Err(_) | Ok(_) => Ok(self.state =
                ReceiveLeUSignalRecombineBuilderState::Unknown(UnknownSignal::new(first, self.payload_length))),
        }
    }

    fn is_complete(&self) -> bool {
        // the signal code (1), identifier (1), and
        // data length (2) are 4 total bytes
        const SIGNAL_HEADER_SIZE: usize = 4;

        let buffer: &[u8] = match &self.state {
            ReceiveLeUSignalRecombineBuilderState::Init => return false,
            ReceiveLeUSignalRecombineBuilderState::Unknown(u) => return u.is_complete(),
            ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(l) => l,
            ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(l) => l,
            ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(l) => l,
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(l) => l,
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(l) => l,
            ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(l) => l,
        };

        let Some(len_0) = buffer.get(2) else { return false };

        let Some(len_1) = buffer.get(3) else { return false };

        let data_size: usize = <u16>::from_le_bytes([*len_0, *len_1]).into();

        buffer.len() >= data_size + SIGNAL_HEADER_SIZE
    }

    /// Get the received bytes
    ///
    /// This returns the received bytes and an option extension of the number of extra bytes that
    /// were relegated. e.g. if ten bytes were received, but only the first two were important, then
    /// a slice of two bytes is returned along with `Some(8)`.
    pub(crate) fn get_bytes_received(&self) -> (&[u8], usize) {
        match &self.state {
            ReceiveLeUSignalRecombineBuilderState::Init => (&[], 0),
            ReceiveLeUSignalRecombineBuilderState::Unknown(b) => (&*b.header, b.received_bytes_ignored),
            ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(b) => (&*b, 0),
            ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(b) => (&*b, 0),
            ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(b) => (&*b, 0),
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(b) => (&*b, 0),
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(b) => (&*b, 0),
            ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(b) => (&*b, 0),
        }
    }
}

impl RecombinePayloadIncrementally for ReceiveLeUSignalRecombineBuilder {
    type Pdu = ReceivedLeUSignal;

    type RecombineError = ConvertSignalError;

    fn add<T>(&mut self, payload_fragment: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        for byte in payload_fragment {
            match &mut self.state {
                ReceiveLeUSignalRecombineBuilderState::Init => self.first_byte(byte)?,
                ReceiveLeUSignalRecombineBuilderState::Unknown(unknown) => unknown.process(byte)?,
                ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
            }
        }

        self.is_complete()
            .then(|| ReceivedLeUSignal::try_from(self))
            .transpose()
    }
}

/// Error when converting received data into a signal
#[derive(Debug)]
pub enum ConvertSignalError {
    ReceivedSignalTooLong,
    IncompleteSignal,
    InvalidDataLengthField,
    InvalidFormat(SignalCode, crate::signals::SignalError),
}

impl core::fmt::Display for ConvertSignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("the received signal is invalid")?;

        match self {
            ConvertSignalError::ReceivedSignalTooLong => f.write_str(", more bytes received than expected"),
            ConvertSignalError::IncompleteSignal => f.write_str(", signal is incomplete"),
            ConvertSignalError::InvalidDataLengthField => f.write_str(", the 'data length' field is incorrect"),
            ConvertSignalError::InvalidFormat(code, err) => write!(f, ", invalid format for signal {code}: {err}"),
        }
    }
}

#[derive(Debug)]
pub struct UnknownSignal {
    header: LinearBuffer<4, u8>,
    payload_length: usize,
    data_length_field: usize,
    received_bytes_ignored: usize,
}

impl UnknownSignal {
    fn new(code: u8, payload_length: usize) -> Self {
        let header = [code].into();
        let data_length_field = 0;
        let received_bytes_ignored = 0;

        Self {
            header,
            payload_length,
            data_length_field,
            received_bytes_ignored,
        }
    }

    fn process(&mut self, byte: u8) -> Result<(), ConvertSignalError> {
        match self.header.len() {
            0..=2 => {
                self.header.try_push(byte).unwrap();

                Ok(())
            }
            3 => {
                self.header.try_push(byte).unwrap();

                let expected_len =
                    <u16>::from_le_bytes([*self.header.get(2).unwrap(), *self.header.get(3).unwrap()]).into();

                self.data_length_field = expected_len;

                if self.data_length_field + 4 != self.payload_length {
                    return Err(ConvertSignalError::InvalidDataLengthField);
                }

                Ok(())
            }
            _ => {
                self.received_bytes_ignored += 1;

                if self.received_bytes_ignored > self.data_length_field {
                    Err(ConvertSignalError::ReceivedSignalTooLong)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn get_identifier(&self) -> Option<NonZeroU8> {
        self.header.get(1).copied().and_then(|v| NonZeroU8::new(v))
    }

    fn is_complete(&self) -> bool {
        self.header.len() == 4 && self.data_length_field == self.received_bytes_ignored
    }
}

/// A Request Signal from the Linked Device
///
/// This is returned whenever a request is received by a Signalling Channel. Depending on the type
/// of request (`T`) there are different operations done.
#[derive(Debug, Copy, Clone)]
pub struct ReceivedRequest<T> {
    request: T,
}

impl<T> ReceivedRequest<T> {
    /// Create a new `Request`
    pub(crate) fn new(request: T) -> Self {
        Self { request }
    }

    /// Reject the request on the basis of the command is not understood
    ///
    /// If ever a request is either not implemented or not used by the application, this can be used
    /// as a 'catch all' for those signals from the linked device.
    pub async fn reject_as_not_understood<L: LogicalLink>(
        self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: Signal,
    {
        let rejection = CommandRejectResponse::new_command_not_understood(self.request.get_identifier());

        let c_frame = rejection.into_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }

    /// Get the inner request
    pub fn into_inner(self) -> T {
        self.request
    }
}

impl<T> core::ops::Deref for ReceivedRequest<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl<T> core::ops::DerefMut for ReceivedRequest<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl ReceivedRequest<DisconnectRequest> {
    /// (Maybe) Send the disconnect response
    ///
    /// # Invalid Disconnect Request
    ///
    /// If a disconnect request is invalid, the following actions are taken.
    ///
    /// * If the destination CID does not match a dynamic channel identifier of the logical link,
    ///   then the requester is sent an error response with the 'invalid CID' message. If no race
    ///   condition occurred, then an error is output by the future returned by
    ///   `send_disconnect_response`.
    /// * If the destination CID matches but the source CID does not match then an error is output
    ///   by the future returned by `send_disconnect_response`.
    ///
    /// ### Disconnect Race
    ///
    /// It's possible that both the peer and this device initiate a disconnection at the same time.
    /// This occurs when both devices send a `DisconnectRequest` before either of them can process
    /// their associate's signal. The logical links (of bo-tie) are able to detect this race as they
    /// put the channel in a 'requesting disconnect' state whenever they send a `DisconnectRequest`.
    /// Then the state is cleared when the future returned by this method is polled to completion.
    /// This is how `send_disconnect_response` can detect whether a peer's disconnect request is
    /// either a bad signal or a disconnect race occurred.
    ///
    /// # Future Output
    ///
    /// `true` is output if the disconnection was successfully initiated and a disconnect response
    /// was sent. `false` is only returned if a disconnect race happened and a command reject
    /// response is sent with the invalid channel ID reason.
    pub async fn maybe_send_disconnect_response<L: LogicalLink>(
        &self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<bool, DisconnectResponseError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        match signalling_channel
            .logical_link
            .get_dyn_channel(self.request.destination_cid)
        {
            Some(LeUChannelType::CreditBasedChannel { data }) => {
                if data.peer_channel_id.get_channel() == self.request.source_cid {
                    signalling_channel
                        .logical_link
                        .remove_dyn_channel(self.request.destination_cid)
                        .unwrap();

                    let response = DisconnectResponse {
                        identifier: self.request.identifier,
                        destination_cid: self.request.destination_cid,
                        source_cid: self.request.source_cid,
                    };

                    let c_frame = response.into_control_frame(signalling_channel.channel_id);

                    signalling_channel
                        .send(c_frame)
                        .await
                        .map_err(|e| DisconnectResponseError::SendErr(e))?;

                    Ok(true)
                } else {
                    Err(DisconnectResponseError::InvalidSourceChannelIdentifier(
                        self.request.source_cid,
                    ))
                }
            }
            Some(LeUChannelType::PendingDisconnect { peer_channel_id })
                if peer_channel_id == &self.request.source_cid =>
            {
                // disconnect request race occurred

                let rejection = CommandRejectResponse::new_invalid_cid_in_request(
                    self.request.identifier,
                    self.request.destination_cid.to_val(),
                    self.request.source_cid.to_val(),
                );

                ReceivedResponse::new(rejection)
                    .send_rejection(signalling_channel)
                    .await
                    .map_err(|e| DisconnectResponseError::SendErr(e))?;

                Ok(false)
            }
            _ => {
                let rejection = CommandRejectResponse::new_invalid_cid_in_request(
                    self.request.identifier,
                    self.request.destination_cid.to_val(),
                    self.request.source_cid.to_val(),
                );

                ReceivedResponse::new(rejection)
                    .send_rejection(signalling_channel)
                    .await
                    .map_err(|e| DisconnectResponseError::SendErr(e))?;

                Err(DisconnectResponseError::InvalidDestinationChannelIdentifier(
                    self.request.destination_cid,
                ))
            }
        }
    }
}

#[derive(Debug)]
pub enum DisconnectResponseError<E> {
    SendErr(E),
    InvalidDestinationChannelIdentifier(ChannelIdentifier),
    InvalidSourceChannelIdentifier(ChannelIdentifier),
}

impl<E: core::fmt::Display> core::fmt::Display for DisconnectResponseError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::SendErr(e) => core::fmt::Display::fmt(e, f),
            Self::InvalidDestinationChannelIdentifier(id) => write!(f, "invalid destination channel identifier: {id}"),
            Self::InvalidSourceChannelIdentifier(id) => write!(f, "invalid source channel identifier {id}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for DisconnectResponseError<E> {}

impl ReceivedRequest<LeCreditBasedConnectionRequest> {
    /// Create a LE Credit Based Connection
    ///
    /// This returns a `LeCreditBasedConnectionResponseBuilder` to configure the LE credit based
    /// connection response to this request and create a [`CreditBasedChannel`] for the connection.
    ///
    /// # Panic
    /// This method will panic if there are no more dynamic channels that can be allocated for a
    /// LE-U logical link.
    pub fn accept_le_credit_based_connection<L: LogicalLink>(
        &self,
        signal_channel: SignallingChannel<L>,
    ) -> LeCreditBasedConnectionResponseBuilder<'_, L> {
        let initial_credits = 0;

        LeCreditBasedConnectionResponseBuilder {
            signal_channel,
            request: &self.request,
            mtu: self.request.mtu.get(),
            mps: self.request.mps.get(),
            initial_credits,
        }
    }

    /// Reject a LE credit based connection request
    ///
    /// # Panic
    /// Input `reason` cannot be [`ConnectionSuccessful`].
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub async fn reject_le_credit_based_connection<L: LogicalLink>(
        &self,
        signal_channel: &mut SignallingChannel<L>,
        reason: LeCreditBasedConnectionResponseResult,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let response = LeCreditBasedConnectionResponse::new_rejected(self.request.identifier, reason);

        signal_channel
            .send(response.into_control_frame(signal_channel.channel_id))
            .await
    }
}

/// Builder used for creating a *LE Credit Based Connection Response*
#[must_use]
pub struct LeCreditBasedConnectionResponseBuilder<'a, L> {
    signal_channel: SignallingChannel<L>,
    request: &'a LeCreditBasedConnectionRequest,
    mtu: u16,
    mps: u16,
    initial_credits: u16,
}

impl<'a, L> LeCreditBasedConnectionResponseBuilder<'a, L> {
    /// Set the initial credits to give to the peer
    ///
    /// This will be the number of credits the peer device has for sending credit based frames on
    /// this channel after connection is made.
    ///
    /// If this is not called the peer device is initially given zero credits.
    pub fn initially_given_credits(mut self, credits: u16) -> Self {
        self.initial_credits = credits;
        self
    }

    /// Set the maximum payload size (MPS)
    ///
    /// This sets the MPS within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MPS.
    pub fn set_responded_mps(mut self, mps: u16) -> Self {
        self.mps = core::cmp::min(mps, self.request.mps.get());
        self
    }

    /// Set the maximum transmission unit (MTU)
    ///
    /// This sets the MTU within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MTS.
    pub fn set_responded_mtu(mut self, mtu: u16) -> Self {
        self.mtu = core::cmp::min(mtu, self.request.mtu.get());
        self
    }

    /// Send the response and create the connection
    ///
    /// This sends the response to establish the LE credit based connection. After this is
    /// successfully polled to completion there will be a new LE credit based connection established
    /// between this device and the peer.
    ///
    /// # Note
    /// The result field within the response will be [`ConnectionSuccessful`]
    ///
    /// # Return
    /// The return is the channel identifier of the credit based connection for this logical link.
    ///
    /// # Error
    /// If this was not called on an LE-U logical link or there was an error sending the response.
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub async fn send_success_response(mut self) -> Result<CreditBasedChannel<L>, LeCreditResponseError<L>>
    where
        L: LogicalLink,
        L::SduBuffer: Default,
    {
        use core::cmp::min;

        let peer_channel_id = ChannelDirection::Source(self.request.get_source_cid());

        let maximum_payload_size = min(self.mps, self.request.mps.get()).into();

        let maximum_transmission_size = min(self.mtu, self.request.mtu.get()).into();

        let initial_peer_given_credits = self.request.initial_credits;

        let initial_credits_given_to_peer = self.initial_credits;

        let state = DynChannelState {
            inner: DynChannelStateInner::EstablishedCreditBasedChannel {
                peer_channel_id,
                maximum_transmission_size,
                maximum_payload_size,
                credits_given_to_peer: initial_credits_given_to_peer,
                peer_provided_credits: initial_peer_given_credits,
            },
        };

        let cid @ ChannelIdentifier::Le(LeCid::DynamicallyAllocated(destination)) = self
            .signal_channel
            .logical_link
            .establish_dyn_channel(state)
            .map_err(|e| LeCreditResponseError::FailedToCreateChannel(e))?
        else {
            unreachable!()
        };

        let response = LeCreditBasedConnectionResponse::new(
            self.request.identifier,
            destination,
            LeCreditMtu::new(self.mtu),
            LeCreditMps::new(self.mps),
            self.initial_credits,
        );

        self.signal_channel
            .send(response.into_control_frame(self.signal_channel.channel_id))
            .await
            .map_err(|e| LeCreditResponseError::SendErr(e))?;

        let channel = self.signal_channel.logical_link.get_credit_based_channel(cid).unwrap();

        Ok(channel)
    }
}

pub enum LeCreditResponseError<L: LogicalLink> {
    LinkIsNotLeU,
    SendErr(<L::PhysicalLink as PhysicalLink>::SendErr),
    FailedToCreateChannel(NewDynChannelError),
}

impl<L> core::fmt::Debug for LeCreditResponseError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::LinkIsNotLeU => f.debug_tuple(stringify!(LinkIsNotLeU)).finish(),
            Self::SendErr(e) => f.debug_tuple(stringify!(SendErr)).field(e).finish(),
            Self::FailedToCreateChannel(e) => f.debug_tuple(stringify!(FailedToCreateChannel)).field(e).finish(),
        }
    }
}

impl<L: LogicalLink> core::fmt::Display for LeCreditResponseError<L>
where
    <L::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use crate::LinkFlavor;

        match self {
            Self::LinkIsNotLeU => write!(
                f,
                "cannot establish an LE credit based channel on an {} logical link",
                <L::LinkFlavor as LinkFlavor>::name()
            ),
            Self::SendErr(s) => core::fmt::Display::fmt(&s, f),
            Self::FailedToCreateChannel(e) => write!(f, "failed to create new dyn channel, {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<L: LogicalLink> std::error::Error for LeCreditResponseError<L> where
    <L::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display
{
}

/// A response signal from the linked device
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ReceivedResponse<T> {
    response: T,
}

impl<T> ReceivedResponse<T> {
    /// Create a new `Response`
    pub(crate) fn new(response: T) -> Self {
        ReceivedResponse { response }
    }

    /// Get the response
    pub fn into_inner(self) -> T {
        self.response
    }
}

impl<T> core::ops::Deref for ReceivedResponse<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

impl<T> core::ops::DerefMut for ReceivedResponse<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.response
    }
}

impl ReceivedResponse<CommandRejectResponse> {
    /// Send the command rejection response
    pub async fn send_rejection<L: LogicalLink>(
        self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let c_frame = self.response.into_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }
}

impl ReceivedResponse<LeCreditBasedConnectionResponse> {
    /// Create a connection from the LE Credit Based Connection Response
    ///
    /// In order to configure the credit based channel, the request originally sent to the peer
    /// device is needed in order to create the [`CreditBasedChannel`]
    ///
    /// # Error
    /// An error is returned if the result field in the response is anything other than
    /// [`ConnectionSuccessful`], or the link failed to allocate a dynamic channel.
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub fn create_le_credit_connection<L>(
        &self,
        request: &LeCreditBasedConnectionRequest,
        mut signals_channel: SignallingChannel<L>,
    ) -> Result<CreditBasedChannel<L>, CreateLeCreditConnectionError>
    where
        L: LogicalLink,
        L::SduBuffer: Default,
    {
        if let LeCreditBasedConnectionResponseResult::ConnectionSuccessful = self.get_result() {
            let peer_channel_id = ChannelDirection::Destination(self.response.get_destination_cid().unwrap());

            let maximum_payload_size = core::cmp::min(self.response.get_mps().unwrap(), request.mps.get()).into();

            let maximum_transmission_size = core::cmp::min(self.response.get_mtu().unwrap(), request.mtu.get()).into();

            let initial_credits_given_to_peer = request.get_initial_credits();

            let initial_credits_from_peer = self.response.get_initial_credits().unwrap();

            let state = DynChannelState {
                inner: DynChannelStateInner::ReserveCreditBasedChannel {
                    reserved_id: request.get_source_cid(),
                    peer_channel_id,
                    maximum_transmission_size,
                    maximum_payload_size,
                    credits_given_to_peer: initial_credits_given_to_peer,
                    peer_provided_credits: initial_credits_from_peer,
                },
            };

            let cid = signals_channel
                .logical_link
                .establish_dyn_channel(state)
                .map_err(|e| CreateLeCreditConnectionError::DynChannelFail(e))?;

            let new_channel = signals_channel.logical_link.get_credit_based_channel(cid).unwrap();

            Ok(new_channel)
        } else {
            Err(CreateLeCreditConnectionError::ResponseError(self.get_result()))
        }
    }
}

/// The error returned by [`create_le_credit_connection`]
///
///
/// [`create_le_credit_connection`]: ReceivedResponse::<LeCreditBasedConnectionResponse>::create_le_credit_connection
#[derive(Debug)]
pub enum CreateLeCreditConnectionError {
    ResponseError(LeCreditBasedConnectionResponseResult),
    DynChannelFail(NewDynChannelError),
}

impl core::fmt::Display for CreateLeCreditConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CreateLeCreditConnectionError::ResponseError(r) => {
                write!(f, "response contained error {r}")
            }
            CreateLeCreditConnectionError::DynChannelFail(n) => {
                write!(f, "failed to create create channel, {n}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CreateLeCreditConnectionError {}

#[cfg(test)]
mod tests {
    use crate::signalling::{ConvertSignalError, UnknownSignal};

    #[test]
    fn unknown_signal_processor() {
        let test_data: &[&[u8]] = &[&[0xf3, 0, 3, 0, 3, 4, 5], &[0x56, 9, 1, 0, 7]];

        for test in test_data {
            let mut unknown = UnknownSignal::new(test[0], test.len());

            for byte in &test[1..] {
                unknown.process(*byte).unwrap();
            }

            assert!(unknown.is_complete())
        }
    }

    #[test]
    fn unknown_signal_processor_invalid_length_field() {
        let test_data = &[0x99, 0, 20, 0, 1, 2, 3, 4, 5];

        let mut unknown = UnknownSignal::new(test_data[0], test_data.len());

        let err = test_data[1..]
            .iter()
            .try_for_each(|b| unknown.process(*b))
            .expect_err("expected convert signal error");

        let ConvertSignalError::InvalidDataLengthField = err else {
            panic!("expected `ConvertSignalError::InvalidDataLengthField`")
        };
    }
}
