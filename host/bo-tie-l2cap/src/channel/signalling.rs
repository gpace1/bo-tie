//! Signalling Channel implementation

use crate::channel::id::{AclCid, ChannelIdentifier, DynChannelId, LeCid};
use crate::channel::{ChannelDirection, DynChannelState, DynChannelStateInner, LeUChannelBuffer};
use crate::link_flavor::LeULink;
use crate::logical_link_private::NewDynChannelError;
use crate::pdu::{FragmentL2capPdu, RecombineL2capPdu, RecombinePayloadIncrementally};
use crate::signals::packets::{
    CommandRejectResponse, DisconnectRequest, DisconnectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse, LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu, Signal,
    SignalCode, SimplifiedProtocolServiceMultiplexer,
};
use crate::{LogicalLink, PhysicalLink, PhysicalLinkExt};
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
        let max_transmission_size = self.logical_link.get_physical_link().max_transmission_size().into();

        self.logical_link
            .get_mut_physical_link()
            .send_pdu(c_frame, max_transmission_size)
            .await
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
        this_channel_id: ChannelIdentifier,
    ) -> Result<(), RequestDisconnectError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        match this_channel_id {
            ChannelIdentifier::Le(LeCid::DynamicallyAllocated(_))
            | ChannelIdentifier::Acl(AclCid::DynamicallyAllocated(_)) => (),
            _ => return Err(RequestDisconnectError::NotAConnectionChannel(this_channel_id)),
        }

        let channel_buffer = self
            .logical_link
            .get_dyn_channel(this_channel_id)
            .ok_or_else(|| RequestDisconnectError::NoChannelFoundForId(this_channel_id))?;

        match channel_buffer {
            LeUChannelBuffer::CreditBasedChannel { data } => {
                let (source_id, destination_id) = match &data.peer_channel_id {
                    ChannelDirection::Source(s) => (*s, this_channel_id),
                    ChannelDirection::Destination(d) => (this_channel_id, *d),
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
        let dyn_channel_buffer_builder = DynChannelState(DynChannelStateInner::ReserveCreditBasedChannel);

        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = self
            .logical_link
            .new_dyn_channel(dyn_channel_buffer_builder)
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
        reject_response: Request<CommandRejectResponse>,
    },
    CommandRejectRsp(Response<CommandRejectResponse>),
    DisconnectRequest(Request<DisconnectRequest>),
    DisconnectResponse(Response<DisconnectResponse>),
    LeCreditBasedConnectionRequest(Request<LeCreditBasedConnectionRequest>),
    LeCreditBasedConnectionResponse(Response<LeCreditBasedConnectionResponse>),
    FlowControlCreditIndication(FlowControlCreditInd),
}

impl ReceivedLeUSignal {
    /// Reject or ignore the received Signal
    ///
    /// If this `ReceivedSignal` is a request, then a *Command Reject Response* is sent to the other
    /// device with the command not understood reason. If this is not a request then the received
    /// signal is ignored and no reject signal is sent.
    pub async fn reject_or_ignore<L: LogicalLink>(
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

                let request = Request::new(command_reject);

                Ok(ReceivedLeUSignal::UnknownSignal {
                    code: signal_code,
                    reject_response: request,
                })
            }
            ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp(raw) => {
                CommandRejectResponse::try_from_raw_control_frame_payload::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::CommandRejectRsp(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::CommandRejectResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::DisconnectRequest(raw) => {
                DisconnectRequest::try_from_raw_control_frame_payload::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::DisconnectRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionRequest, e))
            }
            ReceiveLeUSignalRecombineBuilderState::DisconnectResponse(raw) => {
                DisconnectResponse::try_from_raw_control_frame_payload::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::DisconnectResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest(raw) => {
                LeCreditBasedConnectionRequest::try_from_raw_control_frame_payload::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::LeCreditBasedConnectionRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionRequest, e))
            }
            ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse(raw) => {
                LeCreditBasedConnectionResponse::try_from_raw_control_frame_payload::<LeULink>(raw)
                    .map(|s| ReceivedLeUSignal::LeCreditBasedConnectionResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionResponse, e))
            }
            ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication(raw) => {
                FlowControlCreditInd::try_from_raw_control_frame_payload::<LeULink>(raw)
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
        _: u16,
        _: ChannelIdentifier,
        _: Self::RecombineBuffer<'a>,
        _: Self::RecombineMeta<'a>,
    ) -> Self::PayloadRecombiner<'a> {
        ReceiveLeUSignalRecombineBuilder::default()
    }
}

/// A recombine builder for a `ReceivedSignal`
///
/// This is used whenever a control signal is [received] to convert the transmission data into a
/// signal type.
///
/// # Enumerations
/// [received]: SignallingChannel::receive
#[derive(Default)]
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

#[derive(Default)]
pub struct ReceiveLeUSignalRecombineBuilder {
    state: ReceiveLeUSignalRecombineBuilderState,
}

impl ReceiveLeUSignalRecombineBuilder {
    fn first_byte(&mut self, first: u8) {
        match SignalCode::try_from_code(first) {
            Ok(SignalCode::CommandRejectResponse) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::CommandRejectRsp([first].into())
            }
            Ok(SignalCode::DisconnectionRequest) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::DisconnectRequest([first].into())
            }
            Ok(SignalCode::DisconnectionResponse) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::DisconnectResponse([first].into())
            }
            Ok(SignalCode::LeCreditBasedConnectionRequest) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionRequest([first].into())
            }
            Ok(SignalCode::LeCreditBasedConnectionResponse) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::LeCreditBasedConnectionResponse([first].into())
            }
            Ok(SignalCode::FlowControlCreditIndication) => {
                self.state = ReceiveLeUSignalRecombineBuilderState::FlowControlCreditIndication([first].into())
            }
            Err(_) | Ok(_) => self.state = ReceiveLeUSignalRecombineBuilderState::Unknown(UnknownSignal::new(first)),
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
}

impl RecombinePayloadIncrementally for ReceiveLeUSignalRecombineBuilder {
    type Pdu = ReceivedLeUSignal;

    type RecombineBuffer = ();

    type RecombineError = ConvertSignalError;

    fn add<T>(&mut self, payload_fragment: T) -> Result<Option<Self::Pdu>, Self::RecombineError>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        for byte in payload_fragment {
            match &mut self.state {
                ReceiveLeUSignalRecombineBuilderState::Init => self.first_byte(byte),
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
    InvalidFormat(SignalCode, crate::signals::SignalError),
}

impl core::fmt::Display for ConvertSignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("the received signal is invalid")?;

        match self {
            ConvertSignalError::ReceivedSignalTooLong => f.write_str(", more bytes received than expected"),
            ConvertSignalError::IncompleteSignal => f.write_str(", signal is incomplete"),
            ConvertSignalError::InvalidFormat(code, err) => write!(f, ", invalid format for signal {code}: {err}"),
        }
    }
}

pub struct UnknownSignal {
    header: LinearBuffer<4, u8>,
    expected_len: usize,
    bytes_received: usize,
}

impl UnknownSignal {
    fn new(code: u8) -> Self {
        let header = [code].into();
        let expected_len = 0;
        let bytes_received = 0;

        Self {
            header,
            expected_len,
            bytes_received,
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

                self.expected_len = expected_len;

                Ok(())
            }
            _ => {
                self.bytes_received += 1;

                if self.bytes_received > self.expected_len {
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
        self.header.len() == 4 && self.expected_len == self.bytes_received
    }
}

/// A Request Signal from the Linked Device
///
/// This is returned whenever a request is received by a Signalling Channel. Depending on the type
/// of request (`T`) there are different operations done.
#[derive(Debug, Copy, Clone)]
pub struct Request<T> {
    request: T,
}

impl<T> Request<T> {
    /// Create a new `Request`
    pub fn new(request: T) -> Self {
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

impl<T> core::ops::Deref for Request<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl<T> core::ops::DerefMut for Request<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl Request<CommandRejectResponse> {
    /// Send the command rejection response
    pub async fn send_rejection<L: LogicalLink>(
        self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let c_frame = self.request.into_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }
}

impl Request<DisconnectRequest> {
    /// Check that a requested disconnect is valid
    ///
    /// A disconnect request contains the source and destination channel identifiers of a L2CAP
    /// connection. This is used to check if is a connection channel with the *destination* channel
    /// identifier exists for the `logical_link`.
    ///
    /// If there is no channel associated with the destination channel identifier then an error is
    /// returned containing a command reject response that should be sent to the peer device. This
    /// rejection response contains the *invalid CID in request* reason.
    pub fn check_disconnect_request<L: LogicalLink>(
        &self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), Response<CommandRejectResponse>> {
        signalling_channel
            .logical_link
            .remove_dyn_channel(self.request.destination_cid)
            .then_some(())
            .ok_or_else(|| {
                let rejection = CommandRejectResponse::new_invalid_cid_in_request(
                    self.request.identifier,
                    self.request.destination_cid.to_val(),
                    self.request.source_cid.to_val(),
                );

                let response = Response::new(rejection);

                response
            })
    }

    pub async fn send_disconnect_response<L: LogicalLink>(
        &self,
        signalling_channel: &mut SignallingChannel<L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let response = DisconnectResponse {
            identifier: self.request.identifier,
            destination_cid: self.request.destination_cid,
            source_cid: self.request.source_cid,
        };

        let c_frame = response.into_control_frame(signalling_channel.channel_id);

        signalling_channel.send(c_frame).await
    }
}

impl Request<LeCreditBasedConnectionRequest> {
    /// Create a LE Credit Based Connection
    ///
    /// This returns a `LeCreditBasedConnectionResponseBuilder` to configure the LE credit based
    /// connection response to this request and create a [`CreditBasedChannel`] for the connection.
    ///
    /// # Panic
    /// This method will panic if there are no more dynamic channels that can be allocated for a
    /// LE-U logical link.
    pub fn create_le_credit_based_connection<L: LogicalLink>(
        &self,
        signal_channel: &mut SignallingChannel<L>,
        initial_credits: u16,
    ) -> LeCreditBasedConnectionResponseBuilder<'_> {
        let peer_channel_id = ChannelDirection::Source(ChannelIdentifier::Le(LeCid::DynamicallyAllocated(
            self.request.source_dyn_cid,
        )));

        let dyn_channel_state = DynChannelState(DynChannelStateInner::EstablishedCreditBasedChannel {
            peer_channel_id,
            maximum_transmission_size: self.mtu.get(),
            maximum_payload_size: self.mps.get(),
            peer_credits: self.initial_credits,
        });

        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(destination_dyn_cid)) = signal_channel
            .logical_link
            .new_dyn_channel(dyn_channel_state)
            .expect("failed to create a dynamic channel")
        else {
            panic!("link returned invalid channel")
        };

        LeCreditBasedConnectionResponseBuilder {
            request: &self.request,
            destination_dyn_cid,
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
pub struct LeCreditBasedConnectionResponseBuilder<'a> {
    request: &'a LeCreditBasedConnectionRequest,
    destination_dyn_cid: DynChannelId<LeULink>,
    mtu: u16,
    mps: u16,
    initial_credits: u16,
}

impl LeCreditBasedConnectionResponseBuilder<'_> {
    /// Get the destination channel identifier
    ///
    /// This will be the identifier of the channel created by the output of [`send_success_response`]
    ///
    /// [`send_success_response`]: LeCreditBasedConnectionResponseBuilder::send_success_response
    pub fn get_destination_channel(&self) -> ChannelIdentifier {
        ChannelIdentifier::Le(LeCid::DynamicallyAllocated(self.destination_dyn_cid))
    }

    /// Get the initial credits
    ///
    /// This returns the initial credits that were used to create this
    /// `LeCreditBasedConnectionResponseBuilder`
    pub fn get_initial_credits(&self) -> u16 {
        self.initial_credits
    }

    /// Set the maximum payload size (MPS)
    ///
    /// This sets the MPS within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MPS.
    pub fn set_responded_mps(&mut self, mps: u16) {
        self.mps = core::cmp::min(mps, self.request.mps.get())
    }

    /// Set the maximum transmission unit (MTU)
    ///
    /// This sets the MTU within the *LE Credit Based Connection Response* only if it is smaller
    /// than the request's MTS.
    pub fn set_responded_mtu(&mut self, mtu: u16) {
        self.mtu = core::cmp::min(mtu, self.request.mtu.get())
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
    /// # Error
    /// If this was not called on an LE-U logical link or there was an error sending the response.
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub async fn send_success_response<L: LogicalLink>(
        self,
        signals_channel: &mut SignallingChannel<L>,
    ) -> Result<(), LeCreditResponseError<L>> {
        use crate::LinkFlavor;
        use core::cmp::min;

        L::LinkFlavor::try_channel_from_raw(self.destination_dyn_cid.get_val())
            .ok_or_else(|| LeCreditResponseError::LinkIsNotLeU)?;

        let response = LeCreditBasedConnectionResponse::new(
            self.request.identifier,
            self.destination_dyn_cid,
            LeCreditMtu::new(self.mtu),
            LeCreditMps::new(self.mps),
            self.initial_credits,
        );

        signals_channel
            .send(response.into_control_frame(signals_channel.channel_id))
            .await
            .map_err(|e| LeCreditResponseError::SendErr(e))?;

        let peer_channel_id = ChannelDirection::Source(self.request.get_source_cid());

        let maximum_payload_size = min(self.mps, self.request.mps.get()).into();

        let maximum_transmission_size = min(self.mtu, self.request.mtu.get()).into();

        let initial_peer_credits = self.request.initial_credits.into();

        let state = DynChannelState(DynChannelStateInner::EstablishedCreditBasedChannel {
            peer_channel_id,
            maximum_transmission_size,
            maximum_payload_size,
            peer_credits: initial_peer_credits,
        });

        signals_channel
            .logical_link
            .new_dyn_channel(state)
            .map_err(|e| LeCreditResponseError::FailedToCreateChannel(e))?;

        Ok(())
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
#[derive(Debug, Copy, Clone)]
pub struct Response<T> {
    response: T,
}

impl<T> Response<T> {
    /// Create a new `Response`
    pub fn new(response: T) -> Self {
        Response { response }
    }

    /// Get the response
    pub fn into_inner(self) -> T {
        self.response
    }
}

impl<T> core::ops::Deref for Response<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

impl<T> core::ops::DerefMut for Response<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.response
    }
}

impl Response<LeCreditBasedConnectionResponse> {
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
    pub fn create_le_credit_connection<L: LogicalLink>(
        &self,
        request: &LeCreditBasedConnectionRequest,
        signals_channel: &mut SignallingChannel<L>,
    ) -> Result<(), CreateLeCreditConnectionError> {
        if let LeCreditBasedConnectionResponseResult::ConnectionSuccessful = self.get_result() {
            let peer_channel_id = ChannelDirection::Destination(self.response.get_destination_cid().unwrap());

            let maximum_payload_size = core::cmp::min(self.response.get_mps().unwrap().get(), request.mps.get()).into();

            let maximum_transmission_size =
                core::cmp::min(self.response.get_mtu().unwrap().get(), request.mtu.get()).into();

            let initial_peer_credits = self.response.get_initial_credits().unwrap().into();

            let state = DynChannelState(DynChannelStateInner::EstablishedCreditBasedChannel {
                peer_channel_id,
                maximum_transmission_size,
                maximum_payload_size,
                peer_credits: initial_peer_credits,
            });

            signals_channel
                .logical_link
                .new_dyn_channel(state)
                .map_err(|e| CreateLeCreditConnectionError::DynChannelFail(e))?;

            Ok(())
        } else {
            Err(CreateLeCreditConnectionError::ResponseError(self.get_result()))
        }
    }
}

/// The error returned by [`create_le_credit_connection`]
///
///
/// [`create_le_credit_connection`]: Response::<LeCreditBasedConnectionResponse>::create_le_credit_connection
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
