//! Signalling Channel implementation

use crate::channel::id::{AclCid, ChannelIdentifier, DynChannelId, LeCid};
use crate::channel::shared::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::channel::{ChannelBuffer, ConnectionChannel, CreditBasedChannel, MaybeRecvError};
use crate::link_flavor::LeULink;
use crate::pdu::control_frame::{ControlFrame, RecombineError};
use crate::pdu::{FragmentIterator, FragmentL2capPdu, L2capFragment, RecombineL2capPdu, RecombinePayloadIncrementally};
use crate::signals::packets::{
    CommandRejectResponse, DisconnectRequest, DisconnectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse, LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu, Signal,
    SignalCode, SimplifiedProtocolServiceMultiplexer,
};
use crate::{LeULogicalLink, LogicalLink, PhysicalLink, PhysicalLinkExt, LE_STATIC_CHANNEL_COUNT};
use bo_tie_core::buffer::stack::LinearBuffer;
use bo_tie_core::buffer::TryExtend;
use core::num::NonZeroU8;

/// List of response signals and any data required with them
enum AwaitedSignalResponse {
    None,
    LeCreditConnection(InterimCreditConnectionData),
}

impl AwaitedSignalResponse {
    fn on_fail<L: LogicalLink>(&mut self, link: &L) {
        let last = core::mem::replace(self, AwaitedSignalResponse::None);

        match last {
            AwaitedSignalResponse::None => (),
            AwaitedSignalResponse::LeCreditConnection(i) => i.on_fail(link),
        }
    }
}

/// Interim data held awaiting for a response to a LE or enhanced credit connection response
struct InterimCreditConnectionData {
    source_dyn_cid: ChannelIdentifier,
}

impl InterimCreditConnectionData {
    fn on_fail<L: LogicalLink>(self, link: &L) {
        link.get_shared_link().remove_channel(self.source_dyn_cid)
    }
}

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
    awaited_response: AwaitedSignalResponse,
    receiving_signal: ReceiveSignalRecombineBuilder,
}

impl<L> SignallingChannel<L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: L) -> Self {
        let awaited_response = AwaitedSignalResponse::None;

        let receiving_signal = ReceiveSignalRecombineBuilder::default();

        Self {
            channel_id,
            logical_link,
            awaited_response,
            receiving_signal,
        }
    }

    /// Get the channel identifier for this Signalling Channel
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }
}

impl<L: LogicalLink> SignallingChannel<L> {
    /// Get fragmentation size of L2CAP control PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        self.logical_link.get_physical_link().max_transmission_size()
    }

    /// Send a Signal
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    async fn send<T: FragmentL2capPdu>(
        &mut self,
        c_frame: T,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        self.logical_link
            .get_mut_physical_link()
            .send_pdu(c_frame, self.fragmentation_size())
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
    pub async fn request_disconnection<C: ConnectionChannel>(
        &mut self,
        channel: &mut C,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let destination_id = channel.get_peer_channel_id();
        let source_id = channel.get_this_channel_id();

        let disconnect_request = DisconnectRequest::new(NonZeroU8::new(1).unwrap(), destination_id, source_id);

        let c_frame = disconnect_request.into_control_frame(self.channel_id);

        self.send(c_frame).await
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
    ) -> Result<(), PhysicalLink::SendErr> {
        let credit_ind = FlowControlCreditInd::new(
            NonZeroU8::new(1).unwrap(),
            channel_credits.get_channel_id(),
            channel_credits.get_credits(),
        );

        let c_frame = credit_ind.into_control_frame(self.channel_id);

        self.send(c_frame).await
    }

    /// Request a LE Credit Based Connection
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
        buffer: L::Buffer,
    ) -> Result<LeCreditBasedConnectionRequest, CreditConnectionRequestError<<L::PhysicalLink as PhysicalLink>::SendErr>>
    {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)) = self
            .logical_link
            .new_dyn_channel(mps.get(), buffer)
            .ok_or_else(|| CreditConnectionRequestError::NoMoreDynChannels)?
        else {
            return Err(CreditConnectionRequestError::InvalidChannelIdentifier);
        };

        let request = LeCreditBasedConnectionRequest {
            identifier: NonZeroU8::new(1).unwrap(),
            spsm,
            source_dyn_cid: channel_id,
            mtu,
            mps,
            initial_credits,
        };

        let interim_data = InterimCreditConnectionData {
            source_dyn_cid: ChannelIdentifier::Le(LeCid::DynamicallyAllocated(channel_id)),
        };

        self.awaited_response = AwaitedSignalResponse::LeCreditConnection(interim_data);

        let control_frame = request.into_control_frame(self.channel_id);

        self.logical_link
            .get_mut_physical_link()
            .send_pdu(control_frame, self.fragmentation_size())
            .await
            .map_err(|e| CreditConnectionRequestError::SendError(e))?;

        Ok(request)
    }
}

/// Error returned by a credit based connection request
#[derive(Debug)]
pub enum CreditConnectionRequestError<S> {
    SendError(S),
    NotLeULogicalLink,
    NoMoreDynChannels,
    InvalidChannelIdentifier,
}

impl<S> core::fmt::Display for CreditConnectionRequestError<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::SendError(s) => core::fmt::Display::fmt(s, f),
            Self::NotLeULogicalLink => {
                f.write_str("an LE credit based connection can only be created on a LE-U logical link")
            }
            Self::NoMoreDynChannels => f.write_str("no more dynamic channels can be allocated for this link"),
            Self::InvalidChannelIdentifier => f.write_str("invalid channel identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl<S> std::error::Error for CreditConnectionRequestError<S> where S: std::error::Error {}

/// Signal received from the linked device
#[non_exhaustive]
#[derive(Debug)]
pub enum ReceivedSignal {
    /// `UnknownSignal` is used when a signal that cannot be interpreted by this L2CAP
    /// implementation is received by this device.
    ///
    /// # Fields
    /// `u8` => the signal that was not understood.
    /// `Request<CommandRejectResponse>` => This is always a command reject response containing the
    ///    *command not understood* reason. This response is generated by this L2CAP signalling
    ///    implementation in response to the unknown signal and not actually received.
    UnknownSignal(u8, Request<CommandRejectResponse>),
    CommandRejectRsp(Response<CommandRejectResponse>),
    DisconnectRequest(Request<DisconnectRequest>),
    DisconnectResponse(Response<DisconnectResponse>),
    LeCreditBasedConnectionRequest(Request<LeCreditBasedConnectionRequest>),
    LeCreditBasedConnectionResponse(Response<LeCreditBasedConnectionResponse>),
    FlowControlCreditIndication(FlowControlCreditInd),
}

impl ReceivedSignal {
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
            ReceivedSignal::UnknownSignal(_, _)
            | ReceivedSignal::CommandRejectRsp(_)
            | ReceivedSignal::DisconnectResponse(_)
            | ReceivedSignal::LeCreditBasedConnectionResponse(_)
            | ReceivedSignal::FlowControlCreditIndication(_) => Ok(()),
            ReceivedSignal::DisconnectRequest(request) => request.reject_as_not_understood(signalling_channel).await,
            ReceivedSignal::LeCreditBasedConnectionRequest(request) => {
                request.reject_as_not_understood(signalling_channel).await
            }
        }
    }

    fn try_from<F>(builder: ReceiveSignalRecombineBuilder) -> Result<Self, ConvertSignalError>
    where
        F: crate::link_flavor::LinkFlavor,
    {
        match &builder {
            ReceiveSignalRecombineBuilder::Init => Err(ConvertSignalError::IncompleteSignal),
            ReceiveSignalRecombineBuilder::Unknown(unknown) => {
                let signal_code = *unknown.header.get(0).unwrap();

                let command_reject = CommandRejectResponse::new_command_not_understood(
                    unknown.get_identifier().ok_or(ConvertSignalError::IncompleteSignal)?,
                );

                let request = Request::new(command_reject);

                Ok(ReceivedSignal::UnknownSignal(signal_code, request))
            }
            ReceiveSignalRecombineBuilder::CommandRejectRsp(raw) => {
                CommandRejectResponse::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::CommandRejectRsp(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::CommandRejectResponse, e))
            }
            ReceiveSignalRecombineBuilder::DisconnectRequest(raw) => {
                DisconnectRequest::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::DisconnectRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionRequest, e))
            }
            ReceiveSignalRecombineBuilder::DisconnectResponse(raw) => {
                DisconnectResponse::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::DisconnectResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionResponse, e))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionRequest(raw) => {
                LeCreditBasedConnectionRequest::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionRequest, e))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionResponse(raw) => {
                LeCreditBasedConnectionResponse::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionResponse, e))
            }
            ReceiveSignalRecombineBuilder::FlowControlCreditIndication(raw) => {
                FlowControlCreditInd::try_from_raw_control_frame_payload::<F>(raw)
                    .map(|s| ReceivedSignal::FlowControlCreditIndication(s))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::FlowControlCreditIndication, e))
            }
        }
    }
}

/// Receive Error
///
/// This error is returned by the method [`receive`] of `SignallingChannel`.
///
/// [`receive`]: SignallingChannel::receive
pub enum ReceiveSignalError<L: LogicalLink> {
    Disconnected,
    RecvErr(<L::PhysicalLink as PhysicalLink>::RecvErr),
    InvalidChannel(crate::channel::InvalidChannel),
    Convert(ConvertSignalError),
    Recombine(RecombineError),
    ExpectedFirstFragment,
    UnexpectedFirstFragment,
}

impl<L> core::fmt::Debug for ReceiveSignalError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReceiveSignalError::Disconnected => f.write_str("Disconnected"),
            ReceiveSignalError::RecvErr(e) => write!(f, "RecvErr({e:?})"),
            ReceiveSignalError::InvalidChannel(c) => core::fmt::Debug::fmt(c, f),
            ReceiveSignalError::Convert(c) => core::fmt::Debug::fmt(c, f),
            ReceiveSignalError::Recombine(r) => core::fmt::Debug::fmt(r, f),
            ReceiveSignalError::ExpectedFirstFragment => f.write_str("ExpectedFirstFragment"),
            ReceiveSignalError::UnexpectedFirstFragment => f.write_str("UnexpectedFirstFragment"),
        }
    }
}

impl<L> core::fmt::Display for ReceiveSignalError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReceiveSignalError::Disconnected => f.write_str("peer device disconnected"),
            ReceiveSignalError::RecvErr(e) => write!(f, "failed to receive signal, {e}"),
            ReceiveSignalError::InvalidChannel(c) => core::fmt::Display::fmt(c, f),
            ReceiveSignalError::Convert(c) => core::fmt::Display::fmt(c, f),
            ReceiveSignalError::Recombine(r) => core::fmt::Display::fmt(r, f),
            ReceiveSignalError::ExpectedFirstFragment => f.write_str("expected first fragment of PDU"),
            ReceiveSignalError::UnexpectedFirstFragment => f.write_str("unexpected first fragment of PDU"),
        }
    }
}

impl<L: LogicalLink> From<MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>> for ReceiveSignalError<L> {
    fn from(value: MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>) -> Self {
        match value {
            MaybeRecvError::Disconnected => ReceiveSignalError::Disconnected,
            MaybeRecvError::RecvError(e) => ReceiveSignalError::RecvErr(e),
            MaybeRecvError::InvalidChannel(c) => ReceiveSignalError::InvalidChannel(c),
        }
    }
}

impl<L: LogicalLink> From<ConvertSignalError> for ReceiveSignalError<L> {
    fn from(value: ConvertSignalError) -> Self {
        ReceiveSignalError::Convert(value)
    }
}

impl<L: LogicalLink> From<RecombineError> for ReceiveSignalError<L> {
    fn from(value: RecombineError) -> Self {
        ReceiveSignalError::Recombine(value)
    }
}

#[cfg(feature = "std")]
impl<L: LogicalLink> std::error::Error for ReceiveSignalError<L> where
    ReceiveSignalError<L>: core::fmt::Debug + core::fmt::Display
{
}

/// A recombine builder for a `ReceivedSignal`
///
/// This is used whenever a control signal is [received] to convert the transmission data into a
/// signal type.
///
/// # Enumerations
/// [received]: SignallingChannel::receive
#[derive(Default)]
enum ReceiveSignalRecombineBuilder {
    // state used before the signalling code is received
    #[default]
    Init,
    // Used for a error condition where the L2CAP signalling packet is 'unknown'
    Unknown(UnknownSignal),
    CommandRejectRsp(LinearBuffer<8, u8>),
    DisconnectRequest(LinearBuffer<8, u8>),
    DisconnectResponse(LinearBuffer<8, u8>),
    LeCreditBasedConnectionRequest(LinearBuffer<14, u8>),
    LeCreditBasedConnectionResponse(LinearBuffer<14, u8>),
    FlowControlCreditIndication(LinearBuffer<8, u8>),
}

impl ReceiveSignalRecombineBuilder {
    fn first_byte(&mut self, first: u8) {
        match SignalCode::try_from_code(first) {
            Ok(SignalCode::CommandRejectResponse) => *self = Self::CommandRejectRsp([first].into()),
            Ok(SignalCode::DisconnectionRequest) => *self = Self::DisconnectRequest([first].into()),
            Ok(SignalCode::DisconnectionResponse) => *self = Self::DisconnectResponse([first].into()),
            Ok(SignalCode::LeCreditBasedConnectionRequest) => {
                *self = Self::LeCreditBasedConnectionRequest([first].into())
            }
            Ok(SignalCode::LeCreditBasedConnectionResponse) => {
                *self = Self::LeCreditBasedConnectionResponse([first].into())
            }
            Ok(SignalCode::FlowControlCreditIndication) => *self = Self::FlowControlCreditIndication([first].into()),
            Err(_) | Ok(_) => *self = Self::Unknown(UnknownSignal::new(first)),
        }
    }
}

impl TryExtend<u8> for ReceiveSignalRecombineBuilder {
    type Error = ConvertSignalError;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        for byte in iter {
            match self {
                Self::Init => self.first_byte(byte),
                Self::Unknown(unknown) => unknown.process(byte)?,
                Self::CommandRejectRsp(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::DisconnectRequest(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::DisconnectResponse(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::LeCreditBasedConnectionRequest(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::LeCreditBasedConnectionResponse(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
                Self::FlowControlCreditIndication(buffer) => buffer
                    .try_push(byte)
                    .map_err(|_| ConvertSignalError::ReceivedSignalTooLong)?,
            }
        }

        Ok(())
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

struct UnknownSignal {
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
        logical_link: &L,
    ) -> Result<(), Response<CommandRejectResponse>> {
        if logical_link
            .get_shared_link()
            .is_channel_used(self.request.destination_cid)
        {
            Ok(())
        } else {
            let rejection = CommandRejectResponse::new_invalid_cid_in_request(
                self.request.identifier,
                self.request.destination_cid.to_val(),
                self.request.source_cid.to_val(),
            );

            let response = Response::new(rejection);

            Err(response)
        }
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
    pub fn create_le_credit_based_connection<P: PhysicalLink, B>(
        &self,
        link: &mut LeULogicalLink<P, B>,
        initial_credits: u16,
        buffer: B,
    ) -> LeCreditBasedConnectionResponseBuilder<'_> {
        let ChannelIdentifier::Le(LeCid::DynamicallyAllocated(destination_dyn_cid)) = link
            .new_dyn_channel(self.request.mps.get(), buffer)
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
    destination_dyn_cid: crate::channel::id::DynChannelId<LeULink>,
    mtu: u16,
    mps: u16,
    initial_credits: u16,
}

impl LeCreditBasedConnectionResponseBuilder<'_> {
    /// Get the destination channel identifier
    ///
    /// This will be the identifier of the channel created by the output of [`send_response`]
    ///
    /// [`send_response`]: LeCreditBasedConnectionResponseBuilder::send_response
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
    /// This sends the response to the peer device and returns a [`CreditBasedChannel`] for the new
    /// connection.
    ///
    /// # Note
    /// The result field within the response will be [`ConnectionSuccessful`]
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub async fn send_response<P: PhysicalLink, B>(
        self,
        signals_channel: &mut SignallingChannel<LeULogicalLink<P, B>>,
        buffer: B,
    ) -> Result<(), P::SendErr> {
        use core::cmp::min;

        let response = LeCreditBasedConnectionResponse::new(
            self.request.identifier,
            self.destination_dyn_cid,
            LeCreditMtu::new(self.mtu),
            LeCreditMps::new(self.mps),
            self.initial_credits,
        );

        signals_channel
            .send(response.into_control_frame(signals_channel.channel_id))
            .await?;

        let index = (self.destination_dyn_cid.get_val() - DynChannelId::<LeULink>::LE_BOUNDS.start()) as usize
            + LE_STATIC_CHANNEL_COUNT;

        let peer_channel_id = crate::channel::ChannelDirection::Source(self.request.get_source_cid());

        let maximum_packet_size = min(self.mps, self.request.mps.get()).into();

        let maximum_transmission_size = min(self.mtu, self.request.mtu.get()).into();

        let initial_peer_credits = self.request.initial_credits.into();

        let initial_this_credits = self.initial_credits.into();

        let channel_buffer = ChannelBuffer::CreditBasedChannel {
            peer_channel_id,
            maximum_packet_size,
            maximum_transmission_size,
            peer_credits: initial_peer_credits,
            this_credits: initial_this_credits,
            buffer,
        };

        signals_channel.logical_link.channels[index] = channel_buffer;

        Ok(())
    }
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
    /// [`ConnectionSuccessful`]
    ///
    /// [`ConnectionSuccessful`]: LeCreditBasedConnectionResponseResult::ConnectionSuccessful
    pub fn create_le_credit_connection<P: PhysicalLink, B>(
        &self,
        request: &LeCreditBasedConnectionRequest,
        link: &mut LeULogicalLink<P, B>,
    ) -> Result<(), LeCreditBasedConnectionResponseResult> {
        if let LeCreditBasedConnectionResponseResult::ConnectionSuccessful = self.get_result() {
            let index = (request.get_source_cid().get_val() - DynChannelId::<LeULink>::LE_BOUNDS.start()) as usize
                + LE_STATIC_CHANNEL_COUNT;

            let peer_channel_id =
                crate::channel::ChannelDirection::Destination(self.response.get_destination_cid().unwrap());

            let maximum_packet_size = core::cmp::min(self.response.get_mps().unwrap().get(), request.mps.get()).into();

            let maximum_transmission_size =
                core::cmp::min(self.response.get_mtu().unwrap().get(), request.mtu.get()).into();

            let initial_peer_credits = self.response.get_initial_credits().unwrap().into();

            let initial_this_credits = request.initial_credits.into();

            let channel_buffer = ChannelBuffer::CreditBasedChannel {
                peer_channel_id,
                maximum_packet_size,
                maximum_transmission_size,
                peer_credits: initial_peer_credits,
                this_credits: initial_this_credits,
                buffer,
            };

            link.channels[index] = channel_buffer;

            Ok(())
        } else {
            Err(self.get_result())
        }
    }
}
