//! Signalling Channel implementation

use crate::channel::id::{AclCid, ChannelIdentifier, LeCid};
use crate::channel::shared::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::channel::{BasicHeadedFragment, ConnectionChannel, CreditBasedChannel, MaybeRecvError};
use crate::pdu::control_frame::{ControlFrame, RecombineError};
use crate::pdu::{FragmentIterator, FragmentL2capPdu, L2capFragment, RecombineL2capPdu, RecombinePayloadIncrementally};
use crate::signals::packets::{
    CommandRejectResponse, DisconnectRequest, DisconnectResponse, FlowControlCreditInd, LeCreditBasedConnectionRequest,
    LeCreditBasedConnectionResponse, LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu, Signal,
    SignalCode, SimplifiedProtocolServiceMultiplexer,
};
use crate::{LeULogicalLink, LogicalLink, PhysicalLink};
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

/// The 'inner' field of `SignallingChannel`
struct SignallingChannelInner<'a, L> {
    channel_id: ChannelIdentifier,
    logical_link: &'a L,
}

impl<L: LogicalLink> SignallingChannelInner<'_, L> {
    pub fn fragmentation_size(&self) -> usize {
        self.logical_link.get_shared_link().get_fragmentation_size()
    }

    async fn send_fragment<T>(
        &mut self,
        fragment: L2capFragment<T>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |context| {
            self.logical_link
                .get_shared_link()
                .maybe_send(context, self.channel_id, fragment.take().unwrap())
        })
        .await
        .await
    }

    async fn send_inner<T: FragmentL2capPdu>(
        &mut self,
        c_frame: T,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let mut is_first = true;

        let mut fragments_iter = c_frame.into_fragments(self.fragmentation_size()).unwrap();

        while let Some(data) = fragments_iter.next() {
            let fragment = L2capFragment::new(is_first, data);

            is_first = false;

            self.send_fragment(fragment).await?;
        }

        Ok(())
    }

    async fn receive_fragment(
        &mut self,
    ) -> Result<
        BasicHeadedFragment<<L::PhysicalLink as PhysicalLink>::RecvData>,
        MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>,
    > {
        loop {
            match self
                .logical_link
                .get_shared_link()
                .maybe_recv::<L>(self.channel_id)
                .await
            {
                Ok(Ok(f)) => break Ok(f),
                Ok(Err(reject_response)) => {
                    let output = self.send_inner(reject_response).await;

                    self.logical_link.get_shared_link().clear_owner();

                    output.map_err(|_| MaybeRecvError::Disconnected)?;
                }
                Err(e) => {
                    self.logical_link.get_shared_link().clear_owner();

                    break Err(e);
                }
            }
        }
    }

    async fn receive_inner(
        &mut self,
        buffer: &mut ReceiveSignalRecombineBuilder,
    ) -> Result<ReceivedSignal, ReceiveSignalError<L>> {
        let basic_headed_fragment = self.receive_fragment().await?;

        if !basic_headed_fragment.is_start_of_data() {
            return Err(ReceiveSignalError::ExpectedFirstFragment);
        }

        let meta = &mut ();

        let mut recombiner = ControlFrame::recombine(
            basic_headed_fragment.get_pdu_length(),
            basic_headed_fragment.get_channel_id(),
            buffer,
            meta,
        );

        let c_frame = if let Some(c_frame) = recombiner.add(basic_headed_fragment.into_data())? {
            c_frame
        } else {
            loop {
                let basic_headed_fragment = self.receive_fragment().await?;

                if basic_headed_fragment.is_start_of_data() {
                    return Err(ReceiveSignalError::UnexpectedFirstFragment);
                }

                if let Some(c_frame) = recombiner.add(basic_headed_fragment.into_data())? {
                    break c_frame;
                }
            }
        };

        let received_signal = match self.channel_id {
            ChannelIdentifier::Acl(AclCid::SignalingChannel) => {
                ReceivedSignal::try_from::<crate::AclULink>(c_frame.into_payload())?
            }
            ChannelIdentifier::Le(LeCid::LeSignalingChannel) => {
                ReceivedSignal::try_from::<crate::LeULink>(c_frame.into_payload())?
            }
            _ => unreachable!(),
        };

        Ok(received_signal)
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
pub struct SignallingChannel<'a, L: LogicalLink> {
    inner: SignallingChannelInner<'a, L>,
    awaited_response: AwaitedSignalResponse,
    receiving_signal: ReceiveSignalRecombineBuilder,
}

impl<'a, L: LogicalLink> SignallingChannel<'a, L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: &'a L) -> Self {
        assert!(
            logical_link.get_shared_link().add_channel(channel_id),
            "channel already exists"
        );

        let inner = SignallingChannelInner {
            channel_id,
            logical_link,
        };

        let awaited_response = AwaitedSignalResponse::None;

        let receiving_signal = ReceiveSignalRecombineBuilder::default();

        Self {
            inner,
            awaited_response,
            receiving_signal,
        }
    }
}

impl<L: LogicalLink> SignallingChannel<'_, L> {
    /// Get the channel identifier for this Signalling Channel
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.inner.channel_id
    }

    /// Get the logical link of the channel
    pub fn get_link(&self) -> &L {
        self.inner.logical_link
    }

    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        self.inner.fragmentation_size()
    }

    /// Send a Signal
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    async fn send<T: FragmentL2capPdu>(
        &mut self,
        c_frame: T,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let output = self.inner.send_inner(c_frame).await;

        self.inner.logical_link.get_shared_link().clear_owner();

        output
    }

    /// Receive a Signal on this Channel
    ///
    /// This awaits for a signal to be received by this channel. The output `ReceivedSignal` is an
    /// enum of the signal type that was received.
    ///
    /// ```
    /// # use std::future::Future;
    /// use bo_tie_l2cap::{LeULogicalLink, SignallingChannel};
    /// use bo_tie_l2cap::channel::signalling::ReceivedSignal;
    ///
    /// # fn link<P: bo_tie_l2cap::PhysicalLink>(link: LeULogicalLink<P>) -> impl Future + Send {
    /// # async move {
    ///     let mut signalling_channel = link.get_signalling_channel();
    ///
    ///     // maybe put this in a loop
    ///     match signalling_channel.receive().await? {
    ///         ReceivedSignal::UnknownSignal(_, rsp) => {
    ///             rsp.send_rejection(&mut signalling_channel).await?;
    ///         }
    ///         
    ///         // process other signals
    ///         
    ///         _ => (), // ignored signals
    ///     }
    /// # }}
    /// ```
    /// Receive a Basic Frame for this Channel
    ///
    /// This creates a `receive` future which will output the next `BasicFrame` sent to this
    /// channel.
    ///
    /// # Note
    /// The signalling channels' `receive` future does not suffer from the issues listed within the
    /// [channel] module documentation.
    ///
    /// [channel]: self
    pub async fn receive(&mut self) -> Result<ReceivedSignal, ReceiveSignalError<L>> {
        let output = self.inner.receive_inner(&mut self.receiving_signal).await;

        self.inner.logical_link.get_shared_link().clear_owner();

        if let Ok(ReceivedSignal::CommandRejectRsp(_)) = &output {
            self.awaited_response.on_fail(self.inner.logical_link)
        }

        output
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

        let c_frame = disconnect_request.into_control_frame(self.inner.channel_id);

        self.send(c_frame).await
    }

    /// Give credits to the peer device
    ///
    /// This sends a *flow control credit indication* to the peer device to increase the credit
    /// amount for this channel by `credits`. The number of credits will be increased for the
    /// provided `credit_channel` and the peer device will be able to send up to `credits` amount
    /// of PDUs plus any amount credits that the peer already had.
    pub async fn give_credits_to_peer(
        &mut self,
        credit_channel: &CreditBasedChannel<'_, L>,
        credits: u16,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let credit_ind = FlowControlCreditInd::new(
            NonZeroU8::new(1).unwrap(),
            credit_channel.get_this_channel_id(),
            credits,
        );

        let c_frame = credit_ind.into_control_frame(self.inner.channel_id);

        self.send(c_frame).await
    }
}

impl<P: PhysicalLink> SignallingChannel<'_, LeULogicalLink<P>> {
    /// Request a LE Credit Based Connection
    ///
    /// This will send the request to create a LE credit based connection with the linked device. A
    /// connection is not completed until a response is received via the method [`receive`].
    ///
    /// # Output
    /// The output is a copy of the request sent to the linked device.
    ///
    /// # Error
    /// An error is returned if all dynamic channels for the logical link are already used.
    ///
    /// [`receive`]: SignallingChannel::receive
    pub async fn request_le_credit_connection(
        &mut self,
        spsm: SimplifiedProtocolServiceMultiplexer,
        mtu: LeCreditMtu,
        mps: LeCreditMps,
        initial_credits: u16,
    ) -> Result<LeCreditBasedConnectionRequest, CreditConnectionRequestError<P::SendErr>> {
        let channel_id = self
            .inner
            .logical_link
            .get_shared_link()
            .new_le_dyn_channel()
            .ok_or_else(|| CreditConnectionRequestError::NoMoreDynChannels)?;

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

        let control_frame = request.into_control_frame(self.inner.channel_id);

        self.send(control_frame)
            .await
            .map_err(|e| CreditConnectionRequestError::SendError(e))?;

        Ok(request)
    }
}

impl<L: LogicalLink> Drop for SignallingChannel<'_, L> {
    fn drop(&mut self) {
        self.inner
            .logical_link
            .get_shared_link()
            .remove_channel(self.inner.channel_id)
    }
}

/// Error returned by a credit based connection request
#[derive(Debug)]
pub enum CreditConnectionRequestError<S> {
    SendError(S),
    NoMoreDynChannels,
}

impl<S> core::fmt::Display for CreditConnectionRequestError<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::SendError(s) => core::fmt::Display::fmt(s, f),
            Self::NoMoreDynChannels => f.write_str("no more dynamic channels can be allocated for this link"),
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
        signalling_channel: &mut SignallingChannel<'_, L>,
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

    fn try_from<L>(builder: ReceiveSignalRecombineBuilder) -> Result<Self, ConvertSignalError>
    where
        L: crate::link_flavor::LinkFlavor,
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
                CommandRejectResponse::try_from_raw_control_frame_payload::<L>(raw)
                    .map(|s| ReceivedSignal::CommandRejectRsp(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::CommandRejectResponse, e))
            }
            ReceiveSignalRecombineBuilder::DisconnectRequest(raw) => {
                DisconnectRequest::try_from_raw_control_frame_payload::<L>(raw)
                    .map(|s| ReceivedSignal::DisconnectRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionRequest, e))
            }
            ReceiveSignalRecombineBuilder::DisconnectResponse(raw) => {
                DisconnectResponse::try_from_raw_control_frame_payload::<L>(raw)
                    .map(|s| ReceivedSignal::DisconnectResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::DisconnectionResponse, e))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionRequest(raw) => {
                LeCreditBasedConnectionRequest::try_from_raw_control_frame_payload::<L>(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionRequest(Request::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionRequest, e))
            }
            ReceiveSignalRecombineBuilder::LeCreditBasedConnectionResponse(raw) => {
                LeCreditBasedConnectionResponse::try_from_raw_control_frame_payload::<L>(raw)
                    .map(|s| ReceivedSignal::LeCreditBasedConnectionResponse(Response::new(s)))
                    .map_err(|e| ConvertSignalError::InvalidFormat(SignalCode::LeCreditBasedConnectionResponse, e))
            }
            ReceiveSignalRecombineBuilder::FlowControlCreditIndication(raw) => {
                FlowControlCreditInd::try_from_raw_control_frame_payload::<L>(raw)
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
    DumpRecvError(
        <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error,
    ),
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
            ReceiveSignalError::DumpRecvError(e) => write!(f, "DumpRecvError({e:?})"),
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
            ReceiveSignalError::DumpRecvError(e) => write!(f, "receive error (dump), {e}"),
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
            MaybeRecvError::DumpRecvError(e) => ReceiveSignalError::DumpRecvError(e),
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
        signalling_channel: &mut SignallingChannel<'_, L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: Signal,
    {
        let rejection = CommandRejectResponse::new_command_not_understood(self.request.get_identifier());

        let c_frame = rejection.into_control_frame(signalling_channel.inner.channel_id);

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
        signalling_channel: &mut SignallingChannel<'_, L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let c_frame = self.request.into_control_frame(signalling_channel.inner.channel_id);

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
        signalling_channel: &mut SignallingChannel<'_, L>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let response = DisconnectResponse {
            identifier: self.request.identifier,
            destination_cid: self.request.destination_cid,
            source_cid: self.request.source_cid,
        };

        let c_frame = response.into_control_frame(signalling_channel.inner.channel_id);

        signalling_channel.send(c_frame).await
    }
}

impl Request<LeCreditBasedConnectionRequest> {
    /// Create a LE Credit Based Connection
    ///
    /// This returns a `LeCreditBasedConnectionResponseBuilder` to configure the LE credit based
    /// conneciton response to this request and create a [`CreditBasedChannel`] for the connection.
    ///
    /// # Panic
    /// This method will panic if there are no more dynamic channels that can be allocated for a
    /// LE-U logical link.
    pub fn create_le_credit_based_connection<P: PhysicalLink>(
        &self,
        link: &LeULogicalLink<P>,
        initial_credits: u16,
    ) -> LeCreditBasedConnectionResponseBuilder<'_> {
        let destination_dyn_cid = link
            .shared_link
            .new_le_dyn_channel()
            .expect("failed to create a dynamic channel");

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
        signal_channel: &mut SignallingChannel<'_, L>,
        reason: LeCreditBasedConnectionResponseResult,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let response = LeCreditBasedConnectionResponse::new_rejected(self.request.identifier, reason);

        signal_channel
            .send(response.into_control_frame(signal_channel.inner.channel_id))
            .await
    }
}

/// Builder used for creating a *LE Credit Based Connection Response*
pub struct LeCreditBasedConnectionResponseBuilder<'a> {
    request: &'a LeCreditBasedConnectionRequest,
    destination_dyn_cid: crate::channel::id::DynChannelId<crate::LeULink>,
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
    pub async fn send_response<'a, L: LogicalLink>(
        self,
        signals_channel: &mut SignallingChannel<'a, L>,
    ) -> Result<CreditBasedChannel<'a, L>, <L::PhysicalLink as PhysicalLink>::SendErr> {
        use core::cmp::min;

        let response = LeCreditBasedConnectionResponse::new(
            self.request.identifier,
            self.destination_dyn_cid,
            LeCreditMtu::new(self.mtu),
            LeCreditMps::new(self.mps),
            self.initial_credits,
        );

        signals_channel
            .send(response.into_control_frame(signals_channel.inner.channel_id))
            .await?;

        let this_channel_id = crate::channel::ChannelDirection::Destination(ChannelIdentifier::Le(
            LeCid::DynamicallyAllocated(self.destination_dyn_cid),
        ));

        let peer_channel_id = crate::channel::ChannelDirection::Source(self.request.get_source_cid());

        let maximum_packet_size = min(self.mps, self.request.mps.get()).into();

        let maximum_transmission_size = min(self.mtu, self.request.mtu.get()).into();

        let initial_peer_credits = self.request.initial_credits.into();

        let new_channel = CreditBasedChannel::new(
            this_channel_id,
            peer_channel_id,
            signals_channel.inner.logical_link,
            maximum_packet_size,
            maximum_transmission_size,
            initial_peer_credits,
        );

        Ok(new_channel)
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
    pub fn create_le_credit_connection<'a, P: PhysicalLink>(
        &self,
        request: &LeCreditBasedConnectionRequest,
        link: &'a LeULogicalLink<P>,
    ) -> Result<CreditBasedChannel<'a, LeULogicalLink<P>>, LeCreditBasedConnectionResponseResult> {
        if let LeCreditBasedConnectionResponseResult::ConnectionSuccessful = self.get_result() {
            let this_channel_id = crate::channel::ChannelDirection::Source(request.get_source_cid());

            let peer_channel_id =
                crate::channel::ChannelDirection::Destination(self.response.get_destination_cid().unwrap());

            let maximum_packet_size = core::cmp::min(self.response.get_mps().unwrap().get(), request.mps.get()).into();

            let maximum_transmission_size =
                core::cmp::min(self.response.get_mtu().unwrap().get(), request.mtu.get()).into();

            let initial_peer_credits = self.response.get_initial_credits().unwrap().into();

            Ok(CreditBasedChannel::new(
                this_channel_id,
                peer_channel_id,
                &link,
                maximum_packet_size,
                maximum_transmission_size,
                initial_peer_credits,
            ))
        } else {
            Err(self.get_result())
        }
    }
}
